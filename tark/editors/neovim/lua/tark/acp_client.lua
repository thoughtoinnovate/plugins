-- Generic ACP client over stdio JSON-RPC (Content-Length framing)

local M = {}

M.state = {
    job_id = nil,
    session_id = nil,
    next_id = 1,
    pending = {},
    handlers = {},
    connected = false,
    read_buffer = '',
    expected_len = nil,
    busy = false,
    send_queue = {},
    draining = false,
}

M.config = {
    timeout_ms = 15000,
    command = nil,
    args = nil,
    env = {},
    cwd = nil,
    protocol_version = 1,
    client_capabilities = {
        fs = { readTextFile = false, writeTextFile = false },
        terminal = false,
    },
    profile = 'generic',
}

local function json_decode(raw)
    local ok, val = pcall(vim.fn.json_decode, raw)
    if ok then
        return val
    end
    return nil
end

local function json_encode(val)
    return vim.fn.json_encode(val)
end

local function sanitize_text(value)
    local s = tostring(value or '')
    s = s:gsub('[%z\r]', ' ')
    return s
end

local function parse_error(err)
    if not err then
        return nil
    end
    if type(err) == 'table' then
        local data = err.data or {}
        local code = data.code or err.code or 'unknown_error'
        local message = sanitize_text(err.message or data.message or vim.inspect(err))
        return {
            code = code,
            message = message,
        }
    end
    return {
        code = 'unknown_error',
        message = sanitize_text(err),
    }
end

local function emit(method, params)
    local handler = M.state.handlers[method]
    if handler then
        vim.schedule(function()
            pcall(handler, params or {})
        end)
    end
end

local function emit_queue_update()
    emit('client/queue', { size = #M.state.send_queue })
end

local function normalize_request_error(reason)
    if reason == 'timeout' then
        return { code = 'request_timeout', message = 'ACP request timeout' }
    end
    if reason == 'process_exit' then
        return { code = 'process_exit', message = 'ACP process exited' }
    end
    if reason == 'protocol_error' then
        return { code = 'protocol_error', message = 'ACP protocol decode failure' }
    end
    return { code = 'unknown_error', message = tostring(reason or 'ACP request failed') }
end

local function send_frame(payload_table)
    if not M.state.connected or not M.state.job_id then
        return false
    end
    local payload = json_encode(payload_table)
    local frame = string.format('Content-Length: %d\r\nContent-Type: application/json\r\n\r\n%s', #payload, payload)
    return pcall(vim.fn.chansend, M.state.job_id, frame)
end

local function fail_pending_requests(reason)
    local err = normalize_request_error(reason)
    for id, cb in pairs(M.state.pending) do
        pcall(cb, { code = err.code, message = err.message, data = { code = err.code } }, nil)
        M.state.pending[id] = nil
    end
end

local function on_exit()
    M.state.connected = false
    M.state.session_id = nil
    M.state.job_id = nil
    M.state.busy = false
    M.state.read_buffer = ''
    M.state.expected_len = nil
    fail_pending_requests('process_exit')
    emit('session/disconnected', { code = 'process_exit' })
end

local function request(method, params, cb, timeout_ms)
    if not M.state.connected or not M.state.job_id then
        cb({ code = 'not_connected', message = 'ACP not connected', data = { code = 'not_connected' } }, nil)
        return
    end

    local id = M.state.next_id
    M.state.next_id = id + 1
    M.state.pending[id] = cb

    local ok = send_frame({
        jsonrpc = '2.0',
        id = id,
        method = method,
        params = params or {},
    })

    if not ok then
        M.state.pending[id] = nil
        cb({ code = 'write_failed', message = 'Failed to write ACP request', data = { code = 'write_failed' } }, nil)
        return
    end

    local timeout = timeout_ms or M.config.timeout_ms
    if timeout and timeout > 0 then
        vim.defer_fn(function()
            local pending = M.state.pending[id]
            if pending then
                M.state.pending[id] = nil
                local err = normalize_request_error('timeout')
                pending({ code = err.code, message = err.message, data = { code = err.code } }, nil)
            end
        end, timeout)
    end
end

local function build_permission_outcome(option_id)
    if not option_id or option_id == '' then
        return { outcome = 'cancelled' }
    end
    return { outcome = 'selected', optionId = option_id }
end

local function write_response(id, result, err)
    local payload = {
        jsonrpc = '2.0',
        id = id,
    }
    if err then
        payload.error = err
    else
        payload.result = result or {}
    end
    send_frame(payload)
end

local function handle_server_request(msg)
    local method = msg.method
    local params = msg.params or {}

    if method == 'session/request_permission' then
        local handled = false
        local handler = M.state.handlers['session/request_permission']
        if handler then
            vim.schedule(function()
                local ok = pcall(handler, params, function(option_id)
                    write_response(msg.id, { outcome = build_permission_outcome(option_id) }, nil)
                end)
                if not ok then
                    write_response(msg.id, { outcome = { outcome = 'cancelled' } }, nil)
                end
            end)
            handled = true
        end
        if not handled then
            write_response(msg.id, { outcome = { outcome = 'cancelled' } }, nil)
        end
        return
    end

    if method == 'fs/read_text_file' and M.config.client_capabilities.fs.readTextFile then
        local path = params.path
        local lines = vim.fn.readfile(path)
        local content = table.concat(lines, '\n')
        write_response(msg.id, { content = content }, nil)
        return
    end

    if method == 'fs/write_text_file' and M.config.client_capabilities.fs.writeTextFile then
        local path = params.path
        local content = params.content or ''
        local out = vim.split(content, '\n', { plain = true, trimempty = false })
        vim.fn.writefile(out, path)
        write_response(msg.id, { ok = true }, nil)
        return
    end

    write_response(msg.id, nil, { code = -32601, message = 'Method not found' })
end

local function parse_frames(chunk)
    if not chunk or chunk == '' then
        return
    end

    M.state.read_buffer = M.state.read_buffer .. chunk

    while true do
        if not M.state.expected_len then
            local header_end = M.state.read_buffer:find('\r\n\r\n', 1, true)
            local delim_len = 4
            if not header_end then
                header_end = M.state.read_buffer:find('\n\n', 1, true)
                delim_len = 2
            end

            if not header_end then
                return
            end

            local headers = M.state.read_buffer:sub(1, header_end - 1)
            local len = headers:match('[Cc]ontent%-[Ll]ength:%s*(%d+)')
            if not len then
                M.state.read_buffer = M.state.read_buffer:sub(header_end + delim_len)
                emit('error/event', normalize_request_error('protocol_error'))
                return
            end

            M.state.expected_len = tonumber(len)
            M.state.read_buffer = M.state.read_buffer:sub(header_end + delim_len)
        end

        if not M.state.expected_len or #M.state.read_buffer < M.state.expected_len then
            return
        end

        local body = M.state.read_buffer:sub(1, M.state.expected_len)
        M.state.read_buffer = M.state.read_buffer:sub(M.state.expected_len + 1)
        M.state.expected_len = nil

        local msg = json_decode(body)
        if not msg then
            emit('error/event', normalize_request_error('protocol_error'))
        elseif msg.id ~= nil and M.state.pending[msg.id] then
            local cb = M.state.pending[msg.id]
            M.state.pending[msg.id] = nil
            vim.schedule(function()
                cb(msg.error, msg.result)
            end)
        elseif msg.id ~= nil and msg.method then
            handle_server_request(msg)
        elseif msg.method then
            emit(msg.method, msg.params or {})
        end
    end
end

local function on_stdout(_, data)
    if not data then
        return
    end

    local chunks = {}
    for i, part in ipairs(data) do
        if part ~= nil then
            if i < #data then
                table.insert(chunks, part .. '\n')
            else
                table.insert(chunks, part)
            end
        end
    end

    parse_frames(table.concat(chunks, ''))
end

local function resolve_command()
    if M.config.command and M.config.command ~= '' then
        local args = M.config.args or {}
        local cmd = { M.config.command }
        for _, arg in ipairs(args) do
            table.insert(cmd, arg)
        end
        return cmd
    end

    local binary = require('tark.binary')
    local bin = binary.find(true)
    if not bin then
        return nil
    end

    return { bin, 'acp', '--cwd', M.config.cwd or vim.fn.getcwd() }
end

local function bootstrap(cb)
    request('initialize', {
        protocolVersion = M.config.protocol_version,
        clientCapabilities = M.config.client_capabilities,
        clientInfo = {
            name = 'tark.nvim',
            version = require('tark').version,
        },
    }, function(err)
        if err then
            local parsed = parse_error(err)
            cb(false, string.format('initialize failed: %s', parsed.message))
            return
        end

        request('session/new', {
            cwd = M.config.cwd or vim.fn.getcwd(),
            mcpServers = {},
        }, function(create_err, create_result)
            if create_err then
                local parsed = parse_error(create_err)
                cb(false, string.format('session/new failed: %s', parsed.message))
                return
            end

            M.state.session_id = create_result and (create_result.sessionId or create_result.session_id) or nil
            if not M.state.session_id then
                cb(false, 'session/new returned no sessionId')
                return
            end

            emit('session/started', {
                session_id = M.state.session_id,
                modes = create_result.modes,
                config_options = create_result.configOptions,
            })
            cb(true, nil)
        end)
    end)
end

local function queue_send(message, context, cb)
    table.insert(M.state.send_queue, {
        message = message,
        context = context,
        cb = cb,
        local_id = string.format('q-%d', vim.loop.hrtime()),
        created_at = vim.loop.now(),
    })
    emit_queue_update()
    cb(true, { queued = true, local_id = M.state.send_queue[#M.state.send_queue].local_id })
end

local function context_to_text(context)
    if not context then
        return ''
    end

    local lines = {}
    if context.active_file or context.cursor or context.selection or context.active_excerpt then
        table.insert(lines, '[Editor Context]')
        if context.active_file then
            table.insert(lines, 'Active file: ' .. context.active_file)
        end
        if context.cursor then
            table.insert(lines, string.format('Cursor: line %s, col %s', context.cursor.line, context.cursor.col))
        end
        if context.active_excerpt and context.active_excerpt ~= '' then
            table.insert(lines, 'Active excerpt:')
            table.insert(lines, '```')
            table.insert(lines, context.active_excerpt)
            table.insert(lines, '```')
        end
        if context.selection and context.selection.text and context.selection.text ~= '' then
            table.insert(lines, 'Selection:')
            table.insert(lines, '```')
            table.insert(lines, context.selection.text)
            table.insert(lines, '```')
        end
        if context.buffers and #context.buffers > 0 then
            table.insert(lines, 'Open buffers:')
            for _, b in ipairs(context.buffers) do
                table.insert(lines, '- ' .. (b.name or b.path or '<unknown>'))
            end
        end
        table.insert(lines, '')
        table.insert(lines, '[User Request]')
    end

    return table.concat(lines, '\n')
end

local function send_message_once(message, context, cb)
    local pref = context_to_text(context)
    local text = message
    if pref ~= '' then
        text = pref .. '\n' .. message
    end

    M.state.busy = true
    emit('session/busy', { busy = true })

    request('session/prompt', {
        sessionId = M.state.session_id,
        prompt = {
            { type = 'text', text = text },
        },
    }, function(msg_err, result)
        M.state.busy = false
        emit('session/busy', { busy = false })

        if msg_err then
            local parsed = parse_error(msg_err)
            cb(false, string.format('session/prompt failed: %s', parsed.message))
            vim.defer_fn(function()
                M.try_drain_queue()
            end, 10)
            return
        end

        cb(true, result or { stopReason = 'end_turn' })
        vim.defer_fn(function()
            M.try_drain_queue()
        end, 10)
    end)
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})
end

function M.on(method, handler)
    M.state.handlers[method] = handler
end

function M.ensure_started(cb)
    if M.state.connected and M.state.session_id then
        cb(true, nil)
        return
    end

    local cmd = resolve_command()
    if not cmd then
        cb(false, 'No ACP-compatible command found. Configure acp.command or install tark with ACP support.')
        return
    end

    if not M.state.job_id then
        local opts = {
            stdout_buffered = false,
            stderr_buffered = false,
            on_stdout = on_stdout,
            on_stderr = function(_, lines)
                if lines and #lines > 0 and lines[1] ~= '' then
                    vim.schedule(function()
                        vim.notify('ACP stderr: ' .. table.concat(lines, '\n'), vim.log.levels.DEBUG)
                    end)
                end
            end,
            on_exit = on_exit,
            cwd = M.config.cwd or vim.fn.getcwd(),
            env = M.config.env,
        }
        local job_id = vim.fn.jobstart(cmd, opts)

        if type(job_id) ~= 'number' or job_id <= 0 then
            cb(false, 'Failed to start ACP process')
            return
        end

        M.state.job_id = job_id
        M.state.connected = true
    end

    bootstrap(cb)
end

function M.send_message(message, context, cb)
    M.ensure_started(function(ok, err)
        if not ok then
            cb(false, err)
            return
        end

        if M.state.busy then
            queue_send(message, context, cb)
            return
        end

        send_message_once(message, context, cb)
    end)
end

function M.try_drain_queue()
    if M.state.draining or M.state.busy then
        return
    end
    if #M.state.send_queue == 0 then
        emit_queue_update()
        return
    end

    local item = table.remove(M.state.send_queue, 1)
    emit_queue_update()

    M.state.draining = true
    M.send_message(item.message, item.context, function(ok, result_or_err)
        M.state.draining = false
        if item.cb then
            item.cb(ok, result_or_err)
        end
        if ok and type(result_or_err) == 'table' and result_or_err.queued then
            return
        end
        vim.defer_fn(function()
            M.try_drain_queue()
        end, 10)
    end)
end

function M.set_mode(mode, cb)
    M.ensure_started(function(ok, err)
        if not ok then
            cb(false, err)
            return
        end

        request('session/set_mode', {
            sessionId = M.state.session_id,
            modeId = mode,
        }, function(set_err, result)
            if set_err then
                local parsed = parse_error(set_err)
                cb(false, parsed.message)
                return
            end
            cb(true, result or {})
        end)
    end)
end

function M.set_config_option(config_id, value, cb)
    M.ensure_started(function(ok, err)
        if not ok then
            cb(false, err)
            return
        end

        request('session/set_config_option', {
            sessionId = M.state.session_id,
            configId = config_id,
            value = value,
        }, function(set_err, result)
            if set_err then
                local parsed = parse_error(set_err)
                cb(false, parsed.message)
                return
            end
            cb(true, result or {})
        end)
    end)
end

function M.cancel(cb)
    if not M.state.session_id then
        if cb then
            cb(false, 'No active ACP session')
        end
        return
    end

    request('session/cancel', {
        sessionId = M.state.session_id,
    }, function(err, result)
        if err then
            local parsed = parse_error(err)
            if cb then
                cb(false, parsed.message)
            end
            return
        end
        M.state.busy = false
        if cb then
            cb(true, result or { cancelled = true })
        end
        vim.defer_fn(function()
            M.try_drain_queue()
        end, 10)
    end)
end

-- Legacy compatibility wrappers
function M.respond_approval(_decision, _params, cb)
    if cb then
        cb(false, 'Legacy approval/respond is not supported in generic ACP mode')
    end
end

function M.respond_questionnaire(_params, _cancelled, _answers, cb)
    if cb then
        cb(false, 'Legacy questionnaire/respond is not supported in generic ACP mode')
    end
end

function M.select_permission_option(option_id)
    emit('session/permission_select', { option_id = option_id })
end

function M.queue_size()
    return #M.state.send_queue
end

function M.close()
    if M.state.job_id then
        pcall(vim.fn.jobstop, M.state.job_id)
    end
    on_exit()
end

return M
