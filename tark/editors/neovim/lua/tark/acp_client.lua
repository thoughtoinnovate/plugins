-- ACP client for tark core (stdio JSON-RPC, Content-Length framing)

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
    current_request_id = nil,
}

M.config = {
    mode = 'ask',
    timeout_ms = 8000,
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

local function dispatch_notification(msg)
    local handler = M.state.handlers[msg.method]
    if handler then
        vim.schedule(function()
            pcall(handler, msg.params or {})
        end)
    end
end

local function resolve_binary()
    local binary = require('tark.binary')
    return binary.find(true)
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
        if msg then
            if msg.id ~= nil and M.state.pending[msg.id] then
                local cb = M.state.pending[msg.id]
                M.state.pending[msg.id] = nil
                vim.schedule(function()
                    cb(msg.error, msg.result)
                end)
            elseif msg.method then
                dispatch_notification(msg)
            end
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

local function on_exit()
    M.state.connected = false
    M.state.session_id = nil
    M.state.job_id = nil
    M.state.current_request_id = nil
    for id, cb in pairs(M.state.pending) do
        pcall(cb, { message = 'ACP process exited' }, nil)
        M.state.pending[id] = nil
    end
end

local function request(method, params, cb, timeout_ms)
    if not M.state.connected or not M.state.job_id then
        cb({ message = 'ACP not connected' }, nil)
        return
    end

    local id = M.state.next_id
    M.state.next_id = id + 1

    M.state.pending[id] = cb

    local payload = json_encode({
        jsonrpc = '2.0',
        id = id,
        method = method,
        params = params or {},
    })

    local frame = string.format('Content-Length: %d\r\nContent-Type: application/json\r\n\r\n%s', #payload, payload)
    local ok = pcall(vim.fn.chansend, M.state.job_id, frame)
    if not ok then
        M.state.pending[id] = nil
        cb({ message = 'Failed to write ACP request' }, nil)
        return
    end

    local timeout = timeout_ms or M.config.timeout_ms
    if timeout and timeout > 0 then
        vim.defer_fn(function()
            local pending = M.state.pending[id]
            if pending then
                M.state.pending[id] = nil
                pending({ message = 'ACP request timeout' }, nil)
            end
        end, timeout)
    end
end

local function parse_error(err)
    if not err then
        return nil
    end
    if type(err) == 'table' then
        local code = err.code or ((err.data or {}).code)
        local msg = err.message or vim.inspect(err)
        if code then
            return tostring(code) .. ': ' .. tostring(msg)
        end
        return msg
    end
    return tostring(err)
end

local function bootstrap(cb)
    request('initialize', {
        client = {
            name = 'tark.nvim',
            version = require('tark').version,
        },
        versions = { '2' },
    }, function(err)
        if err then
            cb(false, 'initialize failed: ' .. parse_error(err))
            return
        end

        request('session/create', {
            mode = M.config.mode,
            cwd = vim.fn.getcwd(),
        }, function(create_err, create_result)
            if create_err then
                cb(false, 'session/create failed: ' .. parse_error(create_err))
                return
            end

            M.state.session_id = create_result and create_result.session_id or nil
            if not M.state.session_id then
                cb(false, 'session/create returned no session_id')
                return
            end

            cb(true, nil)
        end)
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

    local bin = resolve_binary()
    if not bin then
        cb(false, 'No ACP-compatible tark binary found. Update/install tark and run :TarkVersion')
        return
    end

    if not M.state.job_id then
        local job_id = vim.fn.jobstart({ bin, 'acp', '--cwd', vim.fn.getcwd() }, {
            stdout_buffered = false,
            stderr_buffered = false,
            on_stdout = on_stdout,
            on_stderr = function(_, lines)
                if lines and #lines > 0 and lines[1] ~= '' then
                    vim.schedule(function()
                        vim.notify('tark ACP stderr: ' .. table.concat(lines, '\n'), vim.log.levels.DEBUG)
                    end)
                end
            end,
            on_exit = on_exit,
        })

        if type(job_id) ~= 'number' or job_id <= 0 then
            cb(false, 'Failed to start tark ACP process')
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

        local session_id = M.state.session_id
        request('context/update', {
            session_id = session_id,
            active_file = context and context.active_file or nil,
            cursor = context and context.cursor or nil,
            selection = context and context.selection or nil,
            active_excerpt = context and context.active_excerpt or nil,
            buffers = context and context.buffers or {},
        }, function(ctx_err)
            if ctx_err then
                cb(false, 'context/update failed: ' .. parse_error(ctx_err))
                return
            end

            request('session/send_message', {
                session_id = session_id,
                message = message,
            }, function(msg_err, result)
                if msg_err then
                    cb(false, 'session/send_message failed: ' .. parse_error(msg_err))
                    return
                end
                M.state.current_request_id = result and result.request_id or nil
                cb(true, result)
            end)
        end)
    end)
end

function M.set_mode(mode, cb)
    M.ensure_started(function(ok, err)
        if not ok then
            cb(false, err)
            return
        end

        request('session/set_mode', {
            session_id = M.state.session_id,
            mode = mode,
        }, function(set_err, result)
            if set_err then
                cb(false, parse_error(set_err))
                return
            end
            M.config.mode = result.mode or mode
            cb(true, result)
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
        session_id = M.state.session_id,
        request_id = M.state.current_request_id,
    }, function(err, result)
        if cb then
            if err then
                cb(false, parse_error(err))
            else
                cb(true, result)
            end
        end
    end)
end

function M.respond_approval(decision, params, cb)
    if not M.state.session_id then
        cb(false, 'No active ACP session')
        return
    end

    request('approval/respond', {
        session_id = M.state.session_id,
        request_id = params.request_id,
        interaction_id = params.interaction_id,
        decision = decision,
    }, function(err, result)
        if err then
            cb(false, parse_error(err))
            return
        end
        cb(true, result)
    end)
end

function M.respond_questionnaire(params, cancelled, answers, cb)
    if not M.state.session_id then
        cb(false, 'No active ACP session')
        return
    end

    request('questionnaire/respond', {
        session_id = M.state.session_id,
        request_id = params.request_id,
        interaction_id = params.interaction_id,
        cancelled = cancelled,
        answers = answers or {},
    }, function(err, result)
        if err then
            cb(false, parse_error(err))
            return
        end
        cb(true, result)
    end)
end

function M.close()
    if M.state.job_id then
        pcall(vim.fn.jobstop, M.state.job_id)
    end
    on_exit()
end

return M
