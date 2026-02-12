-- ACP client for tark core (stdio JSON-RPC)

local M = {}

M.state = {
    job_id = nil,
    session_id = nil,
    next_id = 1,
    pending = {},
    handlers = {},
    connected = false,
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
    return binary.find()
end

local function on_stdout(_, data)
    if not data then
        return
    end

    for _, line in ipairs(data) do
        if line and line ~= '' then
            local msg = json_decode(line)
            if msg and msg.id ~= nil and M.state.pending[msg.id] then
                local cb = M.state.pending[msg.id]
                M.state.pending[msg.id] = nil
                vim.schedule(function()
                    cb(msg.error, msg.result)
                end)
            elseif msg and msg.method then
                dispatch_notification(msg)
            end
        end
    end
end

local function on_exit()
    M.state.connected = false
    M.state.session_id = nil
    M.state.job_id = nil
    M.state.pending = {}
end

local function request(method, params, cb, timeout_ms)
    if not M.state.connected or not M.state.job_id then
        cb({ message = 'ACP not connected' }, nil)
        return
    end

    local id = M.state.next_id
    M.state.next_id = id + 1

    M.state.pending[id] = cb

    local payload = {
        jsonrpc = '2.0',
        id = id,
        method = method,
        params = params or {},
    }

    local ok = pcall(vim.fn.chansend, M.state.job_id, json_encode(payload) .. '\n')
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
        return err.message or vim.inspect(err)
    end
    return tostring(err)
end

local function bootstrap(cb)
    request('initialize', {
        client = {
            name = 'tark.nvim',
            version = require('tark').version,
        },
        versions = { '1' },
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
        cb(false, 'tark binary not found. Run :TarkDownload')
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

function M.close()
    if M.state.job_id then
        pcall(vim.fn.jobstop, M.state.job_id)
    end
    on_exit()
end

return M
