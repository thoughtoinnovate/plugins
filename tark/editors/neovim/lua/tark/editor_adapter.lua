-- tark editor adapter server (HTTP, local-only)
-- Exposes editor capabilities for core tark via Editor Adapter API v1.

local M = {}

M.state = {
    server = nil,
    host = '127.0.0.1',
    port = nil,
    version = 'unknown',
}

M.config = {
    enabled = true,
    host = '127.0.0.1',
    port = 0,
    timeout_ms = 100,
}

local function json_decode(raw)
    if not raw or raw == '' then
        return {}
    end
    local ok, data = pcall(vim.fn.json_decode, raw)
    if ok and type(data) == 'table' then
        return data
    end
    return {}
end

local function json_encode(data)
    return vim.fn.json_encode(data)
end

local function safe_read_line(path, one_based_line)
    local bufnr = vim.fn.bufnr(path)
    if bufnr ~= -1 and vim.api.nvim_buf_is_loaded(bufnr) then
        local line = vim.api.nvim_buf_get_lines(bufnr, one_based_line - 1, one_based_line, false)[1]
        return line or ''
    end
    local f = io.open(path, 'r')
    if not f then
        return ''
    end
    local i = 1
    for line in f:lines() do
        if i == one_based_line then
            f:close()
            return line
        end
        i = i + 1
    end
    f:close()
    return ''
end

local function ensure_buf(path)
    local bufnr = vim.fn.bufnr(path, true)
    if bufnr == -1 then
        return nil
    end
    if not vim.api.nvim_buf_is_loaded(bufnr) then
        pcall(vim.fn.bufload, bufnr)
    end
    return bufnr
end

local function lsp_position_params(path, line, col)
    local bufnr = ensure_buf(path)
    if not bufnr then
        return nil, nil
    end
    return bufnr, {
        textDocument = { uri = vim.uri_from_bufnr(bufnr) },
        position = { line = line or 0, character = col or 0 },
    }
end

local function flatten_definition_result(result)
    if not result then
        return {}
    end
    if result.uri then
        return { result }
    end
    return result
end

local function location_to_json(loc)
    local uri = loc.uri or (loc.targetUri)
    local range = loc.range or loc.targetSelectionRange or loc.targetRange
    if not uri or not range then
        return nil
    end
    local path = vim.uri_to_fname(uri)
    local line = (range.start and range.start.line or 0) + 1
    local col = (range.start and range.start.character or 0) + 1
    return {
        file = path,
        line = line - 1,
        col = col - 1,
        preview = safe_read_line(path, line),
    }
end

local function handle_definition(body)
    local path = body.file
    if not path or path == '' then
        return { locations = {} }
    end
    local bufnr, params = lsp_position_params(path, body.line, body.col)
    if not bufnr then
        return { locations = {} }
    end
    local responses = vim.lsp.buf_request_sync(bufnr, 'textDocument/definition', params, M.config.timeout_ms) or {}
    local out = {}
    for _, resp in pairs(responses) do
        local items = flatten_definition_result(resp.result)
        for _, item in ipairs(items) do
            local converted = location_to_json(item)
            if converted then
                table.insert(out, converted)
            end
        end
    end
    return { locations = out }
end

local function handle_references(body)
    local path = body.file
    if not path or path == '' then
        return { references = {} }
    end
    local bufnr, params = lsp_position_params(path, body.line, body.col)
    if not bufnr then
        return { references = {} }
    end
    params.context = { includeDeclaration = true }
    local responses = vim.lsp.buf_request_sync(bufnr, 'textDocument/references', params, M.config.timeout_ms) or {}
    local out = {}
    for _, resp in pairs(responses) do
        local items = resp.result or {}
        for _, item in ipairs(items) do
            local converted = location_to_json(item)
            if converted then
                table.insert(out, converted)
            end
        end
    end
    return { references = out }
end

local function handle_hover(body)
    local path = body.file
    if not path or path == '' then
        return { hover = nil }
    end
    local bufnr, params = lsp_position_params(path, body.line, body.col)
    if not bufnr then
        return { hover = nil }
    end
    local responses = vim.lsp.buf_request_sync(bufnr, 'textDocument/hover', params, M.config.timeout_ms) or {}
    for _, resp in pairs(responses) do
        if resp.result and resp.result.contents then
            local lines = vim.lsp.util.convert_input_to_markdown_lines(resp.result.contents)
            lines = vim.lsp.util.trim_empty_lines(lines)
            return { hover = table.concat(lines, '\n') }
        end
    end
    return { hover = nil }
end

local function add_symbols(result, out)
    if type(result) ~= 'table' then
        return
    end
    for _, item in ipairs(result) do
        local name = item.name
        local kind = tostring(item.kind or '')
        local detail = item.detail
        local line = 0
        if item.selectionRange and item.selectionRange.start then
            line = item.selectionRange.start.line
        elseif item.location and item.location.range and item.location.range.start then
            line = item.location.range.start.line
        elseif item.range and item.range.start then
            line = item.range.start.line
        end

        if name then
            table.insert(out, {
                name = name,
                kind = kind,
                line = line,
                detail = detail,
            })
        end

        if item.children then
            add_symbols(item.children, out)
        end
    end
end

local function handle_symbols(body)
    local path = body.file
    if not path or path == '' then
        return { symbols = {} }
    end
    local bufnr = ensure_buf(path)
    if not bufnr then
        return { symbols = {} }
    end
    local params = { textDocument = { uri = vim.uri_from_bufnr(bufnr) } }
    local responses = vim.lsp.buf_request_sync(bufnr, 'textDocument/documentSymbol', params, M.config.timeout_ms) or {}
    local out = {}
    for _, resp in pairs(responses) do
        add_symbols(resp.result or {}, out)
    end
    return { symbols = out }
end

local function handle_diagnostics(body)
    local filter_path = body.path
    local diagnostics = {}
    local severity_map = {
        [vim.diagnostic.severity.ERROR] = 'error',
        [vim.diagnostic.severity.WARN] = 'warning',
        [vim.diagnostic.severity.INFO] = 'info',
        [vim.diagnostic.severity.HINT] = 'hint',
    }

    for _, diag in ipairs(vim.diagnostic.get()) do
        local path = vim.api.nvim_buf_get_name(diag.bufnr)
        if path ~= '' and (not filter_path or path:match(filter_path .. '$')) then
            table.insert(diagnostics, {
                path = path,
                line = diag.lnum + 1,
                col = diag.col + 1,
                severity = severity_map[diag.severity] or 'error',
                message = diag.message,
                source = diag.source,
            })
        end
    end

    return { diagnostics = diagnostics }
end

local function handle_cursor()
    local path = vim.api.nvim_buf_get_name(0)
    local cursor = vim.api.nvim_win_get_cursor(0)
    return { path = path, line = cursor[1], col = cursor[2] + 1 }
end

local function handle_buffers()
    local buffers = {}
    for _, bufnr in ipairs(vim.api.nvim_list_bufs()) do
        if vim.api.nvim_buf_is_loaded(bufnr) then
            local name = vim.api.nvim_buf_get_name(bufnr)
            local bt = vim.bo[bufnr].buftype
            if bt == '' and name ~= '' then
                table.insert(buffers, {
                    id = bufnr,
                    path = name,
                    name = vim.fn.fnamemodify(name, ':t'),
                    modified = vim.bo[bufnr].modified,
                    filetype = vim.bo[bufnr].filetype,
                })
            end
        end
    end
    return { buffers = buffers }
end

local function handle_buffer_content(body)
    local path = body.path
    if not path then
        return { error = 'path required' }
    end

    local bufnr = vim.fn.bufnr(path)
    local content = nil
    if bufnr ~= -1 and vim.api.nvim_buf_is_loaded(bufnr) then
        local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
        content = table.concat(lines, '\n')
    else
        local f = io.open(path, 'r')
        if not f then
            return { error = 'File not found: ' .. path }
        end
        content = f:read('*a')
        f:close()
    end

    local max_size = 100 * 1024
    local truncated = #content > max_size
    if truncated then
        content = content:sub(1, max_size)
    end

    return { path = path, content = content, truncated = truncated }
end

local function handle_open_file(body)
    local path = body.path
    if not path then
        return { success = false, error = 'path required' }
    end

    vim.schedule(function()
        local target_win = nil
        for _, win in ipairs(vim.api.nvim_list_wins()) do
            local buf = vim.api.nvim_win_get_buf(win)
            if vim.bo[buf].buftype ~= 'terminal' then
                target_win = win
                break
            end
        end

        if target_win then
            vim.api.nvim_set_current_win(target_win)
        end

        vim.cmd('edit ' .. vim.fn.fnameescape(path))
        if body.line and body.line > 0 then
            local col = (body.col and body.col > 0) and (body.col - 1) or 0
            pcall(vim.api.nvim_win_set_cursor, 0, { body.line, col })
        end
    end)

    return { success = true }
end

local routes = {
    ['POST /editor/definition'] = handle_definition,
    ['POST /editor/references'] = handle_references,
    ['POST /editor/hover'] = handle_hover,
    ['POST /editor/symbols'] = handle_symbols,
    ['POST /editor/diagnostics'] = handle_diagnostics,
    ['GET /editor/cursor'] = handle_cursor,
    ['GET /editor/buffers'] = handle_buffers,
    ['POST /editor/buffer-content'] = handle_buffer_content,
    ['POST /editor/open-file'] = handle_open_file,
    ['GET /editor/health'] = function()
        return {
            status = 'ok',
            adapter = 'tark.nvim',
            api_version = 'v1',
            version = M.state.version,
        }
    end,
}

local function build_response(code, payload)
    local body = json_encode(payload)
    return table.concat({
        'HTTP/1.1 ' .. tostring(code) .. ' OK',
        'Content-Type: application/json',
        'Content-Length: ' .. tostring(#body),
        'Connection: close',
        '',
        body,
    }, '\r\n')
end

local function parse_request(raw)
    local header_end = raw:find('\r\n\r\n', 1, true)
    if not header_end then
        return nil
    end

    local head = raw:sub(1, header_end - 1)
    local body = raw:sub(header_end + 4)
    local first_line = head:match('([^\r\n]+)')
    if not first_line then
        return nil
    end

    local method, path = first_line:match('^(%u+)%s+([^%s]+)')
    if not method or not path then
        return nil
    end

    local content_length = tonumber(head:lower():match('content%-length:%s*(%d+)') or '0')
    if #body < content_length then
        return nil
    end

    if content_length > 0 then
        body = body:sub(1, content_length)
    else
        body = ''
    end

    return {
        method = method,
        path = path,
        body = json_decode(body),
    }
end

local function handle_client(client)
    local buffer = ''
    client:read_start(function(err, data)
        if err then
            pcall(client.close, client)
            return
        end

        if not data then
            pcall(client.close, client)
            return
        end

        buffer = buffer .. data
        local req = parse_request(buffer)
        if not req then
            return
        end

        local key = req.method .. ' ' .. req.path
        local handler = routes[key]
        local status = 200
        local payload

        if handler then
            local ok, result = pcall(handler, req.body)
            if ok then
                payload = result
            else
                status = 500
                payload = { error = tostring(result) }
            end
        else
            status = 404
            payload = { error = 'Unknown endpoint: ' .. key }
        end

        local response = build_response(status, payload)
        client:write(response)
        pcall(client.shutdown, client)
        pcall(client.close, client)
    end)
end

function M.start()
    if not M.config.enabled then
        return nil
    end
    if M.state.server then
        return M.state.port
    end

    local server = vim.loop.new_tcp()
    if not server then
        return nil
    end

    local ok, err = pcall(function()
        server:bind(M.config.host, M.config.port)
        server:listen(128, function(listen_err)
            if listen_err then
                return
            end
            local client = vim.loop.new_tcp()
            server:accept(client)
            handle_client(client)
        end)
    end)

    if not ok then
        pcall(server.close, server)
        vim.notify('tark: failed to start editor adapter: ' .. tostring(err), vim.log.levels.WARN)
        return nil
    end

    local sock = server:getsockname()
    M.state.server = server
    M.state.host = M.config.host
    M.state.port = sock and sock.port or M.config.port
    return M.state.port
end

function M.stop()
    if M.state.server then
        pcall(M.state.server.close, M.state.server)
        M.state.server = nil
    end
    M.state.port = nil
end

function M.context()
    if not M.state.port then
        return nil
    end

    return {
        adapter_id = 'tark.nvim',
        adapter_version = M.state.version,
        api_version = 'v1',
        endpoint = {
            base_url = string.format('http://%s:%d', M.state.host, M.state.port),
        },
        capabilities = {
            definition = true,
            references = true,
            hover = true,
            symbols = true,
            diagnostics = true,
            open_file = true,
            cursor = true,
            buffers = true,
            buffer_content = true,
        },
    }
end

function M.setup(config, version)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})
    M.state.version = version or M.state.version

    if M.config.enabled then
        M.start()
        vim.api.nvim_create_autocmd('VimLeavePre', {
            callback = function()
                M.stop()
            end,
        })
    end
end

return M
