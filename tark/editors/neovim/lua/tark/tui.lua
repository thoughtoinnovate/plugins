-- tark TUI integration
-- Opens tark chat in a terminal and can inject prompts from Neovim selections

local M = {}

-- State
M.state = {
    buf = nil,           -- Terminal buffer
    win = nil,           -- Terminal window
    job_id = nil,        -- Terminal job
    socket_path = nil,   -- Unix socket path
    socket_server = nil, -- Socket server handle
    client = nil,        -- Connected TUI client
}

-- Config (set by setup)
M.config = {
    binary = nil,
    window = {
        position = 'right',
        width = 0.4,
        height = 0.5,
    },
}

-- ============================================================================
-- Helpers
-- ============================================================================

local function get_socket_path()
    local tmpdir = os.getenv('TMPDIR') or os.getenv('TMP') or '/tmp'
    return string.format('%s/tark-nvim-%d.sock', tmpdir, vim.fn.getpid())
end

local function json_encode(data)
    return vim.fn.json_encode(data)
end

local function json_decode(str)
    local ok, result = pcall(vim.fn.json_decode, str)
    return ok and result or nil
end

-- ============================================================================
-- RPC: Send messages to TUI
-- ============================================================================

local function send(msg)
    if M.state.client then
        local ok = pcall(function()
            M.state.client:write(json_encode(msg) .. '\n')
        end)
        return ok
    end
    return false
end

local function respond(id, result)
    send({ type = 'response', id = id, result = result })
end

local function respond_error(id, message)
    send({ type = 'error', id = id, message = message })
end

-- ============================================================================
-- RPC: Handle requests from TUI
-- ============================================================================

local handlers = {}

-- Open a file in Neovim
handlers.open_file = function(msg, id)
    local path = msg.path
    if not path then
        respond_error(id, 'path required')
        return
    end
    
    vim.schedule(function()
        -- Find a non-terminal window to open the file
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
        
        if msg.line and msg.line > 0 then
            local col = (msg.col and msg.col > 0) and (msg.col - 1) or 0
            pcall(vim.api.nvim_win_set_cursor, 0, { msg.line, col })
        end
        
        respond(id, { success = true })
    end)
end

-- Get list of open buffers
handlers.get_buffers = function(_, id)
    vim.schedule(function()
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
        respond(id, { buffers = buffers })
    end)
end

-- Get buffer content
handlers.get_buffer_content = function(msg, id)
    local path = msg.path
    if not path then
        respond_error(id, 'path required')
        return
    end
    
    vim.schedule(function()
        local bufnr = vim.fn.bufnr(path)
        local content
        
        if bufnr ~= -1 and vim.api.nvim_buf_is_loaded(bufnr) then
            local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
            content = table.concat(lines, '\n')
        else
            local f = io.open(path, 'r')
            if f then
                content = f:read('*a')
                f:close()
            else
                respond_error(id, 'File not found: ' .. path)
                return
            end
        end
        
        -- Truncate large files
        local max_size = 100 * 1024
        local truncated = #content > max_size
        if truncated then
            content = content:sub(1, max_size)
        end
        
        respond(id, { path = path, content = content, truncated = truncated })
    end)
end

-- Get diagnostics (LSP errors/warnings)
handlers.get_diagnostics = function(msg, id)
    vim.schedule(function()
        local filter_path = msg.path
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
        
        respond(id, { diagnostics = diagnostics })
    end)
end

-- Get cursor position
handlers.get_cursor = function(_, id)
    vim.schedule(function()
        local path = vim.api.nvim_buf_get_name(0)
        local cursor = vim.api.nvim_win_get_cursor(0)
        respond(id, { path = path, line = cursor[1], col = cursor[2] + 1 })
    end)
end

-- Ping/pong for health check
handlers.ping = function(msg, _)
    send({ type = 'pong', seq = msg.seq })
end

-- Route incoming messages
local function handle_message(msg)
    if not msg or not msg.type then return end
    
    local id = nil
    local cmd = msg
    
    -- Unwrap request envelope
    if msg.type == 'request' then
        id = msg.id
        cmd = msg.command or {}
    end
    
    local handler = handlers[cmd.type]
    if handler then
        handler(cmd, id)
    elseif id then
        respond_error(id, 'Unknown command: ' .. tostring(cmd.type))
    end
end

-- ============================================================================
-- Socket Server
-- ============================================================================

local function start_socket_server()
    local socket_path = get_socket_path()
    M.state.socket_path = socket_path
    
    -- Remove old socket
    os.remove(socket_path)
    
    local server = vim.loop.new_pipe(false)
    if not server then
        vim.notify('tark: Failed to create socket', vim.log.levels.ERROR)
        return false
    end
    
    local ok, err = pcall(function() server:bind(socket_path) end)
    if not ok then
        vim.notify('tark: Socket bind failed: ' .. tostring(err), vim.log.levels.ERROR)
        server:close()
        return false
    end
    
    server:listen(1, function(listen_err)
        if listen_err then return end
        
        local client = vim.loop.new_pipe(false)
        server:accept(client)
        M.state.client = client
        
        local buffer = ''
        client:read_start(function(read_err, data)
            if read_err or not data then
                vim.schedule(function() M.state.client = nil end)
                return
            end
            
            buffer = buffer .. data
            while true do
                local nl = buffer:find('\n')
                if not nl then break end
                
                local line = buffer:sub(1, nl - 1)
                buffer = buffer:sub(nl + 1)
                
                if line ~= '' then
                    local msg = json_decode(line)
                    if msg then
                        vim.schedule(function() handle_message(msg) end)
                    end
                end
            end
        end)
        
        -- Send initial context
        vim.schedule(function()
            local path = vim.api.nvim_buf_get_name(0)
            if path ~= '' then
                send({ type = 'buffer_entered', path = path, filetype = vim.bo.filetype })
            end
        end)
    end)
    
    M.state.socket_server = server
    return true
end

local function stop_socket_server()
    if M.state.client then
        M.state.client:close()
        M.state.client = nil
    end
    if M.state.socket_server then
        M.state.socket_server:close()
        M.state.socket_server = nil
    end
    if M.state.socket_path then
        os.remove(M.state.socket_path)
        M.state.socket_path = nil
    end
end

-- ============================================================================
-- Terminal Window Management
-- ============================================================================

local function get_binary_path()
    if M.config.binary and vim.fn.executable(M.config.binary) == 1 then
        return M.config.binary
    end
    
    -- Check data directory
    local data_bin = vim.fn.stdpath('data') .. '/tark/tark'
    if vim.fn.filereadable(data_bin) == 1 then
        return data_bin
    end
    
    -- Check PATH
    if vim.fn.executable('tark') == 1 then
        return 'tark'
    end
    
    return nil
end

local function build_editor_context_env()
    local ok, adapter = pcall(require, 'tark.editor_adapter')
    if not ok or not adapter or type(adapter.context) ~= 'function' then
        return nil
    end

    local context = adapter.context()
    if not context then
        return nil
    end

    local encoded = vim.fn.json_encode(context)
    return 'TARK_EDITOR_CONTEXT_JSON=' .. vim.fn.shellescape(encoded)
end

local function calculate_size(value, total)
    if value <= 1 then
        return math.floor(total * value)
    end
    return math.floor(value)
end

-- Prevent concurrent opens (global across all requires)
if not _G._tark_opening then
    _G._tark_opening = false
end

function M.open()
    -- Prevent concurrent opens
    if _G._tark_opening then
        return
    end
    _G._tark_opening = true
    
    local function done()
        _G._tark_opening = false
    end
    
    -- Find ALL existing tark windows/buffers and close duplicates
    local tark_wins = {}
    for _, win in ipairs(vim.api.nvim_list_wins()) do
        local buf = vim.api.nvim_win_get_buf(win)
        local name = vim.api.nvim_buf_get_name(buf)
        local buftype = vim.bo[buf].buftype
        -- Check for tark buffer by name or by being a terminal with tark job
        if name:match('tark://') or name:match('tark$') or 
           (buftype == 'terminal' and name:match('tark')) then
            table.insert(tark_wins, { win = win, buf = buf })
        end
    end
    
    -- If we found tark windows, focus the first and close duplicates
    if #tark_wins > 0 then
        for i = 2, #tark_wins do
            pcall(vim.api.nvim_win_close, tark_wins[i].win, true)
        end
        M.state.win = tark_wins[1].win
        M.state.buf = tark_wins[1].buf
        vim.api.nvim_set_current_win(M.state.win)
        vim.cmd('startinsert')
        done()
        return
    end
    
    -- Also check state
    if M.state.win and vim.api.nvim_win_is_valid(M.state.win) then
        vim.api.nvim_set_current_win(M.state.win)
        vim.cmd('startinsert')
        done()
        return
    end
    
    -- Clean up any stale state
    M.cleanup()
    
    -- Find binary
    local bin = get_binary_path()
    if not bin then
        vim.notify('tark: Binary not found. Run :TarkDownload', vim.log.levels.ERROR)
        done()
        return
    end
    
    -- Start socket server
    if not start_socket_server() then
        done()
        return
    end
    
    -- Build command
    local cmd_parts = {}
    local editor_env = build_editor_context_env()
    if editor_env then
        table.insert(cmd_parts, editor_env)
    end
    table.insert(cmd_parts, vim.fn.shellescape(bin))
    table.insert(cmd_parts, 'tui')
    local cmd = table.concat(cmd_parts, ' ')
    
    -- Calculate dimensions
    local pos = M.config.window.position
    local total_width = vim.o.columns
    local total_height = vim.o.lines
    
    -- IMPORTANT: Create a fresh scratch buffer FIRST to avoid buffer sharing
    -- This prevents the issue where vsplit shows the same buffer in both windows
    M.state.buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_name(M.state.buf, 'tark://chat')
    
    -- Create window with the fresh buffer
    if pos == 'float' then
        local width = calculate_size(M.config.window.width, total_width)
        local height = calculate_size(M.config.window.height, total_height)
        
        M.state.win = vim.api.nvim_open_win(M.state.buf, true, {
            relative = 'editor',
            width = width,
            height = height,
            col = math.floor((total_width - width) / 2),
            row = math.floor((total_height - height) / 2),
            style = 'minimal',
            border = 'rounded',
        })
    else
        -- For splits: use API to create window with our buffer directly
        local width = calculate_size(M.config.window.width, total_width)
        local height = calculate_size(M.config.window.height, total_height)
        
        -- Calculate split size
        local split_opts = { win = 0 }  -- split from current window
        
        if pos == 'right' or pos == nil then
            split_opts.vertical = true
            split_opts.width = width
            M.state.win = vim.api.nvim_open_win(M.state.buf, true, split_opts)
            -- Move to far right
            vim.cmd('wincmd L')
        elseif pos == 'left' then
            split_opts.vertical = true
            split_opts.width = width
            M.state.win = vim.api.nvim_open_win(M.state.buf, true, split_opts)
            -- Move to far left
            vim.cmd('wincmd H')
        elseif pos == 'bottom' then
            split_opts.vertical = false
            split_opts.height = height
            M.state.win = vim.api.nvim_open_win(M.state.buf, true, split_opts)
            -- Move to bottom
            vim.cmd('wincmd J')
        elseif pos == 'top' then
            split_opts.vertical = false
            split_opts.height = height
            M.state.win = vim.api.nvim_open_win(M.state.buf, true, split_opts)
            -- Move to top
            vim.cmd('wincmd K')
        end
    end
    
    -- Open terminal in the dedicated buffer
    M.state.job_id = vim.fn.termopen(cmd, {
        on_exit = function()
            vim.schedule(function()
                M.cleanup()
            end)
        end,
    })
    
    -- Configure buffer
    vim.bo[M.state.buf].buflisted = false
    
    -- Configure window to prevent accidental duplication
    vim.wo[M.state.win].winfixwidth = true
    vim.wo[M.state.win].winfixheight = true
    vim.wo[M.state.win].number = false
    vim.wo[M.state.win].relativenumber = false
    vim.wo[M.state.win].signcolumn = 'no'
    
    -- Enter terminal mode
    vim.cmd('startinsert')
    
    -- Setup autocmds for context sync
    M.setup_autocmds()
    
    done()
end

function M.close()
    if M.state.win and vim.api.nvim_win_is_valid(M.state.win) then
        vim.api.nvim_win_close(M.state.win, true)
    end
    M.cleanup()
end

function M.toggle()
    if M.is_open() then
        M.close()
    else
        M.open()
    end
end

function M.is_open()
    return M.state.win ~= nil and vim.api.nvim_win_is_valid(M.state.win)
end

function M.cleanup()
    stop_socket_server()
    M.state.buf = nil
    M.state.win = nil
    M.state.job_id = nil
end

local function send_to_job(text)
    if not text or text == '' then
        return false
    end
    if not M.state.job_id then
        return false
    end
    local ok = pcall(vim.fn.chansend, M.state.job_id, text)
    return ok
end

local function normalize_question(question)
    if not question or question == '' then
        return 'Please analyze this context.'
    end
    return question
end

function M.send_prompt(prompt, submit)
    if not prompt or prompt == '' then
        return false
    end

    if not M.is_open() then
        M.open()
    end

    local payload = prompt
    if submit ~= false then
        payload = payload .. '\n'
    end

    local attempts = 0
    local max_attempts = 20

    local function try_send()
        attempts = attempts + 1
        if send_to_job(payload) then
            return
        end
        if attempts < max_attempts then
            vim.defer_fn(try_send, 100)
        else
            vim.notify('tark: Unable to send prompt to TUI', vim.log.levels.WARN)
        end
    end

    try_send()
    return true
end

function M.ask_buffer(question)
    local path = vim.api.nvim_buf_get_name(0)
    if path == '' then
        vim.notify('tark: Current buffer has no file path', vim.log.levels.WARN)
        return false
    end

    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local content = table.concat(lines, '\n')
    local q = normalize_question(question)
    local prompt = string.format(
        "Context file: %s\nSelection: full buffer\n\n```text\n%s\n```\n\nQuestion: %s",
        path,
        content,
        q
    )
    return M.send_prompt(prompt, true)
end

function M.ask_selection(line1, line2, question)
    local path = vim.api.nvim_buf_get_name(0)
    if path == '' then
        vim.notify('tark: Current buffer has no file path', vim.log.levels.WARN)
        return false
    end

    local start_line = math.max(1, tonumber(line1) or 1)
    local end_line = math.max(start_line, tonumber(line2) or start_line)
    local start_col = vim.fn.col("'<")
    local end_col = vim.fn.col("'>")
    if start_col < 1 then
        start_col = 1
    end
    if end_col < start_col then
        end_col = start_col
    end

    local selected = vim.api.nvim_buf_get_lines(0, start_line - 1, end_line, false)
    if #selected == 0 then
        vim.notify('tark: No selected lines found', vim.log.levels.WARN)
        return false
    end

    selected[1] = string.sub(selected[1], start_col)
    selected[#selected] = string.sub(selected[#selected], 1, end_col)
    local selection_text = table.concat(selected, '\n')
    local q = normalize_question(question)

    local prompt = string.format(
        "Context file: %s\nSelection: lines %d-%d, columns %d-%d\n\n```text\n%s\n```\n\nQuestion: %s",
        path,
        start_line,
        end_line,
        start_col,
        end_col,
        selection_text,
        q
    )
    return M.send_prompt(prompt, true)
end

-- ============================================================================
-- Autocmds for context sync
-- ============================================================================

local augroup = nil

function M.setup_autocmds()
    if augroup then
        vim.api.nvim_del_augroup_by_id(augroup)
    end
    augroup = vim.api.nvim_create_augroup('TarkTUI', { clear = true })
    
    -- Notify TUI when buffer changes
    vim.api.nvim_create_autocmd('BufEnter', {
        group = augroup,
        callback = function()
            if M.state.client then
                local path = vim.api.nvim_buf_get_name(0)
                if path ~= '' and vim.bo.buftype == '' then
                    send({ type = 'buffer_entered', path = path, filetype = vim.bo.filetype })
                end
            end
        end,
    })
    
    -- Notify on diagnostics change
    vim.api.nvim_create_autocmd('DiagnosticChanged', {
        group = augroup,
        callback = function()
            if M.state.client then
                send({ type = 'diagnostics_changed' })
            end
        end,
    })
    
    -- Cleanup on terminal close
    if M.state.buf then
        vim.api.nvim_create_autocmd('TermClose', {
            group = augroup,
            buffer = M.state.buf,
            callback = function()
                vim.schedule(function() M.cleanup() end)
            end,
        })
    end
end

-- ============================================================================
-- Setup
-- ============================================================================

function M.setup(config)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})
    
    -- Cleanup on Neovim exit
    vim.api.nvim_create_autocmd('VimLeavePre', {
        callback = function()
            if M.state.client then
                send({ type = 'editor_closed' })
            end
            M.cleanup()
        end,
    })
end

return M
