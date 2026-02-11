-- tark ghost text completions
-- Displays inline AI suggestions as virtual text

local M = {}

-- State
M.state = {
    server_job = nil,    -- HTTP server job ID
    server_port = 8765,  -- Server port
    current_suggestion = nil,  -- Current ghost text
    extmark_id = nil,    -- Virtual text extmark
    ns_id = nil,         -- Namespace for extmarks
    debounce_timer = nil,  -- Debounce timer
    -- Usage tracking
    session_start = nil,
    completions_requested = 0,
    completions_shown = 0,
    completions_accepted = 0,
}

-- Config
M.config = {
    enabled = true,
    auto_trigger = true,
    debounce_ms = 300,
    server_port = 8765,
    -- Provider for completions (nil = use server default)
    -- Options: 'openai', 'claude', 'copilot', 'ollama'
    provider = nil,
    -- Keymaps
    accept_key = '<C-l>',      -- Ctrl+L to accept (avoids Tab conflicts)
    trigger_key = '<C-Space>', -- Ctrl+Space to manually trigger
    dismiss_key = '<Esc>',
    -- Appearance
    hl_group = 'Comment',
}

-- ============================================================================
-- Helpers
-- ============================================================================

local function get_binary()
    local binary = require('tark.binary')
    return binary.find()
end

local function get_namespace()
    if not M.state.ns_id then
        M.state.ns_id = vim.api.nvim_create_namespace('tark_ghost')
    end
    return M.state.ns_id
end

local function clear_ghost_text()
    if M.state.extmark_id then
        local ns = get_namespace()
        pcall(vim.api.nvim_buf_del_extmark, 0, ns, M.state.extmark_id)
        M.state.extmark_id = nil
    end
    M.state.current_suggestion = nil
end

local function show_ghost_text(text, row, col)
    clear_ghost_text()
    
    if not text or text == '' then
        return
    end
    
    local ns = get_namespace()
    local lines = vim.split(text, '\n')
    
    -- First line as inline virtual text
    local virt_text = {{ lines[1], M.config.hl_group }}
    
    -- Additional lines as virtual lines below
    local virt_lines = {}
    for i = 2, #lines do
        table.insert(virt_lines, {{ lines[i], M.config.hl_group }})
    end
    
    local opts = {
        virt_text = virt_text,
        virt_text_pos = 'inline',
        hl_mode = 'combine',
    }
    
    if #virt_lines > 0 then
        opts.virt_lines = virt_lines
    end
    
    M.state.extmark_id = vim.api.nvim_buf_set_extmark(0, ns, row, col, opts)
    M.state.current_suggestion = text
    M.state.completions_shown = M.state.completions_shown + 1
end

-- ============================================================================
-- HTTP Server Management
-- ============================================================================

function M.start_server()
    if M.state.server_job then
        return true
    end
    
    local bin = get_binary()
    if not bin then
        vim.notify('tark: Binary not found. Run :TarkDownload', vim.log.levels.WARN)
        return false
    end
    
    -- Check for API keys
    local has_key = os.getenv('OPENAI_API_KEY') 
        or os.getenv('ANTHROPIC_API_KEY')
        or os.getenv('GOOGLE_API_KEY')
        or os.getenv('OPENROUTER_API_KEY')
    
    if not has_key then
        -- Check for Copilot token
        local copilot_token = vim.fn.expand('~/.config/tark/copilot_token.json')
        if vim.fn.filereadable(copilot_token) == 0 then
            vim.notify(
                'tark: No API key found. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or run "tark auth copilot"',
                vim.log.levels.WARN
            )
            return false
        end
    end
    
    local cmd = string.format('%s serve --port %d', bin, M.config.server_port)
    
    local server_error = nil
    M.state.server_job = vim.fn.jobstart(cmd, {
        on_exit = function(_, code)
            M.state.server_job = nil
            if code ~= 0 and code ~= 143 then  -- 143 = SIGTERM
                vim.schedule(function()
                    if server_error then
                        vim.notify('tark: Server failed - ' .. server_error, vim.log.levels.ERROR)
                    else
                        vim.notify('tark: Server exited with code ' .. code, vim.log.levels.WARN)
                    end
                end)
            end
        end,
        on_stderr = function(_, data)
            if data then
                for _, line in ipairs(data) do
                    if line ~= '' then
                        -- Capture errors
                        if line:match('Error') or line:match('error') then
                            server_error = line
                        end
                        -- Log in verbose mode
                        if vim.g.tark_verbose then
                            vim.schedule(function()
                                vim.notify('tark server: ' .. line, vim.log.levels.DEBUG)
                            end)
                        end
                    end
                end
            end
        end,
    })
    
    -- Give server time to start
    vim.wait(500, function() return false end)
    
    if M.state.server_job then
        vim.notify('tark: Completion server started on port ' .. M.config.server_port, vim.log.levels.INFO)
    end
    
    return M.state.server_job ~= nil
end

function M.stop_server()
    if M.state.server_job then
        vim.fn.jobstop(M.state.server_job)
        M.state.server_job = nil
    end
    clear_ghost_text()
end

function M.is_server_running()
    return M.state.server_job ~= nil
end

-- ============================================================================
-- Completion Request
-- ============================================================================

local function request_completion()
    if not M.config.enabled then
        return
    end
    
    -- Get current buffer info
    local bufnr = vim.api.nvim_get_current_buf()
    local cursor = vim.api.nvim_win_get_cursor(0)
    local row = cursor[1] - 1
    local col = cursor[2]
    
    -- Skip special buffers
    if vim.bo[bufnr].buftype ~= '' then
        return
    end
    
    -- Get buffer content
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local content = table.concat(lines, '\n')
    
    -- Calculate byte position
    local pos = 0
    for i = 1, row do
        pos = pos + #lines[i] + 1  -- +1 for newline
    end
    pos = pos + col
    
    -- Get file info
    local filepath = vim.api.nvim_buf_get_name(bufnr)
    local filetype = vim.bo[bufnr].filetype
    
    M.state.completions_requested = M.state.completions_requested + 1
    
    -- Make HTTP request
    local url = string.format('http://127.0.0.1:%d/inline-complete', M.config.server_port)
    local request_body = {
        file_path = filepath,
        file_content = content,
        cursor_line = row,
        cursor_col = col,
    }
    
    -- Provider is intentionally not overridden from Neovim.
    -- Local tark configuration chooses provider/model for completions.
    
    local body = vim.fn.json_encode(request_body)
    
    -- Use curl for HTTP request
    local cmd = string.format(
        'curl -s -X POST -H "Content-Type: application/json" -d %s %s 2>/dev/null',
        vim.fn.shellescape(body),
        vim.fn.shellescape(url)
    )
    
    vim.fn.jobstart(cmd, {
        on_stdout = function(_, data)
            if not data or not data[1] or data[1] == '' then
                return
            end
            
            local response_text = table.concat(data, '')
            local ok, response = pcall(vim.fn.json_decode, response_text)
            
            if ok and response and response.completion and response.completion ~= '' then
                vim.schedule(function()
                    -- Only show if cursor hasn't moved
                    local new_cursor = vim.api.nvim_win_get_cursor(0)
                    if new_cursor[1] - 1 == row and new_cursor[2] == col then
                        show_ghost_text(response.completion, row, col)
                    end
                end)
            end
        end,
    })
end

local function trigger_completion()
    -- Cancel any pending request
    if M.state.debounce_timer then
        vim.fn.timer_stop(M.state.debounce_timer)
        M.state.debounce_timer = nil
    end
    
    -- Debounce
    M.state.debounce_timer = vim.fn.timer_start(M.config.debounce_ms, function()
        M.state.debounce_timer = nil
        request_completion()
    end)
end

--- Manually trigger completion (no debounce)
function M.trigger()
    -- Cancel any pending request
    if M.state.debounce_timer then
        vim.fn.timer_stop(M.state.debounce_timer)
        M.state.debounce_timer = nil
    end
    
    -- Request immediately
    request_completion()
end

-- ============================================================================
-- Accept/Dismiss
-- ============================================================================

function M.accept()
    if not M.state.current_suggestion then
        -- No suggestion, use default key behavior
        return false
    end
    
    -- Insert the suggestion
    local cursor = vim.api.nvim_win_get_cursor(0)
    local row = cursor[1] - 1
    local col = cursor[2]
    
    -- Get current line
    local line = vim.api.nvim_buf_get_lines(0, row, row + 1, false)[1] or ''
    
    -- Insert suggestion at cursor
    local before = line:sub(1, col)
    local after = line:sub(col + 1)
    
    local suggestion_lines = vim.split(M.state.current_suggestion, '\n')
    suggestion_lines[1] = before .. suggestion_lines[1]
    suggestion_lines[#suggestion_lines] = suggestion_lines[#suggestion_lines] .. after
    
    -- Replace lines
    vim.api.nvim_buf_set_lines(0, row, row + 1, false, suggestion_lines)
    
    -- Move cursor to end of insertion
    local new_row = row + #suggestion_lines
    local new_col = #suggestion_lines[#suggestion_lines] - #after
    vim.api.nvim_win_set_cursor(0, { new_row, new_col })
    
    M.state.completions_accepted = M.state.completions_accepted + 1
    clear_ghost_text()
    
    return true
end

function M.dismiss()
    clear_ghost_text()
end

-- ============================================================================
-- Usage
-- ============================================================================

function M.usage()
    return {
        enabled = M.config.enabled,
        server_running = M.is_server_running(),
        session_start = M.state.session_start,
        completions_requested = M.state.completions_requested,
        completions_shown = M.state.completions_shown,
        completions_accepted = M.state.completions_accepted,
    }
end

function M.format_usage()
    local stats = M.usage()
    local lines = {}
    
    table.insert(lines, '┌─ tark Ghost Text Stats ─────────────────┐')
    table.insert(lines, string.format('│ Enabled: %-30s │', stats.enabled and 'yes' or 'no'))
    table.insert(lines, string.format('│ Server: %-31s │', stats.server_running and 'running' or 'stopped'))
    table.insert(lines, string.format('│ Completions requested: %-16d │', stats.completions_requested))
    table.insert(lines, string.format('│ Completions shown: %-20d │', stats.completions_shown))
    table.insert(lines, string.format('│ Completions accepted: %-17d │', stats.completions_accepted))
    table.insert(lines, '└──────────────────────────────────────────┘')
    
    return table.concat(lines, '\n')
end

function M.status()
    local lines = {}
    
    -- Check binary
    local bin = get_binary()
    local bin_status = bin and ('found: ' .. bin) or 'NOT FOUND (run :TarkDownload)'
    table.insert(lines, 'Binary: ' .. bin_status)
    
    -- Check API keys
    local keys = {}
    if os.getenv('OPENAI_API_KEY') then table.insert(keys, 'OPENAI') end
    if os.getenv('ANTHROPIC_API_KEY') then table.insert(keys, 'ANTHROPIC') end
    if os.getenv('GOOGLE_API_KEY') then table.insert(keys, 'GOOGLE') end
    if os.getenv('OPENROUTER_API_KEY') then table.insert(keys, 'OPENROUTER') end
    
    local copilot_token = vim.fn.expand('~/.config/tark/copilot_token.json')
    if vim.fn.filereadable(copilot_token) == 1 then
        table.insert(keys, 'COPILOT')
    end
    
    if #keys > 0 then
        table.insert(lines, 'API Keys: ' .. table.concat(keys, ', '))
    else
        table.insert(lines, 'API Keys: NONE - set OPENAI_API_KEY or run "tark auth copilot"')
    end
    
    -- Server status
    table.insert(lines, 'Server: ' .. (M.is_server_running() and 'running' or 'stopped'))
    table.insert(lines, 'Enabled: ' .. (M.config.enabled and 'yes' or 'no'))
    table.insert(lines, 'Provider: local tark default (locked)')
    table.insert(lines, 'Port: ' .. M.config.server_port)
    
    -- Test server connectivity
    if M.is_server_running() then
        local health_check = vim.fn.system(string.format(
            'curl -s -o /dev/null -w "%%{http_code}" http://127.0.0.1:%d/health 2>/dev/null',
            M.config.server_port
        ))
        if health_check == '200' then
            table.insert(lines, 'Server health: OK')
        else
            table.insert(lines, 'Server health: NOT responding (code: ' .. health_check .. ')')
        end
    end
    
    return table.concat(lines, '\n')
end

-- ============================================================================
-- Enable/Disable
-- ============================================================================

function M.enable()
    M.config.enabled = true
    M.start_server()
    M.setup_autocmds()
    vim.notify('tark: Ghost text enabled', vim.log.levels.INFO)
end

function M.disable()
    M.config.enabled = false
    clear_ghost_text()
    M.stop_server()
    if M.augroup then
        vim.api.nvim_del_augroup_by_id(M.augroup)
        M.augroup = nil
    end
    vim.notify('tark: Ghost text disabled', vim.log.levels.INFO)
end

function M.toggle()
    if M.config.enabled then
        M.disable()
    else
        M.enable()
    end
end

--- Provider overrides are intentionally disabled.
---@param provider string|nil
function M.set_provider(provider)
    if provider and provider ~= '' then
        vim.notify(
            'tark: completion provider is managed by local tark configuration; override ignored',
            vim.log.levels.INFO
        )
        return
    end
    vim.notify(
        'tark: completion provider is managed by local tark configuration',
        vim.log.levels.INFO
    )
end

--- Get current provider
---@return string|nil
function M.get_provider()
    return nil
end

-- ============================================================================
-- Autocmds
-- ============================================================================

M.augroup = nil

function M.setup_autocmds()
    if M.augroup then
        vim.api.nvim_del_augroup_by_id(M.augroup)
    end
    
    if not M.config.enabled then
        return
    end
    
    M.augroup = vim.api.nvim_create_augroup('TarkGhost', { clear = true })
    
    -- Trigger on text change (insert mode)
    if M.config.auto_trigger then
        vim.api.nvim_create_autocmd('TextChangedI', {
            group = M.augroup,
            callback = function()
                trigger_completion()
            end,
        })
    end
    
    -- Clear on cursor move
    vim.api.nvim_create_autocmd('CursorMovedI', {
        group = M.augroup,
        callback = function()
            clear_ghost_text()
        end,
    })
    
    -- Clear on leaving insert mode
    vim.api.nvim_create_autocmd('InsertLeave', {
        group = M.augroup,
        callback = function()
            clear_ghost_text()
        end,
    })
    
    -- Stop server on exit
    vim.api.nvim_create_autocmd('VimLeavePre', {
        group = M.augroup,
        callback = function()
            M.stop_server()
        end,
    })
end

-- ============================================================================
-- Keymaps
-- ============================================================================

function M.setup_keymaps()
    -- Accept with Ctrl+L (only when suggestion is shown)
    vim.keymap.set('i', M.config.accept_key, function()
        if M.accept() then
            return ''
        end
        return M.config.accept_key
    end, { expr = true, silent = true, desc = 'Accept tark suggestion' })
    
    -- Trigger with Ctrl+Space (force show completions)
    if M.config.trigger_key then
        vim.keymap.set('i', M.config.trigger_key, function()
            M.trigger()
        end, { silent = true, desc = 'Trigger tark completion' })
    end
end

-- ============================================================================
-- Setup
-- ============================================================================

function M.setup(config)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})
    
    -- Initialize tracking
    M.state.session_start = os.time()
    M.state.completions_requested = 0
    M.state.completions_shown = 0
    M.state.completions_accepted = 0
    
    if M.config.enabled then
        -- Start server
        vim.defer_fn(function()
            M.start_server()
            M.setup_autocmds()
            M.setup_keymaps()
        end, 200)
    end
end

return M
