-- tark LSP client integration
-- Provides inline completions and code intelligence

local M = {}

-- State
M.state = {
    client_id = nil,  -- LSP client ID
    attached_buffers = {},  -- Buffers with LSP attached
    -- Usage tracking
    session_start = nil,  -- Session start time
    completions_requested = 0,  -- Number of completion requests
    completions_accepted = 0,  -- Number of completions accepted
}

-- Config (set by setup)
M.config = {
    -- Enable LSP automatically
    enabled = true,
    -- File patterns to attach LSP
    filetypes = { '*' },
    -- Excluded filetypes
    exclude_filetypes = { 'TelescopePrompt', 'NvimTree', 'neo-tree', 'dashboard', 'alpha' },
    -- Completion settings
    completion = {
        -- Enable inline/ghost text completions
        enabled = true,
        -- Debounce delay in ms
        debounce_ms = 150,
        -- Auto-trigger on typing
        auto_trigger = true,
    },
}

-- ============================================================================
-- Helpers
-- ============================================================================

local function get_binary()
    local binary = require('tark.binary')
    return binary.find()
end

local function is_excluded_filetype(ft)
    for _, excluded in ipairs(M.config.exclude_filetypes) do
        if ft == excluded then
            return true
        end
    end
    return false
end

local function should_attach(bufnr)
    local ft = vim.bo[bufnr].filetype
    local bt = vim.bo[bufnr].buftype
    
    -- Skip special buffers
    if bt ~= '' then
        return false
    end
    
    -- Skip excluded filetypes
    if is_excluded_filetype(ft) then
        return false
    end
    
    -- Check if already attached
    if M.state.attached_buffers[bufnr] then
        return false
    end
    
    return true
end

-- Debug logging (silent by default)
local function tracing_debug(msg)
    -- Only log if verbose mode is enabled
    if vim.g.tark_verbose then
        vim.notify('tark: ' .. msg, vim.log.levels.DEBUG)
    end
end

-- ============================================================================
-- LSP Client
-- ============================================================================

--- Start the LSP client
function M.start()
    if M.state.client_id then
        return M.state.client_id
    end
    
    local bin = get_binary()
    if not bin then
        vim.notify('tark: Binary not found. Run :TarkDownload', vim.log.levels.WARN)
        return nil
    end
    
    -- Create LSP client
    local client_id = vim.lsp.start({
        name = 'tark',
        cmd = { bin, 'lsp' },
        root_dir = vim.fn.getcwd(),
        capabilities = vim.lsp.protocol.make_client_capabilities(),
        on_init = function(client)
            tracing_debug('tark LSP initialized')
        end,
        on_exit = function(code, signal)
            M.state.client_id = nil
            M.state.attached_buffers = {}
            if code ~= 0 then
                tracing_debug('tark LSP exited with code ' .. code)
            end
        end,
    })
    
    if client_id then
        M.state.client_id = client_id
        tracing_debug('tark LSP started with client_id ' .. client_id)
    end
    
    return client_id
end

--- Stop the LSP client
function M.stop()
    if M.state.client_id then
        vim.lsp.stop_client(M.state.client_id)
        M.state.client_id = nil
        M.state.attached_buffers = {}
    end
end

--- Restart the LSP client
function M.restart()
    M.stop()
    vim.defer_fn(function()
        M.start()
        -- Re-attach to current buffer
        local bufnr = vim.api.nvim_get_current_buf()
        M.attach(bufnr)
    end, 100)
end

--- Attach LSP to a buffer
function M.attach(bufnr)
    bufnr = bufnr or vim.api.nvim_get_current_buf()
    
    if not should_attach(bufnr) then
        return false
    end
    
    -- Ensure LSP is started
    local client_id = M.state.client_id or M.start()
    if not client_id then
        return false
    end
    
    -- Attach to buffer
    local attached = vim.lsp.buf_attach_client(bufnr, client_id)
    if attached then
        M.state.attached_buffers[bufnr] = true
        tracing_debug('tark LSP attached to buffer ' .. bufnr)
    end
    
    return attached
end

--- Check if LSP is running
function M.is_running()
    return M.state.client_id ~= nil
end

--- Get LSP status
function M.status()
    if not M.config.enabled then
        return 'disabled'
    end
    
    if not M.state.client_id then
        return 'stopped'
    end
    
    local client = vim.lsp.get_client_by_id(M.state.client_id)
    if not client then
        return 'stopped'
    end
    
    return 'running'
end

--- Enable completions
function M.enable()
    if M.config.enabled then
        return -- Already enabled
    end
    
    M.config.enabled = true
    M.state.session_start = os.time()
    M.state.completions_requested = 0
    M.state.completions_accepted = 0
    
    -- Setup autocmds and start LSP
    M.setup_autocmds()
    M.start()
    
    -- Attach to current buffer
    local bufnr = vim.api.nvim_get_current_buf()
    if vim.bo[bufnr].buftype == '' then
        M.attach(bufnr)
    end
    
    vim.notify('tark: Completions enabled', vim.log.levels.INFO)
end

--- Disable completions
function M.disable()
    if not M.config.enabled then
        return -- Already disabled
    end
    
    M.config.enabled = false
    M.stop()
    
    -- Clear autocmds
    if augroup then
        vim.api.nvim_del_augroup_by_id(augroup)
        augroup = nil
    end
    
    vim.notify('tark: Completions disabled', vim.log.levels.INFO)
end

--- Toggle completions
function M.toggle()
    if M.config.enabled then
        M.disable()
    else
        M.enable()
    end
end

--- Get usage statistics
function M.usage()
    local stats = {
        enabled = M.config.enabled,
        status = M.status(),
        session_start = M.state.session_start,
        completions_requested = M.state.completions_requested,
        completions_accepted = M.state.completions_accepted,
        attached_buffers = vim.tbl_count(M.state.attached_buffers),
    }
    
    -- Calculate session duration
    if M.state.session_start then
        stats.session_duration = os.time() - M.state.session_start
    else
        stats.session_duration = 0
    end
    
    return stats
end

--- Format usage for display
function M.format_usage()
    local stats = M.usage()
    local lines = {}
    
    table.insert(lines, '┌─ tark Completion Stats ─────────────────┐')
    table.insert(lines, string.format('│ Status: %-31s │', stats.status))
    table.insert(lines, string.format('│ Enabled: %-30s │', stats.enabled and 'yes' or 'no'))
    
    if stats.session_duration > 0 then
        local mins = math.floor(stats.session_duration / 60)
        local secs = stats.session_duration % 60
        table.insert(lines, string.format('│ Session: %dm %ds                        │', mins, secs))
    end
    
    table.insert(lines, string.format('│ Buffers attached: %-21d │', stats.attached_buffers))
    table.insert(lines, string.format('│ Completions requested: %-16d │', stats.completions_requested))
    table.insert(lines, string.format('│ Completions accepted: %-17d │', stats.completions_accepted))
    table.insert(lines, '└──────────────────────────────────────────┘')
    
    return table.concat(lines, '\n')
end

--- Increment completion request count (called internally)
function M.track_request()
    M.state.completions_requested = M.state.completions_requested + 1
end

--- Increment completion accepted count (called internally)
function M.track_accepted()
    M.state.completions_accepted = M.state.completions_accepted + 1
end

-- ============================================================================
-- Autocmds
-- ============================================================================

local augroup = nil

function M.setup_autocmds()
    if augroup then
        pcall(vim.api.nvim_del_augroup_by_id, augroup)
        augroup = nil
    end
    
    if not M.config.enabled then
        return
    end
    
    augroup = vim.api.nvim_create_augroup('TarkLSP', { clear = true })
    
    -- Auto-attach to buffers
    vim.api.nvim_create_autocmd('BufEnter', {
        group = augroup,
        callback = function(args)
            if M.config.enabled then
                M.attach(args.buf)
            end
        end,
    })
    
    -- Clean up on buffer delete
    vim.api.nvim_create_autocmd('BufDelete', {
        group = augroup,
        callback = function(args)
            M.state.attached_buffers[args.buf] = nil
        end,
    })
    
    -- Stop LSP on VimLeave
    vim.api.nvim_create_autocmd('VimLeavePre', {
        group = augroup,
        callback = function()
            M.stop()
        end,
    })
end

-- ============================================================================
-- Setup
-- ============================================================================

function M.setup(config)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})
    
    -- Initialize session tracking
    M.state.session_start = os.time()
    M.state.completions_requested = 0
    M.state.completions_accepted = 0
    
    -- Setup autocmds
    M.setup_autocmds()
    
    -- Start LSP if enabled
    if M.config.enabled then
        -- Defer to let Neovim finish startup
        vim.defer_fn(function()
            M.start()
            -- Attach to current buffer
            local bufnr = vim.api.nvim_get_current_buf()
            if vim.bo[bufnr].buftype == '' then
                M.attach(bufnr)
            end
        end, 100)
    end
end

return M

