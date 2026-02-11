-- tark statusline component
-- Shows Tark status in your statusline (lualine, etc.)

local M = {}

-- Icons (Nerd Font compatible)
M.icons = {
    -- Working states
    active = '󱙺',      -- sparkles - AI active
    idle = '',        -- brain - ready but idle
    loading = '󰔟',     -- spinner/loading
    
    -- Error states
    error = '',       -- x circle - error
    disabled = '󰚌',    -- slash - disabled
    no_key = '󰌆',      -- key - missing API key
    
    -- Fallback (no nerd fonts)
    active_text = '✓',
    error_text = '✗',
}

-- Highlight groups
M.highlights = {
    active = 'TarkStatusActive',
    idle = 'TarkStatusIdle', 
    loading = 'TarkStatusLoading',
    error = 'TarkStatusError',
    disabled = 'TarkStatusDisabled',
}

-- Setup highlight groups
local function setup_highlights()
    -- Only set if not already defined by colorscheme
    local function safe_hl(name, opts)
        local ok, existing = pcall(vim.api.nvim_get_hl, 0, { name = name })
        if not ok or vim.tbl_isempty(existing) then
            vim.api.nvim_set_hl(0, name, opts)
        end
    end
    
    safe_hl('TarkStatusActive', { fg = '#7aa2f7', bold = true })   -- Blue
    safe_hl('TarkStatusIdle', { fg = '#9ece6a' })                   -- Green
    safe_hl('TarkStatusLoading', { fg = '#e0af68' })                -- Yellow
    safe_hl('TarkStatusError', { fg = '#f7768e' })                  -- Red
    safe_hl('TarkStatusDisabled', { fg = '#565f89' })               -- Gray
end

--- Get current Tark status
---@return table { status: string, icon: string, text: string, highlight: string }
function M.get_status()
    local ghost = package.loaded['tark.ghost']
    local binary = package.loaded['tark.binary']
    
    -- Check if binary exists
    if binary then
        local bin = binary.find()
        if not bin then
            return {
                status = 'no_binary',
                icon = M.icons.error,
                text = 'tark',
                highlight = M.highlights.error,
            }
        end
    end
    
    -- Check ghost text status
    if ghost then
        if not ghost.config.enabled then
            return {
                status = 'disabled',
                icon = M.icons.disabled,
                text = 'tark',
                highlight = M.highlights.disabled,
            }
        end
        
        if ghost.is_server_running() then
            -- Check if we've had recent activity
            if ghost.state.completions_shown > 0 then
                return {
                    status = 'active',
                    icon = M.icons.active,
                    text = 'tark',
                    highlight = M.highlights.active,
                }
            else
                return {
                    status = 'idle',
                    icon = M.icons.idle,
                    text = 'tark',
                    highlight = M.highlights.idle,
                }
            end
        else
            -- Server not running - might be missing API key
            return {
                status = 'no_server',
                icon = M.icons.no_key,
                text = 'tark',
                highlight = M.highlights.error,
            }
        end
    end
    
    -- Not loaded yet
    return {
        status = 'not_loaded',
        icon = M.icons.disabled,
        text = 'tark',
        highlight = M.highlights.disabled,
    }
end

--- Get statusline string with icon
---@param opts? { show_text: boolean, use_nerd_fonts: boolean }
---@return string
function M.status(opts)
    opts = opts or {}
    local show_text = opts.show_text ~= false  -- default true
    local use_nerd_fonts = opts.use_nerd_fonts ~= false  -- default true
    
    local status = M.get_status()
    local icon = use_nerd_fonts and status.icon or (
        status.status == 'active' and M.icons.active_text or
        status.status == 'idle' and M.icons.active_text or
        M.icons.error_text
    )
    
    if show_text then
        return icon .. ' tark'
    else
        return icon
    end
end

--- Get statusline string with highlight (for use in statusline)
---@param opts? { show_text: boolean, use_nerd_fonts: boolean }
---@return string
function M.status_with_hl(opts)
    local status = M.get_status()
    local text = M.status(opts)
    return '%#' .. status.highlight .. '#' .. text .. '%*'
end

-- Color function shared between components
local function get_color()
    local status = M.get_status()
    local colors = {
        TarkStatusActive = { fg = '#7aa2f7' },
        TarkStatusIdle = { fg = '#9ece6a' },
        TarkStatusLoading = { fg = '#e0af68' },
        TarkStatusError = { fg = '#f7768e' },
        TarkStatusDisabled = { fg = '#565f89' },
    }
    return colors[status.highlight] or { fg = '#565f89' }
end

--- Lualine component (full: icon + text)
--- Usage: require('lualine').setup({ sections = { lualine_x = { require('tark.statusline').lualine } } })
M.lualine = {
    function()
        return M.status()
    end,
    color = get_color,
    -- Always show - status indicates if working or not
}

--- Lualine component (compact - icon only)
M.lualine_icon = {
    function()
        return M.status({ show_text = false })
    end,
    color = get_color,
}

--- Setup (call this to initialize highlights)
function M.setup()
    setup_highlights()
    
    -- Re-setup highlights on colorscheme change
    vim.api.nvim_create_autocmd('ColorScheme', {
        group = vim.api.nvim_create_augroup('TarkStatusline', { clear = true }),
        callback = setup_highlights,
    })
end

-- Auto-setup highlights when module is loaded
setup_highlights()

return M

