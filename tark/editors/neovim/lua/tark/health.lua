-- tark health check for :checkhealth

local M = {}

function M.check()
    vim.health.start('tark.nvim')
    
    -- Check Neovim version
    local version = vim.version()
    if version.major >= 0 and version.minor >= 9 then
        vim.health.ok('Neovim ' .. version.major .. '.' .. version.minor .. '.' .. version.patch)
    else
        vim.health.warn('Neovim 0.9+ recommended')
    end
    
    -- Check binary
    local binary = require('tark.binary')
    local bin = binary.find()
    if bin then
        local ver = binary.version() or 'unknown'
        vim.health.ok('Binary found: ' .. bin .. ' (v' .. ver .. ')')
    else
        vim.health.warn('Binary not found. Run :TarkDownload')
    end
    
    -- Check if plugin is loaded
    local ok, tark = pcall(require, 'tark')
    if ok then
        vim.health.ok('Plugin loaded (v' .. (tark.version or 'unknown') .. ')')
    else
        vim.health.error('Plugin not loaded')
    end
end

return M
