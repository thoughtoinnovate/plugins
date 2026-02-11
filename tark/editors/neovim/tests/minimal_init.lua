-- Minimal init.lua for running plenary tests
-- This file sets up the test environment without loading user config

-- Disable swap files and other unnecessary features for testing
vim.opt.swapfile = false
vim.opt.backup = false
vim.opt.writebackup = false
vim.opt.undofile = false

-- Add current plugin directory to runtimepath
local plugin_dir = vim.fn.fnamemodify(vim.fn.getcwd(), ':p')
vim.opt.rtp:prepend(plugin_dir)

-- Bootstrap plenary.nvim for testing
-- Use a safe path that works across Neovim versions
local data_dir = vim.fn.stdpath('data')
local plenary_dir = data_dir .. '/plenary.nvim'

if vim.fn.isdirectory(plenary_dir) == 0 then
    print('Cloning plenary.nvim for testing...')
    local result = vim.fn.system({
        'git',
        'clone',
        '--depth=1',
        'https://github.com/nvim-lua/plenary.nvim',
        plenary_dir,
    })
    if vim.v.shell_error ~= 0 then
        error('Failed to clone plenary.nvim: ' .. result)
    end
end
vim.opt.rtp:prepend(plenary_dir)

-- Ensure plenary is loaded
local ok, plenary = pcall(require, 'plenary')
if not ok then
    error('Failed to load plenary.nvim. Tests cannot run.')
end

-- Set up test environment
vim.g.tark_test_mode = true

-- Disable auto-start for tests
vim.env.TARK_NO_AUTO_START = '1'

-- Source plugin file to register commands (normally done automatically by Neovim)
local plugin_file = plugin_dir .. 'plugin/tark.lua'
if vim.fn.filereadable(plugin_file) == 1 then
    vim.cmd('source ' .. plugin_file)
end

print('Test environment initialized')
print('Plugin dir: ' .. plugin_dir)
print('Plenary dir: ' .. plenary_dir)

