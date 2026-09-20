-- Minimal init for headless test runs.
-- Usage:
--   nvim --headless -u tests/minimal_init.lua \
--     -c "luafile tests/specs/acp_framing_spec.lua" -c "qa!"
local plugin_root = vim.fn.fnamemodify(debug.getinfo(1, 'S').source:sub(2), ':p:h:h')
vim.opt.rtp:prepend(plugin_root)
vim.opt.swapfile = false
vim.opt.backup = false
vim.opt.writebackup = false

-- plenary.nvim provides the PlenaryBustedDirectory test runner used by CI.
-- CI clones it to stdpath('data') .. '/plenary.nvim' before invoking.
-- Fail fast with an explicit error when absent: without the runner the
-- -c command is unknown (E492) and headless nvim idles instead of exiting.
local plenary_dir = vim.fn.stdpath('data') .. '/plenary.nvim'
if vim.fn.isdirectory(plenary_dir) == 1 then
  vim.opt.rtp:prepend(plenary_dir)
else
  error('plenary.nvim not found at ' .. plenary_dir .. ' (CI installs it before tests)')
end
