-- Minimal init for headless test runs.
-- Usage:
--   nvim --headless -u tests/minimal_init.lua \
--     -c "luafile tests/specs/acp_framing_spec.lua" -c "qa!"
local plugin_root = vim.fn.fnamemodify(debug.getinfo(1, 'S').source:sub(2), ':p:h:h')
vim.opt.rtp:prepend(plugin_root)
vim.opt.swapfile = false
vim.opt.backup = false
vim.opt.writebackup = false
