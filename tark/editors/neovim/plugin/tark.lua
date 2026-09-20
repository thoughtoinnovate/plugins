-- tark.nvim command registration.
-- Loaded from plugin/ so commands exist without requiring setup() first;
-- every command lazy-loads its implementation module.
if vim.g.loaded_tark == 1 then
  return
end
vim.g.loaded_tark = 1

vim.api.nvim_create_user_command('TarkStart', function()
  require('tark').start(function(ok, err)
    if not ok then
      vim.notify('[tark] start failed: ' .. tostring(err), vim.log.levels.ERROR)
    else
      vim.notify('[tark] session ready', vim.log.levels.INFO)
    end
  end)
end, { desc = 'Start the tark ACP subprocess and create a session' })

vim.api.nvim_create_user_command('TarkStop', function()
  require('tark').stop()
  vim.notify('[tark] stopped', vim.log.levels.INFO)
end, { desc = 'Close the tark session and stop the subprocess' })

vim.api.nvim_create_user_command('TarkChat', function(opts)
  require('tark').open_chat(opts.args ~= '' and opts.args or nil)
end, { nargs = '*', desc = 'Open tark chat, optionally sending initial text' })

vim.api.nvim_create_user_command('TarkComplete', function()
  require('tark').complete()
end, { desc = 'Request one tark inline completion at the cursor' })

vim.api.nvim_create_user_command('TarkHealth', function()
  require('tark').health()
end, { desc = 'Run tark health diagnostics' })

vim.api.nvim_create_user_command('TarkCancel', function()
  require('tark.widgets.chat').cancel()
end, { desc = 'Cancel the running tark prompt' })
