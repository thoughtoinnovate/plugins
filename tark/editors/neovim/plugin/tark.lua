-- acp.nvim plugin entry point

if vim.g.loaded_tark then
    return
end
vim.g.loaded_tark = true

vim.api.nvim_create_user_command('AcpChatOpen', function()
    require('tark').chat_open()
end, { desc = 'Open ACP chat widget' })

vim.api.nvim_create_user_command('AcpChatClose', function()
    require('tark').chat_close()
end, { desc = 'Close ACP chat widget' })

vim.api.nvim_create_user_command('AcpChatToggle', function()
    require('tark').chat_toggle()
end, { desc = 'Toggle ACP chat widget' })

vim.api.nvim_create_user_command('AcpSend', function(opts)
    require('tark').chat_send(opts.args)
end, {
    nargs = '*',
    desc = 'Send a chat message from widget input or argument',
})

vim.api.nvim_create_user_command('AcpCancel', function()
    require('tark').chat_cancel()
end, { desc = 'Cancel current ACP request' })

vim.api.nvim_create_user_command('AcpAskBuffer', function(opts)
    require('tark').ask_buffer(opts.args)
end, {
    nargs = '*',
    desc = 'Send current buffer as ACP context and ask a question',
})

vim.api.nvim_create_user_command('AcpAskSelection', function(opts)
    require('tark').ask_selection(opts.line1, opts.line2, opts.args)
end, {
    range = true,
    nargs = '*',
    desc = 'Send selected lines as ACP context and ask a question',
})

vim.api.nvim_create_user_command('AcpMode', function(opts)
    local mode = opts.args
    if mode == '' then
        vim.notify('Usage: :AcpMode ask|plan|build', vim.log.levels.WARN)
        return
    end
    require('tark').set_mode(mode)
end, {
    nargs = 1,
    complete = function()
        return { 'ask', 'plan', 'build' }
    end,
    desc = 'Set ACP session mode (ask|plan|build)',
})

vim.api.nvim_create_user_command('AcpConfigSet', function(opts)
    local parts = vim.split(opts.args, ' ', { plain = true, trimempty = true })
    if #parts < 2 then
        vim.notify('Usage: :AcpConfigSet <configId> <value>', vim.log.levels.WARN)
        return
    end
    local config_id = parts[1]
    table.remove(parts, 1)
    local value = table.concat(parts, ' ')
    require('tark').set_config_option(config_id, value)
end, {
    nargs = '+',
    desc = 'Set ACP session configuration option',
})

vim.api.nvim_create_user_command('AcpUiFocus', function(opts)
    require('tark').ui_focus(opts.args)
end, {
    nargs = 1,
    complete = function()
        return { 'transcript', 'input', 'interaction' }
    end,
    desc = 'Focus ACP UI pane (transcript|input|interaction)',
})

vim.api.nvim_create_user_command('AcpUiNextAction', function()
    require('tark').ui_next_action()
end, { desc = 'Move to next interactive ACP action' })

vim.api.nvim_create_user_command('AcpUiPrevAction', function()
    require('tark').ui_prev_action()
end, { desc = 'Move to previous interactive ACP action' })

vim.api.nvim_create_user_command('AcpUiSubmit', function()
    require('tark').ui_submit()
end, { desc = 'Submit active ACP UI action or send input' })

vim.api.nvim_create_user_command('AcpUiCancel', function()
    require('tark').ui_cancel()
end, { desc = 'Cancel active ACP UI interaction or request' })

-- Legacy aliases (deprecated)
vim.api.nvim_create_user_command('TarkChatToggle', function() vim.cmd('AcpChatToggle') end, { desc = 'Deprecated alias for AcpChatToggle' })
vim.api.nvim_create_user_command('TarkChatOpen', function() vim.cmd('AcpChatOpen') end, { desc = 'Deprecated alias for AcpChatOpen' })
vim.api.nvim_create_user_command('TarkChatClose', function() vim.cmd('AcpChatClose') end, { desc = 'Deprecated alias for AcpChatClose' })
vim.api.nvim_create_user_command('TarkChatSend', function(opts) vim.cmd('AcpSend ' .. opts.args) end, { nargs = '*', desc = 'Deprecated alias for AcpSend' })
vim.api.nvim_create_user_command('TarkChatCancel', function() vim.cmd('AcpCancel') end, { desc = 'Deprecated alias for AcpCancel' })
vim.api.nvim_create_user_command('TarkAskBuffer', function(opts) vim.cmd('AcpAskBuffer ' .. opts.args) end, { nargs = '*', desc = 'Deprecated alias for AcpAskBuffer' })
vim.api.nvim_create_user_command('TarkAskSelection', function(opts) require('tark').ask_selection(opts.line1, opts.line2, opts.args) end, { range = true, nargs = '*', desc = 'Deprecated alias for AcpAskSelection' })
vim.api.nvim_create_user_command('TarkMode', function(opts) vim.cmd('AcpMode ' .. opts.args) end, { nargs = 1, complete = function() return { 'ask', 'plan', 'build' } end, desc = 'Deprecated alias for AcpMode' })
vim.api.nvim_create_user_command('TarkApproval', function(opts)
    require('tark').approve(opts.args)
end, {
    nargs = 1,
    complete = function()
        return { 'approve_once', 'approve_session', 'approve_always', 'deny_once', 'deny_always' }
    end,
    desc = 'Deprecated legacy approval command',
})
vim.api.nvim_create_user_command('TarkQuestionnaireSubmit', function() require('tark').questionnaire_submit() end, { desc = 'Deprecated legacy questionnaire submit' })
vim.api.nvim_create_user_command('TarkQuestionnaireCancel', function() require('tark').questionnaire_cancel() end, { desc = 'Deprecated legacy questionnaire cancel' })
vim.api.nvim_create_user_command('TarkUiFocus', function(opts) vim.cmd('AcpUiFocus ' .. opts.args) end, { nargs = 1, complete = function() return { 'transcript', 'input', 'interaction' } end, desc = 'Deprecated alias for AcpUiFocus' })
vim.api.nvim_create_user_command('TarkUiNextAction', function() vim.cmd('AcpUiNextAction') end, { desc = 'Deprecated alias for AcpUiNextAction' })
vim.api.nvim_create_user_command('TarkUiPrevAction', function() vim.cmd('AcpUiPrevAction') end, { desc = 'Deprecated alias for AcpUiPrevAction' })
vim.api.nvim_create_user_command('TarkUiSubmit', function() vim.cmd('AcpUiSubmit') end, { desc = 'Deprecated alias for AcpUiSubmit' })
vim.api.nvim_create_user_command('TarkUiCancel', function() vim.cmd('AcpUiCancel') end, { desc = 'Deprecated alias for AcpUiCancel' })

vim.api.nvim_create_user_command('TarkDownload', function()
    require('tark.binary').download()
end, { desc = 'Download tark binary' })

vim.api.nvim_create_user_command('TarkVersion', function()
    local binary = require('tark.binary')
    local bin = binary.find()
    if bin then
        local ver = binary.version() or 'unknown'
        vim.notify('tark: v' .. ver .. '\nPath: ' .. bin, vim.log.levels.INFO)
    else
        vim.notify('tark: Binary not found. Run :TarkDownload', vim.log.levels.WARN)
    end
end, { desc = 'Show tark version' })

-- LSP commands
vim.api.nvim_create_user_command('TarkLspStart', function()
    local tark = require('tark')
    local client_id = tark.lsp_start()
    if client_id then
        vim.notify('tark: LSP started (client ' .. client_id .. ')', vim.log.levels.INFO)
    else
        vim.notify('tark: Failed to start LSP', vim.log.levels.ERROR)
    end
end, { desc = 'Start tark LSP server' })

vim.api.nvim_create_user_command('TarkLspStop', function()
    require('tark').lsp_stop()
    vim.notify('tark: LSP stopped', vim.log.levels.INFO)
end, { desc = 'Stop tark LSP server' })

vim.api.nvim_create_user_command('TarkLspRestart', function()
    require('tark').lsp_restart()
    vim.notify('tark: LSP restarting...', vim.log.levels.INFO)
end, { desc = 'Restart tark LSP server' })

vim.api.nvim_create_user_command('TarkLspStatus', function()
    local status = require('tark').lsp_status()
    vim.notify('tark: LSP ' .. status, vim.log.levels.INFO)
end, { desc = 'Show tark LSP status' })

vim.api.nvim_create_user_command('TarkLspEnable', function()
    require('tark').lsp_enable()
end, { desc = 'Enable tark completions' })

vim.api.nvim_create_user_command('TarkLspDisable', function()
    require('tark').lsp_disable()
end, { desc = 'Disable tark completions' })

vim.api.nvim_create_user_command('TarkLspToggle', function()
    require('tark').lsp_toggle()
end, { desc = 'Toggle tark completions' })

vim.api.nvim_create_user_command('TarkLspUsage', function()
    local usage = require('tark').lsp_usage()
    vim.notify(usage, vim.log.levels.INFO)
end, { desc = 'Show tark completion usage stats' })

-- Ghost text commands
vim.api.nvim_create_user_command('TarkGhostEnable', function()
    require('tark').ghost_enable()
end, { desc = 'Enable tark ghost text' })

vim.api.nvim_create_user_command('TarkGhostDisable', function()
    require('tark').ghost_disable()
end, { desc = 'Disable tark ghost text' })

vim.api.nvim_create_user_command('TarkGhostToggle', function()
    require('tark').ghost_toggle()
end, { desc = 'Toggle tark ghost text' })

vim.api.nvim_create_user_command('TarkGhostUsage', function()
    local usage = require('tark').ghost_usage()
    vim.notify(usage, vim.log.levels.INFO)
end, { desc = 'Show tark ghost text usage stats' })

vim.api.nvim_create_user_command('TarkGhostStatus', function()
    local status = require('tark').ghost_status()
    vim.notify(status, vim.log.levels.INFO)
end, { desc = 'Show tark ghost text status (diagnose issues)' })

vim.api.nvim_create_user_command('TarkGhostProvider', function(opts)
    if opts.args and opts.args ~= '' then
        require('tark').ghost_set_provider(opts.args)
        return
    end
    local provider = require('tark').ghost_get_provider() or 'local tark default (locked)'
    vim.notify('tark: Current completion provider: ' .. provider, vim.log.levels.INFO)
end, {
    nargs = '?',
    complete = function()
        return {}
    end,
    desc = 'Show completion provider (managed by local tark configuration)',
})
