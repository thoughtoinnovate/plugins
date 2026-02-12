-- Tests for main tark module (ACP widget migration)

local tark = require('tark')

describe('tark - main module', function()
    it('loads without error', function()
        assert.is_table(tark)
    end)

    it('has version and config', function()
        assert.is_string(tark.version)
        assert.is_table(tark.config)
    end)

    describe('chat API functions', function()
        it('has chat_open function', function()
            assert.is_function(tark.chat_open)
        end)

        it('has chat_close function', function()
            assert.is_function(tark.chat_close)
        end)

        it('has chat_toggle function', function()
            assert.is_function(tark.chat_toggle)
        end)

        it('has ask_buffer function', function()
            assert.is_function(tark.ask_buffer)
        end)

        it('has ask_selection function', function()
            assert.is_function(tark.ask_selection)
        end)

        it('has set_mode function', function()
            assert.is_function(tark.set_mode)
        end)
    end)

    describe('config structure', function()
        it('has chat config', function()
            assert.is_table(tark.config.chat)
            assert.is_table(tark.config.chat.window)
        end)

        it('has auto_download config', function()
            assert.is_boolean(tark.config.auto_download)
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                tark.setup({})
            end)
        end)

        it('merges config with defaults', function()
            tark.setup({ chat = { mode = 'plan' } })
            assert.equals('plan', tark.config.chat.mode)
            tark.setup({ chat = { mode = 'ask' } })
        end)
    end)

    describe('commands registration', function()
        it('TarkChatOpen command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkChatOpen)
        end)

        it('TarkChatClose command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkChatClose)
        end)

        it('TarkChatToggle command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkChatToggle)
        end)

        it('TarkAskBuffer command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkAskBuffer)
        end)

        it('TarkAskSelection command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkAskSelection)
        end)

        it('TarkMode command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkMode)
        end)


        it('TarkChatSend command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkChatSend)
        end)

        it('TarkChatCancel command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkChatCancel)
        end)

        it('TarkApproval command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkApproval)
        end)

        it('TarkQuestionnaireSubmit command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkQuestionnaireSubmit)
        end)

        it('TarkQuestionnaireCancel command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkQuestionnaireCancel)
        end)
    end)
end)
