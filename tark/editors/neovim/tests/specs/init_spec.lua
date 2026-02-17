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

        it('has acp config', function()
            assert.is_table(tark.config.acp)
            assert.is_number(tark.config.acp.protocol_version)
            assert.is_table(tark.config.acp.client_capabilities)
            assert.equals('auto', tark.config.acp.profile)
            assert.is_table(tark.config.acp.timeouts)
            assert.is_number(tark.config.acp.timeouts.initialize_ms)
            assert.is_number(tark.config.acp.timeouts.prompt_ms)
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
        it('AcpChatOpen command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpChatOpen)
        end)

        it('AcpChatClose command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpChatClose)
        end)

        it('AcpChatToggle command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpChatToggle)
        end)

        it('AcpAskBuffer command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpAskBuffer)
        end)

        it('AcpAskSelection command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpAskSelection)
        end)

        it('AcpMode command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpMode)
        end)

        it('AcpSend command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpSend)
        end)

        it('AcpCancel command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpCancel)
        end)

        it('AcpConfigSet command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpConfigSet)
        end)

        it('AcpUiFocus command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpUiFocus)
        end)

        it('AcpUiNextAction command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpUiNextAction)
        end)

        it('AcpUiPrevAction command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpUiPrevAction)
        end)

        it('AcpUiSubmit command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpUiSubmit)
        end)

        it('AcpUiCancel command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.AcpUiCancel)
        end)

        it('legacy ACP Tark commands are absent', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_nil(commands.TarkChatOpen)
            assert.is_nil(commands.TarkChatClose)
            assert.is_nil(commands.TarkChatToggle)
            assert.is_nil(commands.TarkAskBuffer)
            assert.is_nil(commands.TarkAskSelection)
            assert.is_nil(commands.TarkMode)
            assert.is_nil(commands.TarkChatSend)
            assert.is_nil(commands.TarkChatCancel)
            assert.is_nil(commands.TarkApproval)
            assert.is_nil(commands.TarkQuestionnaireSubmit)
            assert.is_nil(commands.TarkQuestionnaireCancel)
            assert.is_nil(commands.TarkUiFocus)
            assert.is_nil(commands.TarkUiNextAction)
            assert.is_nil(commands.TarkUiPrevAction)
            assert.is_nil(commands.TarkUiSubmit)
            assert.is_nil(commands.TarkUiCancel)
        end)
    end)

    describe('config option validation', function()
        it('rejects unsupported config option before RPC call', function()
            local acp = require('tark.acp_client')
            local old_get = acp.get_config_option
            local old_set = acp.set_config_option
            local old_notify = vim.notify
            local called = false
            local last_message = nil

            acp.get_config_option = function()
                return nil
            end
            acp.set_config_option = function()
                called = true
            end
            vim.notify = function(msg)
                last_message = msg
            end

            tark.set_config_option('provider', 'ollama')

            acp.get_config_option = old_get
            acp.set_config_option = old_set
            vim.notify = old_notify

            assert.is_false(called)
            assert.matches('does not expose config option', last_message)
        end)

        it('rejects invalid select value when options are provided', function()
            local acp = require('tark.acp_client')
            local old_get = acp.get_config_option
            local old_set = acp.set_config_option
            local old_notify = vim.notify
            local called = false
            local last_message = nil

            acp.get_config_option = function()
                return {
                    id = 'provider',
                    type = 'select',
                    options = { 'openai', 'ollama' },
                }
            end
            acp.set_config_option = function()
                called = true
            end
            vim.notify = function(msg)
                last_message = msg
            end

            tark.set_config_option('provider', 'claude')

            acp.get_config_option = old_get
            acp.set_config_option = old_set
            vim.notify = old_notify

            assert.is_false(called)
            assert.matches('invalid value', last_message)
        end)
    end)
end)
