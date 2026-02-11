-- Tests for main tark module
-- Tests module loading, setup, and public API

local tark = require('tark')

describe('tark - main module', function()
    describe('module loading', function()
        it('loads without error', function()
            assert.is_table(tark)
        end)

        it('has version defined', function()
            assert.is_string(tark.version)
            assert.is_true(#tark.version > 0)
        end)

        it('has config table', function()
            assert.is_table(tark.config)
        end)
    end)

    describe('public API functions', function()
        it('has open function', function()
            assert.is_function(tark.open)
        end)

        it('has close function', function()
            assert.is_function(tark.close)
        end)

        it('has toggle function', function()
            assert.is_function(tark.toggle)
        end)

        it('has is_open function', function()
            assert.is_function(tark.is_open)
        end)

        it('has setup function', function()
            assert.is_function(tark.setup)
        end)

        it('has ask_buffer function', function()
            assert.is_function(tark.ask_buffer)
        end)

        it('has ask_selection function', function()
            assert.is_function(tark.ask_selection)
        end)
    end)

    describe('is_open function', function()
        it('returns boolean', function()
            local result = tark.is_open()
            assert.is_boolean(result)
        end)

        it('returns false when TUI is not open', function()
            assert.is_false(tark.is_open())
        end)
    end)

    describe('config structure', function()
        it('has window config', function()
            assert.is_table(tark.config.window)
        end)

        it('has auto_download config', function()
            assert.is_boolean(tark.config.auto_download)
        end)

        it('window config has position', function()
            assert.is_string(tark.config.window.position)
        end)

        it('window config has width', function()
            assert.is_number(tark.config.window.width)
        end)

        it('window config has height', function()
            assert.is_number(tark.config.window.height)
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                tark.setup({})
            end)
        end)

        it('merges config with defaults', function()
            tark.setup({ window = { position = 'left' } })
            assert.equals('left', tark.config.window.position)
            -- Reset
            tark.setup({ window = { position = 'right' } })
        end)

        it('preserves other config values', function()
            local original_width = tark.config.window.width
            tark.setup({ window = { position = 'bottom' } })
            assert.equals(original_width, tark.config.window.width)
            -- Reset
            tark.setup({ window = { position = 'right' } })
        end)
    end)

    describe('commands registration', function()
        it('Tark command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.Tark)
        end)

        it('TarkToggle command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkToggle)
        end)

        it('TarkOpen command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkOpen)
        end)

        it('TarkClose command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkClose)
        end)

        it('TarkAskBuffer command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkAskBuffer)
        end)

        it('TarkAskSelection command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkAskSelection)
        end)

        it('TarkDownload command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkDownload)
        end)

        it('TarkVersion command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkVersion)
        end)

        it('TarkLspStart command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspStart)
        end)

        it('TarkLspStop command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspStop)
        end)

        it('TarkLspRestart command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspRestart)
        end)

        it('TarkLspStatus command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspStatus)
        end)

        it('TarkLspEnable command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspEnable)
        end)

        it('TarkLspDisable command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspDisable)
        end)

        it('TarkLspToggle command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspToggle)
        end)

        it('TarkLspUsage command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkLspUsage)
        end)
    end)

    describe('LSP API functions', function()
        it('has lsp_start function', function()
            assert.is_function(tark.lsp_start)
        end)

        it('has lsp_stop function', function()
            assert.is_function(tark.lsp_stop)
        end)

        it('has lsp_restart function', function()
            assert.is_function(tark.lsp_restart)
        end)

        it('has lsp_status function', function()
            assert.is_function(tark.lsp_status)
        end)

        it('has lsp_enable function', function()
            assert.is_function(tark.lsp_enable)
        end)

        it('has lsp_disable function', function()
            assert.is_function(tark.lsp_disable)
        end)

        it('has lsp_toggle function', function()
            assert.is_function(tark.lsp_toggle)
        end)

        it('has lsp_usage function', function()
            assert.is_function(tark.lsp_usage)
        end)
    end)

    describe('Ghost text API functions', function()
        it('has ghost_enable function', function()
            assert.is_function(tark.ghost_enable)
        end)

        it('has ghost_disable function', function()
            assert.is_function(tark.ghost_disable)
        end)

        it('has ghost_toggle function', function()
            assert.is_function(tark.ghost_toggle)
        end)

        it('has ghost_usage function', function()
            assert.is_function(tark.ghost_usage)
        end)

        it('has ghost_accept function', function()
            assert.is_function(tark.ghost_accept)
        end)
    end)

    describe('Ghost text commands registration', function()
        it('TarkGhostEnable command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkGhostEnable)
        end)

        it('TarkGhostDisable command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkGhostDisable)
        end)

        it('TarkGhostToggle command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkGhostToggle)
        end)

        it('TarkGhostUsage command exists', function()
            local commands = vim.api.nvim_get_commands({})
            assert.is_not_nil(commands.TarkGhostUsage)
        end)
    end)
end)
