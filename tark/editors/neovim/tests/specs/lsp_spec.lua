-- Tests for LSP module
-- Tests LSP client management

local lsp = require('tark.lsp')

describe('lsp - LSP client integration', function()
    describe('module functions exist', function()
        it('has start function', function()
            assert.is_function(lsp.start)
        end)

        it('has stop function', function()
            assert.is_function(lsp.stop)
        end)

        it('has restart function', function()
            assert.is_function(lsp.restart)
        end)

        it('has attach function', function()
            assert.is_function(lsp.attach)
        end)

        it('has is_running function', function()
            assert.is_function(lsp.is_running)
        end)

        it('has status function', function()
            assert.is_function(lsp.status)
        end)

        it('has setup function', function()
            assert.is_function(lsp.setup)
        end)

        it('has setup_autocmds function', function()
            assert.is_function(lsp.setup_autocmds)
        end)
    end)

    describe('state tracking', function()
        it('has state table', function()
            assert.is_table(lsp.state)
        end)

        it('state has client_id field', function()
            -- client_id can be nil or number
            assert.is_true(lsp.state.client_id == nil or type(lsp.state.client_id) == 'number')
        end)

        it('state has attached_buffers field', function()
            assert.is_table(lsp.state.attached_buffers)
        end)
    end)

    describe('config', function()
        it('has default config', function()
            assert.is_table(lsp.config)
        end)

        it('has enabled config', function()
            assert.is_boolean(lsp.config.enabled)
        end)

        it('has exclude_filetypes config', function()
            assert.is_table(lsp.config.exclude_filetypes)
        end)

        it('has completion config', function()
            assert.is_table(lsp.config.completion)
        end)

        it('completion config has enabled', function()
            assert.is_boolean(lsp.config.completion.enabled)
        end)
    end)

    describe('is_running function', function()
        it('returns boolean', function()
            local result = lsp.is_running()
            assert.is_boolean(result)
        end)

        it('returns false when LSP is not started', function()
            -- Ensure LSP is stopped
            lsp.stop()
            assert.is_false(lsp.is_running())
        end)
    end)

    describe('status function', function()
        it('returns string', function()
            local result = lsp.status()
            assert.is_string(result)
        end)

        it('returns stopped when LSP is not running', function()
            lsp.stop()
            assert.equals('stopped', lsp.status())
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                lsp.setup({})
            end)
        end)

        it('merges config with defaults', function()
            lsp.setup({ enabled = false })
            assert.is_false(lsp.config.enabled)
            -- Reset
            lsp.setup({ enabled = true })
        end)
    end)

    describe('stop function', function()
        it('can be called safely when not running', function()
            assert.has_no_errors(function()
                lsp.stop()
            end)
        end)

        it('resets state', function()
            lsp.stop()
            assert.is_nil(lsp.state.client_id)
        end)
    end)

    describe('enable/disable functions', function()
        it('has enable function', function()
            assert.is_function(lsp.enable)
        end)

        it('has disable function', function()
            assert.is_function(lsp.disable)
        end)

        it('has toggle function', function()
            assert.is_function(lsp.toggle)
        end)

        it('disable sets enabled to false', function()
            lsp.disable()
            assert.is_false(lsp.config.enabled)
        end)

        it('enable sets enabled to true', function()
            lsp.config.enabled = false
            lsp.enable()
            assert.is_true(lsp.config.enabled)
        end)
    end)

    describe('usage tracking', function()
        it('has usage function', function()
            assert.is_function(lsp.usage)
        end)

        it('has format_usage function', function()
            assert.is_function(lsp.format_usage)
        end)

        it('usage returns table', function()
            local stats = lsp.usage()
            assert.is_table(stats)
        end)

        it('format_usage returns string', function()
            local output = lsp.format_usage()
            assert.is_string(output)
        end)

        it('has track_request function', function()
            assert.is_function(lsp.track_request)
        end)

        it('has track_accepted function', function()
            assert.is_function(lsp.track_accepted)
        end)

        it('track_request increments counter', function()
            local before = lsp.state.completions_requested
            lsp.track_request()
            assert.equals(before + 1, lsp.state.completions_requested)
        end)
    end)
end)

