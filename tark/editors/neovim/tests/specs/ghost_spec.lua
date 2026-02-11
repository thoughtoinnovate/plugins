-- Tests for ghost text module
-- Tests inline completion suggestions

local ghost = require('tark.ghost')

describe('ghost - ghost text completions', function()
    describe('module functions exist', function()
        it('has start_server function', function()
            assert.is_function(ghost.start_server)
        end)

        it('has stop_server function', function()
            assert.is_function(ghost.stop_server)
        end)

        it('has is_server_running function', function()
            assert.is_function(ghost.is_server_running)
        end)

        it('has enable function', function()
            assert.is_function(ghost.enable)
        end)

        it('has disable function', function()
            assert.is_function(ghost.disable)
        end)

        it('has toggle function', function()
            assert.is_function(ghost.toggle)
        end)

        it('has accept function', function()
            assert.is_function(ghost.accept)
        end)

        it('has dismiss function', function()
            assert.is_function(ghost.dismiss)
        end)

        it('has usage function', function()
            assert.is_function(ghost.usage)
        end)

        it('has format_usage function', function()
            assert.is_function(ghost.format_usage)
        end)

        it('has setup function', function()
            assert.is_function(ghost.setup)
        end)

        it('has setup_autocmds function', function()
            assert.is_function(ghost.setup_autocmds)
        end)

        it('has setup_keymaps function', function()
            assert.is_function(ghost.setup_keymaps)
        end)
    end)

    describe('state tracking', function()
        it('has state table', function()
            assert.is_table(ghost.state)
        end)

        it('state has server_job field', function()
            assert.is_true(ghost.state.server_job == nil or type(ghost.state.server_job) == 'number')
        end)

        it('state has current_suggestion field', function()
            assert.is_true(ghost.state.current_suggestion == nil or type(ghost.state.current_suggestion) == 'string')
        end)

        it('state has completions_requested field', function()
            assert.is_number(ghost.state.completions_requested)
        end)

        it('state has completions_shown field', function()
            assert.is_number(ghost.state.completions_shown)
        end)

        it('state has completions_accepted field', function()
            assert.is_number(ghost.state.completions_accepted)
        end)
    end)

    describe('config', function()
        it('has default config', function()
            assert.is_table(ghost.config)
        end)

        it('has enabled config', function()
            assert.is_boolean(ghost.config.enabled)
        end)

        it('has auto_trigger config', function()
            assert.is_boolean(ghost.config.auto_trigger)
        end)

        it('has debounce_ms config', function()
            assert.is_number(ghost.config.debounce_ms)
        end)

        it('has accept_key config', function()
            assert.is_string(ghost.config.accept_key)
        end)

        it('has hl_group config', function()
            assert.is_string(ghost.config.hl_group)
        end)
    end)

    describe('is_server_running function', function()
        it('returns boolean', function()
            local result = ghost.is_server_running()
            assert.is_boolean(result)
        end)

        it('returns false when server is not started', function()
            ghost.stop_server()
            assert.is_false(ghost.is_server_running())
        end)
    end)

    describe('usage function', function()
        it('returns table', function()
            local stats = ghost.usage()
            assert.is_table(stats)
        end)

        it('usage has enabled field', function()
            local stats = ghost.usage()
            assert.is_boolean(stats.enabled)
        end)

        it('usage has server_running field', function()
            local stats = ghost.usage()
            assert.is_boolean(stats.server_running)
        end)

        it('usage has completions_requested field', function()
            local stats = ghost.usage()
            assert.is_number(stats.completions_requested)
        end)
    end)

    describe('format_usage function', function()
        it('returns string', function()
            local output = ghost.format_usage()
            assert.is_string(output)
        end)

        it('contains stats header', function()
            local output = ghost.format_usage()
            assert.is_true(output:match('Ghost Text Stats') ~= nil)
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                ghost.setup({})
            end)
        end)

        it('merges config with defaults', function()
            ghost.setup({ debounce_ms = 500 })
            assert.equals(500, ghost.config.debounce_ms)
            -- Reset
            ghost.setup({ debounce_ms = 300 })
        end)
    end)

    describe('stop_server function', function()
        it('can be called safely when not running', function()
            assert.has_no_errors(function()
                ghost.stop_server()
            end)
        end)

        it('resets server_job state', function()
            ghost.stop_server()
            assert.is_nil(ghost.state.server_job)
        end)
    end)

    describe('dismiss function', function()
        it('can be called safely', function()
            assert.has_no_errors(function()
                ghost.dismiss()
            end)
        end)

        it('clears current_suggestion', function()
            ghost.dismiss()
            assert.is_nil(ghost.state.current_suggestion)
        end)
    end)
end)

