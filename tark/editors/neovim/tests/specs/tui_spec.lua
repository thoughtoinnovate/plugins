-- Tests for TUI module
-- Tests window management and state tracking

local tui = require('tark.tui')

describe('tui - TUI integration', function()
    describe('module functions exist', function()
        it('has open function', function()
            assert.is_function(tui.open)
        end)

        it('has close function', function()
            assert.is_function(tui.close)
        end)

        it('has toggle function', function()
            assert.is_function(tui.toggle)
        end)

        it('has is_open function', function()
            assert.is_function(tui.is_open)
        end)

        it('has cleanup function', function()
            assert.is_function(tui.cleanup)
        end)

        it('has setup function', function()
            assert.is_function(tui.setup)
        end)

        it('has setup_autocmds function', function()
            assert.is_function(tui.setup_autocmds)
        end)

        it('has send_prompt function', function()
            assert.is_function(tui.send_prompt)
        end)

        it('has ask_buffer function', function()
            assert.is_function(tui.ask_buffer)
        end)

        it('has ask_selection function', function()
            assert.is_function(tui.ask_selection)
        end)
    end)

    describe('state tracking', function()
        it('has state table', function()
            assert.is_table(tui.state)
        end)

        it('state has buf field', function()
            -- buf can be nil or number
            assert.is_true(tui.state.buf == nil or type(tui.state.buf) == 'number')
        end)

        it('state has win field', function()
            -- win can be nil or number
            assert.is_true(tui.state.win == nil or type(tui.state.win) == 'number')
        end)

        it('state has job_id field', function()
            -- job_id can be nil or number
            assert.is_true(tui.state.job_id == nil or type(tui.state.job_id) == 'number')
        end)

        it('state has socket_path field', function()
            -- socket_path can be nil or string
            assert.is_true(tui.state.socket_path == nil or type(tui.state.socket_path) == 'string')
        end)
    end)

    describe('is_open function', function()
        it('returns boolean', function()
            local result = tui.is_open()
            assert.is_boolean(result)
        end)

        it('returns false when TUI is not open', function()
            -- Ensure TUI is closed
            tui.cleanup()
            assert.is_false(tui.is_open())
        end)
    end)

    describe('config', function()
        it('has default config', function()
            assert.is_table(tui.config)
        end)

        it('has window config', function()
            assert.is_table(tui.config.window)
        end)

        it('window config has position', function()
            assert.is_string(tui.config.window.position)
        end)

        it('window config has width', function()
            assert.is_number(tui.config.window.width)
        end)

        it('window config has height', function()
            assert.is_number(tui.config.window.height)
        end)

        it('position is valid value', function()
            local valid_positions = { right = true, left = true, bottom = true, top = true, float = true }
            assert.is_true(valid_positions[tui.config.window.position])
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                tui.setup({})
            end)
        end)

        it('merges config with defaults', function()
            tui.setup({ window = { position = 'float' } })
            assert.equals('float', tui.config.window.position)
            -- Reset
            tui.setup({ window = { position = 'right' } })
        end)
    end)

    describe('cleanup function', function()
        it('can be called safely', function()
            assert.has_no_errors(function()
                tui.cleanup()
            end)
        end)

        it('resets state', function()
            tui.cleanup()
            assert.is_nil(tui.state.buf)
            assert.is_nil(tui.state.win)
            assert.is_nil(tui.state.job_id)
        end)
    end)
end)
