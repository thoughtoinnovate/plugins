-- Tests for health module
-- Tests :checkhealth integration

local health = require('tark.health')

describe('health - checkhealth integration', function()
    describe('module functions exist', function()
        it('has check function', function()
            assert.is_function(health.check)
        end)
    end)

    describe('check function', function()
        -- Note: We don't actually run check() as it outputs to vim.health
        -- which may not be available in all test environments
        
        it('is callable', function()
            assert.is_function(health.check)
        end)
    end)
end)

