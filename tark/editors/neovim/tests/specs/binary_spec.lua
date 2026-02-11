-- Tests for binary module
-- Tests binary finding, platform detection, and download functionality

local binary = require('tark.binary')

describe('binary - binary management', function()
    describe('module functions exist', function()
        it('has find function', function()
            assert.is_function(binary.find)
        end)

        it('has download function', function()
            assert.is_function(binary.download)
        end)

        it('has version function', function()
            assert.is_function(binary.version)
        end)

        it('has setup function', function()
            assert.is_function(binary.setup)
        end)
    end)

    describe('find function', function()
        it('returns nil or string', function()
            local result = binary.find()
            assert.is_true(result == nil or type(result) == 'string')
        end)

        it('can be called multiple times', function()
            local result1 = binary.find()
            local result2 = binary.find()
            assert.equals(result1, result2)
        end)
    end)

    describe('version function', function()
        it('returns nil or string', function()
            local result = binary.version()
            assert.is_true(result == nil or type(result) == 'string')
        end)
    end)

    describe('config', function()
        it('has default config', function()
            assert.is_table(binary.config)
        end)

        it('has auto_download config', function()
            assert.is_boolean(binary.config.auto_download)
        end)
    end)

    describe('setup function', function()
        it('accepts empty config', function()
            assert.has_no_errors(function()
                binary.setup({})
            end)
        end)

        it('merges config with defaults', function()
            binary.setup({ auto_download = false })
            assert.is_false(binary.config.auto_download)
            -- Reset
            binary.setup({ auto_download = true })
        end)
    end)
end)

