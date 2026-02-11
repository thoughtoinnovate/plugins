-- Tests for tark statusline module
local statusline = require('tark.statusline')

describe('statusline', function()
    describe('module structure', function()
        it('has icons table', function()
            assert.is_table(statusline.icons)
        end)
        
        it('has highlights table', function()
            assert.is_table(statusline.highlights)
        end)
        
        it('has required icon keys', function()
            assert.is_string(statusline.icons.active)
            assert.is_string(statusline.icons.idle)
            assert.is_string(statusline.icons.error)
            assert.is_string(statusline.icons.disabled)
        end)
        
        it('has fallback text icons', function()
            assert.is_string(statusline.icons.active_text)
            assert.is_string(statusline.icons.error_text)
        end)
    end)
    
    describe('get_status function', function()
        it('exists', function()
            assert.is_function(statusline.get_status)
        end)
        
        it('returns table with required fields', function()
            local status = statusline.get_status()
            assert.is_table(status)
            assert.is_string(status.status)
            assert.is_string(status.icon)
            assert.is_string(status.text)
            assert.is_string(status.highlight)
        end)
        
        it('returns valid status value', function()
            local status = statusline.get_status()
            local valid_statuses = {
                'active', 'idle', 'loading', 'error',
                'disabled', 'no_server', 'no_binary', 'not_loaded'
            }
            local found = false
            for _, v in ipairs(valid_statuses) do
                if status.status == v then
                    found = true
                    break
                end
            end
            assert.is_true(found, 'Invalid status: ' .. status.status)
        end)
    end)
    
    describe('status function', function()
        it('exists', function()
            assert.is_function(statusline.status)
        end)
        
        it('returns string', function()
            local result = statusline.status()
            assert.is_string(result)
        end)
        
        it('includes tark by default', function()
            local result = statusline.status()
            assert.matches('tark', result)
        end)
        
        it('respects show_text option', function()
            local with_text = statusline.status({ show_text = true })
            local without_text = statusline.status({ show_text = false })
            
            assert.matches('tark', with_text)
            -- Without text should be shorter
            assert.is_true(#without_text < #with_text)
        end)
        
        it('respects use_nerd_fonts option', function()
            local with_nerd = statusline.status({ use_nerd_fonts = true })
            local without_nerd = statusline.status({ use_nerd_fonts = false })
            
            -- Both should be valid strings
            assert.is_string(with_nerd)
            assert.is_string(without_nerd)
        end)
    end)
    
    describe('status_with_hl function', function()
        it('exists', function()
            assert.is_function(statusline.status_with_hl)
        end)
        
        it('returns string with highlight', function()
            local result = statusline.status_with_hl()
            assert.is_string(result)
            -- Should contain highlight group
            assert.matches('%%#Tark', result)
        end)
    end)
    
    describe('lualine component', function()
        it('is table', function()
            assert.is_table(statusline.lualine)
        end)
        
        it('has function as first element', function()
            assert.is_function(statusline.lualine[1])
        end)
        
        it('has color function', function()
            assert.is_function(statusline.lualine.color)
        end)
        
        it('function returns string', function()
            local result = statusline.lualine[1]()
            assert.is_string(result)
        end)
        
        it('color returns table with fg', function()
            local result = statusline.lualine.color()
            assert.is_table(result)
            assert.is_string(result.fg)
        end)
    end)
    
    describe('lualine_icon component', function()
        it('is table', function()
            assert.is_table(statusline.lualine_icon)
        end)
        
        it('returns shorter string than full component', function()
            local full = statusline.lualine[1]()
            local icon_only = statusline.lualine_icon[1]()
            assert.is_true(#icon_only < #full)
        end)
    end)
    
    describe('setup function', function()
        it('exists', function()
            assert.is_function(statusline.setup)
        end)
        
        it('can be called without error', function()
            assert.has_no_errors(function()
                statusline.setup()
            end)
        end)
    end)
    
    describe('highlight groups', function()
        it('are defined after setup', function()
            statusline.setup()
            
            -- Check highlight groups exist
            local highlights = {
                'TarkStatusActive',
                'TarkStatusIdle',
                'TarkStatusLoading',
                'TarkStatusError',
                'TarkStatusDisabled',
            }
            
            for _, hl in ipairs(highlights) do
                local ok, result = pcall(vim.api.nvim_get_hl, 0, { name = hl })
                assert.is_true(ok, 'Highlight ' .. hl .. ' should exist')
            end
        end)
    end)
end)

