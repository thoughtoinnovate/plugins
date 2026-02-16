local chat = require('tark.widgets.chat')
local state = require('tark.widgets.state')

describe('permission widget model', function()
    before_each(function()
        state.pending_permission = nil
    end)

    it('defaults selection to first option', function()
        chat.on_permission_request({
            options = {
                { optionId = 'allow_once', name = 'Allow once' },
                { optionId = 'reject_once', name = 'Reject once' },
            },
        }, function() end)

        assert.equals(1, state.pending_permission.selected_index)
    end)

    it('cancel clears pending permission', function()
        chat.on_permission_request({
            options = {
                { optionId = 'allow_once', name = 'Allow once' },
            },
        }, function() end)

        assert.is_not_nil(state.pending_permission)
        chat.clear_pending_permission()
        assert.is_nil(state.pending_permission)
    end)
end)
