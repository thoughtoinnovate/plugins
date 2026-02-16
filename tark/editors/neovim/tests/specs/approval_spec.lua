local chat = require('tark.widgets.chat')

describe('approval widget model', function()
    it('defaults approval decision to approve_once', function()
        chat.on_approval_request({
            interaction_id = 'itx-approval-1',
            request_id = 'req-approval-1',
            tool = 'shell',
            pattern_options = {
                { pattern = 'rm -rf tmp/*' },
                { pattern = 'git clean -fd' },
            },
            timeout_seconds = 30,
        })

        assert.equals('approve_once', chat.pending_approval_decision())
    end)

    it('exposes selected pattern through pending_approval payload', function()
        chat.on_approval_request({
            interaction_id = 'itx-approval-2',
            request_id = 'req-approval-2',
            tool = 'shell',
            pattern_options = {
                { pattern = 'echo *' },
            },
            timeout_seconds = 30,
        })

        local pending = chat.pending_approval()
        pending.selected_pattern = 'echo *'
        assert.equals('echo *', pending.selected_pattern)
    end)
end)
