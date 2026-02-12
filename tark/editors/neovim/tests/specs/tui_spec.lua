-- Tests for ACP chat widget module

local chat = require('tark.widgets.chat')
local state = require('tark.widgets.state')

describe('chat widget - ACP integration', function()
    it('has expected functions', function()
        assert.is_function(chat.open)
        assert.is_function(chat.close)
        assert.is_function(chat.toggle)
        assert.is_function(chat.append_user)
        assert.is_function(chat.on_delta)
        assert.is_function(chat.on_final)
        assert.is_function(chat.on_status)
        assert.is_function(chat.on_error)
        assert.is_function(chat.on_approval_request)
        assert.is_function(chat.on_questionnaire_request)
    end)

    it('state table exists', function()
        assert.is_table(state)
        assert.is_table(state.messages)
    end)

    it('on_status updates busy flag', function()
        chat.on_status({ busy = true, mode = 'ask' })
        assert.is_true(state.busy)
        chat.on_status({ busy = false, mode = 'plan' })
        assert.is_false(state.busy)
        assert.equals('plan', state.mode)
    end)

    it('on_delta creates assistant stream message', function()
        state.messages = {}
        state.current_stream = nil
        chat.on_delta({ delta = 'hello' })
        assert.equals(1, #state.messages)
        assert.equals('assistant', state.messages[1].role)
        assert.equals('hello', state.messages[1].text)
    end)

    it('on_final clears stream state', function()
        state.messages = { { role = 'assistant', text = 'partial' } }
        state.current_stream = 1
        chat.on_final({ text = 'final' })
        assert.is_nil(state.current_stream)
        assert.equals('final', state.messages[1].text)
    end)

    it('tracks pending approval and questionnaire state', function()
        chat.on_approval_request({ interaction_id = 'itx-1', request_id = 'req-1', tool = 'shell' })
        assert.is_not_nil(chat.pending_approval())
        chat.clear_pending_approval()
        assert.is_nil(chat.pending_approval())

        chat.on_questionnaire_request({ interaction_id = 'itx-2', request_id = 'req-2', questionnaire = { title = 'Q' } })
        assert.is_not_nil(chat.pending_questionnaire())
        chat.clear_pending_questionnaire()
        assert.is_nil(chat.pending_questionnaire())
    end)
end)
