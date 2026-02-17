local chat = require('tark.widgets.chat')
local state = require('tark.widgets.state')

describe('chat widget - ACP lifecycle', function()
    before_each(function()
        state.messages = {}
        state.current_stream = nil
        state.current_stream_request_id = nil
        state.response_index_by_request = {}
        state.finalized_requests = {}
        state.pending_permission = nil
        state.busy = false
    end)

    it('has expected functions', function()
        assert.is_function(chat.open)
        assert.is_function(chat.close)
        assert.is_function(chat.toggle)
        assert.is_function(chat.append_user)
        assert.is_function(chat.on_update)
        assert.is_function(chat.on_status)
        assert.is_function(chat.on_error)
        assert.is_function(chat.on_permission_request)
    end)

    it('renders start -> chunk -> end lifecycle without duplicates', function()
        chat.on_update({ update = { sessionUpdate = 'agent_message_start', responseId = 'r1' } })
        chat.on_update({ update = { sessionUpdate = 'agent_message_chunk', responseId = 'r1', content = { text = 'hello' } } })
        chat.on_update({ update = { sessionUpdate = 'agent_message_end', responseId = 'r1', stopReason = 'end_turn' } })
        chat.on_update({ update = { sessionUpdate = 'agent_message_end', responseId = 'r1', stopReason = 'end_turn' } })

        assert.equals(1, #state.messages)
        assert.equals('assistant', state.messages[1].role)
        assert.equals('hello', state.messages[1].text)
        assert.is_true(state.finalized_requests.r1)
    end)

    it('tracks permission requests', function()
        local responded = nil
        chat.on_permission_request({
            options = {
                { optionId = 'allow_once', name = 'Allow once' },
                { optionId = 'reject_once', name = 'Reject once' },
            },
        }, function(option_id)
            responded = option_id
        end)

        assert.is_not_nil(state.pending_permission)
        state.pending_permission.respond('allow_once')
        assert.equals('allow_once', responded)
    end)

    it('applies queue size updates', function()
        chat.on_queue(3)
        assert.equals(3, state.queue_size)
    end)

    it('tracks discovered config option support', function()
        chat.on_config_options({
            config_options_by_id = {
                provider = { id = 'provider', current_value = 'ollama' },
            },
            supports_config_switch = true,
        })
        assert.is_true(state.supports_config_switch)
        assert.is_not_nil(state.config_options_by_id.provider)
    end)

    it('renders multiline error safely', function()
        state.transcript_buf = vim.api.nvim_create_buf(false, true)
        vim.bo[state.transcript_buf].modifiable = false

        assert.has_no_errors(function()
            chat.on_error({ message = 'line one\nline two\nline three' })
        end)

        state.transcript_buf = nil
    end)
end)
