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

    it('renders progress indicator above prompt area while busy', function()
        state.messages = {}
        state.transcript_buf = vim.api.nvim_create_buf(false, true)
        vim.bo[state.transcript_buf].modifiable = false

        chat.on_status({ busy = true, mode = 'ask' })
        local lines = vim.api.nvim_buf_get_lines(state.transcript_buf, 0, -1, false)
        local joined = table.concat(lines, '\n')
        assert.is_true(joined:match('Progress: ') ~= nil)
        assert.is_true(joined:match('Progress: %-') == nil)
        local progress_idx = nil
        local input_keys_idx = nil
        for i, line in ipairs(lines) do
            if line:match('^Progress: ') then
                progress_idx = i
            end
            if line:match('^Input keys: ') then
                input_keys_idx = i
            end
        end
        assert.is_not_nil(progress_idx)
        assert.is_not_nil(input_keys_idx)
        assert.is_true(progress_idx > input_keys_idx)

        chat.on_status({ busy = false, mode = 'ask' })
        lines = vim.api.nvim_buf_get_lines(state.transcript_buf, 0, -1, false)
        joined = table.concat(lines, '\n')
        assert.is_true(joined:match('Progress: %-') ~= nil)

        state.transcript_buf = nil
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

    it('on_final does not append duplicate assistant message when stream is not active', function()
        state.messages = { { role = 'assistant', text = 'same text' } }
        state.current_stream = nil
        chat.on_final({ text = 'same text' })
        assert.equals(1, #state.messages)
    end)

    it('ignores duplicate final events for same request_id', function()
        state.messages = {}
        state.current_stream = nil
        state.response_index_by_request = {}
        state.finalized_requests = {}

        chat.on_final({ request_id = 'req-dup-1', text = 'hello once' })
        chat.on_final({ request_id = 'req-dup-1', text = 'hello once' })

        assert.equals(1, #state.messages)
        assert.equals('hello once', state.messages[1].text)
    end)

    it('tracks pending approval and questionnaire state', function()
        chat.on_approval_request({ interaction_id = 'itx-1', request_id = 'req-1', tool = 'shell' })
        assert.is_not_nil(chat.pending_approval())
        assert.equals('approve_once', chat.pending_approval_decision())
        chat.clear_pending_approval()
        assert.is_nil(chat.pending_approval())

        chat.on_questionnaire_request({ interaction_id = 'itx-2', request_id = 'req-2', questionnaire = { title = 'Q' } })
        assert.is_not_nil(chat.pending_questionnaire())
        chat.clear_pending_questionnaire()
        assert.is_nil(chat.pending_questionnaire())
    end)

    it('applies queue size updates to status model', function()
        chat.on_queue(2)
        assert.equals(2, state.queue_size)
    end)

    it('validates questionnaire answers before submit', function()
        chat.on_questionnaire_request({
            interaction_id = 'itx-3',
            request_id = 'req-3',
            questionnaire = {
                title = 'Test',
                questions = {
                    {
                        id = 'q1',
                        text = 'Pick one',
                        type = 'single_select',
                        options = {
                            { value = 'a', label = 'A' },
                        },
                    },
                },
            },
        })
        assert.is_false(chat.can_submit_questionnaire())
        state.pending_questionnaire.answers.q1 = 'a'
        assert.is_true(chat.can_submit_questionnaire())
    end)

    it('renders multiline error text without buffer line errors', function()
        state.messages = {}
        state.transcript_buf = vim.api.nvim_create_buf(false, true)
        vim.bo[state.transcript_buf].modifiable = false

        local ok = pcall(function()
            chat.on_error({ message = 'line one\nline two\nline three' })
        end)

        assert.is_true(ok)

        state.transcript_buf = nil
    end)

    it('renders assistant markdown message as multiline content', function()
        state.messages = {}
        state.current_stream = nil
        state.response_index_by_request = {}
        state.finalized_requests = {}
        state.transcript_buf = vim.api.nvim_create_buf(false, true)
        vim.bo[state.transcript_buf].modifiable = false

        chat.on_final({ request_id = 'req-md-1', text = '## Title\n- item one\n- item two' })
        local lines = vim.api.nvim_buf_get_lines(state.transcript_buf, 0, -1, false)
        local joined = table.concat(lines, '\n')
        assert.is_true(joined:match('### assistant') ~= nil)
        assert.is_true(joined:match('## Title') ~= nil)
        assert.is_true(joined:match('%- item one') ~= nil)
        assert.is_true(joined:match('%- item two') ~= nil)

        state.transcript_buf = nil
    end)

    it('auto-scrolls transcript window to latest message', function()
        state.messages = {}
        state.current_stream = nil
        state.response_index_by_request = {}
        state.finalized_requests = {}

        vim.cmd('new')
        local win = vim.api.nvim_get_current_win()
        local buf = vim.api.nvim_create_buf(false, true)
        vim.api.nvim_win_set_buf(win, buf)
        vim.bo[buf].modifiable = false
        state.transcript_win = win
        state.transcript_buf = buf

        local long_text = {}
        for i = 1, 60 do
            long_text[#long_text + 1] = string.format('line %d', i)
        end
        chat.on_final({ request_id = 'req-scroll-1', text = table.concat(long_text, '\n') })

        local cursor = vim.api.nvim_win_get_cursor(win)
        local last_line = vim.api.nvim_buf_line_count(buf)
        assert.equals(last_line, cursor[1])

        vim.api.nvim_win_close(win, true)
        state.transcript_win = nil
        state.transcript_buf = nil
    end)
end)
