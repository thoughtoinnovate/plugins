local chat = require('tark.widgets.chat')
local state = require('tark.widgets.state')

describe('questionnaire widget model', function()
    it('requires answers for required fields', function()
        chat.on_questionnaire_request({
            interaction_id = 'itx-q-1',
            request_id = 'req-q-1',
            questionnaire = {
                title = 'Questions',
                questions = {
                    {
                        id = 'q_text',
                        text = 'Why?',
                        type = 'free_text',
                        validation = { required = true },
                    },
                },
            },
        })

        assert.is_false(chat.can_submit_questionnaire())
        state.pending_questionnaire.answers.q_text = 'Because'
        assert.is_true(chat.can_submit_questionnaire())
    end)

    it('returns questionnaire answers payload', function()
        chat.on_questionnaire_request({
            interaction_id = 'itx-q-2',
            request_id = 'req-q-2',
            questionnaire = {
                title = 'Choices',
                questions = {
                    {
                        id = 'q_single',
                        text = 'Pick',
                        type = 'single_select',
                        options = {
                            { value = 'a', label = 'A' },
                        },
                    },
                },
            },
        })

        state.pending_questionnaire.answers.q_single = 'a'
        local answers = chat.questionnaire_answers()
        assert.equals('a', answers.q_single)
    end)
end)
