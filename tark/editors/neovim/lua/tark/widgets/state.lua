local M = {
    transcript_buf = nil,
    transcript_win = nil,
    input_buf = nil,
    input_win = nil,
    messages = {},
    current_stream = nil,
    busy = false,
    mode = 'ask',
    provider = nil,
    model = nil,
    pending_request_id = nil,
    pending_approval = nil,
    pending_questionnaire = nil,
}

function M.reset_stream()
    M.current_stream = nil
end

return M
