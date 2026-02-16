local M = {
    transcript_buf = nil,
    transcript_win = nil,
    input_buf = nil,
    input_win = nil,

    messages = {},
    current_stream = nil,
    current_stream_request_id = nil,
    response_index_by_request = {},
    finalized_requests = {},

    busy = false,
    mode = 'ask',
    provider = nil,
    model = nil,

    send_queue = {},
    queue_size = 0,
    active_request_id = nil,

    pending_permission = nil,

    ui_focus = 'input',
    ui_action_cursor = 1,
    ui_actions = {},

    last_error = nil,
}

function M.reset_stream()
    M.current_stream = nil
end

function M.reset_ui_actions()
    M.ui_actions = {}
    M.ui_action_cursor = 1
end

function M.set_focus(focus)
    if focus == 'transcript' or focus == 'input' or focus == 'interaction' then
        M.ui_focus = focus
    end
end

return M
