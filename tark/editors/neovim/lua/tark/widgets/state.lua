local M = {
    buf = nil,
    win = nil,
    messages = {},
    current_stream = nil,
    busy = false,
    mode = 'ask',
    provider = nil,
    model = nil,
}

function M.reset_stream()
    M.current_stream = nil
end

return M
