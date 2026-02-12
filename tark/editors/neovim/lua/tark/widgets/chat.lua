local state = require('tark.widgets.state')

local M = {}

M.config = {
    window = {
        position = 'right',
        width = 0.4,
        height = 0.5,
    },
}

local function compute_width()
    local width = M.config.window.width
    if width <= 1 then
        return math.max(40, math.floor(vim.o.columns * width))
    end
    return math.floor(width)
end

local function ensure_window()
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        return
    end

    vim.cmd('vsplit')
    state.win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_width(state.win, compute_width())

    state.buf = vim.api.nvim_create_buf(false, true)
    vim.bo[state.buf].buftype = 'nofile'
    vim.bo[state.buf].swapfile = false
    vim.bo[state.buf].bufhidden = 'hide'
    vim.bo[state.buf].modifiable = true
    vim.api.nvim_win_set_buf(state.win, state.buf)
    vim.api.nvim_buf_set_name(state.buf, 'tark://chat')
end

local function render()
    if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
        return
    end

    local lines = { 'tark chat (ACP)', string.rep('=', 32), '' }
    for _, msg in ipairs(state.messages) do
        table.insert(lines, string.format('%s: %s', msg.role, msg.text))
        table.insert(lines, '')
    end

    if state.busy then
        table.insert(lines, '[processing...]')
    else
        table.insert(lines, '[ready]')
    end

    table.insert(lines, 'Use :TarkAskBuffer or :TarkAskSelection to send context')

    vim.bo[state.buf].modifiable = true
    vim.api.nvim_buf_set_lines(state.buf, 0, -1, false, lines)
    vim.bo[state.buf].modifiable = false
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})
end

function M.open()
    ensure_window()
    render()
end

function M.close()
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        vim.api.nvim_win_close(state.win, true)
    end
    state.win = nil
end

function M.toggle()
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        M.close()
    else
        M.open()
    end
end

function M.append_user(text)
    table.insert(state.messages, { role = 'user', text = text })
    state.current_stream = nil
    render()
end

function M.on_delta(params)
    if not state.current_stream then
        table.insert(state.messages, { role = 'assistant', text = '' })
        state.current_stream = #state.messages
    end

    local msg = state.messages[state.current_stream]
    msg.text = msg.text .. (params.delta or '')
    render()
end

function M.on_final(params)
    if not state.current_stream then
        table.insert(state.messages, { role = 'assistant', text = params.text or '' })
    else
        if params.text and params.text ~= '' then
            state.messages[state.current_stream].text = params.text
        end
    end

    state.current_stream = nil
    state.busy = false
    render()
end

function M.on_status(params)
    state.busy = params.busy == true
    state.mode = params.mode or state.mode
    state.provider = params.provider or state.provider
    state.model = params.model or state.model
    render()
end

function M.on_error(params)
    local message = params.message or 'Unknown ACP error'
    table.insert(state.messages, { role = 'error', text = message })
    state.busy = false
    state.current_stream = nil
    render()
end

return M
