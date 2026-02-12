local state = require('tark.widgets.state')

local M = {}

M.config = {
    window = {
        position = 'right',
        width = 0.4,
        height = 0.5,
        input_height = 3,
    },
}

local function compute_width()
    local width = M.config.window.width
    if width <= 1 then
        return math.max(50, math.floor(vim.o.columns * width))
    end
    return math.floor(width)
end

local function status_line()
    local busy = state.busy and 'busy' or 'idle'
    local mode = state.mode or 'ask'
    local provider = state.provider or '-'
    local model = state.model or '-'
    local parts = {
        string.format('[%s]', busy),
        string.format('mode=%s', mode),
        string.format('provider=%s', provider),
        string.format('model=%s', model),
    }

    if state.pending_approval then
        table.insert(parts, 'approval=pending')
    end
    if state.pending_questionnaire then
        table.insert(parts, 'questionnaire=pending')
    end

    return table.concat(parts, '  ')
end

local function render_transcript()
    if not state.transcript_buf or not vim.api.nvim_buf_is_valid(state.transcript_buf) then
        return
    end

    local lines = { 'tark chat (ACP v2)', string.rep('=', 40), status_line(), '' }

    for _, msg in ipairs(state.messages) do
        table.insert(lines, string.format('%s: %s', msg.role, msg.text))
        table.insert(lines, '')
    end

    if state.pending_approval then
        table.insert(lines, 'Approval required: use :TarkApproval approve_once|approve_session|approve_always|deny_once|deny_always')
    end

    if state.pending_questionnaire then
        table.insert(lines, 'Questionnaire pending: use :TarkQuestionnaireSubmit or :TarkQuestionnaireCancel')
    end

    table.insert(lines, 'Enter in input pane sends. Ctrl-C cancels current request.')

    vim.bo[state.transcript_buf].modifiable = true
    vim.api.nvim_buf_set_lines(state.transcript_buf, 0, -1, false, lines)
    vim.bo[state.transcript_buf].modifiable = false
end

local function get_input_text()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return ''
    end
    local lines = vim.api.nvim_buf_get_lines(state.input_buf, 0, -1, false)
    return table.concat(lines, '\n')
end

local function clear_input()
    if state.input_buf and vim.api.nvim_buf_is_valid(state.input_buf) then
        vim.bo[state.input_buf].modifiable = true
        vim.api.nvim_buf_set_lines(state.input_buf, 0, -1, false, { '' })
        vim.bo[state.input_buf].modifiable = true
    end
end

local function setup_input_keymaps()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return
    end

    local opts = { buffer = state.input_buf, silent = true, noremap = true }
    vim.keymap.set('n', '<CR>', '<cmd>TarkChatSend<cr>', opts)
    vim.keymap.set('i', '<CR>', '<Esc><cmd>TarkChatSend<cr>', opts)
    vim.keymap.set('n', '<C-c>', '<cmd>TarkChatCancel<cr>', opts)
    vim.keymap.set('i', '<C-c>', '<Esc><cmd>TarkChatCancel<cr>', opts)
end

local function ensure_windows()
    if state.transcript_win and vim.api.nvim_win_is_valid(state.transcript_win) then
        return
    end

    vim.cmd('vsplit')
    state.transcript_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_width(state.transcript_win, compute_width())

    state.transcript_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[state.transcript_buf].buftype = 'nofile'
    vim.bo[state.transcript_buf].swapfile = false
    vim.bo[state.transcript_buf].bufhidden = 'hide'
    vim.bo[state.transcript_buf].modifiable = false
    vim.api.nvim_win_set_buf(state.transcript_win, state.transcript_buf)
    vim.api.nvim_buf_set_name(state.transcript_buf, 'tark://chat/transcript')

    vim.cmd('belowright split')
    state.input_win = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_height(state.input_win, M.config.window.input_height or 3)
    state.input_buf = vim.api.nvim_create_buf(false, true)
    vim.bo[state.input_buf].buftype = 'nofile'
    vim.bo[state.input_buf].swapfile = false
    vim.bo[state.input_buf].bufhidden = 'hide'
    vim.bo[state.input_buf].modifiable = true
    vim.api.nvim_win_set_buf(state.input_win, state.input_buf)
    vim.api.nvim_buf_set_name(state.input_buf, 'tark://chat/input')
    vim.api.nvim_buf_set_lines(state.input_buf, 0, -1, false, { '' })

    setup_input_keymaps()
    vim.api.nvim_set_current_win(state.input_win)
    vim.cmd('startinsert')
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})
end

function M.open()
    ensure_windows()
    render_transcript()
end

function M.close()
    if state.input_win and vim.api.nvim_win_is_valid(state.input_win) then
        vim.api.nvim_win_close(state.input_win, true)
    end
    if state.transcript_win and vim.api.nvim_win_is_valid(state.transcript_win) then
        vim.api.nvim_win_close(state.transcript_win, true)
    end

    state.input_win = nil
    state.input_buf = nil
    state.transcript_win = nil
    state.transcript_buf = nil
end

function M.toggle()
    if state.transcript_win and vim.api.nvim_win_is_valid(state.transcript_win) then
        M.close()
    else
        M.open()
    end
end

function M.consume_input_or(text)
    local value = text
    if not value or value == '' then
        value = get_input_text()
    end
    value = (value or ''):gsub('^%s+', ''):gsub('%s+$', '')
    clear_input()
    return value
end

function M.append_user(text)
    table.insert(state.messages, { role = 'user', text = text })
    state.current_stream = nil
    render_transcript()
end

function M.on_delta(params)
    if not state.current_stream then
        table.insert(state.messages, { role = 'assistant', text = '' })
        state.current_stream = #state.messages
    end

    local msg = state.messages[state.current_stream]
    msg.text = msg.text .. (params.delta or '')
    render_transcript()
end

function M.on_final(params)
    if not state.current_stream then
        table.insert(state.messages, { role = 'assistant', text = params.text or '' })
    else
        if params.text and params.text ~= '' then
            state.messages[state.current_stream].text = params.text
        end
    end

    state.pending_request_id = nil
    state.current_stream = nil
    state.busy = false
    render_transcript()
end

function M.on_status(params)
    state.busy = params.busy == true
    state.mode = params.mode or state.mode
    state.provider = params.provider or state.provider
    state.model = params.model or state.model
    render_transcript()
end

function M.on_error(params)
    local message = params.message or 'Unknown ACP error'
    table.insert(state.messages, { role = 'error', text = message })
    state.busy = false
    state.current_stream = nil
    render_transcript()
end

function M.on_send_accepted(request_id)
    state.pending_request_id = request_id
    state.busy = true
    render_transcript()
end

function M.on_approval_request(params)
    state.pending_approval = params
    table.insert(state.messages, {
        role = 'system',
        text = string.format('Approval requested for tool %s', tostring(params.tool or 'unknown')),
    })
    render_transcript()
end

function M.on_questionnaire_request(params)
    state.pending_questionnaire = params
    table.insert(state.messages, {
        role = 'system',
        text = string.format('Questionnaire requested: %s', tostring((params.questionnaire or {}).title or '')),
    })
    render_transcript()
end

function M.clear_pending_approval()
    state.pending_approval = nil
    render_transcript()
end

function M.clear_pending_questionnaire()
    state.pending_questionnaire = nil
    render_transcript()
end

function M.pending_approval()
    return state.pending_approval
end

function M.pending_questionnaire()
    return state.pending_questionnaire
end

return M
