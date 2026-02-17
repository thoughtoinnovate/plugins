local state = require('tark.widgets.state')

local M = {}

M.config = {
    auto_scroll = true,
    window = {
        position = 'right',
        width = 0.4,
        height = 0.5,
        input_height = 3,
    },
}

local SPINNER_FRAMES = { '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏' }
local spinner_frame = 1
local spinner_active = false
local render_transcript

local function compute_width()
    local width = M.config.window.width
    if width <= 1 then
        return math.max(50, math.floor(vim.o.columns * width))
    end
    return math.floor(width)
end

local function sanitize_text(value)
    local s = tostring(value or '')
    s = s:gsub('[%z\r\n]', ' ')
    return s
end

local function sanitize_lines(value)
    local s = tostring(value or '')
    s = s:gsub('%z', '')
    s = s:gsub('\r', '')
    return vim.split(s, '\n', { plain = true, trimempty = false })
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
        string.format('queue=%d', state.queue_size or 0),
        string.format('focus=%s', state.ui_focus or 'input'),
    }

    if state.pending_permission then
        table.insert(parts, 'permission=pending')
    end
    return table.concat(parts, '  ')
end

local function progress_line()
    local progress = state.busy and SPINNER_FRAMES[spinner_frame] or '-'
    return string.format('Progress: %s', progress)
end

local function tick_spinner()
    if not spinner_active then
        return
    end
    if not state.busy then
        spinner_active = false
        spinner_frame = 1
        return
    end
    if not state.transcript_buf or not vim.api.nvim_buf_is_valid(state.transcript_buf) then
        spinner_active = false
        return
    end
    spinner_frame = (spinner_frame % #SPINNER_FRAMES) + 1
    render_transcript()
    vim.defer_fn(tick_spinner, 120)
end

local function ensure_spinner()
    if spinner_active then
        return
    end
    spinner_active = true
    vim.defer_fn(tick_spinner, 120)
end

local function stop_spinner()
    spinner_active = false
    spinner_frame = 1
end

local function action_count()
    return #(state.ui_actions or {})
end

local function clamp_action_cursor()
    local count = action_count()
    if count == 0 then
        state.ui_action_cursor = 1
        return
    end
    if state.ui_action_cursor < 1 then
        state.ui_action_cursor = 1
    end
    if state.ui_action_cursor > count then
        state.ui_action_cursor = count
    end
end

local function get_input_text()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return ''
    end
    local lines = vim.api.nvim_buf_get_lines(state.input_buf, 0, -1, false)
    return table.concat(lines, '\n')
end

local function set_input_text(text)
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return
    end
    vim.bo[state.input_buf].modifiable = true
    local lines = vim.split(text or '', '\n', { plain = true, trimempty = false })
    if #lines == 0 then
        lines = { '' }
    end
    vim.api.nvim_buf_set_lines(state.input_buf, 0, -1, false, lines)
    vim.bo[state.input_buf].modifiable = true
end

local function clear_input()
    set_input_text('')
end

local function apply_focus(target)
    if target == 'transcript' or target == 'interaction' then
        if state.transcript_win and vim.api.nvim_win_is_valid(state.transcript_win) then
            vim.api.nvim_set_current_win(state.transcript_win)
            vim.cmd('stopinsert')
            state.ui_focus = target
        end
        return
    end

    if state.input_win and vim.api.nvim_win_is_valid(state.input_win) then
        vim.api.nvim_set_current_win(state.input_win)
        vim.cmd('startinsert')
        state.ui_focus = 'input'
    end
end

local function pending_interaction_exists()
    return state.pending_permission ~= nil
end

local function request_key(request_id)
    if not request_id or request_id == '' then
        return nil
    end
    return tostring(request_id)
end

local function ensure_ui_actions()
    if not state.ui_actions then
        state.ui_actions = {}
    end
end

local function add_action(label, handler, metadata)
    ensure_ui_actions()
    table.insert(state.ui_actions, {
        label = sanitize_text(label),
        handler = handler,
        kind = metadata and metadata.kind or nil,
        data = metadata and metadata.data or nil,
    })
end

render_transcript = function()
    if not state.transcript_buf or not vim.api.nvim_buf_is_valid(state.transcript_buf) then
        return
    end

    state.ui_actions = {}

    local lines = { 'tark chat (ACP v2)', string.rep('=', 40), status_line(), '' }

    local function push_line(text)
        table.insert(lines, sanitize_text(text))
    end

    local function push_multiline(prefix, body)
        local parts = sanitize_lines(body)
        if #parts == 0 then
            push_line(prefix)
            return
        end
        push_line(prefix .. parts[1])
        for i = 2, #parts do
            push_line('  ' .. parts[i])
        end
    end

    for _, msg in ipairs(state.messages) do
        push_line(string.format('### %s', sanitize_text(msg.role)))
        local parts = sanitize_lines(msg.text)
        if #parts == 0 then
            push_line('')
        else
            for _, part in ipairs(parts) do
                table.insert(lines, part)
            end
        end
        if msg.thinking and msg.thinking ~= '' then
            push_line('')
            push_line('> reasoning')
            local tparts = sanitize_lines(msg.thinking)
            for _, tpart in ipairs(tparts) do
                push_line('> ' .. tpart)
            end
        end
        push_line('')
    end

    if state.pending_permission then
        local permission = state.pending_permission
        push_line('Permission Request')
        if permission.title and permission.title ~= '' then
            push_multiline('  title: ', permission.title)
        end
        if permission.tool and permission.tool ~= '' then
            push_multiline('  tool: ', permission.tool)
        end
        if permission.command and permission.command ~= '' then
            push_multiline('  command: ', permission.command)
        end

        local options = permission.options or {}
        if #options == 0 then
            push_line('  no permission options provided by server')
        else
            push_line('  options:')
            for idx, option in ipairs(options) do
                local selected = permission.selected_index == idx
                local marker = selected and '>' or ' '
                add_action('permission-option:' .. tostring(option.optionId or idx), function()
                    permission.selected_index = idx
                end, { kind = 'permission_option', data = { index = idx, option_id = option.optionId } })
                push_line(string.format(
                    '  %s [%s] %s',
                    marker,
                    selected and 'x' or ' ',
                    sanitize_text(option.name or option.optionId or ('option-' .. idx))
                ))
            end
        end

        add_action('permission-submit', function()
            local selected = options[permission.selected_index or 1]
            local option_id = selected and selected.optionId or nil
            if permission.respond then
                permission.respond(option_id)
            end
            state.pending_permission = nil
        end, { kind = 'permission_submit' })
        add_action('permission-cancel', function()
            if permission.respond then
                permission.respond(nil)
            end
            state.pending_permission = nil
        end, { kind = 'permission_cancel' })
        push_line('  [submit] send selected option')
        push_line('  [cancel] cancel permission request')
        push_line('')
    end

    if state.last_error then
        push_line(string.format('Last error: [%s] %s', sanitize_text(state.last_error.code), sanitize_text(state.last_error.message)))
        push_line('')
    end

    push_line('Input keys: Enter=send, Ctrl-C=cancel, q=close')
    push_line('Interaction keys: j/k=move, Enter=activate, space=toggle option, Ctrl-C=cancel')

    clamp_action_cursor()

    if action_count() > 0 then
        local action = state.ui_actions[state.ui_action_cursor]
        push_line('')
        push_line('Selected action: ' .. sanitize_text(action.label))
    end

    push_line('')
    push_line(progress_line())

    vim.bo[state.transcript_buf].modifiable = true
    vim.api.nvim_buf_set_lines(state.transcript_buf, 0, -1, false, lines)
    vim.bo[state.transcript_buf].modifiable = false

    if M.config.auto_scroll and state.transcript_win and vim.api.nvim_win_is_valid(state.transcript_win) then
        local last_line = vim.api.nvim_buf_line_count(state.transcript_buf)
        pcall(vim.api.nvim_win_set_cursor, state.transcript_win, { math.max(1, last_line), 0 })
    end
end

local function setup_transcript_keymaps()
    if not state.transcript_buf or not vim.api.nvim_buf_is_valid(state.transcript_buf) then
        return
    end

    local opts = { buffer = state.transcript_buf, silent = true, noremap = true }
    vim.keymap.set('n', 'j', '<cmd>AcpUiNextAction<cr>', opts)
    vim.keymap.set('n', 'k', '<cmd>AcpUiPrevAction<cr>', opts)
    vim.keymap.set('n', '<CR>', '<cmd>AcpUiSubmit<cr>', opts)
    vim.keymap.set('n', '<Space>', function()
        require('tark.widgets.chat').toggle_selected_option()
    end, opts)
    vim.keymap.set('n', 'i', function()
        require('tark.widgets.chat').edit_selected_text()
    end, opts)
    vim.keymap.set('n', '<Esc>', function()
        require('tark.widgets.chat').leave_edit_mode()
    end, opts)
    vim.keymap.set('n', '<C-c>', '<cmd>AcpUiCancel<cr>', opts)
    vim.keymap.set('n', 'q', '<cmd>AcpChatClose<cr>', opts)
end

local function setup_input_keymaps()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return
    end

    local opts = { buffer = state.input_buf, silent = true, noremap = true }
    vim.keymap.set('n', '<CR>', '<cmd>AcpUiSubmit<cr>', opts)
    vim.keymap.set('i', '<CR>', '<Esc><cmd>AcpUiSubmit<cr>', opts)
    vim.keymap.set('n', '<C-c>', '<cmd>AcpUiCancel<cr>', opts)
    vim.keymap.set('i', '<C-c>', '<Esc><cmd>AcpUiCancel<cr>', opts)
    vim.keymap.set('n', 'q', '<cmd>AcpChatClose<cr>', opts)
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
    vim.bo[state.transcript_buf].filetype = 'markdown'
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

    setup_transcript_keymaps()
    setup_input_keymaps()
    apply_focus('input')
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})
end

function M.open()
    ensure_windows()
    if state.busy then
        ensure_spinner()
    end
    render_transcript()
end

function M.close()
    stop_spinner()
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

function M.focus(target)
    apply_focus(target)
    render_transcript()
end

function M.next_action()
    if action_count() == 0 then
        return
    end
    state.ui_action_cursor = math.min(action_count(), state.ui_action_cursor + 1)
    state.ui_focus = pending_interaction_exists() and 'interaction' or 'transcript'
    render_transcript()
end

function M.prev_action()
    if action_count() == 0 then
        return
    end
    state.ui_action_cursor = math.max(1, state.ui_action_cursor - 1)
    state.ui_focus = pending_interaction_exists() and 'interaction' or 'transcript'
    render_transcript()
end

function M.toggle_selected_option()
    local action = state.ui_actions[state.ui_action_cursor]
    if not action then
        return
    end
    if action.kind == 'question_multi'
        or action.kind == 'question_single'
        or action.kind == 'approval_decision'
        or action.kind == 'approval_pattern'
        or action.kind == 'permission_option'
    then
        action.handler()
        render_transcript()
    end
end

function M.edit_selected_text()
    local action = state.ui_actions[state.ui_action_cursor]
    if not action or action.kind ~= 'question_text' then
        return
    end
    action.handler()
    render_transcript()
end

function M.leave_edit_mode()
    return
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
    state.current_stream_request_id = nil
    render_transcript()
end

local function ensure_response_message(response_id)
    local key = request_key(response_id)
    if not key then
        return nil
    end
    local idx = state.response_index_by_request[key]
    if idx then
        return idx
    end
    table.insert(state.messages, { role = 'assistant', text = '', response_id = key })
    idx = #state.messages
    state.response_index_by_request[key] = idx
    return idx
end

function M.on_update(params)
    local update = params.update or {}
    local update_type = update.sessionUpdate
    local response_id = request_key(update.responseId)

    if update_type == 'agent_message_start' then
        if response_id and not state.finalized_requests[response_id] then
            ensure_response_message(response_id)
            state.current_stream_request_id = response_id
            state.busy = true
            ensure_spinner()
            render_transcript()
        end
        return
    end

    if update_type == 'agent_message_chunk' and response_id then
        if state.finalized_requests[response_id] then
            return
        end
        local idx = ensure_response_message(response_id)
        local content = update.content or {}
        local content_type = tostring(content.type or 'text')
        local text = content.text or ''
        local msg = state.messages[idx]
        if content_type == 'reasoning' or content_type == 'thinking' then
            msg.thinking = (msg.thinking or '') .. text
        else
            msg.text = (msg.text or '') .. text
        end
        state.current_stream = idx
        state.current_stream_request_id = response_id
        state.busy = true
        ensure_spinner()
        render_transcript()
        return
    end

    if update_type == 'agent_message_end' and response_id then
        if state.finalized_requests[response_id] then
            return
        end
        state.finalized_requests[response_id] = true
        state.active_request_id = nil
        if state.current_stream_request_id == response_id then
            state.current_stream_request_id = nil
            state.current_stream = nil
        end
        state.busy = false
        stop_spinner()
        render_transcript()
        return
    end

    if update_type == 'tool_call' then
        local title = update.title or update.toolCallId or 'tool call'
        table.insert(state.messages, { role = 'system', text = '[tool:start] ' .. title })
        render_transcript()
        return
    end

    if update_type == 'tool_call_update' then
        local title = update.title or update.toolCallId or 'tool call'
        local status = update.status or 'updated'
        table.insert(state.messages, { role = 'system', text = string.format('[tool:%s] %s', status, title) })
        render_transcript()
        return
    end

    if update_type == 'current_mode_update' then
        if update.currentModeId and update.currentModeId ~= '' then
            state.mode = update.currentModeId
        end
        render_transcript()
    end
end

function M.on_status(params)
    local was_busy = state.busy
    state.busy = params.busy == true
    state.mode = params.mode or state.mode
    state.provider = params.provider or state.provider
    state.model = params.model or state.model
    if params.queue_size ~= nil then
        state.queue_size = tonumber(params.queue_size) or state.queue_size
    end
    if state.busy then
        ensure_spinner()
    elseif was_busy then
        stop_spinner()
    end
    render_transcript()
end

function M.on_permission_request(params, respond)
    local options = params.options or {}
    local title = nil
    local tool = nil
    local command = nil
    local tc = params.toolCall or {}
    title = tc.title
    command = tc.rawInput
    if params._meta and params._meta.tark then
        tool = params._meta.tark.tool
    end

    state.pending_permission = {
        options = options,
        selected_index = 1,
        title = title,
        tool = tool,
        command = command,
        respond = respond,
    }
    state.ui_focus = 'interaction'
    table.insert(state.messages, {
        role = 'system',
        text = 'Permission requested by ACP server',
    })
    render_transcript()
end

function M.on_error(params)
    local code = sanitize_text(params.code or 'error')
    local message = sanitize_text(params.message or 'Unknown ACP error')
    table.insert(state.messages, { role = 'error', text = message })
    state.last_error = {
        code = code,
        message = message,
        request_id = params.request_id,
    }
    state.busy = false
    state.current_stream = nil
    stop_spinner()
    render_transcript()
end

function M.on_send_accepted(request_id)
    state.active_request_id = request_id
    state.current_stream_request_id = request_key(request_id)
    state.busy = true
    ensure_spinner()
    render_transcript()
end

function M.on_queue(size)
    state.queue_size = tonumber(size) or 0
    render_transcript()
end

function M.clear_pending_permission()
    state.pending_permission = nil
    render_transcript()
end

function M.submit_contextual()
    local action = state.ui_actions[state.ui_action_cursor]
    if action then
        action.handler()
        render_transcript()
        return 'action_executed'
    end

    return 'send_message'
end

function M.cancel_contextual()
    if state.pending_permission then
        return 'cancel_permission'
    end

    return 'cancel_request'
end

return M
