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

local DECISIONS = {
    'approve_once',
    'approve_session',
    'approve_always',
    'deny_once',
    'deny_always',
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

local function now_secs()
    return math.floor(vim.loop.now() / 1000)
end

local function status_line()
    local busy = state.busy and 'busy' or 'idle'
    local mode = state.mode or 'ask'
    local provider = state.provider or '-'
    local model = state.model or '-'
    local parts = {
        string.format('[%s]', busy),
        string.format('progress=%s', state.busy and SPINNER_FRAMES[spinner_frame] or '-'),
        string.format('mode=%s', mode),
        string.format('provider=%s', provider),
        string.format('model=%s', model),
        string.format('queue=%d', state.queue_size or 0),
        string.format('focus=%s', state.ui_focus or 'input'),
    }

    if state.pending_approval then
        table.insert(parts, 'approval=pending')
    end
    if state.pending_questionnaire then
        table.insert(parts, 'questionnaire=pending')
    end

    return table.concat(parts, '  ')
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
    return state.pending_approval ~= nil or state.pending_questionnaire ~= nil
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

local function get_selected_pattern(approval)
    if not approval then
        return nil
    end
    local idx = approval.selected_pattern_index
    if not idx or idx < 1 then
        return nil
    end
    local options = approval.pattern_options or {}
    local item = options[idx]
    return item and item.pattern or nil
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
        local raw = sanitize_text(body or '')
        local parts = vim.split(raw, '\n', { plain = true, trimempty = false })
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
        push_multiline(string.format('%s: ', msg.role), msg.text)
        push_line('')
    end

    if state.pending_approval then
        local approval = state.pending_approval
        push_line('Approval Request')
        push_line(string.format('  tool=%s risk=%s', sanitize_text(approval.tool), sanitize_text(approval.risk)))
        if approval.command and approval.command ~= '' then
            push_multiline('  command: ', approval.command)
        end
        if approval.timeout_seconds and approval.timeout_seconds > 0 then
            local remaining = math.max(0, (approval.expires_at or now_secs()) - now_secs())
            push_line(string.format('  timeout=%ss (remaining %ss)', approval.timeout_seconds, remaining))
        end
        push_line('  decision:')

        for _, decision in ipairs(DECISIONS) do
            local selected = approval.selected_decision == decision
            local marker = selected and '>' or ' '
            add_action('approval-decision:' .. decision, function()
                approval.selected_decision = decision
            end, { kind = 'approval_decision', data = { decision = decision } })
            push_line(string.format('  %s [%s] %s', marker, selected and 'x' or ' ', decision))
        end

        local needs_pattern = approval.selected_decision == 'approve_session'
            or approval.selected_decision == 'approve_always'
            or approval.selected_decision == 'deny_always'
        local options = approval.pattern_options or {}
        if #options > 0 then
            push_line('  pattern options:')
            for idx, option in ipairs(options) do
                local is_selected = approval.selected_pattern_index == idx
                local marker = is_selected and '>' or ' '
                add_action('approval-pattern:' .. idx, function()
                    approval.selected_pattern_index = idx
                end, { kind = 'approval_pattern', data = { index = idx } })
                push_line(string.format('  %s [%s] %s', marker, is_selected and 'x' or ' ', sanitize_text(option.pattern or option.description or ('pattern-' .. idx))))
            end
        elseif needs_pattern then
            push_line('  pattern required for this decision (server provided no options)')
        end

        add_action('approval-submit', function()
            local tark = require('tark')
            tark.approve(approval.selected_decision or 'approve_once')
        end, { kind = 'approval_submit' })
        add_action('approval-cancel', function()
            local tark = require('tark')
            tark.approve('deny_once')
        end, { kind = 'approval_cancel' })
        push_line('  [submit] approve/deny selected decision')
        push_line('  [cancel] deny once')
        push_line('')
    end

    if state.pending_questionnaire then
        local pq = state.pending_questionnaire
        local q = pq.questionnaire or {}
        push_line('Questionnaire')
        push_line('  ' .. sanitize_text(q.title or 'Untitled'))
        if q.description then
            push_multiline('  ', q.description)
        end

        local questions = q.questions or {}
        for q_idx, question in ipairs(questions) do
            push_line(string.format('  Q%d %s', q_idx, sanitize_text(question.text or question.id or 'question')))
            local qtype = question.type

            if qtype == 'single_select' then
                local selected = pq.answers[question.id]
                local options = question.options or {}
                for _, option in ipairs(options) do
                    local selected_value = selected and selected.value or selected
                    local is_selected = selected_value == option.value
                    add_action('q-single:' .. question.id .. ':' .. tostring(option.value), function()
                        pq.answers[question.id] = option.value
                    end, { kind = 'question_single', data = { id = question.id, value = option.value } })
                    push_line(string.format('    [%s] %s', is_selected and 'x' or ' ', sanitize_text(option.label or option.value)))
                end
            elseif qtype == 'multi_select' then
                pq.answers[question.id] = pq.answers[question.id] or {}
                local options = question.options or {}
                local selected_map = {}
                for _, value in ipairs(pq.answers[question.id]) do
                    selected_map[value] = true
                end
                for _, option in ipairs(options) do
                    local is_selected = selected_map[option.value] == true
                    add_action('q-multi:' .. question.id .. ':' .. tostring(option.value), function()
                        local current = pq.answers[question.id] or {}
                        local map = {}
                        for _, value in ipairs(current) do
                            map[value] = true
                        end
                        if map[option.value] then
                            map[option.value] = nil
                        else
                            map[option.value] = true
                        end
                        local next_values = {}
                        for value, enabled in pairs(map) do
                            if enabled then
                                table.insert(next_values, value)
                            end
                        end
                        table.sort(next_values)
                        pq.answers[question.id] = next_values
                    end, { kind = 'question_multi', data = { id = question.id, value = option.value } })
                    push_line(string.format('    [%s] %s', is_selected and 'x' or ' ', sanitize_text(option.label or option.value)))
                end
            elseif qtype == 'free_text' then
                local value = pq.answers[question.id]
                if type(value) ~= 'string' then
                    value = question.default or ''
                    pq.answers[question.id] = value
                end
                local marker = (pq.edit_mode_question_id == question.id) and '*' or ' '
                add_action('q-text:' .. question.id, function()
                    pq.edit_mode_question_id = question.id
                    pq.focused_question_index = q_idx
                    set_input_text(value)
                    apply_focus('input')
                end, { kind = 'question_text', data = { id = question.id } })
                push_multiline(string.format('    %s text: ', marker), value)
            else
                push_line('    unsupported question type: ' .. sanitize_text(qtype))
            end

            local err = pq.validation_errors and pq.validation_errors[question.id]
            if err then
                push_line('    ! ' .. sanitize_text(err))
            end
        end

        add_action('questionnaire-submit', function()
            local tark = require('tark')
            tark.questionnaire_submit()
        end, { kind = 'questionnaire_submit' })
        add_action('questionnaire-cancel', function()
            local tark = require('tark')
            tark.questionnaire_cancel()
        end, { kind = 'questionnaire_cancel' })
        push_line('  [submit] send questionnaire answers')
        push_line('  [cancel] cancel questionnaire')
        push_line('')
    end

    if state.last_error then
        push_line(string.format('Last error: [%s] %s', sanitize_text(state.last_error.code), sanitize_text(state.last_error.message)))
        push_line('')
    end

    push_line('Input keys: Enter=send/save, Ctrl-C=cancel, q=close')
    push_line('Interaction keys: j/k=move, Enter=activate, space=toggle, i=edit text, Esc=leave edit')

    clamp_action_cursor()

    if action_count() > 0 then
        local action = state.ui_actions[state.ui_action_cursor]
        push_line('')
        push_line('Selected action: ' .. sanitize_text(action.label))
    end

    vim.bo[state.transcript_buf].modifiable = true
    vim.api.nvim_buf_set_lines(state.transcript_buf, 0, -1, false, lines)
    vim.bo[state.transcript_buf].modifiable = false
end

local function validate_questionnaire_answers(pq)
    local errors = {}
    local q = pq.questionnaire or {}

    for _, question in ipairs(q.questions or {}) do
        local value = pq.answers[question.id]
        if question.type == 'single_select' then
            if value == nil or value == '' then
                errors[question.id] = 'single choice required'
            end
        elseif question.type == 'multi_select' then
            local arr = value
            if type(arr) ~= 'table' then
                arr = {}
            end
            local rules = question.validation or {}
            local min = rules.min_selections
            local max = rules.max_selections
            if min and #arr < min then
                errors[question.id] = string.format('pick at least %d option(s)', min)
            end
            if max and #arr > max then
                errors[question.id] = string.format('pick at most %d option(s)', max)
            end
        elseif question.type == 'free_text' then
            local text = tostring(value or '')
            local rules = question.validation or {}
            if rules.required and vim.trim(text) == '' then
                errors[question.id] = 'text is required'
            elseif rules.min_length and #text < rules.min_length then
                errors[question.id] = string.format('min length is %d', rules.min_length)
            elseif rules.max_length and #text > rules.max_length then
                errors[question.id] = string.format('max length is %d', rules.max_length)
            end
        end
    end

    pq.validation_errors = errors
    return next(errors) == nil
end

local function setup_transcript_keymaps()
    if not state.transcript_buf or not vim.api.nvim_buf_is_valid(state.transcript_buf) then
        return
    end

    local opts = { buffer = state.transcript_buf, silent = true, noremap = true }
    vim.keymap.set('n', 'j', '<cmd>TarkUiNextAction<cr>', opts)
    vim.keymap.set('n', 'k', '<cmd>TarkUiPrevAction<cr>', opts)
    vim.keymap.set('n', '<CR>', '<cmd>TarkUiSubmit<cr>', opts)
    vim.keymap.set('n', '<Space>', function()
        require('tark.widgets.chat').toggle_selected_option()
    end, opts)
    vim.keymap.set('n', 'i', function()
        require('tark.widgets.chat').edit_selected_text()
    end, opts)
    vim.keymap.set('n', '<Esc>', function()
        require('tark.widgets.chat').leave_edit_mode()
    end, opts)
    vim.keymap.set('n', '<C-c>', '<cmd>TarkUiCancel<cr>', opts)
    vim.keymap.set('n', 'q', '<cmd>TarkChatClose<cr>', opts)
end

local function setup_input_keymaps()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return
    end

    local opts = { buffer = state.input_buf, silent = true, noremap = true }
    vim.keymap.set('n', '<CR>', '<cmd>TarkUiSubmit<cr>', opts)
    vim.keymap.set('i', '<CR>', '<Esc><cmd>TarkUiSubmit<cr>', opts)
    vim.keymap.set('n', '<C-c>', '<cmd>TarkUiCancel<cr>', opts)
    vim.keymap.set('i', '<C-c>', '<Esc><cmd>TarkUiCancel<cr>', opts)
    vim.keymap.set('n', 'q', '<cmd>TarkChatClose<cr>', opts)
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
    if action.kind == 'question_multi' or action.kind == 'question_single' or action.kind == 'approval_decision' or action.kind == 'approval_pattern' then
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
    if state.pending_questionnaire and state.pending_questionnaire.edit_mode_question_id then
        state.pending_questionnaire.edit_mode_question_id = nil
        clear_input()
        apply_focus('interaction')
        render_transcript()
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
        local text = params.text or ''
        local last = state.messages[#state.messages]
        local is_duplicate = last and last.role == 'assistant' and last.text == text
        if not is_duplicate then
            table.insert(state.messages, { role = 'assistant', text = text })
        end
    else
        if params.text and params.text ~= '' then
            state.messages[state.current_stream].text = params.text
        end
    end

    state.active_request_id = nil
    state.current_stream = nil
    state.busy = false
    stop_spinner()
    render_transcript()
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
    state.busy = true
    ensure_spinner()
    render_transcript()
end

function M.on_queue(size)
    state.queue_size = tonumber(size) or 0
    render_transcript()
end

function M.on_approval_request(params)
    state.pending_approval = {
        interaction_id = params.interaction_id,
        request_id = params.request_id,
        tool = params.tool,
        command = params.command,
        risk = params.risk,
        pattern_options = params.pattern_options or {},
        timeout_seconds = params.timeout_seconds,
        selected_decision = 'approve_once',
        selected_pattern_index = nil,
        expires_at = now_secs() + tonumber(params.timeout_seconds or 0),
    }
    table.insert(state.messages, {
        role = 'system',
        text = string.format('Approval requested for tool %s', tostring(params.tool or 'unknown')),
    })
    state.ui_focus = 'interaction'
    render_transcript()
end

function M.on_questionnaire_request(params)
    state.pending_questionnaire = {
        interaction_id = params.interaction_id,
        request_id = params.request_id,
        questionnaire = params.questionnaire or {},
        answers = {},
        focused_question_index = 1,
        edit_mode_question_id = nil,
        validation_errors = {},
        timeout_seconds = params.timeout_seconds,
        expires_at = now_secs() + tonumber(params.timeout_seconds or 0),
    }
    table.insert(state.messages, {
        role = 'system',
        text = string.format('Questionnaire requested: %s', tostring((params.questionnaire or {}).title or '')),
    })
    state.ui_focus = 'interaction'
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
    if not state.pending_approval then
        return nil
    end

    return {
        interaction_id = state.pending_approval.interaction_id,
        request_id = state.pending_approval.request_id,
        selected_pattern = get_selected_pattern(state.pending_approval),
    }
end

function M.pending_approval_decision()
    if not state.pending_approval then
        return nil
    end
    return state.pending_approval.selected_decision or 'approve_once'
end

function M.pending_questionnaire()
    return state.pending_questionnaire
end

function M.questionnaire_answers()
    if not state.pending_questionnaire then
        return {}
    end
    return state.pending_questionnaire.answers or {}
end

function M.submit_contextual()
    if state.pending_questionnaire and state.pending_questionnaire.edit_mode_question_id then
        local qid = state.pending_questionnaire.edit_mode_question_id
        state.pending_questionnaire.answers[qid] = get_input_text()
        state.pending_questionnaire.edit_mode_question_id = nil
        clear_input()
        apply_focus('interaction')
        render_transcript()
        return 'questionnaire_text_saved'
    end

    local action = state.ui_actions[state.ui_action_cursor]
    if action then
        action.handler()
        render_transcript()
        return 'action_executed'
    end

    return 'send_message'
end

function M.cancel_contextual()
    if state.pending_questionnaire and state.pending_questionnaire.edit_mode_question_id then
        state.pending_questionnaire.edit_mode_question_id = nil
        clear_input()
        apply_focus('interaction')
        render_transcript()
        return 'questionnaire_text_cancelled'
    end

    if state.pending_approval then
        return 'cancel_approval'
    end

    if state.pending_questionnaire then
        return 'cancel_questionnaire'
    end

    return 'cancel_request'
end

function M.can_submit_questionnaire()
    if not state.pending_questionnaire then
        return false
    end
    return validate_questionnaire_answers(state.pending_questionnaire)
end

return M
