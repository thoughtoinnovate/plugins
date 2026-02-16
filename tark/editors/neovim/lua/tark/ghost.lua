-- ACP-backed ghost text completions
-- Uses tark/inline_completion over ACP stdio

local M = {}

M.state = {
    current_suggestion = nil,
    extmark_id = nil,
    ns_id = nil,
    debounce_timer = nil,
    request_seq = 0,
    active_request_seq = 0,
    session_start = nil,
    completions_requested = 0,
    completions_shown = 0,
    completions_accepted = 0,
}

M.config = {
    enabled = true,
    auto_trigger = true,
    debounce_ms = 300,
    accept_key = '<C-l>',
    trigger_key = '<C-Space>',
    hl_group = 'Comment',
    max_tokens = nil,
}

M.augroup = nil

local function get_namespace()
    if not M.state.ns_id then
        M.state.ns_id = vim.api.nvim_create_namespace('tark_ghost')
    end
    return M.state.ns_id
end

local function clear_ghost_text()
    if M.state.extmark_id then
        local ns = get_namespace()
        pcall(vim.api.nvim_buf_del_extmark, 0, ns, M.state.extmark_id)
        M.state.extmark_id = nil
    end
    M.state.current_suggestion = nil
end

local function show_ghost_text(text, row, col)
    clear_ghost_text()
    if not text or text == '' then
        return
    end

    local ns = get_namespace()
    local lines = vim.split(text, '\n', { plain = true, trimempty = false })
    local opts = {
        virt_text = { { lines[1], M.config.hl_group } },
        virt_text_pos = 'inline',
        hl_mode = 'combine',
    }

    if #lines > 1 then
        local virt_lines = {}
        for i = 2, #lines do
            table.insert(virt_lines, { { lines[i], M.config.hl_group } })
        end
        opts.virt_lines = virt_lines
    end

    M.state.extmark_id = vim.api.nvim_buf_set_extmark(0, ns, row, col, opts)
    M.state.current_suggestion = text
    M.state.completions_shown = M.state.completions_shown + 1
end

local function buffer_prefix_suffix(bufnr, row, col)
    local lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
    local line = lines[row + 1] or ''

    local prefix_parts = {}
    for i = 1, row do
        table.insert(prefix_parts, lines[i] or '')
    end
    table.insert(prefix_parts, line:sub(1, col))

    local suffix_parts = { line:sub(col + 1) }
    for i = row + 2, #lines do
        table.insert(suffix_parts, lines[i])
    end

    return table.concat(prefix_parts, '\n'), table.concat(suffix_parts, '\n')
end

local function request_completion()
    if not M.config.enabled then
        return
    end

    local bufnr = vim.api.nvim_get_current_buf()
    if vim.bo[bufnr].buftype ~= '' then
        clear_ghost_text()
        return
    end

    local cursor = vim.api.nvim_win_get_cursor(0)
    local row = cursor[1] - 1
    local col = cursor[2]
    local path = vim.api.nvim_buf_get_name(bufnr)
    if path == '' then
        path = 'untitled://buffer/' .. tostring(bufnr)
    end

    local prefix, suffix = buffer_prefix_suffix(bufnr, row, col)
    local language = vim.bo[bufnr].filetype

    M.state.request_seq = M.state.request_seq + 1
    local req_seq = M.state.request_seq
    M.state.active_request_seq = req_seq
    M.state.completions_requested = M.state.completions_requested + 1

    require('tark.acp_client').inline_completion({
        path = path,
        cursor = { line = row, col = col },
        prefix = prefix,
        suffix = suffix,
        language = language ~= '' and language or nil,
        max_tokens = M.config.max_tokens,
        trigger_kind = 'automatic',
    }, function(ok, result_or_err)
        vim.schedule(function()
            if req_seq ~= M.state.active_request_seq then
                return
            end

            if not ok then
                clear_ghost_text()
                return
            end

            local completion = result_or_err and result_or_err.completion or ''
            if completion == '' then
                clear_ghost_text()
                return
            end

            local now_cursor = vim.api.nvim_win_get_cursor(0)
            if now_cursor[1] - 1 ~= row or now_cursor[2] ~= col then
                return
            end
            show_ghost_text(completion, row, col)
        end)
    end)
end

local function trigger_completion()
    if M.state.debounce_timer then
        vim.fn.timer_stop(M.state.debounce_timer)
        M.state.debounce_timer = nil
    end

    M.state.debounce_timer = vim.fn.timer_start(M.config.debounce_ms, function()
        M.state.debounce_timer = nil
        request_completion()
    end)
end

function M.trigger()
    if M.state.debounce_timer then
        vim.fn.timer_stop(M.state.debounce_timer)
        M.state.debounce_timer = nil
    end
    request_completion()
end

function M.accept()
    if not M.state.current_suggestion then
        return false
    end

    local cursor = vim.api.nvim_win_get_cursor(0)
    local row = cursor[1] - 1
    local col = cursor[2]
    local line = vim.api.nvim_buf_get_lines(0, row, row + 1, false)[1] or ''

    local before = line:sub(1, col)
    local after = line:sub(col + 1)
    local suggestion_lines = vim.split(M.state.current_suggestion, '\n', { plain = true, trimempty = false })

    suggestion_lines[1] = before .. suggestion_lines[1]
    suggestion_lines[#suggestion_lines] = suggestion_lines[#suggestion_lines] .. after

    vim.api.nvim_buf_set_lines(0, row, row + 1, false, suggestion_lines)

    local new_row = row + #suggestion_lines
    local new_col = #suggestion_lines[#suggestion_lines] - #after
    vim.api.nvim_win_set_cursor(0, { new_row, new_col })

    M.state.completions_accepted = M.state.completions_accepted + 1
    clear_ghost_text()
    return true
end

function M.dismiss()
    clear_ghost_text()
end

function M.usage()
    return {
        enabled = M.config.enabled,
        acp_connected = require('tark.acp_client').is_connected(),
        session_start = M.state.session_start,
        completions_requested = M.state.completions_requested,
        completions_shown = M.state.completions_shown,
        completions_accepted = M.state.completions_accepted,
    }
end

function M.format_usage()
    local stats = M.usage()
    local lines = {}

    table.insert(lines, '┌─ tark Ghost Text Stats ─────────────────┐')
    table.insert(lines, string.format('│ Enabled: %-30s │', stats.enabled and 'yes' or 'no'))
    table.insert(lines, string.format('│ ACP: %-34s │', stats.acp_connected and 'connected' or 'disconnected'))
    table.insert(lines, string.format('│ Completions requested: %-16d │', stats.completions_requested))
    table.insert(lines, string.format('│ Completions shown: %-20d │', stats.completions_shown))
    table.insert(lines, string.format('│ Completions accepted: %-17d │', stats.completions_accepted))
    table.insert(lines, '└──────────────────────────────────────────┘')

    return table.concat(lines, '\n')
end

function M.status()
    local lines = {}
    table.insert(lines, 'Inline completion transport: ACP (tark/inline_completion)')
    table.insert(lines, 'ACP session: ' .. (require('tark.acp_client').is_connected() and 'connected' or 'disconnected'))
    table.insert(lines, 'Enabled: ' .. (M.config.enabled and 'yes' or 'no'))
    table.insert(lines, 'Provider/model: managed by tark session config')
    return table.concat(lines, '\n')
end

function M.start_server()
    local started = false
    require('tark.acp_client').ensure_started(function(ok)
        started = ok == true
    end)
    return started
end

function M.stop_server()
    clear_ghost_text()
end

function M.is_server_running()
    return require('tark.acp_client').is_connected()
end

function M.enable()
    M.config.enabled = true
    M.setup_autocmds()
    vim.notify('tark: Ghost text enabled', vim.log.levels.INFO)
end

function M.disable()
    M.config.enabled = false
    if M.state.debounce_timer then
        vim.fn.timer_stop(M.state.debounce_timer)
        M.state.debounce_timer = nil
    end
    M.state.active_request_seq = M.state.request_seq + 1
    clear_ghost_text()

    if M.augroup then
        vim.api.nvim_del_augroup_by_id(M.augroup)
        M.augroup = nil
    end

    vim.notify('tark: Ghost text disabled', vim.log.levels.INFO)
end

function M.toggle()
    if M.config.enabled then
        M.disable()
    else
        M.enable()
    end
end

function M.set_provider(provider)
    if provider and provider ~= '' then
        vim.notify('tark: completion provider override ignored (uses ACP session config)', vim.log.levels.INFO)
        return
    end
    vim.notify('tark: completion provider is managed by ACP session config', vim.log.levels.INFO)
end

function M.get_provider()
    return nil
end

function M.setup_autocmds()
    if M.augroup then
        vim.api.nvim_del_augroup_by_id(M.augroup)
    end

    if not M.config.enabled then
        return
    end

    M.augroup = vim.api.nvim_create_augroup('TarkGhost', { clear = true })

    if M.config.auto_trigger then
        vim.api.nvim_create_autocmd('TextChangedI', {
            group = M.augroup,
            callback = function()
                clear_ghost_text()
                trigger_completion()
            end,
        })
    end

    vim.api.nvim_create_autocmd('CursorMovedI', {
        group = M.augroup,
        callback = function()
            clear_ghost_text()
        end,
    })

    vim.api.nvim_create_autocmd('InsertLeave', {
        group = M.augroup,
        callback = function()
            clear_ghost_text()
        end,
    })
end

function M.setup_keymaps()
    vim.keymap.set('i', M.config.accept_key, function()
        if M.accept() then
            return ''
        end
        return M.config.accept_key
    end, { expr = true, silent = true, desc = 'Accept tark suggestion' })

    if M.config.trigger_key then
        vim.keymap.set('i', M.config.trigger_key, function()
            M.trigger()
        end, { silent = true, desc = 'Trigger tark completion' })
    end
end

function M.setup(config)
    M.config = vim.tbl_deep_extend('force', M.config, config or {})

    M.state.session_start = os.time()
    M.state.completions_requested = 0
    M.state.completions_shown = 0
    M.state.completions_accepted = 0

    if M.config.enabled then
        vim.defer_fn(function()
            M.setup_autocmds()
            M.setup_keymaps()
        end, 200)
    end
end

return M
