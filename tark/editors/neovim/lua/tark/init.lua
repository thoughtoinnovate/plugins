-- tark.nvim - ACP-based Neovim integration

local M = {}

M.version = '0.11.9'

M.config = {
    binary = nil,
    auto_download = true,
    chat = {
        window = {
            position = 'right',
            width = 0.4,
            height = 0.5,
            input_height = 3,
        },
        timeout_ms = 8000,
    },
    lsp = {
        enabled = false,
        exclude_filetypes = { 'TelescopePrompt', 'NvimTree', 'neo-tree', 'dashboard', 'alpha' },
    },
    ghost = {
        enabled = true,
        auto_trigger = true,
        debounce_ms = 300,
        accept_key = '<C-l>',
        trigger_key = '<C-Space>',
        provider = nil,
    },
}

local binary = nil
local lsp = nil
local ghost = nil
local acp = nil
local chat = nil
local context = nil

local function get_binary()
    if not binary then
        binary = require('tark.binary')
    end
    return binary
end

local function get_lsp()
    if not lsp then
        lsp = require('tark.lsp')
    end
    return lsp
end

local function get_ghost()
    if not ghost then
        ghost = require('tark.ghost')
    end
    return ghost
end

local function get_acp()
    if not acp then
        acp = require('tark.acp_client')
    end
    return acp
end

local function get_chat()
    if not chat then
        chat = require('tark.widgets.chat')
    end
    return chat
end

local function get_context()
    if not context then
        context = require('tark.widgets.context')
    end
    return context
end

function M.setup(opts)
    M.config = vim.tbl_deep_extend('force', M.config, opts or {})

    get_binary().setup(M.config)

    if M.config.auto_download then
        local bin = get_binary().find()
        if not bin then
            vim.notify('tark: Binary not found. Downloading...', vim.log.levels.INFO)
            get_binary().download(function(success)
                if success and M.config.lsp.enabled then
                    get_lsp().setup(M.config.lsp)
                end
            end)
        end
    end

    if M.config.lsp.enabled then
        get_lsp().setup(M.config.lsp)
    end

    if M.config.ghost.enabled then
        get_ghost().setup(M.config.ghost)
    end

    get_chat().setup(M.config.chat)
    get_acp().setup(M.config.chat)

    get_acp().on('response/delta', function(params)
        get_chat().on_delta(params)
    end)
    get_acp().on('response/final', function(params)
        get_chat().on_final(params)
    end)
    get_acp().on('session/status', function(params)
        get_chat().on_status(params)
    end)
    get_acp().on('error/event', function(params)
        get_chat().on_error(params)
    end)
    get_acp().on('client/queue', function(params)
        get_chat().on_queue(params.size or 0)
    end)
    get_acp().on('approval/request', function(params)
        get_chat().on_approval_request(params)
    end)
    get_acp().on('questionnaire/request', function(params)
        get_chat().on_questionnaire_request(params)
    end)
end

function M.chat_open()
    get_chat().open()
    get_acp().ensure_started(function(ok, err)
        if not ok then
            vim.notify('tark: ' .. tostring(err), vim.log.levels.ERROR)
        end
    end)
end

function M.chat_close()
    get_chat().close()
end

function M.chat_toggle()
    get_chat().toggle()
    get_acp().ensure_started(function(ok, err)
        if not ok then
            vim.notify('tark: ' .. tostring(err), vim.log.levels.ERROR)
        end
    end)
end

function M.chat_send(message)
    local prompt = get_chat().consume_input_or(message)
    if not prompt or prompt == '' then
        return
    end

    local ctx = get_context().from_current_buffer()
    get_chat().open()
    get_chat().append_user(prompt)

    get_acp().send_message(prompt, ctx, function(ok, result_or_err)
        if ok then
            if result_or_err and result_or_err.queued then
                get_chat().on_error({ code = 'queued', message = 'Request queued until current response completes' })
            else
                get_chat().on_send_accepted(result_or_err.request_id)
            end
        else
            get_chat().on_error({ message = result_or_err })
        end
    end)
end

function M.chat_cancel()
    get_acp().cancel(function(ok, err)
        if ok then
            get_chat().on_error({ message = 'Request cancelled' })
        else
            get_chat().on_error({ message = err })
        end
    end)
end

function M.ask_buffer(question)
    local prompt = question
    if not prompt or prompt == '' then
        prompt = 'Analyze current buffer'
    end

    local ctx = get_context().from_current_buffer()
    get_chat().open()
    get_chat().append_user(prompt)

    get_acp().send_message(prompt, ctx, function(ok, result_or_err)
        if ok then
            if result_or_err and result_or_err.queued then
                get_chat().on_error({ code = 'queued', message = 'Request queued until current response completes' })
            else
                get_chat().on_send_accepted(result_or_err.request_id)
            end
        else
            get_chat().on_error({ message = result_or_err })
        end
    end)
end

function M.ask_selection(line1, line2, question)
    local prompt = question
    if not prompt or prompt == '' then
        prompt = 'Analyze selected code'
    end

    local ctx = get_context().from_visual_selection(line1, line2)
    get_chat().open()
    get_chat().append_user(prompt)

    get_acp().send_message(prompt, ctx, function(ok, result_or_err)
        if ok then
            if result_or_err and result_or_err.queued then
                get_chat().on_error({ code = 'queued', message = 'Request queued until current response completes' })
            else
                get_chat().on_send_accepted(result_or_err.request_id)
            end
        else
            get_chat().on_error({ message = result_or_err })
        end
    end)
end

function M.set_mode(mode)
    get_acp().set_mode(mode, function(ok, result_or_err)
        if ok then
            vim.notify('tark mode: ' .. tostring(result_or_err.mode), vim.log.levels.INFO)
        else
            vim.notify('tark: mode switch failed: ' .. tostring(result_or_err), vim.log.levels.ERROR)
        end
    end)
end

function M.approve(decision)
    local params = get_chat().pending_approval()
    if not params then
        vim.notify('tark: no pending approval', vim.log.levels.WARN)
        return
    end

    get_acp().respond_approval(decision, params, function(ok, err)
        if ok then
            get_chat().clear_pending_approval()
        else
            get_chat().on_error({ message = err })
        end
    end)
end

function M.questionnaire_submit()
    local params = get_chat().pending_questionnaire()
    if not params then
        vim.notify('tark: no pending questionnaire', vim.log.levels.WARN)
        return
    end

    if not get_chat().can_submit_questionnaire() then
        vim.notify('tark: questionnaire validation failed', vim.log.levels.WARN)
        return
    end

    get_acp().respond_questionnaire(params, false, get_chat().questionnaire_answers(), function(ok, err)
        if ok then
            get_chat().clear_pending_questionnaire()
        else
            get_chat().on_error({ message = err })
        end
    end)
end

function M.ui_focus(target)
    get_chat().focus(target)
end

function M.ui_next_action()
    get_chat().next_action()
end

function M.ui_prev_action()
    get_chat().prev_action()
end

function M.ui_submit()
    local result = get_chat().submit_contextual()
    if result == 'send_message' then
        M.chat_send()
    elseif result == 'questionnaire_submit' or result == 'action_executed' then
        -- handled by action callback
    end
end

function M.ui_cancel()
    local action = get_chat().cancel_contextual()
    if action == 'cancel_approval' then
        M.approve('deny_once')
    elseif action == 'cancel_questionnaire' then
        M.questionnaire_cancel()
    elseif action == 'cancel_request' then
        M.chat_cancel()
    end
end

function M.questionnaire_cancel()
    local params = get_chat().pending_questionnaire()
    if not params then
        vim.notify('tark: no pending questionnaire', vim.log.levels.WARN)
        return
    end

    get_acp().respond_questionnaire(params, true, {}, function(ok, err)
        if ok then
            get_chat().clear_pending_questionnaire()
        else
            get_chat().on_error({ message = err })
        end
    end)
end

-- LSP API
function M.lsp_start() return get_lsp().start() end
function M.lsp_stop() get_lsp().stop() end
function M.lsp_restart() get_lsp().restart() end
function M.lsp_status() return get_lsp().status() end
function M.lsp_enable() get_lsp().enable() end
function M.lsp_disable() get_lsp().disable() end
function M.lsp_toggle() get_lsp().toggle() end
function M.lsp_usage() return get_lsp().format_usage() end

-- Ghost API
function M.ghost_enable() get_ghost().enable() end
function M.ghost_disable() get_ghost().disable() end
function M.ghost_toggle() get_ghost().toggle() end
function M.ghost_usage() return get_ghost().format_usage() end
function M.ghost_status() return get_ghost().status() end
function M.ghost_accept() return get_ghost().accept() end
function M.ghost_trigger() get_ghost().trigger() end
function M.ghost_set_provider(provider) get_ghost().set_provider(provider) end
function M.ghost_get_provider() return get_ghost().get_provider() end

return M
