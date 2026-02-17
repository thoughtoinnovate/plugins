-- Generic ACP-based Neovim integration

local M = {}

M.version = '0.12.4'

M.config = {
    binary = nil,
    auto_download = true,
    acp = {
        command = nil,
        args = nil,
        env = {},
        cwd = nil,
        protocol_version = 1,
        profile = 'generic',
        client_capabilities = {
            fs = { readTextFile = false, writeTextFile = false },
            terminal = false,
        },
    },
    chat = {
        window = {
            position = 'right',
            width = 0.4,
            height = 0.5,
            input_height = 3,
        },
        timeout_ms = 15000,
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
        local bin = get_binary().find(true)
        if not bin and not M.config.acp.command then
            vim.notify('acp.nvim: Binary not found. Downloading tark...', vim.log.levels.INFO)
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
    get_acp().setup(vim.tbl_deep_extend('force', M.config.chat, M.config.acp))

    get_acp().on('session/update', function(params)
        get_chat().on_update(params)
    end)
    get_acp().on('session/busy', function(params)
        get_chat().on_status({ busy = params.busy == true })
    end)
    get_acp().on('error/event', function(params)
        get_chat().on_error(params)
    end)
    get_acp().on('client/queue', function(params)
        get_chat().on_queue(params.size or 0)
    end)
    get_acp().on('session/request_permission', function(params, respond)
        get_chat().on_permission_request(params, respond)
    end)
end

function M.chat_open()
    get_chat().open()
    get_acp().ensure_started(function(ok, err)
        if not ok then
            vim.notify('acp.nvim: ' .. tostring(err), vim.log.levels.ERROR)
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
            vim.notify('acp.nvim: ' .. tostring(err), vim.log.levels.ERROR)
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
    get_acp().send_message(prompt, ctx, function(ok, err)
        if not ok then
            get_chat().on_error({ message = err })
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
    get_acp().send_message(prompt, ctx, function(ok, err)
        if not ok then
            get_chat().on_error({ message = err })
        end
    end)
end

function M.set_mode(mode)
    get_acp().set_mode(mode, function(ok, result_or_err)
        if ok then
            vim.notify('acp mode: ' .. tostring(mode), vim.log.levels.INFO)
        else
            vim.notify('acp: mode switch failed: ' .. tostring(result_or_err), vim.log.levels.ERROR)
        end
    end)
end

function M.set_config_option(config_id, value)
    get_acp().set_config_option(config_id, value, function(ok, result_or_err)
        if ok then
            vim.notify('acp config updated: ' .. config_id, vim.log.levels.INFO)
        else
            vim.notify('acp: config update failed: ' .. tostring(result_or_err), vim.log.levels.ERROR)
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
    end
end

function M.ui_cancel()
    local action = get_chat().cancel_contextual()
    if action == 'cancel_permission' then
        local pending = require('tark.widgets.state').pending_permission
        if pending and pending.respond then
            pending.respond(nil)
        end
        get_chat().clear_pending_permission()
    elseif action == 'cancel_request' then
        M.chat_cancel()
    end
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
