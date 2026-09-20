--- Chat buffer: streaming messages, tool calls, cancellation, cleanup (S26).
---
--- Owns the single ACP client + session used by the plugin. Neovim stays
--- responsive (async jobstart only); subprocesses are cleaned up on
--- buffer wipe and editor exit; cancellation is session-scoped (NFR4).
local M = {}

local state = {
  client = nil,
  starting = false,
  buf = nil,
  win = nil,
  input_buf = nil,
  input_win = nil,
  active_request = nil,
}

--- Append lines to the chat buffer safely (no-op when wiped).
---@param lines table
local function append(lines)
  if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
    return
  end
  vim.schedule(function()
    if not (state.buf and vim.api.nvim_buf_is_valid(state.buf)) then
      return
    end
    local was_modifiable = vim.bo[state.buf].modifiable
    vim.bo[state.buf].modifiable = true
    local last = vim.api.nvim_buf_line_count(state.buf)
    vim.api.nvim_buf_set_lines(state.buf, last, last, false, lines)
    vim.bo[state.buf].modifiable = was_modifiable
    if state.win and vim.api.nvim_win_is_valid(state.win) then
      vim.api.nvim_win_set_cursor(state.win, { vim.api.nvim_buf_line_count(state.buf), 0 })
    end
  end)
end

--- Format one session/update notification into chat lines (pure).
---@param params table session/update params
---@return table lines, string|nil kind
function M.format_update(params)
  local update = (params or {}).update or {}
  local kind = update.sessionUpdate
  if kind == 'agent_message_start' then
    return { '', '── assistant ──' }, kind
  elseif kind == 'agent_message_chunk' then
    local content = update.content or {}
    local text = content.text or ''
    if text == '' then
      return {}, kind
    end
    if content.type == 'reasoning' then
      return { '…' .. text }, kind
    end
    return vim.split(text, '\n', { plain = true }), kind
  elseif kind == 'agent_message_end' then
    local reason = update.stopReason or ''
    if reason == 'cancelled' then
      return { '(cancelled)' }, kind
    elseif reason == 'refusal' then
      local meta = (params._meta and params._meta.tark) or {}
      local detail = meta.errorMessage or 'request failed'
      return { '(error: ' .. detail .. ')' }, kind
    end
    return { '' }, kind
  elseif kind == 'tool_call' then
    return { string.format('🔧 %s', update.title or update.toolCallId or 'tool'), update.rawInput or '' }, kind
  elseif kind == 'tool_call_update' then
    return { string.format('   → %s (%s)', update.title or 'tool', update.status or '?') }, kind
  end
  return {}, kind
end

local function on_update(params)
  local lines = M.format_update(params)
  if #lines > 0 then
    append(lines)
  end
  local update = (params or {}).update or {}
  if update.sessionUpdate == 'agent_message_end' then
    state.active_request = nil
  end
end

local function on_exit(code)
  state.client = nil
  state.starting = false
  state.active_request = nil
  append({ '', string.format('(tark subprocess exited: %s; use :TarkStart to reconnect)', tostring(code)) })
end

--- Ensure a live client + session, then cb(ok, err).
---@param config table plugin config
---@param cb function called as cb(ok, err_or_nil)
function M.ensure_session(config, cb)
  cb = cb or function() end
  if state.client and state.client.session_id then
    vim.schedule(function()
      cb(true, nil)
    end)
    return
  end
  if state.starting then
    vim.schedule(function()
      cb(false, 'tark is already starting; wait a moment and retry')
    end)
    return
  end
  state.starting = true
  local binary = require('tark.binary')
  local init = require('tark')
  binary.ensure(config, function(path, err)
    if not path then
      state.starting = false
      vim.schedule(function()
        cb(false, err)
      end)
      return
    end
    local acp = require('tark.acp_client')
    local permission = require('tark.permission')
    local client, serr = acp.start(path, config.acp.extra_args or {}, {
      on_update = on_update,
      on_permission = function(id, params)
        permission.show(client, id, params)
      end,
      on_exit = on_exit,
    })
    if not client then
      state.starting = false
      vim.schedule(function()
        cb(false, serr or 'spawn failed')
      end)
      return
    end
    acp.initialize(client, init.version, config.acp.completion_extension ~= false, function(ok, ierr)
      if not ok then
        acp.stop(client)
        state.starting = false
        cb(false, ierr)
        return
      end
      local cwd = (config.acp and config.acp.cwd) or vim.fn.getcwd()
      acp.session_new(client, cwd, function(sid, nerr)
        state.starting = false
        if not sid then
          acp.stop(client)
          cb(false, nerr)
          return
        end
        state.client = client
        cb(true, nil)
      end)
    end)
  end)
end

--- Open the chat window (vertical/horizontal split per config).
---@param config table plugin config
---@param prompt string|nil text to send immediately
function M.open(config, prompt)
  M.ensure_session(config, function(ok, err)
    vim.schedule(function()
      if not ok then
        vim.notify('[tark] ' .. tostring(err), vim.log.levels.ERROR)
        return
      end
      if not (state.win and vim.api.nvim_win_is_valid(state.win)) then
        if (config.chat.split or 'vertical') == 'horizontal' then
          vim.cmd('botright ' .. tostring(config.chat.height or 15) .. 'split')
        else
          vim.cmd('botright vertical ' .. tostring(config.chat.width or 60) .. 'split')
        end
        if not (state.buf and vim.api.nvim_buf_is_valid(state.buf)) then
          state.buf = vim.api.nvim_create_buf(false, true)
          vim.bo[state.buf].filetype = 'tark-chat'
          vim.bo[state.buf].buflisted = false
        end
        vim.api.nvim_win_set_buf(0, state.buf)
        state.win = vim.api.nvim_get_current_win()
        vim.api.nvim_create_autocmd('BufWipeout', {
          buffer = state.buf,
          once = true,
          callback = function()
            vim.schedule(function()
              M.close_all()
              state.buf = nil
              state.win = nil
            end)
          end,
        })
      else
        vim.api.nvim_set_current_win(state.win)
      end
      if prompt and prompt ~= '' then
        M.send(prompt)
      else
        M.prompt_input()
      end
    end)
  end)
end

--- Ask for prompt text without blocking (vim.ui.input is async).
function M.prompt_input()
  vim.ui.input({ prompt = 'Tark> ' }, function(input)
    if input and input ~= '' then
      M.send(input)
    end
  end)
end

--- Send one prompt over the live session with editor context.
---@param text string
function M.send(text)
  if not (state.client and state.client.session_id) then
    vim.notify('[tark] No session; run :TarkStart first.', vim.log.levels.WARN)
    return
  end
  local acp = require('tark.acp_client')
  append({ '', '── you ──', text })
  -- Attach lightweight editor context (context/update); bounded and
  -- best-effort so a large buffer can never stall the prompt (NFR3).
  local fname = vim.api.nvim_buf_get_name(0)
  local ok_cur, cursor = pcall(vim.api.nvim_win_get_cursor, 0)
  local context = { buffers = {} }
  if fname ~= '' then
    context.activeFile = fname
  end
  if ok_cur then
    context.cursor = { line = cursor[1], col = cursor[2] }
  end
  local ok_sel = pcall(function()
    local s = vim.fn.getpos("'<")
    local e = vim.fn.getpos("'>")
    if s[2] > 0 and e[2] >= s[2] then
      local lines = vim.api.nvim_buf_get_lines(0, s[2] - 1, math.min(e[2], s[2] + 200), false)
      return table.concat(lines, '\n'):sub(1, 8000)
    end
    return nil
  end)
  if ok_sel and type(ok_sel) == 'string' and ok_sel ~= '' then
    context.selection = { start_line = 0, start_col = 0, end_line = 0, end_col = 0, text = ok_sel }
  end
  pcall(acp.context_update, state.client, context)
  state.active_request = true
  acp.prompt(state.client, text, function(_, err)
    if err then
      state.active_request = nil
      append({ '(prompt failed: ' .. tostring(err) .. ')' })
    end
  end)
end

--- Cancel the running prompt (session/cancel, session-scoped).
function M.cancel()
  if not state.client then
    return
  end
  local acp = require('tark.acp_client')
  acp.cancel(state.client, function(cancelled)
    if cancelled then
      append({ '(cancelling…)' })
    end
  end)
end

--- Close session + subprocess and dismiss permission UI (S26 cleanup).
function M.close_all()
  local permission = require('tark.permission')
  permission.dismiss()
  if state.client then
    local acp = require('tark.acp_client')
    acp.stop(state.client)
    state.client = nil
  end
  state.starting = false
  state.active_request = nil
end

--- Live client for the completion module. Returns nil unless a session
--- is established; completion never starts its own subprocess.
---@return table|nil
function M._client_for_completion()
  if state.client and state.client.session_id then
    return state.client
  end
  return nil
end

--- One-line status for statuslines.
---@return string
function M.status()
  if state.active_request then
    return 'tark:working'
  end
  if state.client and state.client.session_id then
    local v = state.client.agent_info and state.client.agent_info.version or '?'
    return 'tark:' .. tostring(v)
  end
  return 'tark:off'
end

-- Cleanup on editor exit so no ACP subprocess is orphaned (S26).
pcall(vim.api.nvim_create_autocmd, 'VimLeavePre', {
  pattern = '*',
  callback = function()
    pcall(M.close_all)
  end,
})

return M
