--- Inline completion via the optional `_tark/inlineCompletion` extension (S26).
---
--- Ghost text is rendered with extmarks/virtual text; a result is applied
--- ONLY when it still targets the originating buffer version
--- (clientRequestId + bufferVersion echo, changedtick match, cursor match).
--- Stale or cancelled results are discarded, never applied (R8 S22), and
--- read-only/unmodifiable buffers are never touched.
local M = {}

local ns = nil
local seq = 0
local pending = {} -- bufnr -> {request_id, version, line, col, text}
local completion_cfg = { enabled = true, debounce_ms = 250, max_tokens = 128 }
local debounce_timers = {}

local function namespace()
  if not ns then
    ns = vim.api.nvim_create_namespace('tark_completion')
  end
  return ns
end

--- Update module configuration (called from init.setup()).
---@param opts table|nil
function M.configure(opts)
  completion_cfg = vim.tbl_extend('force', completion_cfg, opts or {})
end

--- Split completion text into ghost-text parts (pure).
---@param text string
---@return string first_line, table rest_lines
function M.split_ghost(text)
  local lines = vim.split(text or '', '\n', { plain = true })
  return lines[1] or '', vim.list_slice(lines, 2)
end

--- Decide whether a completion result may be shown (pure).
--- All conditions must hold or the result is stale and dropped.
---@param req table {request_id, version, line, col}
---@param res_meta table result _meta.tark echo
---@param current table {version, line, col}
---@return boolean ok, string reason
function M.is_fresh(req, res_meta, current)
  res_meta = res_meta or {}
  if res_meta.clientRequestId ~= nil and res_meta.clientRequestId ~= req.request_id then
    return false, 'superseded request'
  end
  if res_meta.bufferVersion ~= nil and res_meta.bufferVersion ~= req.version then
    return false, 'stale buffer version'
  end
  if current.version ~= req.version then
    return false, 'buffer changed since request'
  end
  if current.line ~= req.line or current.col ~= req.col then
    return false, 'cursor moved since request'
  end
  return true, 'fresh'
end

--- Clear ghost text for a buffer.
---@param bufnr integer
function M.clear(bufnr)
  if bufnr and vim.api.nvim_buf_is_valid(bufnr) then
    vim.api.nvim_buf_clear_namespace(bufnr, namespace(), 0, -1)
  end
  pending[bufnr] = nil
end

--- Show ghost text for a fresh result; drops stale results silently.
---@param bufnr integer
---@param req table request record
---@param text string completion text
function M.show(bufnr, req, text)
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  if not text or text == '' then
    return
  end
  if vim.bo[bufnr].readonly or not vim.bo[bufnr].modifiable then
    return
  end
  M.clear(bufnr)
  local first, rest = M.split_ghost(text)
  local virt_lines = {}
  for _, l in ipairs(rest) do
    virt_lines[#virt_lines + 1] = { { l, 'Comment' } }
  end
  local ok = pcall(
    vim.api.nvim_buf_set_extmark,
    bufnr,
    namespace(),
    req.line - 1,
    req.col,
    { virt_text = { { first, 'Comment' } }, virt_lines = virt_lines, hl_mode = 'combine' }
  )
  if ok then
    pending[bufnr] = { request_id = req.request_id, version = req.version, line = req.line, col = req.col, text = text }
  end
end

--- Accept the visible ghost text, only when preconditions still hold.
--- Never corrupts the buffer: revalidates version, cursor, and mode.
function M.accept()
  local bufnr = vim.api.nvim_get_current_buf()
  local rec = pending[bufnr]
  if not rec then
    return false
  end
  if not vim.api.nvim_buf_is_valid(bufnr) then
    pending[bufnr] = nil
    return false
  end
  if vim.bo[bufnr].readonly or not vim.bo[bufnr].modifiable then
    M.clear(bufnr)
    return false
  end
  local mode = vim.api.nvim_get_mode().mode
  if mode ~= 'i' and mode ~= 'ic' and mode ~= 'ix' then
    M.clear(bufnr)
    return false
  end
  if vim.b[bufnr].changedtick ~= rec.version then
    M.clear(bufnr)
    return false
  end
  local cursor = vim.api.nvim_win_get_cursor(0)
  if cursor[1] ~= rec.line or cursor[2] ~= rec.col then
    M.clear(bufnr)
    return false
  end
  local lines = vim.split(rec.text, '\n', { plain = true })
  vim.api.nvim_buf_set_text(bufnr, rec.line - 1, rec.col, rec.line - 1, rec.col, lines)
  M.clear(bufnr)
  return true
end

--- Build extension request args from buffer state (pure given inputs).
---@param path string
---@param line integer 1-indexed
---@param col integer 0-indexed byte col
---@param all_lines table buffer lines
---@param max_tokens integer
---@param request_id string
---@param version integer changedtick
---@return table
function M.build_args(path, line, col, all_lines, max_tokens, request_id, version)
  local before = vim.list_slice(all_lines, 1, line - 1)
  local cur = all_lines[line] or ''
  local after = vim.list_slice(all_lines, line + 1)
  local prefix = table.concat(before, '\n')
  if #before > 0 then
    prefix = prefix .. '\n'
  end
  prefix = prefix .. cur:sub(1, col)
  local suffix = cur:sub(col + 1)
  if #after > 0 then
    suffix = suffix .. '\n' .. table.concat(after, '\n')
  end
  return {
    path = path,
    line = line,
    col = col,
    prefix = prefix,
    suffix = suffix,
    maxTokens = max_tokens,
    clientRequestId = request_id,
    bufferVersion = version,
  }
end

--- Fire one completion request for the current buffer/cursor.
---@param config table|nil plugin config (for max_tokens)
function M.request_now(config)
  config = config or {}
  if completion_cfg.enabled == false then
    return
  end
  local chat = require('tark.widgets.chat')
  local bufnr = vim.api.nvim_get_current_buf()
  if not vim.api.nvim_buf_is_valid(bufnr) then
    return
  end
  if vim.bo[bufnr].readonly or not vim.bo[bufnr].modifiable then
    return
  end
  local mode = vim.api.nvim_get_mode().mode
  if mode ~= 'i' and mode ~= 'ic' and mode ~= 'ix' then
    return
  end
  local cursor = vim.api.nvim_win_get_cursor(0)
  local version = vim.b[bufnr].changedtick
  local path = vim.api.nvim_buf_get_name(bufnr)
  if path == '' then
    path = vim.fn.getcwd() .. '/untitled'
  end
  local all_lines = vim.api.nvim_buf_get_lines(bufnr, 0, -1, false)
  seq = seq + 1
  local request_id = 'nvim-' .. tostring(seq)
  local req = { request_id = request_id, version = version, line = cursor[1], col = cursor[2] }
  local args = M.build_args(
    path,
    cursor[1],
    cursor[2],
    all_lines,
    (config.completion and config.completion.max_tokens) or completion_cfg.max_tokens,
    request_id,
    version
  )
  local init = require('tark')
  chat.ensure_session(init.get_config(), function(ok_session)
    if not ok_session then
      return
    end
    local acp = require('tark.acp_client')
    -- Reach into the live client via the chat module state through a
    -- bounded public path: chat exposes no client getter, so completions
    -- only run when a session exists (created by :TarkStart/:TarkChat).
    local client = chat._client_for_completion and chat._client_for_completion()
    if not client then
      return
    end
    acp.inline_completion(client, args, function(result, err)
      vim.schedule(function()
        if err or type(result) ~= 'table' then
          return
        end
        if not vim.api.nvim_buf_is_valid(bufnr) then
          return
        end
        local res_meta = (result._meta and result._meta.tark) or {}
        local current = {
          version = vim.b[bufnr].changedtick,
          line = vim.api.nvim_win_is_valid(0) and vim.api.nvim_win_get_cursor(0)[1] or -1,
          col = vim.api.nvim_win_is_valid(0) and vim.api.nvim_win_get_cursor(0)[2] or -1,
        }
        -- Only valid while still in insert mode at the same buffer.
        local m = vim.api.nvim_get_mode().mode
        if m ~= 'i' and m ~= 'ic' and m ~= 'ix' then
          return
        end
        local fresh = M.is_fresh(req, res_meta, current)
        if fresh then
          M.show(bufnr, req, result.completion)
        end
      end)
    end)
  end)
end

--- Debounced TextChangedI/CursorMovedI handler for an attached buffer.
---@param bufnr integer
function M.on_change(bufnr)
  if completion_cfg.enabled == false then
    return
  end
  local timer = debounce_timers[bufnr]
  if timer then
    timer:stop()
  end
  timer = vim.loop.new_timer()
  debounce_timers[bufnr] = timer
  timer:start(completion_cfg.debounce_ms, 0, function()
    timer:stop()
    vim.schedule(function()
      if vim.api.nvim_get_current_buf() == bufnr then
        M.request_now()
      end
    end)
  end)
end

--- Attach completion triggers to a buffer (idempotent).
---@param bufnr integer
function M.attach(bufnr)
  bufnr = bufnr or vim.api.nvim_get_current_buf()
  local group = vim.api.nvim_create_augroup('TarkCompletion', { clear = false })
  vim.api.nvim_create_autocmd({ 'TextChangedI', 'CursorMovedI' }, {
    group = group,
    buffer = bufnr,
    callback = function()
      M.on_change(bufnr)
    end,
  })
  vim.api.nvim_create_autocmd({ 'InsertLeave', 'BufLeave' }, {
    group = group,
    buffer = bufnr,
    callback = function()
      M.clear(bufnr)
    end,
  })
end

return M
