--- Floating-window approval/elicitation UI (R8 S21, user-visible requirements).
---
--- Renders backend session/request_permission requests: approval prompts
--- identify tool, command, working directory, and options; elicitation
--- prompts (single single-select, flagged via _meta.tark.elicitation)
--- render as a selection list. Answers are wired back through
--- acp_client.respond_permission; denial is fail-closed (NFR1).
local M = {}

--- Extract a UI-friendly view of a permission request (pure).
---@param params table raw session/request_permission params
---@return table {title, input, working_dir, options, is_elicitation}
function M.parse_request(params)
  params = params or {}
  local tool_call = params.toolCall or {}
  local meta = (params._meta and params._meta.tark) or {}
  local options = {}
  for _, opt in ipairs(params.options or {}) do
    options[#options + 1] = {
      option_id = opt.optionId,
      name = opt.name or opt.optionId,
      kind = opt.kind or '',
    }
  end
  return {
    title = tool_call.title or '(unnamed request)',
    input = tool_call.rawInput or '',
    working_dir = meta.workingDir,
    options = options,
    is_elicitation = meta.elicitation == true,
  }
end

--- Map a chosen option to the ACP result payload (pure).
--- Unknown option ids deny fail-closed.
---@param option_id string|nil chosen optionId; nil denies
---@param known table|nil list of {option_id=...} to validate against
---@return table {outcome=...} result payload
function M.outcome_for(option_id, known)
  if option_id == nil then
    return { outcome = 'cancelled' }
  end
  if known then
    local allowed = false
    for _, opt in ipairs(known) do
      if opt.option_id == option_id then
        allowed = true
        break
      end
    end
    if not allowed then
      return { outcome = 'cancelled' }
    end
  end
  return { outcome = 'selected', optionId = option_id }
end

--- Render request lines for the floating window (pure).
---@param view table from parse_request
---@return table lines
function M.render_lines(view)
  local lines = {}
  if view.is_elicitation then
    lines[#lines + 1] = 'Tark question'
  else
    lines[#lines + 1] = 'Tark permission request'
  end
  lines[#lines + 1] = ''
  lines[#lines + 1] = view.title
  if view.input ~= '' then
    lines[#lines + 1] = '> ' .. view.input
  end
  if view.working_dir and view.working_dir ~= '' then
    lines[#lines + 1] = 'in ' .. view.working_dir
  end
  lines[#lines + 1] = ''
  for i, opt in ipairs(view.options) do
    lines[#lines + 1] = string.format('[%d] %s', i, opt.name)
  end
  lines[#lines + 1] = ''
  lines[#lines + 1] = 'number/Enter: approve option   q/Esc: deny'
  return lines
end

local active = nil

--- Close any active permission window without answering.
local function close_active()
  if active then
    pcall(vim.api.nvim_win_close, active.win, true)
    pcall(vim.api.nvim_buf_delete, active.buf, { force = true })
    active = nil
  end
end

--- Show a permission/elicitation floating window for one request.
--- Exactly one window is visible at a time; a newer request replaces
--- the older one, and the replaced request is denied fail-closed.
---@param client table acp_client handle (for respond_permission)
---@param req_id any backend request id to answer
---@param params table raw session/request_permission params
function M.show(client, req_id, params)
  local acp = require('tark.acp_client')
  local view = M.parse_request(params)
  if active then
    -- Replaced request must not linger unanswered: deny it so the
    -- backend fails closed instead of timing out (NFR1).
    acp.respond_permission(active.client, active.req_id, nil)
    close_active()
  end

  local lines = M.render_lines(view)
  local width = 10
  for _, l in ipairs(lines) do
    width = math.max(width, vim.fn.strdisplaywidth(l))
  end
  width = math.min(width + 4, 100)
  local height = math.min(#lines, 30)
  local buf = vim.api.nvim_create_buf(false, true)
  vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
  vim.bo[buf].modifiable = false
  vim.bo[buf].filetype = 'tark-permission'
  local win = vim.api.nvim_open_win(buf, true, {
    relative = 'editor',
    row = math.max(0, math.floor((vim.o.lines - height) / 2 - 1)),
    col = math.max(0, math.floor((vim.o.columns - width) / 2)),
    width = width,
    height = height,
    style = 'minimal',
    border = 'rounded',
    title = view.is_elicitation and ' Tark question ' or ' Tark permission ',
  })
  active = { buf = buf, win = win, client = client, req_id = req_id, view = view }

  local function answer(option_id)
    local current = active
    close_active()
    if current then
      local result = M.outcome_for(option_id, current.view.options)
      if result.outcome == 'cancelled' then
        acp.respond_permission(current.client, current.req_id, nil)
      else
        acp.respond_permission(current.client, current.req_id, result.optionId)
      end
    end
  end

  for i, opt in ipairs(view.options) do
    vim.keymap.set('n', tostring(i), function()
      answer(opt.option_id)
    end, { buffer = buf, nowait = true, silent = true })
  end
  vim.keymap.set('n', '<CR>', function()
    answer(view.options[1] and view.options[1].option_id or nil)
  end, { buffer = buf, nowait = true, silent = true })
  vim.keymap.set('n', 'q', function()
    answer(nil)
  end, { buffer = buf, nowait = true, silent = true })
  vim.keymap.set('n', '<Esc>', function()
    answer(nil)
  end, { buffer = buf, nowait = true, silent = true })
  vim.api.nvim_create_autocmd({ 'BufWipeout', 'WinClosed' }, {
    buffer = buf,
    once = true,
    callback = function()
      vim.schedule(function()
        if active and active.buf == buf then
          local current = active
          active = nil
          -- Window killed without a choice: deny fail-closed.
          acp.respond_permission(current.client, current.req_id, nil)
        end
      end)
    end,
  })
end

--- Dismiss any active window (used on session close/stop).
function M.dismiss()
  vim.schedule(close_active)
end

return M
