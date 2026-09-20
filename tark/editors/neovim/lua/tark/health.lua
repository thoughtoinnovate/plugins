--- Health diagnostics: :checkhealth-equivalent for the plugin (R10/R12, S25).
---
--- Every check returns {ok, name, message, remediation}; failures always
--- carry an actionable next step, never a bare error (user-visible reqs).
local M = {}

--- Run the binary-present check (pure logic over injected facts).
---@param facts table {path=string|nil}
---@return table check result
function M.check_binary_present(facts)
  if facts.path and facts.path ~= '' then
    return { ok = true, name = 'binary', message = 'tark binary: ' .. facts.path, remediation = '' }
  end
  return {
    ok = false,
    name = 'binary',
    message = 'no tark binary found',
    remediation = 'Install tark from https://github.com/thoughtoinnovate/tark/releases, '
      .. "put it on PATH, set setup({ binary = '<path>' }), or enable setup({ auto_download = true }).",
  }
end

--- Run the version-compatibility check (pure logic over injected facts).
---@param facts table {plugin_version=string, binary_version=string|nil}
---@return table check result
function M.check_version_compat(facts)
  local binary = require('tark.binary')
  local ok, msg = binary.is_compatible(facts.plugin_version, facts.binary_version)
  if ok then
    return { ok = true, name = 'version', message = msg, remediation = '' }
  end
  return { ok = false, name = 'version', message = 'version incompatible', remediation = msg }
end

--- Run the ACP initialize smoke check (pure logic over injected facts).
---@param facts table {reachable=boolean, detail=string|nil}
---@return table check result
function M.check_acp_smoke(facts)
  if facts.reachable then
    return {
      ok = true,
      name = 'acp',
      message = 'ACP initialize smoke passed' .. (facts.detail and (' (' .. facts.detail .. ')') or ''),
      remediation = '',
    }
  end
  return {
    ok = false,
    name = 'acp',
    message = 'ACP initialize smoke failed' .. (facts.detail and (': ' .. facts.detail) or ''),
    remediation = 'Verify the binary runs (`tark acp` speaks NDJSON on stdio), '
      .. 'check :messages for backend errors, and ensure no Content-Length framing proxy sits in between.',
  }
end

--- Run the configuration check (pure logic over injected facts).
---@param facts table {setup_called=boolean, cwd=string|nil, cwd_exists=boolean}
---@return table check result
function M.check_config(facts)
  if not facts.setup_called then
    return {
      ok = false,
      name = 'config',
      message = "setup() was not called",
      remediation = "Add require('tark').setup({}) to your config (see README) and restart Neovim.",
    }
  end
  if facts.cwd and not facts.cwd_exists then
    return {
      ok = false,
      name = 'config',
      message = 'configured cwd does not exist: ' .. facts.cwd,
      remediation = 'Fix acp.cwd in setup() to an existing workspace directory.',
    }
  end
  return { ok = true, name = 'config', message = 'configuration ok', remediation = '' }
end

--- Render check results as human-readable lines (pure).
---@param checks table list of check results
---@return table lines
function M.render(checks)
  local lines = { 'Tark health', '' }
  for _, c in ipairs(checks) do
    lines[#lines + 1] = (c.ok and 'ok  ' or 'FAIL') .. ' ' .. c.name .. ': ' .. c.message
    if not c.ok and c.remediation and c.remediation ~= '' then
      lines[#lines + 1] = '      -> ' .. c.remediation:gsub('\n', ' ')
    end
  end
  return lines
end

--- Perform the live ACP initialize smoke test against a binary.
--- Spawns `<binary> acp`, sends initialize, expects protocolVersion 1
--- with agentCapabilities; always cleans the job up (S26).
---@param binary_path string
---@param client_version string
---@param cb function called as cb(reachable_bool, detail_string)
local function acp_smoke(binary_path, client_version, cb)
  local acp = require('tark.acp_client')
  local done = false
  local client, err = acp.start(binary_path, {}, {
    on_exit = function(_)
      if not done then
        done = true
        cb(false, 'subprocess exited before answering initialize')
      end
    end,
  })
  if not client then
    cb(false, err or 'spawn failed')
    return
  end
  acp.initialize(client, client_version, false, function(ok, init_err)
    if done then
      return
    end
    done = true
    local detail = nil
    if ok and client.agent_info then
      detail = 'backend ' .. tostring(client.agent_info.name) .. ' ' .. tostring(client.agent_info.version)
    elseif not ok then
      detail = init_err
    end
    acp.stop(client)
    cb(ok, detail)
  end)
  vim.defer_fn(function()
    if not done then
      done = true
      acp.stop(client)
      cb(false, 'timed out waiting for initialize response')
    end
  end, 8000)
end

--- Run all checks live and invoke cb(checks).
---@param config table plugin config
---@param cb function called as cb(checks)
function M.run(config, cb)
  local init = require('tark')
  local binary = require('tark.binary')
  local path, _ = binary.resolve(config)
  local checks = {}
  checks[#checks + 1] = M.check_binary_present({ path = path })
  local cwd = config.acp and config.acp.cwd or vim.fn.getcwd()
  checks[#checks + 1] = M.check_config({
    setup_called = init._config ~= nil,
    cwd = cwd,
    cwd_exists = vim.fn.isdirectory(cwd) == 1,
  })
  if not path then
    checks[#checks + 1] = M.check_version_compat({ plugin_version = init.version, binary_version = nil })
    checks[#checks + 1] = M.check_acp_smoke({ reachable = false, detail = 'no binary to probe' })
    vim.schedule(function()
      cb(checks)
    end)
    return
  end
  binary.query_version(path, function(ver)
    checks[#checks + 1] = M.check_version_compat({ plugin_version = init.version, binary_version = ver })
    acp_smoke(path, init.version, function(reachable, detail)
      checks[#checks + 1] = M.check_acp_smoke({ reachable = reachable, detail = detail })
      cb(checks)
    end)
  end)
end

--- Run all checks and show the report in a scratch window.
---@param config table plugin config
function M.show(config)
  M.run(config, function(checks)
    vim.schedule(function()
      local lines = M.render(checks)
      local buf = vim.api.nvim_create_buf(false, true)
      vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
      vim.bo[buf].modifiable = false
      vim.bo[buf].filetype = 'tark-health'
      local width = 0
      for _, l in ipairs(lines) do
        width = math.max(width, vim.fn.strdisplaywidth(l))
      end
      vim.api.nvim_open_win(buf, true, {
        relative = 'editor',
        row = 2,
        col = math.max(0, math.floor((vim.o.columns - math.min(width + 4, 110)) / 2)),
        width = math.min(width + 4, 110),
        height = math.min(#lines + 1, 25),
        style = 'minimal',
        border = 'rounded',
        title = ' Tark health ',
      })
    end)
  end)
end

return M
