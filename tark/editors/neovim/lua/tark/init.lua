--- tark.nvim entry point.
---
--- Production Neovim integration for the tark AI agent (R10, S25/S26).
--- Talks to the backend exclusively over ACP v1 NDJSON stdio
--- (`tark acp`); see lua/tark/acp_client.lua for the wire contract.
---
--- Conventions: modules are lazy-loaded (required inside functions),
--- UI-touching callbacks go through vim.schedule(), the editor is never
--- blocked (jobstart only), and all public state lives on this module
--- table (no globals).
local M = {}

--- Plugin version. Must match Cargo.toml `version` (R12 compatibility).
M.version = '0.12.6'

--- Backend ACP protocol version this plugin speaks (R8).
M.acp_protocol_version = 1

--- Default configuration. Applied with vim.tbl_deep_extend in setup().
M.defaults = {
  -- Explicit path to the tark binary. When nil, resolved as:
  -- config path -> vim.fn.exepath('tark') -> downloaded release.
  binary = nil,
  -- Expected backend version (compared against `tark --version`).
  expected_version = M.version,
  -- GitHub repo used for secure binary downloads (R12).
  repo = 'thoughtoinnovate/tark',
  -- Directory downloaded binaries are installed into. Defaults to
  -- stdpath('data') .. '/tark/bin' (resolved in setup()).
  install_dir = nil,
  -- Download a matching release when no compatible binary is found.
  auto_download = true,
  acp = {
    -- Working directory sent in session/new. Defaults to vim.fn.getcwd().
    cwd = nil,
    -- Extra argv appended after `tark acp`.
    extra_args = {},
    -- Advertise the optional `_tark/inlineCompletion` extension (R8 S22).
    completion_extension = true,
  },
  completion = {
    enabled = true,
    debounce_ms = 250,
    max_tokens = 128,
  },
  chat = {
    -- 'vertical' or 'horizontal' split for the chat window.
    split = 'vertical',
    width = 60,
    height = 15,
  },
}

M._config = nil

--- Return the active configuration (defaults until setup() runs).
---@return table
function M.get_config()
  if M._config then
    return M._config
  end
  local defaults = vim.deepcopy(M.defaults)
  defaults.install_dir = vim.fn.stdpath('data') .. '/tark/bin'
  return defaults
end

--- Configure the plugin. Merges opts over defaults.
---@param opts table|nil user options
function M.setup(opts)
  local base = vim.deepcopy(M.defaults)
  base.install_dir = vim.fn.stdpath('data') .. '/tark/bin'
  M._config = vim.tbl_deep_extend('force', base, opts or {})
  local completion = require('tark.completion')
  completion.configure(M._config.completion)
end

--- Start the ACP subprocess and create a session (TarkStart).
---@param cb function|nil called as cb(ok, err) on completion
function M.start(cb)
  local chat = require('tark.widgets.chat')
  chat.ensure_session(M.get_config(), cb)
end

--- Close the session and stop the ACP subprocess (TarkStop).
function M.stop()
  local chat = require('tark.widgets.chat')
  chat.close_all()
end

--- Open the chat window, optionally sending prompt text (TarkChat).
---@param prompt string|nil initial prompt to send
function M.open_chat(prompt)
  local chat = require('tark.widgets.chat')
  chat.open(M.get_config(), prompt)
end

--- Request one inline completion at the cursor (TarkComplete).
function M.complete()
  local completion = require('tark.completion')
  completion.request_now(M.get_config())
end

--- Run health diagnostics and show the report (TarkHealth).
function M.health()
  local health = require('tark.health')
  health.show(M.get_config())
end

--- One-line connection/backend status for statuslines.
---@return string
function M.status()
  local chat = require('tark.widgets.chat')
  return chat.status()
end

return M
