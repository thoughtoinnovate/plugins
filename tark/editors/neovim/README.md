# tark.nvim

Production Neovim integration for the [tark](https://github.com/thoughtoinnovate/tark) AI agent
(requirements R10, scenarios S25/S26).

The plugin spawns `tark acp` and talks to it over **ACP v1 newline-delimited
JSON stdio** — no Content-Length framing, no blocking calls. It provides chat
with permission handling, cancellation, inline completions (ghost text), and
health diagnostics with actionable remediation.

## Requirements

- Neovim 0.9+ (0.10.x recommended)
- A compatible `tark` binary (plugin version and backend share
  `major.minor`; the plugin tells you exactly what to install on mismatch)
- `curl` only if you want the plugin to auto-download the binary

## Install

### lazy.nvim

```lua
{
  'thoughtoinnovate/tark',
  -- load only the Neovim adapter:
  -- (if your manager cannot scope to a subdirectory, clone the repo and
  -- point rtp at plugins/tark/editors/neovim)
  config = function()
    require('tark').setup({
      -- auto_download = true,  -- default: fetch matching release if missing
    })
  end,
  keys = {
    { '<leader>tc', '<cmd>TarkChat<cr>', desc = 'Tark chat' },
    { '<leader>th', '<cmd>TarkHealth<cr>', desc = 'Tark health' },
  },
}
```

### packer.nvim

```lua
use({
  'thoughtoinnovate/tark',
  config = function()
    require('tark').setup({})
  end,
})
```

Then `:TarkHealth` to verify the backend, protocol, version, and config.

## Configuration

```lua
require('tark').setup({
  binary = nil,              -- explicit tark path; else PATH, else download
  expected_version = '0.12.6',
  repo = 'thoughtoinnovate/tark',
  install_dir = vim.fn.stdpath('data') .. '/tark/bin',
  auto_download = true,      -- download pinned release (SHA256-verified)
  acp = {
    cwd = nil,               -- session cwd; defaults to vim.fn.getcwd()
    extra_args = {},         -- extra argv after `tark acp`
    completion_extension = true, -- advertise _tark/inlineCompletion
  },
  completion = {
    enabled = true,
    debounce_ms = 250,
    max_tokens = 128,
  },
  chat = { split = 'vertical', width = 60, height = 15 },
})
```

## Commands

| Command        | Action                                              |
| -------------- | --------------------------------------------------- |
| `:TarkStart`   | Start ACP subprocess + create session               |
| `:TarkStop`    | Close session + stop subprocess                     |
| `:TarkChat [text]` | Open chat window, optionally sending text       |
| `:TarkComplete` | Request one inline completion at the cursor        |
| `:TarkCancel`  | Cancel the running prompt                           |
| `:TarkHealth`  | Diagnostics: binary, version, ACP smoke, config     |

Lua API mirrors the commands: `require('tark').start/open_chat/complete/stop/health/status()`.

Inline-completion ghost text is accepted with `require('tark.completion').accept()` —
map it yourself, e.g. `vim.keymap.set('i', '<C-]>', function() return require('tark.completion').accept() end, { expr = false })`.
A result is applied only when the buffer version and cursor still match the
request; stale results are silently dropped and read-only buffers are never touched.

## Protocol notes

- Transport: `tark acp` over stdio, one JSON object per line. The legacy
  `Content-Length` envelope is not sent and inbound framed lines are ignored.
- Advertised client surface: `initialize` (protocolVersion 1),
  `session/new` (empty `mcpServers`), `session/prompt`, `session/cancel`,
  `session/close`, `session/set_mode` (ask/plan/build),
  `session/set_config_option` (only `mode`), `context/update`, and the
  optional `_tark/inlineCompletion` extension (opt-in via initialize `_meta`).
- Permission answers deny fail-closed when the dialog is dismissed.

## Troubleshooting

| Symptom | Next step |
| ------- | --------- |
| `:TarkHealth` FAIL binary | Install from the releases page, put `tark` on PATH, or enable `auto_download` |
| Version mismatch | Install the release named in the remediation message, then restart Neovim |
| ACP smoke FAIL | Run `tark acp` manually; check `:messages`; ensure nothing reframes stdio |
| Permission dialog never appears | Check `:messages` for backend errors; `:TarkStop` + `:TarkStart` to reconnect |
| Ghost text never shows | `:TarkHealth` must pass; completion needs an active session (`:TarkStart`) and insert mode |

## Tests

Headless smoke (no plenary needed):

```sh
nvim --headless -u tests/minimal_init.lua \
  -c "luafile tests/specs/acp_framing_spec.lua" \
  -c "luafile tests/specs/permission_spec.lua" \
  -c "luafile tests/specs/version_spec.lua" \
  -c "qa!"
```

With plenary installed, the same files run under `:PlenaryBustedFile`.
