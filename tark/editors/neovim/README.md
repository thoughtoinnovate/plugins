# tark.nvim (Generic ACP Widget Client)

Neovim ACP widget client for any ACP-compatible agent (with a Tark compatibility profile).

This plugin lives outside the core repo under the plugins monorepo path:
`plugins/tark/editors/neovim`.

## Install (local checkout)

```lua
return {
  dir = "~/code/plugins/tark/editors/neovim",
  lazy = false,
  keys = {
    { "<leader>ac", "<cmd>AcpChatToggle<cr>", desc = "Toggle ACP chat" },
  },
}
```

## Install (lazy.nvim from monorepo)

```lua
return {
  url = "https://github.com/thoughtoinnovate/plugins",
  name = "tark-editors",
  lazy = false,
  init = function(plugin)
    vim.opt.rtp:prepend(plugin.dir .. "/tark/editors/neovim")
  end,
  keys = {
    { "<leader>ac", "<cmd>AcpChatToggle<cr>", desc = "Toggle ACP chat" },
  },
}
```

Git-based plugin managers clone repositories, not single folders. If you want only `tark/editors/neovim`, use sparse checkout and then point Lazy.nvim to local `dir`.

## Requirements

- ACP-compatible binary installed and on `PATH` (or configure `acp.command` and `acp.args`).
- Neovim `0.9+`.
- Agent supports Content-Length framed JSON-RPC (ACP).

## ACP widget workflow

- `:AcpChatToggle` / `:AcpChatOpen` opens ACP chat widget.
- `:AcpChatClose` closes chat widget.
- `:AcpAskBuffer [question]` sends current buffer context.
- `:'<,'>AcpAskSelection [question]` sends selected lines and range metadata.
- `:AcpSend [message]` sends from input pane or argument.
- `:AcpCancel` cancels active ACP request.
- `:AcpMode ask|plan|build` changes agent mode when supported.
- `:AcpConfigSet <configId> <value>` sets ACP config options when supported.
- `:AcpUiFocus transcript|input|interaction` moves focus between panes.
- `:AcpUiNextAction` / `:AcpUiPrevAction` navigates interactive actions.
- `:AcpUiSubmit` submits active interaction action or sends input text.
- `:AcpUiCancel` cancels active interaction/request contextually.

### Interactive keymaps (buffer-local in Tark widget)

- Input pane:
  - `Enter`: send message
  - `Ctrl-C`: cancel current request/interaction
  - `q`: close chat widget
- Transcript/interaction pane:
  - `j/k`: move interactive selection
  - `Enter`: activate selected action
  - `Space`: toggle permission option
  - `Ctrl-C`: cancel active interaction/request

## ACP configuration

```lua
require("tark").setup({
  acp = {
    command = "tark",           -- nil => auto-detect tark binary
    args = { "acp" },           -- optional
    env = {},                   -- extra env for ACP process
    cwd = nil,                  -- nil => current working directory
    protocol_version = 1,
    profile = "auto",           -- auto | generic | tark_extension
    client_capabilities = {
      fs = { readTextFile = false, writeTextFile = false },
      terminal = false,
    },
  },
})
```

## Compatibility matrix

| Agent profile | initialize | session/new | prompt stream | cancel | permission request |
|---|---|---|---|---|---|
| Codex ACP | ✅ | ✅ | ✅ | ✅ | ✅ |
| Gemini ACP | ✅ | ✅ | ✅ | ✅ | capability fallback |
| JetBrains ACP | ✅ | ✅ | ✅ | ✅ | capability fallback |

## Breaking migration

- Primary command namespace is now `:Acp*`.
- ACP-related `:Tark*` chat aliases were removed.
- Removed terminal embedding commands: `:Tark`, `:TarkToggle`, `:TarkOpen`, `:TarkClose`.

## Tests

```bash
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedDirectory tests/specs/ {minimal_init = 'tests/minimal_init.lua'}"
```
