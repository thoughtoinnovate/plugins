# tark.nvim (ACP Widget Client)

Neovim ACP widget client for `tark`.

This plugin lives outside the core repo under the plugins monorepo path:
`plugins/tark/editors/neovim`.

## Install (local checkout)

```lua
return {
  dir = "~/code/plugins/tark/editors/neovim",
  lazy = false,
  keys = {
    { "<leader>tc", "<cmd>TarkChatToggle<cr>", desc = "Toggle tark chat" },
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
    { "<leader>tc", "<cmd>TarkChatToggle<cr>", desc = "Toggle tark chat" },
  },
}
```

Git-based plugin managers clone repositories, not single folders. If you want only `tark/editors/neovim`, use sparse checkout and then point Lazy.nvim to local `dir`.

## Core requirements

- `tark` binary installed and on `PATH` (or configure `binary` path).
- Neovim `0.9+`.
- Core `tark` supports `tark acp --cwd <project>` and ACP v2 Content-Length framing.

## ACP widget workflow

- `:TarkChatToggle` / `:TarkChatOpen` opens ACP chat widget.
- `:TarkChatClose` closes chat widget.
- `:TarkAskBuffer [question]` sends current buffer context to ACP session.
- `:'<,'>TarkAskSelection [question]` sends selected lines and range metadata.
- `:TarkChatSend [message]` sends from input pane or argument.
- `:TarkChatCancel` cancels active ACP request.
- `:TarkMode ask|plan|build` changes ACP session mode.
- `:TarkApproval ...` and questionnaire commands handle interactive tool gates.
- Completion provider/model remain managed by local `tark` configuration.

## Breaking migration

- Removed terminal embedding commands: `:Tark`, `:TarkToggle`, `:TarkOpen`, `:TarkClose`.
- Chat no longer uses core `/chat` editor payload path.

## Tests

```bash
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedDirectory tests/specs/ {minimal_init = 'tests/minimal_init.lua'}"
```
