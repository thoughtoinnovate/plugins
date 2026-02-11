# tark.nvim (Editor Adapter)

Neovim editor adapter for `tark`.

This plugin lives outside the core repo under the plugins monorepo path:
`plugins/tark/editors/neovim`.

## Install (local checkout)

```lua
return {
  dir = "~/code/plugins/tark/editors/neovim",
  lazy = false,
  keys = {
    { "<leader>tc", "<cmd>TarkToggle<cr>", desc = "Toggle tark chat" },
  },
}
```

## Core requirements

- `tark` binary installed and on `PATH` (or configure `binary` path).
- Neovim `0.9+`.

## TUI workflow

- `:TarkToggle` / `:TarkOpen` opens `tark tui` inside a Neovim terminal split.
- `:TarkAskBuffer [question]` sends current buffer content to the running TUI prompt.
- `:'<,'>TarkAskSelection [question]` sends selected lines with file/line/column metadata.
- Completion provider/model are managed by local `tark` configuration.

## Editor Adapter API v1

The plugin starts a local HTTP adapter server and exposes context via:

```lua
require('tark').editor_context()
```

The context payload can be passed to core `/chat` requests as `editor`.

## Tests

```bash
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedDirectory tests/specs/ {minimal_init = 'tests/minimal_init.lua'}"
```
