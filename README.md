# Tark Plugins

External plugins for tark CLI.

## Editor Adapters

Editor-specific integrations live under `tark/editors/`.

- `tark/editors/neovim` - Neovim adapter plugin (`tark.nvim`)

## Available Plugins

### InnoDrupe/gemini-auth
OAuth authentication for Google Gemini using Gemini CLI credentials.

## Usage

Add to `~/.config/tark/plugins.toml`:

```toml
[[plugins]]
source = "github:thoughtoinnovate/plugins/InnoDrupe/gemini-auth"
enabled = true
```
