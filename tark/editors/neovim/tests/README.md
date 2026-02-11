# Neovim Tests

Automated tests for the tark Neovim plugin using plenary.nvim.

## Requirements

- **Neovim 0.8.0+** (required for plenary.nvim and stdpath('log'))
- Git (for cloning plenary.nvim)

**Note**: Neovim 0.7.x and earlier will fail with `"log" is not a valid stdpath` error.

## Running Tests

### Run All Tests

```bash
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedDirectory tests/specs/ {minimal_init = 'tests/minimal_init.lua'}"
```

### Run Specific Test File

```bash
# Init module tests
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedFile tests/specs/init_spec.lua"

# TUI tests
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedFile tests/specs/tui_spec.lua"

# Binary tests
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedFile tests/specs/binary_spec.lua"

# Health tests
nvim --headless -u tests/minimal_init.lua \
  -c "PlenaryBustedFile tests/specs/health_spec.lua"
```

### Interactive Test Run

```bash
# See test output in real-time
nvim -u tests/minimal_init.lua \
  -c "PlenaryBustedFile tests/specs/init_spec.lua"
```

## Test Structure

```
tests/
├── minimal_init.lua      # Test environment setup
├── README.md             # This file
├── cli.rs                # CLI integration tests (Rust)
├── session_api.rs        # Session API tests (Rust)
├── tool_isolation.rs     # Tool isolation tests (Rust)
├── trust_level.rs        # Trust level tests (Rust)
├── usage_api.rs          # Usage API tests (Rust)
└── specs/                # Neovim/Lua tests
    ├── init_spec.lua     # Main module tests (setup, API, commands)
    ├── tui_spec.lua      # TUI integration tests
    ├── binary_spec.lua   # Binary management tests
    ├── ghost_spec.lua    # Ghost text completion tests
    ├── lsp_spec.lua      # LSP integration tests
    ├── statusline_spec.lua # Statusline helper tests
    └── health_spec.lua   # Health check tests
```

## Test Coverage

### Rust Tests

| Test File | Coverage |
|-----------|----------|
| `cli.rs` | CLI commands, usage output formats, help text |
| `session_api.rs` | Session CRUD, metadata fields, status flags |
| `tool_isolation.rs` | Mode-based tool access, Plan/Build/Ask isolation |
| `trust_level.rs` | Trust level cycling, storage, risk level checks |
| `usage_api.rs` | Usage endpoints, dashboard, CSV export |

### Lua Tests

### Init Module (`init_spec.lua`)
- ✅ Module loading
- ✅ Version info
- ✅ Config structure (window, auto_download)
- ✅ Public API functions (open, close, toggle, is_open)
- ✅ Setup function
- ✅ Commands registration (Tark, TarkOpen, TarkClose, TarkDownload, TarkVersion)
- ✅ LSP API functions
- ✅ Ghost text API functions

### TUI Module (`tui_spec.lua`)
- ✅ Module functions (open, close, toggle, is_open, cleanup)
- ✅ State tracking (buf, win, job_id, socket_path)
- ✅ Config validation (window position, width, height)
- ✅ Setup function
- ✅ Cleanup function

### Binary Module (`binary_spec.lua`)
- ✅ Module functions (find, download, version)
- ✅ Config validation
- ✅ Setup function

### Ghost Module (`ghost_spec.lua`)
- ✅ Server lifecycle (start, stop, is_running)
- ✅ Enable/disable/toggle functions
- ✅ Usage statistics tracking
- ✅ Config validation

### LSP Module (`lsp_spec.lua`)
- ✅ Module functions
- ✅ State management

### Statusline Module (`statusline_spec.lua`)
- ✅ Status functions
- ✅ Lualine integration

### Health Module (`health_spec.lua`)
- ✅ Check function exists

## CI Integration

Tests run automatically on every push/PR via GitHub Actions:

```yaml
neovim-tests:
  name: Neovim Tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Install Neovim
      uses: rhysd/action-setup-vim@v1
      with:
        neovim: true
        version: stable
    - name: Install plenary.nvim
      run: |
        mkdir -p "$HOME/.local/share/nvim"
        git clone --depth=1 https://github.com/nvim-lua/plenary.nvim \
          "$HOME/.local/share/nvim/plenary.nvim"
    - name: Run Neovim tests
      run: |
        nvim --headless -u tests/minimal_init.lua \
          -c "PlenaryBustedDirectory tests/specs/ {minimal_init = 'tests/minimal_init.lua'}"
```

## Troubleshooting

### Error: "log" is not a valid stdpath

This means your Neovim version is too old. Upgrade to Neovim 0.8.0 or later:

```bash
# Check version
nvim --version

# Ubuntu/Debian
sudo add-apt-repository ppa:neovim-ppa/stable
sudo apt update
sudo apt install neovim

# macOS
brew install neovim

# From source
git clone https://github.com/neovim/neovim
cd neovim && make CMAKE_BUILD_TYPE=Release
sudo make install
```

### Tests Hang or Timeout

Some tests involve async operations. If tests hang:
- Ensure tark server is not running (`pkill tark`)
- Check for zombie Neovim processes (`ps aux | grep nvim`)
- Increase timeout: `timeout 60 nvim --headless ...`

### Plenary Not Found

The minimal_init.lua automatically clones plenary.nvim. If it fails:

```bash
# Manual clone
git clone --depth=1 https://github.com/nvim-lua/plenary.nvim \
  ~/.local/share/nvim/plenary.nvim
```

## Writing New Tests

Follow the existing test structure:

```lua
describe('module - feature', function()
    before_each(function()
        -- Setup before each test
    end)

    after_each(function()
        -- Cleanup after each test
    end)

    describe('sub-feature', function()
        it('does something', function()
            assert.equals(expected, actual)
        end)
    end)
end)
```

### Assertion API

```lua
assert.equals(expected, actual)
assert.is_true(value)
assert.is_false(value)
assert.is_nil(value)
assert.is_not_nil(value)
assert.is_table(value)
assert.is_string(value)
assert.is_number(value)
assert.is_boolean(value)
assert.is_function(value)
assert.has_no_errors(function() ... end)
```

## Resources

- [plenary.nvim](https://github.com/nvim-lua/plenary.nvim)
- [Neovim Lua Guide](https://neovim.io/doc/user/lua-guide.html)
- [tark Documentation](../README.md)
