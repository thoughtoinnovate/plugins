# ChatGPT OAuth Plugin for Tark

Auth-only WASM plugin that provides OAuth authentication for ChatGPT Pro/Plus users, enabling access to Codex models.

## Features

- OAuth token management (storage, refresh)
- Account ID extraction from JWT tokens
- Automatic token refresh when expired
- Compatible with tark's native OpenAI provider

## Supported Models

- `gpt-5.1-codex-max` - GPT-5.1 Codex Max
- `gpt-5.1-codex-mini` - GPT-5.1 Codex Mini  
- `gpt-5.2` - GPT-5.2
- `gpt-5.2-codex` - GPT-5.2 Codex

## Installation

### Build from Source

```bash
# Install Rust wasm target
rustup target add wasm32-unknown-unknown

# Build
./build.sh

# Install
mkdir -p ~/.config/tark/plugins/chatgpt-oauth
cp dist/* ~/.config/tark/plugins/chatgpt-oauth/

# Enable
tark plugin enable chatgpt-oauth
```

## Authentication

Since WASM plugins cannot run HTTP servers for OAuth callbacks, authentication must be performed externally.

### Option 1: Manual Token Setup

Create `~/.config/tark/chatgpt_oauth.json`:

```json
{
  "access_token": "your_access_token",
  "refresh_token": "your_refresh_token",
  "id_token": "your_id_token",
  "expires_at": 1234567890
}
```

### Option 2: Browser Extension (Future)

A browser extension can capture tokens after authenticating at ChatGPT and save them to the credentials file.

### Option 3: CLI Auth Command (Future)

```bash
tark auth chatgpt
```

This will:
1. Open browser to `https://auth.openai.com/oauth/authorize`
2. Start local callback server on port 1455
3. Exchange authorization code for tokens using PKCE
4. Save tokens to `~/.config/tark/chatgpt_oauth.json`

## Configuration

### Environment Variables

- `CHATGPT_OAUTH_CREDENTIALS_PATH` - Override default credentials file path

### Credentials File

Default location: `~/.config/tark/chatgpt_oauth.json`

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "id_token": "...",
  "expires_at": 1234567890,
  "account_id": "..."
}
```

## How It Works

This is an **auth-only** plugin:

1. Plugin exports `provider_auth_credentials()` instead of `provider_chat()`
2. Tark calls the plugin to get OAuth credentials
3. Tark creates a native OpenAI-compatible provider with:
   - Custom endpoint: `https://chatgpt.com/backend-api/codex/responses`
   - Bearer token authentication
   - `ChatGPT-Account-Id` header (for organization subscriptions)
   - `originator: opencode` header

This approach enables:
- Native streaming support
- Tool/function calling
- All future provider improvements

## OAuth Details

- **Client ID**: `app_EMoamEEZ73f0CkXaXp7hrann`
- **Issuer**: `https://auth.openai.com`
- **Token endpoint**: `https://auth.openai.com/oauth/token`
- **API endpoint**: `https://chatgpt.com/backend-api/codex/responses`
- **Flow**: OAuth 2.0 with PKCE

## Troubleshooting

### "No credentials stored"

Ensure credentials file exists at `~/.config/tark/chatgpt_oauth.json` with valid tokens.

### Token refresh fails

The plugin needs a valid `refresh_token` to refresh expired access tokens. Re-authenticate if refresh fails.

### Account ID issues

For organization subscriptions, the `ChatGPT-Account-Id` header is required. The plugin extracts this from JWT tokens automatically.

## License

MIT
