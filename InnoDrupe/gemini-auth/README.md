# Gemini Auth Proxy Plugin

OAuth authentication for Google Gemini using Gemini CLI credentials.

## Overview

This plugin enables tark to use OAuth tokens from Google's Gemini CLI. It runs as a local proxy that:

1. Reads credentials from `~/.gemini/oauth_creds.json`
2. Transforms requests to Cloud Code Assist API format
3. Refreshes tokens when possible (without shipping any secrets in code)
4. Auto-provisions managed projects for free tier

## Prerequisites

1. Install Gemini CLI:
   ```bash
   npm install -g @google/gemini-cli
   ```

2. Authenticate with Gemini CLI:
   ```bash
   gemini
   # Follow the browser authentication flow
   ```

This creates OAuth credentials at `~/.gemini/oauth_creds.json`.

## Installation

Build the proxy:
```bash
cd plugins/InnoDrupe/gemini-auth
cargo build --release
```

## Usage

1. **Start the proxy:**
   ```bash
   ./target/release/gemini-auth-proxy --port 9876
   ```

2. **Configure tark to use the proxy:**
   ```bash
   export GEMINI_API_BASE=http://localhost:9876
   ```

3. **Run tark as normal:**
   ```bash
   tark chat
   ```

## How It Works

```
┌─────────┐     standard Gemini API     ┌────────────────┐
│  tark   │ ──────────────────────────► │ gemini-auth    │
│         │                             │ proxy          │
└─────────┘                             └────────────────┘
                                               │
                                               │ transforms to
                                               │ Code Assist API
                                               ▼
                                        ┌────────────────┐
                                        │ cloudcode-pa.  │
                                        │ googleapis.com │
                                        └────────────────┘
```

The proxy:
- Accepts requests in standard Gemini API format
- Wraps them in Code Assist API format with project ID
- Adds required headers (Client-Metadata, etc.)
- Unwraps responses back to standard format

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /status` | Auth status and project ID |
| `POST /v1beta/models/{model}:generateContent` | Chat completion |
| `POST /v1beta/models/{model}:streamGenerateContent` | Streaming chat |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLOUD_PROJECT` | Override auto-provisioned project ID |
| `GEMINI_OAUTH_CREDENTIALS_PATH` | Override credentials file path (defaults to `~/.gemini/oauth_creds.json`) |
| `GEMINI_OAUTH_CLIENT_ID` | OAuth client id used for refresh (optional; required only if token refresh is needed) |
| `GEMINI_OAUTH_CLIENT_SECRET` | OAuth client secret used for refresh (optional; required only if token refresh is needed) |
| `RUST_LOG` | Logging level (e.g., `gemini_auth_proxy=debug`) |

### OAuth refresh client (local-only)

This repo intentionally **does not** embed any OAuth client secrets. If your `~/.gemini/oauth_creds.json` does not include client info and you want automatic refresh, provide it locally via either:

- **Environment variables**: `GEMINI_OAUTH_CLIENT_ID` and `GEMINI_OAUTH_CLIENT_SECRET`
- **Local file**: `~/.gemini/oauth_client.json` with:

```json
{ "client_id": "…", "client_secret": "…" }
```

## License

MIT
