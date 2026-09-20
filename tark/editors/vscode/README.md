# Tark for VS Code

Production VS Code extension for the [tark](https://github.com/anomalyco/opencode)
AI agent (requirements R11, scenario S27: behavior and backend protocol
contracts match Neovim; only the presentation uses native VS Code surfaces).

The extension spawns a `tark acp` subprocess and talks to it over
newline-delimited JSON stdio using ACP v1 (`initialize` -> `session/new` ->
`session/prompt` with streamed `session/update`s -> `session/cancel` ->
`session/close`, plus `session/request_permission` and the optional
`_tark/inlineCompletion` extension). `Content-Length` framing and
`session/load` are not used: the backend does not implement them.

## Install

1. Install a `tark` backend release whose **major.minor** version matches
   this extension (`0.12.x` for extension `0.12.6`; patch may differ).
2. Make sure `tark` is on your `PATH`, or set `tark.binaryPath` (see below).
3. Install the extension:
   - From source: `npm install && npm run compile`, then run the
     **Extension Development Host** (`F5`) or package with
     `npx vsce package` and install the `.vsix`.
   - From a release: install the published `tark-*.vsix` via
     **Extensions: Install from VSIX…**.

## Configuration

| Setting            | Default | Meaning                                                        |
| ------------------ | ------- | -------------------------------------------------------------- |
| `tark.binaryPath`  | `""`    | Absolute path to the `tark` binary. Empty = search `PATH`.     |
| `tark.serverArgs`  | `[]`    | Extra args inserted before the `acp` subcommand at spawn time. |

Set them in **Settings** (`@ext:tark`) or `settings.json`:

```json
{
  "tark.binaryPath": "/usr/local/bin/tark",
  "tark.serverArgs": []
}
```

## Commands

| Command                          | What it does                                              |
| -------------------------------- | --------------------------------------------------------- |
| `Tark: Open Chat`                | Reveal the Tark Chat side panel.                          |
| `Tark: Request Inline Completion`| Trigger an inline suggestion at the cursor.               |
| `Tark: Start Agent`              | Resolve the binary, verify compatibility, start backend.  |
| `Tark: Stop Agent`               | Close the session and stop the backend.                   |

The chat panel additionally offers **Send**, **Cancel** (cancels the
in-flight prompt via `session/cancel`), **New session**, and an
**Ask/Plan/Build** mode selector (`session/set_mode`).

## Permissions

When the agent needs approval, VS Code shows a native picker with
**Allow once**, **Reject once**, and — when the backend suggests a scope —
**Always allow/reject `<pattern>`** options. Dismissing the picker denies
fail-closed. The prompt names the tool, the exact command, and the working
directory it runs in.

## Troubleshooting

| Symptom                                            | Next safe action                                                                 |
| -------------------------------------------------- | -------------------------------------------------------------------------------- |
| `No 'tark' binary found on PATH`                   | Install a `0.12.x` backend or set `tark.binaryPath`, then `Tark: Start Agent`.   |
| `Incompatible tark backend '…'`                    | Install the matching release or repoint `tark.binaryPath`; patch drift is fine. |
| `Tark backend exited unexpectedly`                 | Use **Restart Agent** in the error dialog; inspect the **Tark** output channel.  |
| `No workspace folder is open`                      | Open a folder first: the agent is confined to the workspace root.                |
| Inline completion does nothing                     | Check the **Tark** output channel; chat keeps working when the extension lapses. |
| `Unsupported ACP protocolVersion`                  | Backend and extension disagree on ACP v1; install the matching backend release.  |

Diagnostics live in the **Tark** output channel (**View → Output**, pick
`Tark`). Secrets (tokens, API keys, URL passwords) are redacted there.

## Compatibility

- Extension `0.12.6` requires backend major.minor `0.12` and ACP protocol
  version `1`. Mismatches are refused with a remediation message, never
  silently reinterpreted.
- Only backend-advertised capabilities are used: text prompts with embedded
  context, no image/audio, no MCP passthrough, no `session/load`.

## Development

```bash
npm install
npm run compile   # type-check + emit to dist/
npm test          # compile + node:test unit suite (no vscode module needed)
```

End-to-end coverage via `@vscode/test-electron` (real headless editor run:
startup, chat, permission, cancellation, shutdown) is a follow-up: it needs
a network download of the test editor build and is not wired here.
