/**
 * Tark chat panel (`WebviewViewProvider`, view id `tark.chatView`).
 *
 * Native VS Code presentation for the editor-neutral ACP chat workflow
 * (R11, S27): streaming agent messages, tool-call activity, permission
 * notices (the decision itself is taken in a native QuickPick by
 * `extension.ts`), a cancel button (`session/cancel`), and session
 * lifecycle controls (`session/new`, `session/close` via new/close).
 *
 * Correlates streamed `session/update` notifications by `responseId`; only
 * the `vscode` module boundary touches `any` (see justification comments).
 */
import * as vscode from "vscode";

export type ChatRole = "user" | "agent" | "tool" | "system";

export interface ChatStreamChunk {
  streamId: string;
  text: string;
  reasoning: boolean;
}

export interface ChatStreamEnd {
  streamId: string;
  stopReason: string;
  errorMessage?: string;
}

export interface ChatToolEvent {
  streamId: string;
  toolCallId: string;
  title: string;
  status: string;
  output?: string;
}

/** Backend operations the chat panel drives; implemented in `extension.ts`. */
export interface ChatBackend {
  sendPrompt(text: string): Promise<void>;
  cancel(): Promise<void>;
  startNewSession(): Promise<void>;
  setMode(modeId: string): Promise<void>;
  describeState(): {
    connected: boolean;
    busy: boolean;
    sessionId?: string;
    backendVersion?: string;
    mode?: string;
  };
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export class TarkChatViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewId = "tark.chatView";

  private view: vscode.WebviewView | null = null;

  public constructor(private readonly backend: ChatBackend) {}

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    // Justification: signature is dictated by the vscode API (`ResolveOptions`
    // uses `any`-typed internals); the parameter is unused by this provider.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _context: any,
    // Justification: same as above; the token is intentionally unused.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _token: any,
  ): void {
    this.view = webviewView;
    webviewView.webview.options = { enableScripts: true };
    webviewView.webview.html = this.renderHtml(webviewView.webview);
    webviewView.onDidDispose(() => {
      this.view = null;
    });
    webviewView.webview.onDidReceiveMessage((message: unknown) => {
      void this.handleMessage(message);
    });
    this.postState();
  }

  /** Reveal the chat view (used by the `tark.chat` command). */
  public async reveal(): Promise<void> {
    await vscode.commands.executeCommand(`${TarkChatViewProvider.viewId}.focus`);
  }

  public postSystem(text: string): void {
    void this.post({ type: "system", text });
  }

  public postError(text: string): void {
    void this.post({ type: "error", text });
  }

  public postUserPrompt(text: string): void {
    void this.post({ type: "user", text });
  }

  public postPermissionNotice(title: string, detail: string): void {
    void this.post({ type: "permissionNotice", title, detail });
  }

  public postChunk(chunk: ChatStreamChunk): void {
    void this.post({
      type: "chunk",
      streamId: chunk.streamId,
      text: chunk.text,
      reasoning: chunk.reasoning,
    });
  }

  public postStreamEnd(end: ChatStreamEnd): void {
    void this.post({
      type: "streamEnd",
      streamId: end.streamId,
      stopReason: end.stopReason,
      errorMessage: end.errorMessage,
    });
  }

  public postToolEvent(kind: "toolStart" | "toolUpdate", event: ChatToolEvent): void {
    void this.post({
      type: kind,
      streamId: event.streamId,
      toolCallId: event.toolCallId,
      title: event.title,
      status: event.status,
      output: event.output,
    });
  }

  public postState(): void {
    const state = this.backend.describeState();
    void this.post({
      type: "state",
      connected: state.connected,
      busy: state.busy,
      sessionId: state.sessionId,
      backendVersion: state.backendVersion,
      mode: state.mode,
    });
  }

  private async post(payload: Record<string, unknown>): Promise<void> {
    if (this.view) {
      await this.view.webview.postMessage(payload);
    }
  }

  private async handleMessage(message: unknown): Promise<void> {
    if (typeof message !== "object" || message === null) {
      return;
    }
    const record = message as Record<string, unknown>;
    try {
      switch (record["type"]) {
        case "prompt": {
          const text = record["text"];
          if (typeof text === "string" && text.trim().length > 0) {
            this.postUserPrompt(text);
            await this.backend.sendPrompt(text);
          }
          break;
        }
        case "cancel":
          await this.backend.cancel();
          break;
        case "newSession":
          await this.backend.startNewSession();
          break;
        case "setMode": {
          const modeId = record["modeId"];
          if (typeof modeId === "string") {
            await this.backend.setMode(modeId);
          }
          break;
        }
        default:
          break;
      }
    } catch (err) {
      this.postError(err instanceof Error ? err.message : String(err));
    } finally {
      this.postState();
    }
  }

  private renderHtml(webview: vscode.Webview): string {
    const nonce = Buffer.from(String(Date.now())).toString("base64").replace(/[^a-zA-Z0-9]/g, "x");
    const csp =
      `default-src 'none'; ` +
      `script-src 'nonce-${nonce}'; ` +
      `style-src 'unsafe-inline'; ` +
      `img-src ${webview.cspSource} https:; ` +
      `font-src ${webview.cspSource};`;
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="${escapeHtml(csp)}">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Tark Chat</title>
<style>
  body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size);
         color: var(--vscode-foreground); background: var(--vscode-sideBar-background);
         margin: 0; padding: 8px; display: flex; flex-direction: column; height: 100vh; box-sizing: border-box; }
  #toolbar { display: flex; gap: 6px; align-items: center; margin-bottom: 8px; flex-wrap: wrap; }
  #toolbar .meta { font-size: 11px; opacity: 0.8; }
  #messages { flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; margin-bottom: 8px; }
  .msg { border-radius: 6px; padding: 6px 8px; white-space: pre-wrap; word-break: break-word; font-size: 12.5px; }
  .msg.user { background: var(--vscode-input-background); border: 1px solid var(--vscode-input-border, transparent); align-self: flex-end; max-width: 95%; }
  .msg.agent { background: transparent; border-left: 3px solid var(--vscode-activityBar-activeBorder, #888); }
  .msg.agent.reasoning { opacity: 0.75; font-style: italic; }
  .msg.tool { border: 1px dashed var(--vscode-input-border, #888); font-size: 12px; }
  .msg.system, .msg.error, .msg.permission { font-size: 12px; }
  .msg.error { color: var(--vscode-errorForeground); border: 1px solid var(--vscode-errorForeground); }
  .msg.permission { border: 1px solid var(--vscode-warningForeground, #ca0); }
  #composer { display: flex; gap: 6px; }
  #input { flex: 1; background: var(--vscode-input-background); color: var(--vscode-input-foreground);
           border: 1px solid var(--vscode-input-border, transparent); border-radius: 4px; padding: 6px; resize: none; }
  button, select { background: var(--vscode-button-background); color: var(--vscode-button-foreground);
                   border: none; border-radius: 4px; padding: 5px 10px; cursor: pointer; }
  button.secondary { background: var(--vscode-button-secondaryBackground, transparent);
                     color: var(--vscode-button-secondaryForeground, inherit);
                     border: 1px solid var(--vscode-input-border, #888); }
  button:disabled { opacity: 0.5; cursor: default; }
</style>
</head>
<body>
  <div id="toolbar">
    <select id="mode" title="Agent mode">
      <option value="ask">Ask</option>
      <option value="plan">Plan</option>
      <option value="build">Build</option>
    </select>
    <button id="sendBtn" class="secondary" title="Send">Send</button>
    <button id="cancelBtn" class="secondary" title="Cancel running prompt">Cancel</button>
    <button id="newBtn" class="secondary" title="Start a new session">New session</button>
    <span class="meta" id="meta">disconnected</span>
  </div>
  <div id="messages"></div>
  <div id="composer">
    <textarea id="input" rows="3" placeholder="Ask Tark… (Enter to send, Shift+Enter for newline)"></textarea>
  </div>
<script nonce="${nonce}">
(function () {
  const api = acquireVsCodeApi();
  const messages = document.getElementById('messages');
  const input = document.getElementById('input');
  const meta = document.getElementById('meta');
  const mode = document.getElementById('mode');
  const cancelBtn = document.getElementById('cancelBtn');
  const streams = {};
  function esc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
  function add(role, text, cls) {
    const div = document.createElement('div');
    div.className = 'msg ' + role + (cls ? ' ' + cls : '');
    div.textContent = text;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
    return div;
  }
  function streamDiv(id, reasoning) {
    if (!streams[id]) {
      streams[id] = add('agent', '', reasoning ? 'reasoning' : '');
    }
    return streams[id];
  }
  document.getElementById('sendBtn').addEventListener('click', () => {
    const text = input.value.trim();
    if (text) { input.value = ''; api.postMessage({ type: 'prompt', text }); }
  });
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      const text = input.value.trim();
      if (text) { input.value = ''; api.postMessage({ type: 'prompt', text }); }
    }
  });
  cancelBtn.addEventListener('click', () => api.postMessage({ type: 'cancel' }));
  document.getElementById('newBtn').addEventListener('click', () => api.postMessage({ type: 'newSession' }));
  mode.addEventListener('change', () => api.postMessage({ type: 'setMode', modeId: mode.value }));
  window.addEventListener('message', (event) => {
    const m = event.data || {};
    switch (m.type) {
      case 'user': add('user', m.text); break;
      case 'system': add('system', m.text); break;
      case 'error': add('error', m.text); break;
      case 'permissionNotice': add('permission', 'Permission requested: ' + m.title + '\\n' + m.detail + '\\nAnswer in the VS Code prompt.'); break;
      case 'chunk': {
        const div = streamDiv(m.streamId, m.reasoning);
        div.textContent += m.text || '';
        messages.scrollTop = messages.scrollHeight;
        break;
      }
      case 'streamEnd': {
        const div = streams[m.streamId];
        if (div && m.stopReason && m.stopReason !== 'end_turn') {
          div.textContent += '\\n[' + m.stopReason + (m.errorMessage ? ': ' + m.errorMessage : '') + ']';
        }
        delete streams[m.streamId];
        break;
      }
      case 'toolStart': add('tool', 'Running: ' + m.title + ' [' + m.status + ']'); break;
      case 'toolUpdate': add('tool', (m.title || '') + ' -> ' + m.status + (m.output ? '\\n' + String(m.output).slice(0, 2000) : '')); break;
      case 'state': {
        const parts = [m.connected ? 'connected' : 'disconnected'];
        if (m.sessionId) parts.push(m.sessionId);
        if (m.backendVersion) parts.push('tark ' + m.backendVersion);
        if (m.mode) { parts.push(m.mode); try { mode.value = m.mode; } catch (e) { /* keep selection */ } }
        if (m.busy) parts.push('working…');
        meta.textContent = parts.join(' · ');
        cancelBtn.disabled = !m.busy;
        break;
      }
    }
  });
})();
</script>
</body>
</html>`;
  }
}
