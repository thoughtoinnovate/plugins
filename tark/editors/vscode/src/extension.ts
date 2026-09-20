/**
 * Tark VS Code extension entry point (R11, S27).
 *
 * - Binary resolution: `tark.binaryPath` config -> `PATH` -> error with
 *   remediation actions (R10/R12 style health reporting).
 * - ACP subprocess lifecycle: async spawn/kill, restart offered on
 *   unexpected exit with a message, status-bar connection state.
 * - Output-channel logging with secret redaction (R3 S6); no API keys in
 *   code or logs.
 * - Permissions use native QuickPick/modal surfaces; completion uses the
 *   optional `_tark/inlineCompletion` extension with stale suppression.
 */
import * as vscode from "vscode";
import { AcpClient, InlineCompletionResult } from "./acpClient";
import { SessionUpdateNotification } from "./acpTypes";
import { BinaryIncompatibleError, BinaryNotFoundError, checkBinaryCompat } from "./binary";
import { TarkChatViewProvider } from "./chatView";
import { TarkCompletionProvider } from "./completionProvider";
import { describePermissionRequest } from "./permissions";
import { redactSecrets } from "./redact";

const REPO_URL = "https://github.com/anomalyco/opencode";
const OUTPUT_CHANNEL_NAME = "Tark";

type ConnectionState = "stopped" | "starting" | "connected";

interface RemediationAction {
  id: string;
  label: string;
  detail: string;
}

function hasRemediations(err: unknown): err is Error & { remediations: RemediationAction[] } {
  return (
    err instanceof Error &&
    Array.isArray((err as unknown as Record<string, unknown>)["remediations"])
  );
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL_NAME);
  const log = (line: string): void => {
    output.appendLine(redactSecrets(line));
  };
  const extensionVersion =
    (context.extension.packageJSON as { version?: string }).version ?? "0.0.0";

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = "tark.chat";
  context.subscriptions.push(statusBar, output);

  const manager = new TarkManager(
    extensionVersion,
    log,
    (text) => {
      statusBar.text = text;
      statusBar.show();
    },
    (message, actions) => showErrorWithRemediations(message, actions, output),
  );

  const chatProvider = new TarkChatViewProvider({
    sendPrompt: (text) => manager.sendPrompt(text),
    cancel: () => manager.cancelPrompt(),
    startNewSession: () => manager.startNewSession(),
    setMode: (modeId) => manager.setMode(modeId),
    describeState: () => manager.describeState(),
  });
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(TarkChatViewProvider.viewId, chatProvider, {
      webviewOptions: { retainContextWhenHidden: true },
    }),
  );
  manager.attachChat(chatProvider);

  const completionProvider = new TarkCompletionProvider(
    {
      ensureCompletionSession: () => manager.ensureSession(),
      requestCompletion: (args) => manager.requestCompletion(args),
      completionEnabled: () => manager.isConnected(),
    },
    log,
  );
  context.subscriptions.push(
    vscode.languages.registerInlineCompletionItemProvider({ pattern: "**" }, completionProvider),
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("tark.chat", async () => {
      await chatProvider.reveal();
    }),
    vscode.commands.registerCommand("tark.complete", async () => {
      await vscode.commands.executeCommand("editor.action.inlineSuggest.trigger");
    }),
    vscode.commands.registerCommand("tark.start", async () => {
      await manager.start();
    }),
    vscode.commands.registerCommand("tark.stop", async () => {
      await manager.stop();
    }),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("tark.binaryPath") || event.affectsConfiguration("tark.serverArgs")) {
        log("tark settings changed; restart the agent to apply them");
        void vscode.window
          .showInformationMessage("Tark settings changed. Restart the agent to apply them.", "Restart")
          .then((choice) => {
            if (choice === "Restart") {
              void manager.restart();
            }
          });
      }
    }),
  );

  manager.setStatus("stopped");
  log(`tark extension ${extensionVersion} activated`);
}

export function deactivate(): Thenable<void> | undefined {
  // The manager is module-local to `activate`; VS Code disposes registered
  // subscriptions (output channel, status bar) automatically. The ACP child
  // process is tracked and killed in `TarkManager.dispose`, registered below
  // via the returned handle on activation.
  const handle = (globalThis as unknown as { __tarkDeactivate?: () => Thenable<void> }).__tarkDeactivate;
  return handle ? handle() : undefined;
}

async function showErrorWithRemediations(
  message: string,
  actions: RemediationAction[],
  output: vscode.OutputChannel,
): Promise<void> {
  const choice = await vscode.window.showErrorMessage(
    redactSecrets(message),
    ...actions.map((action) => action.label),
  );
  const selected = actions.find((action) => action.label === choice);
  if (!selected) {
    return;
  }
  switch (selected.id) {
    case "open-settings":
      await vscode.commands.executeCommand("workbench.action.openSettings", "tark");
      break;
    case "open-downloads":
      await vscode.env.openExternal(vscode.Uri.parse(REPO_URL));
      break;
    case "show-output":
      output.show(true);
      break;
    case "retry":
      await vscode.commands.executeCommand("tark.start");
      break;
    default:
      output.show(true);
      break;
  }
}

class TarkManager {
  private client: AcpClient | null = null;
  private chat: TarkChatViewProvider | null = null;
  private sessionId: string | null = null;
  private state: ConnectionState = "stopped";
  private busy = false;
  private busyStreamId: string | null = null;
  private backendVersion: string | null = null;
  private mode = "ask";
  private starting: Promise<void> | null = null;

  public constructor(
    private readonly extensionVersion: string,
    private readonly log: (line: string) => void,
    private readonly setStatusText: (text: string) => void,
    private readonly showError: (message: string, actions: RemediationAction[]) => Promise<void>,
  ) {
    (globalThis as unknown as { __tarkDeactivate?: () => Thenable<void> }).__tarkDeactivate = () =>
      this.dispose();
  }

  public attachChat(chat: TarkChatViewProvider): void {
    this.chat = chat;
  }

  public describeState(): {
    connected: boolean;
    busy: boolean;
    sessionId?: string;
    backendVersion?: string;
    mode?: string;
  } {
    return {
      connected: this.state === "connected",
      busy: this.busy,
      sessionId: this.sessionId ?? undefined,
      backendVersion: this.backendVersion ?? undefined,
      mode: this.mode,
    };
  }

  public isConnected(): boolean {
    return this.state === "connected" && this.client !== null && this.sessionId !== null;
  }

  public setStatus(state: ConnectionState): void {
    this.state = state;
    const base = "$(comment-discussion) Tark";
    if (state === "stopped") {
      this.setStatusText(`${base}: stopped`);
    } else if (state === "starting") {
      this.setStatusText(`${base}: starting…`);
    } else if (this.backendVersion) {
      this.setStatusText(`${base} ${this.backendVersion}${this.busy ? " (working…)" : ""}`);
    } else {
      this.setStatusText(`${base}: connected`);
    }
    this.chat?.postState();
  }

  public async start(): Promise<void> {
    if (this.starting) {
      await this.starting;
      return;
    }
    this.starting = this.doStart();
    try {
      await this.starting;
    } catch (err) {
      await this.reportStartFailure(err);
      throw err;
    } finally {
      this.starting = null;
    }
  }

  public async restart(): Promise<void> {
    await this.stop();
    await this.start();
  }

  public async stop(): Promise<void> {
    const client = this.client;
    const sessionId = this.sessionId;
    this.client = null;
    this.sessionId = null;
    this.busy = false;
    this.busyStreamId = null;
    if (client && sessionId) {
      try {
        await client.closeSession(sessionId);
      } catch {
        // Best effort: the process may already be gone.
      }
    }
    if (client) {
      await client.stop();
    }
    this.backendVersion = null;
    this.setStatus("stopped");
    this.log("tark backend stopped");
  }

  public async dispose(): Promise<void> {
    await this.stop();
  }

  /** Ensure a live session, starting the backend when needed. */
  public async ensureSession(): Promise<string> {
    if (this.sessionId && this.client?.running) {
      return this.sessionId;
    }
    await this.start();
    if (!this.sessionId) {
      throw new Error("Tark backend started but no session is available. Check the Tark output channel, then retry.");
    }
    return this.sessionId;
  }

  public async sendPrompt(text: string): Promise<void> {
    const sessionId = await this.ensureSession();
    const client = this.client;
    if (!client) {
      throw new Error("Tark backend is not running. Run 'Tark: Start Agent', then retry.");
    }
    await this.publishEditorContext(client, sessionId);
    const receipt = await client.prompt(sessionId, text);
    if (!receipt.accepted) {
      throw new Error("The backend did not accept the prompt. Check the Tark output channel, then retry.");
    }
    this.busy = true;
    this.busyStreamId = receipt.requestId || null;
    this.setStatus("connected");
  }

  public async cancelPrompt(): Promise<void> {
    if (!this.client || !this.sessionId) {
      this.chat?.postSystem("Nothing to cancel: the agent is not running.");
      return;
    }
    if (!this.busy) {
      this.chat?.postSystem("Nothing to cancel: no prompt is in flight.");
      return;
    }
    const cancelled = await this.client.cancel(this.sessionId);
    this.log(`session/cancel acknowledged: cancelled=${cancelled}`);
    if (!cancelled) {
      this.chat?.postSystem("Cancel reported no in-flight prompt; the turn may already have finished.");
    }
  }

  public async startNewSession(): Promise<void> {
    await this.ensureSession();
    const client = this.client;
    const oldSession = this.sessionId;
    if (!client) {
      throw new Error("Tark backend is not running. Run 'Tark: Start Agent', then retry.");
    }
    const cwd = this.workspaceRoot();
    if (oldSession) {
      try {
        await client.closeSession(oldSession);
      } catch {
        // Best effort; continue with a fresh session.
      }
    }
    await this.createSession(client, cwd);
    this.chat?.postSystem(`New session ${this.sessionId ?? ""} started in ${cwd}.`);
  }

  public async setMode(modeId: string): Promise<void> {
    if (modeId !== "ask" && modeId !== "plan" && modeId !== "build") {
      throw new Error(`Unknown mode '${modeId}'. Supported modes: ask, plan, build.`);
    }
    const sessionId = await this.ensureSession();
    const client = this.client;
    if (!client) {
      throw new Error("Tark backend is not running. Run 'Tark: Start Agent', then retry.");
    }
    await client.setMode(sessionId, modeId);
    this.mode = modeId;
    this.log(`session mode -> ${modeId}`);
    this.chat?.postSystem(`Mode set to ${modeId}.`);
  }

  public async requestCompletion(args: {
    sessionId: string;
    path: string;
    line: number;
    col: number;
    prefix: string;
    suffix: string;
    language?: string;
    triggerKind?: string;
    clientRequestId: string;
    bufferVersion: number;
  }): Promise<InlineCompletionResult> {
    if (!this.client) {
      throw new Error("Tark backend is not running.");
    }
    return this.client.inlineCompletion(args);
  }

  private async doStart(): Promise<void> {
    if (this.state === "connected" && this.client?.running && this.sessionId) {
      return;
    }
    await this.stop();
    this.setStatus("starting");
    try {
      const config = vscode.workspace.getConfiguration("tark");
      const binaryPath = config.get<string>("binaryPath", "");
      const serverArgs = config.get<string[]>("serverArgs", []);
      const compat = await checkBinaryCompat(binaryPath || undefined, this.extensionVersion);
      this.log(compat.message);
      this.backendVersion = `${compat.backendVersion.major}.${compat.backendVersion.minor}.${compat.backendVersion.patch}`;

      const client = new AcpClient({
        binaryPath: compat.binary.path,
        serverArgs: [...serverArgs],
        extensionVersion: this.extensionVersion,
        log: this.log,
        onPermission: (request) => this.askPermission(request),
      });
      client.onUpdate((update) => this.handleSessionUpdate(update));
      client.onExit((code, signal) => {
        void this.handleUnexpectedExit(code, signal);
      });
      this.client = client;
      await client.start();
      const cwd = this.workspaceRoot();
      await this.createSession(client, cwd);
      this.setStatus("connected");
      this.chat?.postSystem(
        `Connected to tark ${this.backendVersion ?? ""} (session ${this.sessionId ?? ""}, cwd ${cwd}).`,
      );
    } catch (err) {
      await this.stop();
      throw err;
    }
  }

  private async createSession(client: AcpClient, cwd: string): Promise<void> {
    const result = await client.newSession(cwd);
    const sessionId = result["sessionId"];
    if (typeof sessionId !== "string" || sessionId.length === 0) {
      throw new Error("Backend session/new returned no sessionId. Check the Tark output channel, then retry.");
    }
    this.sessionId = sessionId;
    this.busy = false;
    this.busyStreamId = null;
    this.log(`session/new -> ${sessionId}`);
  }

  private workspaceRoot(): string {
    const folders = vscode.workspace.workspaceFolders;
    if (folders && folders.length > 0) {
      const active = vscode.window.activeTextEditor?.document.uri;
      if (active) {
        const match = vscode.workspace.getWorkspaceFolder(active);
        if (match) {
          return match.uri.fsPath;
        }
      }
      const first = folders[0];
      if (first) {
        return first.uri.fsPath;
      }
    }
    throw new Error(
      "No workspace folder is open. Open a folder (the agent is confined to it), then run 'Tark: Start Agent'.",
    );
  }

  private async handleUnexpectedExit(code: number | null, signal: string | null): Promise<void> {
    const wasBusy = this.busy;
    this.client = null;
    this.sessionId = null;
    this.busy = false;
    this.busyStreamId = null;
    this.backendVersion = null;
    this.setStatus("stopped");
    this.chat?.postError(
      `Tark backend exited unexpectedly (code=${String(code)} signal=${String(signal)}). ` +
        (wasBusy ? "The in-flight prompt was lost. " : "") +
        "Use 'Tark: Start Agent' to restart.",
    );
    await this.showError(
      `Tark backend exited unexpectedly (code=${String(code)}). Restart to continue.`,
      [
        { id: "retry", label: "Restart Agent", detail: "Start the backend again." },
        { id: "show-output", label: "Show Output", detail: "Inspect backend diagnostics." },
      ],
    );
  }

  private async askPermission(request: {
    sessionId: string;
    toolCallId: string;
    title: string;
    kind: string;
    rawInput: string;
    workingDir?: string;
    tool?: string;
    elicitation: boolean;
    options: Array<{ optionId: string; name: string; kind: string; pattern?: string }>;
  }): Promise<string | undefined> {
    this.chat?.postPermissionNotice(
      request.title,
      describePermissionRequest({
        sessionId: request.sessionId,
        toolCallId: request.toolCallId,
        title: request.title,
        status: "pending",
        kind: request.kind,
        rawInput: request.rawInput,
        options: request.options,
        workingDir: request.workingDir,
        tool: request.tool,
        elicitation: request.elicitation,
      }),
    );
    const items: Array<vscode.QuickPickItem & { optionId: string }> = request.options.map((option) => ({
      label: option.name,
      description: option.pattern ? `pattern: ${option.pattern}` : option.kind,
      detail: redactSecrets(request.title + (request.workingDir ? ` (in ${request.workingDir})` : "")),
      optionId: option.optionId,
    }));
    const picked = await vscode.window.showQuickPick(items, {
      title: request.elicitation ? "Tark asks a question" : "Tark requests permission",
      placeHolder: redactSecrets(request.title),
      ignoreFocusOut: true,
      canPickMany: false,
    });
    // Dismissal resolves to undefined; the client answers `cancelled` fail-closed.
    return picked?.optionId;
  }

  private handleSessionUpdate(update: SessionUpdateNotification): void {
    if (!this.chat) {
      return;
    }
    if (this.sessionId && update.sessionId !== this.sessionId) {
      return;
    }
    const kind = update.update.sessionUpdate;
    const streamId = update.update.responseId ?? update._meta?.tark?.requestId ?? "stream";
    switch (kind) {
      case "agent_message_start":
        this.busy = true;
        this.busyStreamId = streamId;
        this.setStatus("connected");
        break;
      case "agent_message_chunk": {
        const content = update.update.content;
        this.chat.postChunk({
          streamId,
          text: content?.text ?? "",
          reasoning: content?.type === "reasoning",
        });
        break;
      }
      case "agent_message_end": {
        const stopReason = update.update.stopReason ?? "end_turn";
        this.chat.postStreamEnd({
          streamId,
          stopReason,
          errorMessage: update._meta?.tark?.errorMessage,
        });
        if (this.busyStreamId === null || this.busyStreamId === streamId) {
          this.busy = false;
          this.busyStreamId = null;
        }
        this.setStatus("connected");
        break;
      }
      case "tool_call":
        this.chat.postToolEvent("toolStart", {
          streamId,
          toolCallId: update.update.toolCallId ?? "",
          title: update.update.title ?? "tool",
          status: update.update.status ?? "pending",
        });
        break;
      case "tool_call_update":
        this.chat.postToolEvent("toolUpdate", {
          streamId,
          toolCallId: update.update.toolCallId ?? "",
          title: update.update.title ?? "tool",
          status: update.update.status ?? "completed",
          output: update.update.rawOutput,
        });
        break;
      default:
        this.log(`ignoring unknown sessionUpdate '${kind}'`);
        break;
    }
  }

  private async reportStartFailure(err: unknown): Promise<void> {
    const message = err instanceof Error ? err.message : String(err);
    this.log(`start failed: ${message}`);
    this.chat?.postError(message);
    if (err instanceof BinaryNotFoundError || err instanceof BinaryIncompatibleError) {
      await this.showError(message, err.remediations);
    } else if (hasRemediations(err)) {
      await this.showError(message, err.remediations);
    } else {
      await this.showError(message, [
        { id: "show-output", label: "Show Output", detail: "Inspect diagnostics." },
        { id: "retry", label: "Retry", detail: "Try starting again." },
      ]);
    }
  }

  private async publishEditorContext(client: AcpClient, sessionId: string): Promise<void> {
    try {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document.uri.scheme !== "file") {
        return;
      }
      const position = editor.selection.active;
      const selection = editor.selection.isEmpty
        ? undefined
        : {
            startLine: editor.selection.start.line,
            startCol: editor.selection.start.character,
            endLine: editor.selection.end.line,
            endCol: editor.selection.end.character,
            text: editor.document.getText(editor.selection).slice(0, 4000),
          };
      await client.updateContext(sessionId, {
        activeFile: editor.document.uri.fsPath,
        cursor: { line: position.line, col: position.character },
        selection,
      });
    } catch (err) {
      // Context publishing is best-effort; the prompt still proceeds.
      this.log(`context/update skipped: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
