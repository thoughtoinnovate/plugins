/**
 * NDJSON stdio ACP v1 client for the tark backend (R8, R11, S27).
 *
 * Lifecycle: `initialize` -> `session/new` -> `session/prompt` (streamed
 * `session/update` notifications: `agent_message_*` / `tool_call*`) ->
 * `session/cancel` -> `session/close`.
 *
 * - Framing is newline-delimited JSON only; `Content-Length` framing is
 *   never used (parse errors surface, never reinterpreted).
 * - Capability advertisement matches the backend exactly: only implemented
 *   methods are sent, and `_meta.tark.completion.supported: true` opts into
 *   the `_tark/inlineCompletion` extension (R8 S22).
 * - `session/request_permission` inbound requests are delegated to an
 *   injected handler (the extension shows a native QuickPick/modal); an
 *   unoffered or missing choice resolves fail-closed to `cancelled`.
 * - The child process is spawned/killed asynchronously without blocking the
 *   extension host; unexpected exits are reported via `onExit` so the
 *   extension can offer a restart with a message.
 *
 * No `vscode` imports: logging and permission UI are injected callbacks.
 */
import { spawn, ChildProcess } from "node:child_process";
import { NdjsonDecoder, encodeFrame } from "./framing";
import {
  ACP_PROTOCOL_VERSION,
  InitializeResult,
  SessionUpdateNotification,
  buildInitializeParams,
  buildSessionNewParams,
  buildPromptParams,
  buildInlineCompletionParams,
  findCapabilityMismatches,
} from "./acpTypes";
import { parsePermissionRequest, buildPermissionResult } from "./permissions";

export type LogFn = (line: string) => void;

/** Resolves a permission request to the chosen `optionId`, or `undefined` when dismissed. */
export type PermissionHandler = (request: {
  sessionId: string;
  toolCallId: string;
  title: string;
  kind: string;
  rawInput: string;
  workingDir?: string;
  tool?: string;
  elicitation: boolean;
  options: Array<{ optionId: string; name: string; kind: string; pattern?: string }>;
}) => Promise<string | undefined>;

export interface AcpClientOptions {
  binaryPath: string;
  serverArgs: string[];
  extensionVersion: string;
  log: LogFn;
  onPermission: PermissionHandler;
  requestTimeoutMs?: number;
}

export interface PromptAccepted {
  accepted: boolean;
  requestId: string;
}

export interface InlineCompletionResult {
  completion: string;
  stopReason: string;
  completionEpoch?: number;
  clientRequestId?: string;
  bufferVersion?: number;
  provider?: string;
  model?: string;
}

interface PendingRequest {
  resolve: (value: Record<string, unknown>) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
  method: string;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 60_000;
const KILL_GRACE_MS = 2_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class AcpClient {
  private readonly options: AcpClientOptions;
  private readonly decoder = new NdjsonDecoder();
  private readonly pending = new Map<number | string, PendingRequest>();
  private readonly updateListeners: Array<(update: SessionUpdateNotification) => void> = [];
  private readonly exitListeners: Array<(code: number | null, signal: string | null) => void> = [];
  private readonly stderrBuffer: string[] = [];
  private child: ChildProcess | null = null;
  private nextId = 1;
  private stopped = false;
  private initializeResult: InitializeResult | null = null;

  public constructor(options: AcpClientOptions) {
    this.options = options;
  }

  public get agentInfo(): InitializeResult | null {
    return this.initializeResult;
  }

  public get running(): boolean {
    return this.child !== null && this.child.exitCode === null && !this.child.killed;
  }

  public onUpdate(listener: (update: SessionUpdateNotification) => void): void {
    this.updateListeners.push(listener);
  }

  public onExit(listener: (code: number | null, signal: string | null) => void): void {
    this.exitListeners.push(listener);
  }

  /** Spawn the backend and run the `initialize` handshake. Throws on failure. */
  public async start(): Promise<InitializeResult> {
    if (this.running) {
      if (this.initializeResult) {
        return this.initializeResult;
      }
      throw new Error("ACP client is already starting");
    }
    this.stopped = false;
    const args = [...this.options.serverArgs, "acp"];
    this.options.log(`spawning backend: ${this.options.binaryPath} ${args.join(" ")}`);
    const child = spawn(this.options.binaryPath, args, { stdio: ["pipe", "pipe", "pipe"] });
    this.child = child;

    child.stdout?.on("data", (chunk: Buffer) => this.handleStdout(chunk));
    child.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8");
      this.stderrBuffer.push(text);
      if (this.stderrBuffer.length > 50) {
        this.stderrBuffer.shift();
      }
      const line = text.trim();
      if (line.length > 0) {
        this.options.log(`backend stderr: ${line.slice(0, 500)}`);
      }
    });
    child.on("error", (err: Error) => {
      this.options.log(`backend process error: ${err.message}`);
      this.failAllPending(err);
    });
    child.on("exit", (code, signal) => {
      this.options.log(`backend exited (code=${String(code)} signal=${String(signal)})`);
      if (this.stderrBuffer.length > 0) {
        this.options.log(`backend stderr tail: ${this.stderrBuffer.join("").slice(-2000)}`);
      }
      this.failAllPending(new Error(`backend exited (code=${String(code)})`));
      this.child = null;
      if (!this.stopped) {
        for (const listener of this.exitListeners) {
          listener(code, signal);
        }
      }
    });

    const result = await this.sendRequest("initialize", buildInitializeParams(this.options.extensionVersion));
    const parsed = result as unknown as InitializeResult;
    if (parsed.protocolVersion !== ACP_PROTOCOL_VERSION) {
      await this.stop();
      throw new Error(
        `Unsupported ACP protocolVersion ${String(parsed.protocolVersion)} ` +
          `(this extension requires ${ACP_PROTOCOL_VERSION}); install a matching tark release.`,
      );
    }
    const mismatches = findCapabilityMismatches(parsed);
    for (const mismatch of mismatches) {
      this.options.log(`backend capability notice: ${mismatch}`);
    }
    this.initializeResult = parsed;
    const agentVersion = parsed.agentInfo?.version ?? "unknown";
    this.options.log(`initialized backend ${parsed.agentInfo?.name ?? "?"} ${agentVersion}`);
    return parsed;
  }

  /** Create a session. `mcpServers` is always empty (backend rejects entries). */
  public async newSession(cwd: string): Promise<Record<string, unknown>> {
    return this.sendRequest("session/new", buildSessionNewParams(cwd));
  }

  /** Send a prompt; resolves with the accept receipt, updates stream via `onUpdate`. */
  public async prompt(sessionId: string, text: string): Promise<PromptAccepted> {
    const result = await this.sendRequest("session/prompt", buildPromptParams(sessionId, text));
    return {
      accepted: result["accepted"] === true,
      requestId: typeof result["requestId"] === "string" ? (result["requestId"] as string) : "",
    };
  }

  /** Cancel the in-flight prompt for a session (request form; backend also tolerates notifications). */
  public async cancel(sessionId: string): Promise<boolean> {
    const result = await this.sendRequest("session/cancel", { sessionId });
    return result["cancelled"] === true;
  }

  /** Close a session. */
  public async closeSession(sessionId: string): Promise<void> {
    await this.sendRequest("session/close", { sessionId });
  }

  /** Switch the session mode (`ask` | `plan` | `build`). */
  public async setMode(sessionId: string, modeId: string): Promise<void> {
    await this.sendRequest("session/set_mode", { sessionId, modeId });
  }

  /** Publish editor context (active file/cursor/selection) for the session. */
  public async updateContext(
    sessionId: string,
    context: {
      activeFile?: string;
      cursor?: { line: number; col: number };
      selection?: { startLine: number; startCol: number; endLine: number; endCol: number; text: string };
      activeExcerpt?: string;
    },
  ): Promise<void> {
    const params: Record<string, unknown> = { sessionId };
    if (context.activeFile !== undefined) {
      params["activeFile"] = context.activeFile;
    }
    if (context.cursor !== undefined) {
      params["cursor"] = context.cursor;
    }
    if (context.selection !== undefined) {
      params["selection"] = context.selection;
    }
    if (context.activeExcerpt !== undefined) {
      params["activeExcerpt"] = context.activeExcerpt;
    }
    await this.sendRequest("context/update", params);
  }

  /** Optional `_tark/inlineCompletion` extension call (requires negotiated opt-in). */
  public async inlineCompletion(args: {
    sessionId: string;
    path: string;
    line: number;
    col: number;
    prefix: string;
    suffix: string;
    maxTokens?: number;
    language?: string;
    triggerKind?: string;
    clientRequestId?: string;
    bufferVersion?: number;
  }): Promise<InlineCompletionResult> {
    const result = await this.sendRequest(
      "_tark/inlineCompletion",
      buildInlineCompletionParams(args),
    );
    const meta = isRecord(result["_meta"]) && isRecord(result["_meta"]["tark"])
      ? (result["_meta"]["tark"] as Record<string, unknown>)
      : {};
    return {
      completion: typeof result["completion"] === "string" ? (result["completion"] as string) : "",
      stopReason: typeof result["stopReason"] === "string" ? (result["stopReason"] as string) : "",
      completionEpoch: typeof meta["completionEpoch"] === "number" ? (meta["completionEpoch"] as number) : undefined,
      clientRequestId: typeof meta["clientRequestId"] === "string" ? (meta["clientRequestId"] as string) : undefined,
      bufferVersion: typeof meta["bufferVersion"] === "number" ? (meta["bufferVersion"] as number) : undefined,
      provider: typeof meta["provider"] === "string" ? (meta["provider"] as string) : undefined,
      model: typeof meta["model"] === "string" ? (meta["model"] as string) : undefined,
    };
  }

  /** Kill the backend subprocess. Safe to call when already stopped. */
  public async stop(): Promise<void> {
    this.stopped = true;
    this.failAllPending(new Error("ACP client stopped"));
    const child = this.child;
    this.child = null;
    this.initializeResult = null;
    if (!child || child.exitCode !== null) {
      return;
    }
    await new Promise<void>((resolve) => {
      const done = (): void => {
        child.removeAllListeners("exit");
        resolve();
      };
      child.once("exit", done);
      try {
        child.kill("SIGTERM");
      } catch {
        done();
        return;
      }
      setTimeout(() => {
        try {
          if (child.exitCode === null) {
            child.kill("SIGKILL");
          }
        } catch {
          // Already gone; the exit handler below resolves.
        }
        done();
      }, KILL_GRACE_MS);
    });
  }

  private sendRequest(method: string, params: Record<string, unknown>): Promise<Record<string, unknown>> {
    const child = this.child;
    const stdin = child?.stdin;
    if (!stdin || !this.running) {
      return Promise.reject(new Error(`Cannot send '${method}': backend is not running`));
    }
    const id = this.nextId++;
    const timeoutMs = this.options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    return new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`ACP request '${method}' timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer, method });
      let frame: string;
      try {
        frame = encodeFrame({ jsonrpc: "2.0", id, method, params });
      } catch (err) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }
      child.stdin?.write(frame, (err) => {
        if (err) {
          this.pending.delete(id);
          clearTimeout(timer);
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });
  }

  private sendResponse(id: number | string, result: Record<string, unknown>): void {
    const child = this.child;
    if (!child?.stdin) {
      this.options.log("cannot answer permission request: backend is not running");
      return;
    }
    try {
      child.stdin?.write(encodeFrame({ jsonrpc: "2.0", id, result }));
    } catch (err) {
      this.options.log(`failed to answer permission request: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private sendError(id: number | string, code: number, message: string): void {
    const child = this.child;
    if (!child?.stdin) {
      return;
    }
    try {
      child.stdin?.write(encodeFrame({ jsonrpc: "2.0", id, error: { code, message } }));
    } catch {
      // Nothing useful to do on the error path.
    }
  }

  private handleStdout(chunk: Buffer): void {
    let messages: unknown[];
    try {
      messages = this.decoder.push(chunk.toString("utf8"));
    } catch (err) {
      this.options.log(`protocol framing error: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    for (const message of messages) {
      this.handleMessage(message);
    }
  }

  private handleMessage(message: unknown): void {
    if (!isRecord(message)) {
      this.options.log("protocol error: backend sent a non-object message");
      return;
    }
    const method = message["method"];
    const id = message["id"];
    if (typeof method === "string" && id !== undefined && (typeof id === "number" || typeof id === "string")) {
      // Inbound request from the backend (today only session/request_permission).
      void this.handleInboundRequest(id, method, message["params"]);
      return;
    }
    if (typeof method === "string") {
      this.handleNotification(method, message["params"]);
      return;
    }
    if (id !== undefined && (typeof id === "number" || typeof id === "string")) {
      const pending = this.pending.get(id);
      if (!pending) {
        this.options.log(`protocol warning: response for unknown request id ${String(id)}`);
        return;
      }
      this.pending.delete(id);
      clearTimeout(pending.timer);
      if (isRecord(message["error"])) {
        const errRecord = message["error"] as Record<string, unknown>;
        pending.reject(new Error(`ACP '${pending.method}' failed: ${String(errRecord["message"] ?? "unknown error")}`));
        return;
      }
      const result = message["result"];
      pending.resolve(isRecord(result) ? result : {});
      return;
    }
    this.options.log("protocol error: backend sent a message with neither method nor id");
  }

  private handleNotification(method: string, params: unknown): void {
    if (method === "session/update") {
      if (!isRecord(params)) {
        this.options.log("protocol error: session/update with non-object params");
        return;
      }
      for (const listener of this.updateListeners) {
        listener(params as unknown as SessionUpdateNotification);
      }
      return;
    }
    this.options.log(`protocol notice: ignoring unsupported notification '${method}'`);
  }

  private async handleInboundRequest(
    id: number | string,
    method: string,
    params: unknown,
  ): Promise<void> {
    if (method !== "session/request_permission") {
      this.sendError(id, -32601, `Method '${method}' not found`);
      return;
    }
    const request = parsePermissionRequest(params);
    if (!request) {
      // Malformed permission payload: answer cancelled fail-closed (R8 S21, NFR1).
      this.options.log("protocol error: malformed session/request_permission; answering cancelled");
      this.sendResponse(id, { outcome: { outcome: "cancelled" } });
      return;
    }
    let chosen: string | undefined;
    try {
      chosen = await this.options.onPermission({
        sessionId: request.sessionId,
        toolCallId: request.toolCallId,
        title: request.title,
        kind: request.kind,
        rawInput: request.rawInput,
        workingDir: request.workingDir,
        tool: request.tool,
        elicitation: request.elicitation,
        options: request.options,
      });
    } catch (err) {
      this.options.log(
        `permission prompt failed: ${err instanceof Error ? err.message : String(err)}; answering cancelled`,
      );
      chosen = undefined;
    }
    this.sendResponse(id, buildPermissionResult(chosen, request.options));
  }

  private failAllPending(err: Error): void {
    for (const [id, pending] of this.pending) {
      this.pending.delete(id);
      clearTimeout(pending.timer);
      pending.reject(err);
    }
  }
}
