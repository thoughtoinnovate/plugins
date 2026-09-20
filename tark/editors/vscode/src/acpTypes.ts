/**
 * Editor-neutral ACP v1 contract constants and types for the Tark backend.
 *
 * These values mirror `src/transport/acp/protocol.rs` and the initialize
 * handler in `src/transport/acp/server.rs` exactly. The extension must use
 * only these methods/capabilities (R8, R11, S27):
 *
 * - Client -> server: `initialize`, `session/new`, `session/prompt`,
 *   `session/cancel`, `session/close`, `session/set_mode`,
 *   `session/set_config_option` (only `mode` is effective),
 *   `context/update`, and the optional `_tark/inlineCompletion` extension.
 * - Server -> client: `session/request_permission` (approvals and
 *   single-select elicitation), `session/update` notifications.
 * - Framing is newline-delimited JSON only; `Content-Length` framing and
 *   `session/load` are NOT supported by the backend.
 *
 * This module is intentionally free of `vscode` and `node` imports so it can
 * be unit-tested with plain `node:test`.
 */

/** ACP protocol version implemented by the backend (`ACP_PROTOCOL_VERSION`). */
export const ACP_PROTOCOL_VERSION = 1;

/** Name of the optional inline-completion extension method (R8 S22). */
export const COMPLETION_EXTENSION_METHOD = "_tark/inlineCompletion";

/** Version of the completion extension contract advertised in `_meta`. */
export const COMPLETION_EXTENSION_VERSION = 1;

/** Client name advertised in `initialize` -> `clientInfo`. */
export const CLIENT_NAME = "tark-vscode";

/** Backend agent name expected in `initialize` -> `agentInfo`. */
export const AGENT_NAME = "tark";

/** Backend subcommand used to spawn the ACP stdio server. */
export const ACP_SUBCOMMAND = "acp";

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: number | string;
  method: string;
  params: Record<string, unknown>;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params: Record<string, unknown>;
}

export interface InitializeResult {
  protocolVersion: number;
  agentInfo: { name: string; version: string };
  agentCapabilities: AgentCapabilities;
  authMethods: unknown[];
  _meta?: {
    tark?: {
      completion?: { method: string; version: number };
    };
  };
}

export interface AgentCapabilities {
  loadSession: boolean;
  promptCapabilities: {
    image: boolean;
    audio: boolean;
    embeddedContext: boolean;
  };
  mcpCapabilities: {
    http: boolean;
    sse: boolean;
  };
  sessionCapabilities: Record<string, unknown>;
}

export type SessionUpdateKind =
  | "agent_message_start"
  | "agent_message_chunk"
  | "agent_message_end"
  | "tool_call"
  | "tool_call_update";

export interface SessionUpdateNotification {
  sessionId: string;
  update: {
    sessionUpdate: SessionUpdateKind;
    responseId?: string;
    content?: { type: string; text?: string };
    stopReason?: string;
    toolCallId?: string;
    title?: string;
    status?: string;
    kind?: string;
    rawInput?: string;
    rawOutput?: string;
  };
  _meta?: {
    tark?: {
      requestId?: string;
      usage?: unknown;
      toolCallsMade?: number;
      contextUsagePercent?: number;
      errorCode?: string;
      errorMessage?: string;
    };
  };
}

/**
 * Compare an `initialize` result against the exact contract the backend
 * implements. Returns one human-readable mismatch per violated expectation;
 * an empty array means the backend matches the known contract.
 *
 * A `protocolVersion` mismatch is fatal (incompatible backend); capability
 * drift is a warning with a remediation hint (R12, K5).
 */
export function findCapabilityMismatches(
  result: InitializeResult | null | undefined,
): string[] {
  const mismatches: string[] = [];
  if (!result || typeof result !== "object") {
    return ["initialize returned no result; cannot verify backend capabilities"];
  }
  if (result.protocolVersion !== ACP_PROTOCOL_VERSION) {
    mismatches.push(
      `protocolVersion ${String(result.protocolVersion)} is not supported ` +
        `(this extension requires ${ACP_PROTOCOL_VERSION}); install a matching tark release`,
    );
    return mismatches;
  }
  if (result.agentInfo?.name !== AGENT_NAME) {
    mismatches.push(
      `agentInfo.name is '${result.agentInfo?.name ?? "missing"}', expected '${AGENT_NAME}'`,
    );
  }
  const caps = result.agentCapabilities;
  if (!caps || typeof caps !== "object") {
    return [...mismatches, "initialize result is missing agentCapabilities"];
  }
  if (caps.loadSession !== false) {
    mismatches.push(
      "agentCapabilities.loadSession should be false (session/load is not implemented); " +
        "this extension will not call session/load",
    );
  }
  const prompt = caps.promptCapabilities;
  if (!prompt || prompt.image !== false || prompt.audio !== false || prompt.embeddedContext !== true) {
    mismatches.push(
      "agentCapabilities.promptCapabilities drifted from {image:false, audio:false, embeddedContext:true}; " +
        "text prompts with embedded context remain supported",
    );
  }
  const mcp = caps.mcpCapabilities;
  if (!mcp || mcp.http !== false || mcp.sse !== false) {
    mismatches.push(
      "agentCapabilities.mcpCapabilities drifted from {http:false, sse:false}; " +
        "this extension will not send mcpServers entries",
    );
  }
  const completion = result._meta?.tark?.completion;
  if (
    !completion ||
    completion.method !== COMPLETION_EXTENSION_METHOD ||
    completion.version !== COMPLETION_EXTENSION_VERSION
  ) {
    mismatches.push(
      `completion extension contract drifted from ${COMPLETION_EXTENSION_METHOD} v${COMPLETION_EXTENSION_VERSION}; ` +
        "inline completion will be disabled until the backend is updated",
    );
  }
  return mismatches;
}

/** Build the `initialize` params. The `_meta` opt-in enables `_tark/inlineCompletion` (R8 S22). */
export function buildInitializeParams(extensionVersion: string): Record<string, unknown> {
  return {
    protocolVersion: ACP_PROTOCOL_VERSION,
    clientCapabilities: {},
    clientInfo: { name: CLIENT_NAME, version: extensionVersion },
    _meta: { tark: { completion: { supported: true } } },
  };
}

/** Build `session/new` params. `mcpServers` must stay empty (backend rejects entries, R8). */
export function buildSessionNewParams(cwd: string): Record<string, unknown> {
  return { cwd, mcpServers: [] };
}

/** Build `session/prompt` params for a plain-text prompt. */
export function buildPromptParams(sessionId: string, text: string): Record<string, unknown> {
  return { sessionId, prompt: [{ type: "text", text }] };
}

/** Build `_tark/inlineCompletion` params. */
export function buildInlineCompletionParams(args: {
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
}): Record<string, unknown> {
  const params: Record<string, unknown> = {
    sessionId: args.sessionId,
    path: args.path,
    cursor: { line: args.line, col: args.col },
    prefix: args.prefix,
    suffix: args.suffix,
  };
  if (args.maxTokens !== undefined) {
    params["maxTokens"] = args.maxTokens;
  }
  if (args.language !== undefined) {
    params["language"] = args.language;
  }
  if (args.triggerKind !== undefined) {
    params["triggerKind"] = args.triggerKind;
  }
  if (args.clientRequestId !== undefined) {
    params["clientRequestId"] = args.clientRequestId;
  }
  if (args.bufferVersion !== undefined) {
    params["bufferVersion"] = args.bufferVersion;
  }
  return params;
}
