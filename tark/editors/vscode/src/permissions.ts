/**
 * Pure mapping for the backend's `session/request_permission` round-trip
 * (R8 S21, R2).
 *
 * The backend offers `allow_once` / `reject_once`, plus persistent
 * `allow_always:<pattern>` / `reject_always:<pattern>` options when the
 * request carries a suggested pattern. Elicitation (single single-select
 * question) reuses the same round-trip with `kind: "elicit_option"`.
 *
 * Wire shapes mirror `permission_request_params` /
 * `map_permission_response` in `src/transport/acp/server.rs`:
 * - request params: `{ sessionId, toolCall: { toolCallId, title, status,
 *   kind, rawInput }, options: [{ optionId, name, kind }], _meta: { tark:
 *   { requestId, tool?, workingDir?, elicitation? } } }`
 * - response result: `{ outcome: { outcome: "selected", optionId } }` or
 *   `{ outcome: { outcome: "cancelled" } }`.
 *
 * Anything unexpected (unknown option, dismissed prompt, malformed request)
 * resolves fail-closed to `cancelled`/deny. Pure module: no imports.
 */

export interface PermissionOption {
  optionId: string;
  name: string;
  kind: string;
  pattern?: string;
}

export interface PermissionRequest {
  sessionId: string;
  toolCallId: string;
  title: string;
  status: string;
  kind: string;
  rawInput: string;
  options: PermissionOption[];
  requestId?: string;
  tool?: string;
  workingDir?: string;
  elicitation: boolean;
}

export type PersistentDecision = "allow" | "reject";

export interface PersistentChoice {
  persistent: true;
  decision: PersistentDecision;
  pattern: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Parse raw `session/request_permission` params. Returns `null` when the
 * payload is malformed; callers must then answer `cancelled` fail-closed.
 */
export function parsePermissionRequest(params: unknown): PermissionRequest | null {
  if (!isRecord(params)) {
    return null;
  }
  const sessionId = params["sessionId"];
  const toolCall = params["toolCall"];
  const options = params["options"];
  if (typeof sessionId !== "string" || !isRecord(toolCall) || !Array.isArray(options)) {
    return null;
  }
  const { toolCallId, title, status, kind, rawInput } = toolCall;
  if (
    typeof toolCallId !== "string" ||
    typeof title !== "string" ||
    typeof status !== "string" ||
    typeof kind !== "string" ||
    typeof rawInput !== "string"
  ) {
    return null;
  }
  const parsedOptions: PermissionOption[] = [];
  for (const entry of options) {
    if (!isRecord(entry)) {
      return null;
    }
    const { optionId, name, kind: optionKind } = entry;
    if (typeof optionId !== "string" || typeof name !== "string" || typeof optionKind !== "string") {
      return null;
    }
    const option: PermissionOption = { optionId, name, kind: optionKind };
    const meta = entry["_meta"];
    if (isRecord(meta)) {
      const tark = meta["tark"];
      if (isRecord(tark) && typeof tark["pattern"] === "string") {
        option.pattern = tark["pattern"] as string;
      }
    }
    parsedOptions.push(option);
  }
  if (parsedOptions.length === 0) {
    return null;
  }
  let requestId: string | undefined;
  let tool: string | undefined;
  let workingDir: string | undefined;
  let elicitation = kind === "elicit";
  const meta = params["_meta"];
  if (isRecord(meta)) {
    const tark = meta["tark"];
    if (isRecord(tark)) {
      if (typeof tark["requestId"] === "string") {
        requestId = tark["requestId"] as string;
      }
      if (typeof tark["tool"] === "string") {
        tool = tark["tool"] as string;
      }
      if (typeof tark["workingDir"] === "string") {
        workingDir = tark["workingDir"] as string;
      }
      if (tark["elicitation"] === true) {
        elicitation = true;
      }
    }
  }
  return {
    sessionId,
    toolCallId,
    title,
    status,
    kind,
    rawInput,
    options: parsedOptions,
    requestId,
    tool,
    workingDir,
    elicitation,
  };
}

/** True when the option id was actually offered for this request. */
export function isOfferedOption(optionId: string, options: PermissionOption[]): boolean {
  return options.some((option) => option.optionId === optionId);
}

/**
 * Split a persistent `allow_always:<pattern>` / `reject_always:<pattern>`
 * option id. Returns `null` for one-shot options.
 */
export function parsePersistentChoice(optionId: string): PersistentChoice | null {
  const allowPrefix = "allow_always:";
  const rejectPrefix = "reject_always:";
  if (optionId.startsWith(allowPrefix) && optionId.length > allowPrefix.length) {
    return { persistent: true, decision: "allow", pattern: optionId.slice(allowPrefix.length) };
  }
  if (optionId.startsWith(rejectPrefix) && optionId.length > rejectPrefix.length) {
    return { persistent: true, decision: "reject", pattern: optionId.slice(rejectPrefix.length) };
  }
  return null;
}

/**
 * Build the exact `session/request_permission` response result for the
 * backend. `undefined` (dismissed prompt), empty, or unoffered option ids
 * all resolve fail-closed to `cancelled`, matching the backend's
 * deny-by-default mapping.
 */
export function buildPermissionResult(
  optionId: string | undefined,
  offered: PermissionOption[],
): Record<string, unknown> {
  if (
    typeof optionId === "string" &&
    optionId.length > 0 &&
    isOfferedOption(optionId, offered)
  ) {
    return { outcome: { outcome: "selected", optionId } };
  }
  return { outcome: { outcome: "cancelled" } };
}

/**
 * One-line summary for QuickPick detail rows: actor, operation, target,
 * scope, and persistence (R8 user-visible interaction requirements).
 */
export function describePermissionRequest(request: PermissionRequest): string {
  const actor = request.tool ?? "agent";
  const scope = request.workingDir ? ` (in ${request.workingDir})` : "";
  const persistence = request.options.some((option) => parsePersistentChoice(option.optionId) !== null)
    ? "; persistent allow/reject options available"
    : "; one-time decision only";
  return `${actor}: ${request.rawInput}${scope}${persistence}`;
}
