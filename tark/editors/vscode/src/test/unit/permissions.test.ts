/**
 * Unit tests for `session/request_permission` mapping (`src/permissions.ts`
 * plus wire-shape helpers in `src/acpTypes.ts`).
 * Runnable WITHOUT the `vscode` module: `node --test dist/test/unit/`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parsePermissionRequest,
  isOfferedOption,
  parsePersistentChoice,
  buildPermissionResult,
  describePermissionRequest,
  PermissionOption,
} from "../../permissions";
import { findCapabilityMismatches, InitializeResult } from "../../acpTypes";

const OFFERED: PermissionOption[] = [
  { optionId: "allow_once", name: "Allow once", kind: "allow_once" },
  { optionId: "reject_once", name: "Reject once", kind: "reject_once" },
];

function validParams(): unknown {
  return {
    sessionId: "acp-1",
    toolCall: {
      toolCallId: "toolcall-1",
      title: "shell_exec ls -la (in /tmp/work)",
      status: "pending",
      kind: "execute",
      rawInput: "ls -la",
    },
    options: OFFERED,
    _meta: { tark: { requestId: "req-7", tool: "shell_exec", workingDir: "/tmp/work" } },
  };
}

describe("parsePermissionRequest", () => {
  it("parses a full approval request including _meta", () => {
    const req = parsePermissionRequest(validParams());
    assert.ok(req);
    assert.equal(req.sessionId, "acp-1");
    assert.equal(req.toolCallId, "toolcall-1");
    assert.equal(req.tool, "shell_exec");
    assert.equal(req.workingDir, "/tmp/work");
    assert.equal(req.requestId, "req-7");
    assert.equal(req.elicitation, false);
    assert.equal(req.options.length, 2);
  });

  it("parses a minimal request without _meta", () => {
    const params = validParams() as Record<string, unknown>;
    delete params["_meta"];
    const req = parsePermissionRequest(params);
    assert.ok(req);
    assert.equal(req.tool, undefined);
    assert.equal(req.workingDir, undefined);
  });

  it("detects elicitation via kind", () => {
    const params = validParams() as Record<string, unknown>;
    (params["toolCall"] as Record<string, unknown>)["kind"] = "elicit";
    const req = parsePermissionRequest(params);
    assert.ok(req);
    assert.equal(req.elicitation, true);
  });

  it("returns null for malformed payloads (fail-closed)", () => {
    assert.equal(parsePermissionRequest(null), null);
    assert.equal(parsePermissionRequest("nope"), null);
    assert.equal(parsePermissionRequest({}), null);
    assert.equal(parsePermissionRequest({ sessionId: "x", toolCall: {}, options: [] }), null);
    assert.equal(
      parsePermissionRequest({
        sessionId: "x",
        toolCall: { toolCallId: "t", title: "t", status: "s", kind: "k", rawInput: "r" },
        options: [{ optionId: "o" }],
      }),
      null,
    );
  });
});

describe("buildPermissionResult", () => {
  it("maps allow_once to the exact backend wire shape", () => {
    assert.deepEqual(buildPermissionResult("allow_once", OFFERED), {
      outcome: { outcome: "selected", optionId: "allow_once" },
    });
  });

  it("maps reject_once to selected/reject_once", () => {
    assert.deepEqual(buildPermissionResult("reject_once", OFFERED), {
      outcome: { outcome: "selected", optionId: "reject_once" },
    });
  });

  it("passes through persistent options only when offered", () => {
    const offered: PermissionOption[] = [
      ...OFFERED,
      { optionId: "allow_always:ls *", name: "Always allow ls *", kind: "allow_always" },
    ];
    assert.deepEqual(buildPermissionResult("allow_always:ls *", offered), {
      outcome: { outcome: "selected", optionId: "allow_always:ls *" },
    });
  });

  it("cancels fail-closed on dismissed, empty, or unoffered ids", () => {
    const cancelled = { outcome: { outcome: "cancelled" } };
    assert.deepEqual(buildPermissionResult(undefined, OFFERED), cancelled);
    assert.deepEqual(buildPermissionResult("", OFFERED), cancelled);
    assert.deepEqual(buildPermissionResult("allow_always:rm -rf /", OFFERED), cancelled);
    assert.deepEqual(buildPermissionResult("approve", OFFERED), cancelled);
  });
});

describe("persistent choices", () => {
  it("parses allow_always/reject_always patterns", () => {
    assert.deepEqual(parsePersistentChoice("allow_always:ls *"), {
      persistent: true,
      decision: "allow",
      pattern: "ls *",
    });
    assert.deepEqual(parsePersistentChoice("reject_always:rm *"), {
      persistent: true,
      decision: "reject",
      pattern: "rm *",
    });
  });

  it("returns null for one-shot options and bare prefixes", () => {
    assert.equal(parsePersistentChoice("allow_once"), null);
    assert.equal(parsePersistentChoice("allow_always:"), null);
    assert.equal(isOfferedOption("allow_once", OFFERED), true);
    assert.equal(isOfferedOption("bogus", OFFERED), false);
  });
});

describe("describePermissionRequest", () => {
  it("identifies actor, operation, scope, and persistence", () => {
    const req = parsePermissionRequest(validParams());
    assert.ok(req);
    const text = describePermissionRequest(req);
    assert.ok(text.includes("shell_exec"));
    assert.ok(text.includes("ls -la"));
    assert.ok(text.includes("/tmp/work"));
  });
});

describe("backend capability contract", () => {
  function exactBackendResult(): InitializeResult {
    return {
      protocolVersion: 1,
      agentInfo: { name: "tark", version: "0.12.6" },
      agentCapabilities: {
        loadSession: false,
        promptCapabilities: { image: false, audio: false, embeddedContext: true },
        mcpCapabilities: { http: false, sse: false },
        sessionCapabilities: {},
      },
      authMethods: [],
      _meta: { tark: { completion: { method: "_tark/inlineCompletion", version: 1 } } },
    };
  }

  it("accepts the exact backend contract with zero mismatches", () => {
    assert.deepEqual(findCapabilityMismatches(exactBackendResult()), []);
  });

  it("flags protocol version drift as fatal", () => {
    const result = exactBackendResult();
    result.protocolVersion = 2;
    assert.ok(findCapabilityMismatches(result).length > 0);
  });

  it("flags capability drift (image, mcp http, loadSession)", () => {
    const image = exactBackendResult();
    image.agentCapabilities.promptCapabilities.image = true;
    assert.ok(findCapabilityMismatches(image).length > 0);

    const mcp = exactBackendResult();
    mcp.agentCapabilities.mcpCapabilities.http = true;
    assert.ok(findCapabilityMismatches(mcp).length > 0);

    const load = exactBackendResult();
    load.agentCapabilities.loadSession = true;
    assert.ok(findCapabilityMismatches(load).length > 0);
  });

  it("flags completion extension drift", () => {
    const result = exactBackendResult();
    result._meta = undefined;
    assert.ok(findCapabilityMismatches(result).length > 0);
  });

  it("handles a missing result fail-closed", () => {
    assert.ok(findCapabilityMismatches(null).length > 0);
    assert.ok(findCapabilityMismatches(undefined).length > 0);
  });
});
