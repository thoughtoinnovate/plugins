/**
 * Unit tests for version parsing and compatibility (`src/version.ts`) and
 * secret redaction (`src/redact.ts`).
 * Runnable WITHOUT the `vscode` module: `node --test dist/test/unit/`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseSemver,
  compareSemver,
  isBackendCompatible,
  incompatibilityMessage,
} from "../../version";
import { redactSecrets } from "../../redact";

describe("parseSemver", () => {
  it("parses plain triples", () => {
    assert.deepEqual(parseSemver("0.12.6"), { major: 0, minor: 12, patch: 6 });
  });

  it("parses 'tark --version' style output", () => {
    assert.deepEqual(parseSemver("tark 0.12.6"), { major: 0, minor: 12, patch: 6 });
    assert.deepEqual(parseSemver("tark-cli 0.12.6 (build abc123)"), {
      major: 0,
      minor: 12,
      patch: 6,
    });
  });

  it("parses a leading v", () => {
    assert.deepEqual(parseSemver("v1.2.3"), { major: 1, minor: 2, patch: 3 });
  });

  it("returns null when no triple is present", () => {
    assert.equal(parseSemver(""), null);
    assert.equal(parseSemver("nightly"), null);
    assert.equal(parseSemver("1.2"), null);
  });
});

describe("compareSemver", () => {
  it("orders by major, then minor, then patch", () => {
    const base = { major: 0, minor: 12, patch: 6 };
    assert.equal(compareSemver(base, { ...base }), 0);
    assert.equal(compareSemver(base, { major: 0, minor: 12, patch: 7 }), -1);
    assert.equal(compareSemver(base, { major: 0, minor: 11, patch: 9 }), 1);
    assert.equal(compareSemver(base, { major: 1, minor: 0, patch: 0 }), -1);
  });
});

describe("isBackendCompatible", () => {
  it("accepts equal versions and patch-only drift", () => {
    assert.equal(
      isBackendCompatible({ major: 0, minor: 12, patch: 6 }, { major: 0, minor: 12, patch: 6 }),
      true,
    );
    assert.equal(
      isBackendCompatible({ major: 0, minor: 12, patch: 4 }, { major: 0, minor: 12, patch: 6 }),
      true,
    );
  });

  it("rejects minor and major drift", () => {
    assert.equal(
      isBackendCompatible({ major: 0, minor: 11, patch: 6 }, { major: 0, minor: 12, patch: 6 }),
      false,
    );
    assert.equal(
      isBackendCompatible({ major: 1, minor: 12, patch: 6 }, { major: 0, minor: 12, patch: 6 }),
      false,
    );
  });

  it("produces a remediation message naming both sides", () => {
    const message = incompatibilityMessage("0.11.0", "0.12.6");
    assert.ok(message.includes("0.11.0"));
    assert.ok(message.includes("0.12.6"));
    assert.ok(message.includes("tark.binaryPath"));
  });
});

describe("redactSecrets", () => {
  it("redacts bearer tokens but keeps the scheme", () => {
    const out = redactSecrets("call failed: Authorization: Bearer abcdefgh123456");
    assert.ok(!out.includes("abcdefgh123456"));
    assert.ok(out.includes("Bearer"));
  });

  it("redacts api_key assignments", () => {
    const out = redactSecrets('config error for "api_key": "sk-live-value-123"');
    assert.ok(!out.includes("sk-live-value-123"));
  });

  it("redacts credentials embedded in URLs", () => {
    const out = redactSecrets("fetch https://user:s3cret-host@proxy.local/v1 failed");
    assert.ok(!out.includes("s3cret-host"));
    assert.ok(out.includes("proxy.local"));
  });

  it("redacts sk- and ghp_-style tokens", () => {
    assert.ok(!redactSecrets("key sk-abcdefghijklmnop broke").includes("abcdefghijklmnop"));
    assert.ok(!redactSecrets("token ghp_abcdefghijklmnop broke").includes("abcdefghijklmnop"));
  });

  it("leaves ordinary diagnostics untouched", () => {
    const text = "session/acp-1 prompt accepted: requestId req-9 in /tmp/work";
    assert.equal(redactSecrets(text), text);
  });
});
