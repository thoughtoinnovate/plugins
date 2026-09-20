/**
 * Unit tests for NDJSON framing (`src/framing.ts`).
 * Runnable WITHOUT the `vscode` module: `node --test dist/test/unit/`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { NdjsonDecoder, encodeFrame, MAX_FRAME_BYTES } from "../../framing";

describe("encodeFrame", () => {
  it("emits a single newline-terminated line", () => {
    const frame = encodeFrame({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.ok(frame.endsWith("\n"));
    assert.equal(frame.slice(0, -1).includes("\n"), false);
    assert.deepEqual(JSON.parse(frame), {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    });
  });

  it("never emits Content-Length framing", () => {
    const frame = encodeFrame({ method: "session/prompt" });
    assert.ok(!/^content-length:/im.test(frame));
  });

  it("refuses undefined payloads", () => {
    assert.throws(() => encodeFrame(undefined), /undefined/);
  });
});

describe("NdjsonDecoder", () => {
  it("decodes one frame per line", () => {
    const decoder = new NdjsonDecoder();
    const out = decoder.push('{"a":1}\n{"b":2}\n');
    assert.deepEqual(out, [{ a: 1 }, { b: 2 }]);
  });

  it("reassembles frames split across chunks", () => {
    const decoder = new NdjsonDecoder();
    assert.deepEqual(decoder.push('{"a":'), []);
    assert.deepEqual(decoder.push('1}\n{"b"'), [{ a: 1 }]);
    assert.deepEqual(decoder.push(':2}\n'), [{ b: 2 }]);
  });

  it("skips blank lines (tolerated keep-alives)", () => {
    const decoder = new NdjsonDecoder();
    assert.deepEqual(decoder.push('\n\n{"a":1}\n\n'), [{ a: 1 }]);
  });

  it("tolerates CRLF line endings", () => {
    const decoder = new NdjsonDecoder();
    assert.deepEqual(decoder.push('{"a":1}\r\n'), [{ a: 1 }]);
  });

  it("rejects oversized frames fail-closed", () => {
    const decoder = new NdjsonDecoder(16);
    assert.throws(() => decoder.push(`{"a":"${"x".repeat(64)}"}\n`), /Frame too large/);
  });

  it("rejects unbounded buffered input fail-closed", () => {
    const decoder = new NdjsonDecoder(8);
    assert.throws(() => decoder.push("x".repeat(64)), /Frame too large/);
  });

  it("surfaces invalid JSON as a parse error, not silent data", () => {
    const decoder = new NdjsonDecoder();
    assert.throws(() => decoder.push("Content-Length: 12\n"), SyntaxError);
  });
});

describe("frame size cap", () => {
  it("matches the backend 1 MiB cap", () => {
    assert.equal(MAX_FRAME_BYTES, 1024 * 1024);
  });
});
