/**
 * Newline-delimited JSON (NDJSON) framing for ACP v1 over stdio (R8 S20).
 *
 * Every message is one JSON value followed by `\n`. `Content-Length`
 * framing is intentionally NOT supported: such input fails JSON parsing and
 * is surfaced as a protocol error, never silently reinterpreted.
 *
 * Pure module: no `vscode`/`node` imports, unit-testable with `node:test`.
 */

/** Backend cap on a single stdio frame (`MAX_FRAME_BYTES` in server.rs). */
export const MAX_FRAME_BYTES = 1024 * 1024;

/** Serialize a value as one NDJSON frame (payload bytes plus `\n`). */
export function encodeFrame(value: unknown): string {
  const payload = JSON.stringify(value);
  if (payload === undefined) {
    throw new Error("Refusing to encode undefined as an NDJSON frame");
  }
  if (payload.includes("\n")) {
    throw new Error("Refusing to emit multi-line NDJSON frame");
  }
  if (payload.length === 0) {
    throw new Error("Refusing to emit empty NDJSON frame");
  }
  return payload + "\n";
}

/**
 * Incremental NDJSON decoder. Feed arbitrary string chunks via `push`;
 * complete non-empty lines are returned as parsed JSON values. Blank lines
 * are skipped (tolerated keep-alives) and a trailing `\r` is stripped, so
 * CRLF writers interoperate. A single line longer than `maxFrameBytes`
 * throws fail-closed.
 */
export class NdjsonDecoder {
  private buffer = "";
  private readonly maxFrameBytes: number;

  public constructor(maxFrameBytes: number = MAX_FRAME_BYTES) {
    this.maxFrameBytes = maxFrameBytes;
  }

  public push(chunk: string): unknown[] {
    this.buffer += chunk;
    const out: unknown[] = [];
    let newlineIndex = this.buffer.indexOf("\n");
    while (newlineIndex >= 0) {
      let line = this.buffer.slice(0, newlineIndex);
      this.buffer = this.buffer.slice(newlineIndex + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      if (line.length > this.maxFrameBytes) {
        throw new Error(
          `Frame too large: ${line.length} > ${this.maxFrameBytes}`,
        );
      }
      if (line.length > 0) {
        out.push(JSON.parse(line));
      }
      newlineIndex = this.buffer.indexOf("\n");
    }
    if (this.buffer.length > this.maxFrameBytes + 1) {
      throw new Error(
        `Frame too large: buffered ${this.buffer.length} > ${this.maxFrameBytes}`,
      );
    }
    return out;
  }
}
