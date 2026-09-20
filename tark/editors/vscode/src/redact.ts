/**
 * Secret redaction for logs, traces, and UI history (R3 S6).
 *
 * Provider credentials, bearer tokens, and command environments must never
 * appear in the output channel or error messages. When in doubt this module
 * over-redacts; enough non-secret context (key names, hosts) is preserved
 * to diagnose failures.
 *
 * Pure module: no imports.
 */

const PATTERNS: Array<{ re: RegExp; replacement: string }> = [
  // Authorization: Bearer <token> / Basic <blob> / Token <token>
  {
    re: /\b(Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/=]{8,}/gi,
    replacement: "$1 [REDACTED]",
  },
  // api_key / apikey / api-key assignments (JSON, TOML, env, CLI flags)
  {
    re: /((?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)\s*["'\s:=]+)(["']?)[A-Za-z0-9\-._~+/=]{8,}\2/gi,
    replacement: "$1[REDACTED]",
  },
  // OpenAI-style and GitHub-style tokens
  {
    re: /\bsk-[A-Za-z0-9\-_]{8,}/g,
    replacement: "sk-[REDACTED]",
  },
  {
    re: /\bgh[pousr]_[A-Za-z0-9_]{8,}/g,
    replacement: "gh_[REDACTED]",
  },
  // user:password embedded in URLs
  {
    re: /(\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/\s:]+:)([^@/\s]{1,200})(@)/g,
    replacement: "$1[REDACTED]$3",
  },
];

/** Redact credential values from arbitrary text destined for logs or UI. */
export function redactSecrets(text: string): string {
  if (typeof text !== "string" || text.length === 0) {
    return text;
  }
  let out = text;
  for (const { re, replacement } of PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, replacement);
  }
  return out;
}
