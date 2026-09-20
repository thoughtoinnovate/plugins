/**
 * Version parsing and backend/extension compatibility (R12, K5).
 *
 * The backend reports its version via `initialize` -> `agentInfo.version`
 * (Cargo package version) and via `tark --version`. The extension requires
 * the same major AND minor version; patch releases may differ. Anything
 * else is an incompatibility with a direct remediation path, never a silent
 * reinterpretation.
 *
 * Pure module: no imports.
 */

export interface Semver {
  major: number;
  minor: number;
  patch: number;
}

/**
 * Extract `major.minor.patch` from strings like `0.12.6`, `v0.12.6`,
 * `tark 0.12.6`, or `tark-cli 0.12.6 (build abc)`. Returns `null` when no
 * triple is present.
 */
export function parseSemver(text: string): Semver | null {
  if (typeof text !== "string") {
    return null;
  }
  const match = text.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return null;
  }
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

/** Compare two versions: -1 when `a < b`, 0 when equal, 1 when `a > b`. */
export function compareSemver(a: Semver, b: Semver): -1 | 0 | 1 {
  if (a.major !== b.major) {
    return a.major < b.major ? -1 : 1;
  }
  if (a.minor !== b.minor) {
    return a.minor < b.minor ? -1 : 1;
  }
  if (a.patch !== b.patch) {
    return a.patch < b.patch ? -1 : 1;
  }
  return 0;
}

/** True when backend and extension share major AND minor versions. */
export function isBackendCompatible(backend: Semver, extension: Semver): boolean {
  return backend.major === extension.major && backend.minor === extension.minor;
}

/**
 * Human-readable incompatibility message with the next safe action (R12):
 * install the matching release or point `tark.binaryPath` at it.
 */
export function incompatibilityMessage(
  backendRaw: string,
  extensionVersion: string,
): string {
  return (
    `Incompatible tark backend '${backendRaw}' (extension ${extensionVersion}): ` +
    "major.minor versions must match. Install the matching tark release or " +
    "set 'tark.binaryPath' to a compatible binary, then run 'Tark: Start Agent' again."
  );
}
