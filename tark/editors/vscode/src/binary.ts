/**
 * Backend binary resolution and version-compatibility checking (R10/R11,
 * R12, K5), shared by `extension.ts`.
 *
 * Resolution order: explicit `tark.binaryPath` config -> `PATH` lookup for
 * `tark` -> `BinaryNotFoundError` carrying remediation actions. A resolved
 * binary is version-checked (`tark --version`): major.minor must match the
 * extension version, otherwise use is refused with a direct remediation
 * path instead of a silent behavior drift.
 *
 * No `vscode` imports: errors expose machine-readable `remediation` hints
 * that the extension renders as actions.
 */
import { execFile } from "node:child_process";
import { access, constants } from "node:fs/promises";
import { delimiter } from "node:path";
import { parseSemver, isBackendCompatible, incompatibilityMessage, Semver } from "./version";

export const BINARY_NAME = "tark";

export type BinarySource = "config" | "path";

export interface ResolvedBinary {
  path: string;
  source: BinarySource;
}

export interface BinaryCompat {
  binary: ResolvedBinary;
  backendVersion: Semver;
  backendRaw: string;
  compatible: boolean;
  message: string;
}

/** Remediation hint rendered by the extension as a button or help text. */
export interface Remediation {
  /** Stable id: `open-settings` | `show-output` | `retry` | `open-downloads`. */
  id: string;
  label: string;
  detail: string;
}

export class BinaryNotFoundError extends Error {
  public readonly remediations: Remediation[];

  public constructor(searched: string[], configured?: string) {
    super(
      configured && configured.length > 0
        ? `Configured tark binary '${configured}' is not executable.`
        : `No 'tark' binary found on PATH (searched ${searched.length} directories).`,
    );
    this.name = "BinaryNotFoundError";
    this.remediations = [
      {
        id: "open-settings",
        label: "Open Settings",
        detail: "Set 'tark.binaryPath' to the absolute path of a compatible tark binary.",
      },
      {
        id: "open-downloads",
        label: "Install tark",
        detail: "Install a tark release whose major.minor version matches this extension, then retry.",
      },
      {
        id: "show-output",
        label: "Show Output",
        detail: "Open the Tark output channel for diagnostics.",
      },
    ];
  }
}

export class BinaryIncompatibleError extends Error {
  public readonly remediations: Remediation[];

  public constructor(message: string) {
    super(message);
    this.name = "BinaryIncompatibleError";
    this.remediations = [
      {
        id: "open-downloads",
        label: "Install Matching Release",
        detail: "Install the tark release whose major.minor version matches this extension.",
      },
      {
        id: "open-settings",
        label: "Open Settings",
        detail: "Point 'tark.binaryPath' at a compatible tark binary.",
      },
      {
        id: "show-output",
        label: "Show Output",
        detail: "Open the Tark output channel for diagnostics.",
      },
    ];
  }
}

async function isExecutable(filePath: string): Promise<boolean> {
  try {
    if (process.platform === "win32") {
      await access(filePath, constants.F_OK);
      return true;
    }
    await access(filePath, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** Search `PATH` for an executable named `tark` (plus PATHEXT on Windows). */
export async function findOnPath(): Promise<string | null> {
  const pathValue = process.env["PATH"] ?? "";
  const directories = pathValue.split(delimiter).filter((dir) => dir.length > 0);
  const candidates: string[] = [];
  const extensions =
    process.platform === "win32"
      ? (process.env["PATHEXT"] ?? ".EXE;.CMD;.BAT").split(";")
      : [""];
  for (const dir of directories) {
    for (const ext of extensions) {
      candidates.push(`${dir}/${BINARY_NAME}${ext}`);
    }
  }
  for (const candidate of candidates) {
    if (await isExecutable(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * Resolve the backend binary: explicit config first, then `PATH`.
 * Throws `BinaryNotFoundError` with remediation hints when nothing usable
 * is found.
 */
export async function resolveBinaryPath(configuredPath?: string): Promise<ResolvedBinary> {
  const configured = (configuredPath ?? "").trim();
  if (configured.length > 0) {
    if (await isExecutable(configured)) {
      return { path: configured, source: "config" };
    }
    throw new BinaryNotFoundError([], configured);
  }
  const found = await findOnPath();
  if (found) {
    return { path: found, source: "path" };
  }
  const pathValue = process.env["PATH"] ?? "";
  throw new BinaryNotFoundError(pathValue.split(delimiter));
}

/** Run `tark --version` and parse the reported version. */
export function getBinaryVersion(binaryPath: string): Promise<{ raw: string; version: Semver }> {
  return new Promise((resolve, reject) => {
    execFile(binaryPath, ["--version"], { timeout: 15_000 }, (error, stdout, stderr) => {
      if (error) {
        reject(
          new Error(
            `Could not run '${binaryPath} --version': ${error.message}${stderr ? ` (${stderr.trim().slice(0, 300)})` : ""}. ` +
              "Install a working tark binary or fix 'tark.binaryPath', then retry.",
          ),
        );
        return;
      }
      const raw = `${stdout} ${stderr}`.trim();
      const version = parseSemver(raw);
      if (!version) {
        reject(
          new Error(
            `Could not parse a version from '${binaryPath} --version' output '${raw.slice(0, 120)}'. ` +
              "Install a released tark binary or fix 'tark.binaryPath', then retry.",
          ),
        );
        return;
      }
      resolve({ raw, version });
    });
  });
}

/**
 * Resolve the binary and verify major.minor compatibility with the
 * extension. Throws `BinaryNotFoundError` / `BinaryIncompatibleError`.
 */
export async function checkBinaryCompat(
  configuredPath: string | undefined,
  extensionVersion: string,
): Promise<BinaryCompat> {
  const binary = await resolveBinaryPath(configuredPath);
  const { raw, version: backendVersion } = await getBinaryVersion(binary.path);
  const extension = parseSemver(extensionVersion);
  if (!extension) {
    throw new Error(`Extension version '${extensionVersion}' is not a valid semver triple.`);
  }
  const compatible = isBackendCompatible(backendVersion, extension);
  if (!compatible) {
    throw new BinaryIncompatibleError(incompatibilityMessage(raw.trim(), extensionVersion));
  }
  return {
    binary,
    backendVersion,
    backendRaw: raw.trim(),
    compatible: true,
    message: `tark backend ${backendVersion.major}.${backendVersion.minor}.${backendVersion.patch} ` +
      `(from ${binary.source === "config" ? "tark.binaryPath" : "PATH"}) is compatible.`,
  };
}
