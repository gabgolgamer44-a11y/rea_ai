import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { findWindowsExecutable } from "../process/WindowsExecutable.js";
import type { ProviderIdentity } from "../application/AnalysisProvider.js";

/** Provider identity for Radare2. */
export const RADARE2_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "radare2",
  name: "radare2",
  version: null,
});

/** Environment variable for explicit radare2 binary path. */
export const REA_RADARE2_COMMAND = "REA_RADARE2_COMMAND";
/** Secondary alias for radare2 command. */
export const REA_R2_COMMAND = "REA_R2_COMMAND";
/** Environment variable for explicit rabin2 binary path. */
export const REA_RABIN2_COMMAND = "REA_RABIN2_COMMAND";
/** Environment variable for radare2 execution timeout in milliseconds. */
export const REA_RADARE2_TIMEOUT_MS = "REA_RADARE2_TIMEOUT_MS";
/** Secondary alias for radare2 timeout. */
export const REA_R2_TIMEOUT_MS = "REA_R2_TIMEOUT_MS";
/** Environment variable for maximum stdout/stderr buffer size in bytes. */
export const REA_RADARE2_MAX_BUFFER_BYTES = "REA_RADARE2_MAX_BUFFER_BYTES";

/** Default execution timeout in milliseconds (30 seconds). */
export const DEFAULT_RADARE2_TIMEOUT_MS = 30_000;
/** Default maximum buffer allowance in bytes (32 MiB). */
export const DEFAULT_RADARE2_MAX_BUFFER_BYTES = 32 * 1024 * 1024;

/** Remediation instructions for missing or misconfigured radare2 installation. */
export const RADARE2_REMEDIATION =
  "Install radare2 and verify 'r2' and 'rabin2' are on PATH, or set REA_RADARE2_COMMAND and REA_RABIN2_COMMAND environment variables. Restart REA after changes.";

/** Resolved configuration for radare2 tools and limits. */
export interface Radare2Configuration {
  readonly r2Command: string;
  readonly rabin2Command: string;
  readonly r2CommandSource: "environment" | "path" | "custom";
  readonly rabin2CommandSource: "environment" | "path" | "custom";
  readonly timeoutMs: number;
  readonly maxBufferBytes: number;
  readonly hasDecompilerPlugin?: boolean | undefined;
}

/** Caller-selected overrides for radare2 configuration. */
export interface Radare2ConfigurationOptions {
  readonly r2Command?: string | undefined;
  readonly rabin2Command?: string | undefined;
  readonly timeoutMs?: number | undefined;
  readonly maxBufferBytes?: number | undefined;
  readonly hasDecompilerPlugin?: boolean | undefined;
}

const parsePositiveInteger = (
  value: string | undefined,
  defaultValue: number,
): number => {
  if (value === undefined) return defaultValue;
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : defaultValue;
};

/**
 * Resolve radare2 configuration using caller overrides, environment variables,
 * or host PATH resolution.
 */
export const resolveRadare2Configuration = async (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  platform: NodeJS.Platform = process.platform,
  signal?: AbortSignal,
  options?: Radare2ConfigurationOptions,
): Promise<Radare2Configuration> => {
  const env = snapshotEnvironment(environment, platform);

  const timeoutMs =
    options?.timeoutMs ??
    parsePositiveInteger(
      env[REA_RADARE2_TIMEOUT_MS] ?? env[REA_R2_TIMEOUT_MS],
      DEFAULT_RADARE2_TIMEOUT_MS,
    );

  const maxBufferBytes =
    options?.maxBufferBytes ??
    parsePositiveInteger(
      env[REA_RADARE2_MAX_BUFFER_BYTES],
      DEFAULT_RADARE2_MAX_BUFFER_BYTES,
    );

  // 1. Resolve r2 command
  let r2Command = options?.r2Command;
  let r2CommandSource: "environment" | "path" | "custom" = "custom";

  if (r2Command === undefined) {
    const envR2 = env[REA_RADARE2_COMMAND] ?? env[REA_R2_COMMAND];
    if (envR2 !== undefined && envR2.trim() !== "") {
      r2Command = envR2.trim();
      r2CommandSource = "environment";
    } else if (platform === "win32") {
      const abortSignal = signal ?? new AbortController().signal;
      const found = await findWindowsExecutable("r2", env, {
        signal: abortSignal,
      });
      if (found.ok) {
        r2Command = found.value;
        r2CommandSource = "path";
      } else {
        const foundRadare2 = await findWindowsExecutable("radare2", env, {
          signal: abortSignal,
        });
        if (foundRadare2.ok) {
          r2Command = foundRadare2.value;
          r2CommandSource = "path";
        } else {
          r2Command = "r2.exe";
          r2CommandSource = "path";
        }
      }
    } else {
      r2Command = "r2";
      r2CommandSource = "path";
    }
  }

  // 2. Resolve rabin2 command
  let rabin2Command = options?.rabin2Command;
  let rabin2CommandSource: "environment" | "path" | "custom" = "custom";

  if (rabin2Command === undefined) {
    const envRabin2 = env[REA_RABIN2_COMMAND];
    if (envRabin2 !== undefined && envRabin2.trim() !== "") {
      rabin2Command = envRabin2.trim();
      rabin2CommandSource = "environment";
    } else if (platform === "win32") {
      const abortSignal = signal ?? new AbortController().signal;
      const found = await findWindowsExecutable("rabin2", env, {
        signal: abortSignal,
      });
      if (found.ok) {
        rabin2Command = found.value;
        rabin2CommandSource = "path";
      } else {
        rabin2Command = "rabin2.exe";
        rabin2CommandSource = "path";
      }
    } else {
      rabin2Command = "rabin2";
      rabin2CommandSource = "path";
    }
  }

  return {
    r2Command,
    rabin2Command,
    r2CommandSource,
    rabin2CommandSource,
    timeoutMs,
    maxBufferBytes,
    hasDecompilerPlugin: options?.hasDecompilerPlugin,
  };
};

/**
 * Synchronous radare2 configuration reader from environment and defaults.
 */
export const readRadare2Configuration = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options?: Radare2ConfigurationOptions,
  platform: NodeJS.Platform = process.platform,
): Radare2Configuration => {
  const env = snapshotEnvironment(environment, platform);

  const timeoutMs =
    options?.timeoutMs ??
    parsePositiveInteger(
      env[REA_RADARE2_TIMEOUT_MS] ?? env[REA_R2_TIMEOUT_MS],
      DEFAULT_RADARE2_TIMEOUT_MS,
    );

  const maxBufferBytes =
    options?.maxBufferBytes ??
    parsePositiveInteger(
      env[REA_RADARE2_MAX_BUFFER_BYTES],
      DEFAULT_RADARE2_MAX_BUFFER_BYTES,
    );

  let r2Command = options?.r2Command;
  let r2CommandSource: "environment" | "path" | "custom" = "custom";

  if (r2Command === undefined) {
    const envR2 = env[REA_RADARE2_COMMAND] ?? env[REA_R2_COMMAND];
    if (envR2 !== undefined && envR2.trim() !== "") {
      r2Command = envR2.trim();
      r2CommandSource = "environment";
    } else {
      r2Command = platform === "win32" ? "r2.exe" : "r2";
      r2CommandSource = "path";
    }
  }

  let rabin2Command = options?.rabin2Command;
  let rabin2CommandSource: "environment" | "path" | "custom" = "custom";

  if (rabin2Command === undefined) {
    const envRabin2 = env[REA_RABIN2_COMMAND];
    if (envRabin2 !== undefined && envRabin2.trim() !== "") {
      rabin2Command = envRabin2.trim();
      rabin2CommandSource = "environment";
    } else {
      rabin2Command = platform === "win32" ? "rabin2.exe" : "rabin2";
      rabin2CommandSource = "path";
    }
  }

  return {
    r2Command,
    rabin2Command,
    r2CommandSource,
    rabin2CommandSource,
    timeoutMs,
    maxBufferBytes,
    hasDecompilerPlugin: options?.hasDecompilerPlugin,
  };
};
