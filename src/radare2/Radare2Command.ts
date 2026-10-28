import { spawn } from "node:child_process";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  DEFAULT_RADARE2_MAX_BUFFER_BYTES,
  DEFAULT_RADARE2_TIMEOUT_MS,
  RADARE2_REMEDIATION,
} from "./Radare2Configuration.js";

/** Captured process output and exit code from a radare2 invocation. */
export interface Radare2CommandResult {
  readonly exitCode: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

/** Function signature for custom or mocked process execution in tests. */
export type Radare2ProcessLauncher = (
  executable: string,
  args: readonly string[],
  options: {
    readonly env?: Readonly<NodeJS.ProcessEnv> | undefined;
    readonly signal?: AbortSignal | undefined;
    readonly timeoutMs?: number | undefined;
    readonly maxBufferBytes?: number | undefined;
  },
) => Promise<Radare2CommandResult>;

/** Options for executing a radare2 command. */
export interface Radare2CommandOptions {
  readonly r2Path: string;
  readonly targetPath: string;
  readonly commands: readonly string[];
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number | undefined;
  readonly maxBufferBytes?: number | undefined;
  readonly env?: Readonly<NodeJS.ProcessEnv> | undefined;
  readonly operation?: string | undefined;
  readonly extraArgs?: readonly string[] | undefined;
  readonly launcher?: Radare2ProcessLauncher | undefined;
}

/**
 * Execute radare2 asynchronously with `-q`, `-e scr.color=0`, `-c <commands>`,
 * supporting AbortSignal cancellation, timeout, and buffer bounding.
 */
export const executeRadare2Command = async (
  options: Radare2CommandOptions,
): Promise<Radare2CommandResult> => {
  const operation = options.operation ?? "radare2_command";
  const timeoutMs = options.timeoutMs ?? DEFAULT_RADARE2_TIMEOUT_MS;
  const maxBufferBytes =
    options.maxBufferBytes ?? DEFAULT_RADARE2_MAX_BUFFER_BYTES;

  if (options.signal?.aborted === true) {
    throw new AnalysisCancelledError(operation, {
      cause: options.signal.reason,
    });
  }

  const args: string[] = [
    "-q",
    "-e",
    "scr.color=0",
    ...(options.extraArgs ?? []),
    "-c",
    options.commands.join("; "),
    options.targetPath,
  ];

  if (options.launcher !== undefined) {
    return options.launcher(options.r2Path, args, {
      env: options.env,
      signal: options.signal,
      timeoutMs,
      maxBufferBytes,
    });
  }

  return new Promise<Radare2CommandResult>((resolve, reject) => {
    let timer: NodeJS.Timeout | undefined;
    let interrupted: "cancelled" | "timeout" | "buffer_overflow" | undefined;
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let totalBytes = 0;

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(options.r2Path, args, {
        env: options.env ?? process.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (cause: unknown) {
      reject(
        new AnalysisCapabilityUnavailableError(
          "radare2",
          operation,
          `Failed to spawn radare2 at ${options.r2Path}: ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause, remediationAction: RADARE2_REMEDIATION },
        ),
      );
      return;
    }

    const cleanup = () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      if (options.signal !== undefined) {
        options.signal.removeEventListener("abort", onAbort);
      }
    };

    const onAbort = () => {
      interrupted = "cancelled";
      try {
        child.kill();
      } catch {
        // Child process may already have terminated.
      }
    };

    if (options.signal !== undefined) {
      options.signal.addEventListener("abort", onAbort, { once: true });
    }

    if (timeoutMs > 0) {
      timer = setTimeout(() => {
        interrupted = "timeout";
        try {
          child.kill();
        } catch {
          // Child process may already have terminated.
        }
      }, timeoutMs);
    }

    if (child.stdout !== null) {
      child.stdout.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength;
        if (totalBytes > maxBufferBytes) {
          interrupted = "buffer_overflow";
          try {
            child.kill();
          } catch {}
          return;
        }
        stdoutChunks.push(chunk);
      });
    }

    if (child.stderr !== null) {
      child.stderr.on("data", (chunk: Buffer) => {
        totalBytes += chunk.byteLength;
        if (totalBytes > maxBufferBytes) {
          interrupted = "buffer_overflow";
          try {
            child.kill();
          } catch {}
          return;
        }
        stderrChunks.push(chunk);
      });
    }

    child.on("error", (error: NodeJS.ErrnoException) => {
      cleanup();
      if (error.code === "ENOENT") {
        reject(
          new AnalysisCapabilityUnavailableError(
            "radare2",
            operation,
            `radare2 executable not found at ${options.r2Path}`,
            { cause: error, remediationAction: RADARE2_REMEDIATION },
          ),
        );
      } else {
        reject(
          new AnalysisOutputError(
            operation,
            `radare2 process error: ${error.message}`,
            { cause: error },
          ),
        );
      }
    });

    child.on("close", (code) => {
      cleanup();

      if (interrupted === "cancelled") {
        reject(
          new AnalysisCancelledError(operation, {
            cause: options.signal?.reason,
          }),
        );
        return;
      }

      if (interrupted === "timeout") {
        reject(
          new AnalysisTimeoutError(operation, timeoutMs, {
            userMessage: `radare2 command timed out after ${String(timeoutMs)}ms`,
            remediationAction:
              "Increase timeout via REA_RADARE2_TIMEOUT_MS or configure timeoutMs.",
          }),
        );
        return;
      }

      if (interrupted === "buffer_overflow") {
        reject(
          new AnalysisResourceConstraintError(
            operation,
            "capacity",
            `radare2 output exceeded maximum buffer allowance of ${String(maxBufferBytes)} bytes`,
            { max_buffer_bytes: maxBufferBytes },
            { retryable: false },
          ),
        );
        return;
      }

      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");

      resolve({
        exitCode: code,
        stdout,
        stderr,
      });
    });
  });
};

/**
 * Run a radare2 command and parse its stdout as JSON, propagating typed
 * errors on failure, timeout, cancellation, or malformed JSON.
 */
export const runRadare2JsonCommand = async <T>(
  options: Radare2CommandOptions,
): Promise<Result<T, AnalysisError>> => {
  const operation = options.operation ?? "radare2_json_command";
  try {
    const result = await executeRadare2Command(options);
    const trimmed = result.stdout.trim();
    if (trimmed === "") {
      return err(
        new AnalysisOutputError(
          operation,
          "radare2 returned empty output when JSON was expected",
          {
            diagnostics: {
              exitCode: result.exitCode,
              stderr: result.stderr,
            },
          },
        ),
      );
    }
    try {
      const parsed = JSON.parse(trimmed) as T;
      return ok(parsed);
    } catch (parseError: unknown) {
      return err(
        new AnalysisOutputError(
          operation,
          `Failed to parse radare2 JSON output: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
          {
            cause: parseError,
            diagnostics: {
              rawOutput: trimmed.slice(0, 1024),
              stderr: result.stderr,
              exitCode: result.exitCode,
            },
          },
        ),
      );
    }
  } catch (cause: unknown) {
    if (cause instanceof AnalysisError) {
      return err(cause);
    }
    return err(
      new AnalysisOutputError(
        operation,
        `Unexpected failure executing radare2: ${cause instanceof Error ? cause.message : String(cause)}`,
        { cause },
      ),
    );
  }
};

/** Result of probing radare2 plugins for decompiler support. */
export interface DecompilerProbeResult {
  readonly r2ghidra: boolean;
  readonly r2dec: boolean;
  readonly anyDecompiler: boolean;
}

/** Options for probing radare2 decompiler plugins. */
export interface ProbeDecompilerPluginsOptions {
  readonly launcher?: Radare2ProcessLauncher | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number | undefined;
  readonly env?: Readonly<NodeJS.ProcessEnv> | undefined;
}

/**
 * Probe radare2 for available decompilation plugins (e.g. r2ghidra, r2dec).
 */
export const probeDecompilerPlugins = async (
  r2Path: string,
  options?: ProbeDecompilerPluginsOptions,
): Promise<DecompilerProbeResult> => {
  try {
    const launcher = options?.launcher;
    let output = "";

    if (launcher !== undefined) {
      const res = await launcher(r2Path, ["-L"], {
        signal: options?.signal,
        timeoutMs: options?.timeoutMs ?? 5000,
        env: options?.env,
      });
      output = `${res.stdout} ${res.stderr}`;
    } else {
      const args = ["-L"];
      const child = spawn(r2Path, args, {
        env: options?.env ?? process.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
      const chunks: Buffer[] = [];
      if (child.stdout !== null) {
        child.stdout.on("data", (c: Buffer) => chunks.push(c));
      }
      if (child.stderr !== null) {
        child.stderr.on("data", (c: Buffer) => chunks.push(c));
      }
      output = await new Promise<string>((resolve) => {
        child.on("close", () => {
          resolve(Buffer.concat(chunks).toString("utf8"));
        });
        child.on("error", () => resolve(""));
      });
    }

    const lower = output.toLowerCase();
    const r2ghidra = lower.includes("r2ghidra") || lower.includes("ghidra");
    const r2dec = lower.includes("r2dec") || lower.includes("jsdec");
    return {
      r2ghidra,
      r2dec,
      anyDecompiler: r2ghidra || r2dec,
    };
  } catch {
    return {
      r2ghidra: false,
      r2dec: false,
      anyDecompiler: false,
    };
  }
};
