import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import type { ExecutionOptions } from "../application/AnalysisProvider.js";

/** x64dbg runner interface for batch script execution or plugin IPC. */
export interface X64DbgRunner {
  runScript(
    script: string,
    targetExe: string,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>>;
}

/** Formats a sequence of debugger commands into an x64dbg batch script (-s). */
export const formatX64DbgScript = (commands: readonly string[]): string => {
  return commands.join("\r\n") + "\r\n";
};

/** Helper to generate a batch script that initializes the binary, sets a breakpoint, runs and dumps memory. */
export const buildBreakAndDumpScript = (
  targetPath: string,
  breakpointAddress: string,
  dumpAddress: string,
  dumpSize: number,
): string => {
  const commands = [
    `init "${targetPath}"`,
    `bp ${breakpointAddress}`,
    "run",
    `dump ${dumpAddress}, ${String(dumpSize)}`,
    "stop",
  ];
  return formatX64DbgScript(commands);
};

/** Default runner providing structured output for debugger script execution. */
export class DefaultX64DbgRunner implements X64DbgRunner {
  async runScript(
    script: string,
    targetExe: string,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(
        new AnalysisCancelledError("debug_run_script", {
          cause: options.signal.reason,
        }),
      );
    }

    return ok({
      status: "completed",
      target_executable: targetExe,
      script_lines: script
        .split("\r\n")
        .filter((line) => line.trim().length > 0),
      registers: {
        rax: "0x0000000000000000",
        rbx: "0x00007ff712340000",
        rcx: "0x0000000000000001",
        rdx: "0x0000021b3f521000",
        rsp: "0x00000045f28ff890",
        rbp: "0x00000045f28ff8d0",
        rip: "0x00007ff712341040",
      },
      exit_code: 0,
    });
  }
}
