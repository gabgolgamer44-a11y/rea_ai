import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { X64DBG_PROVIDER_IDENTITY } from "./X64DbgProviderCapabilities.js";
import {
  selectX64DbgExecutable,
  type X64DbgConfiguration,
} from "./X64DbgConfiguration.js";
import {
  DefaultX64DbgRunner,
  formatX64DbgScript,
  type X64DbgRunner,
} from "./X64DbgBridge.js";

/** Active client session driving x64dbg/x32dbg on Windows. */
export class X64DbgClient implements AnalysisClient {
  private readonly runner: X64DbgRunner;

  constructor(
    private readonly target: BinaryTarget,
    private readonly config: X64DbgConfiguration,
    runner?: X64DbgRunner,
  ) {
    this.runner = runner ?? new DefaultX64DbgRunner();
  }

  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    }

    const exeSelection = selectX64DbgExecutable(this.config, this.target);
    if (!exeSelection.ok) {
      return err(
        new AnalysisCapabilityUnavailableError(
          X64DBG_PROVIDER_IDENTITY.id,
          operation,
          exeSelection.error.message,
        ),
      );
    }

    const targetExe = exeSelection.value;
    let script: string;

    if (parameters.script !== undefined) {
      const scriptContent = parameters.script;
      if (typeof scriptContent === "string") {
        script = scriptContent;
      } else if (Array.isArray(scriptContent)) {
        script = formatX64DbgScript(scriptContent.map(String));
      } else {
        script = formatX64DbgScript([
          `init "${this.target.path}"`,
          "run",
          "stop",
        ]);
      }
    } else if (operation === "procedure_assembly") {
      const proc = parameters.procedure ?? "main";
      script = formatX64DbgScript([
        `init "${this.target.path}"`,
        `disasm ${String(proc)}`,
        "stop",
      ]);
    } else if (operation === "read_bytes") {
      const addr = parameters.address ?? "0x401000";
      const size = parameters.size ?? 64;
      script = formatX64DbgScript([
        `init "${this.target.path}"`,
        `dump ${String(addr)}, ${String(size)}`,
        "stop",
      ]);
    } else if (operation === "list_procedures") {
      script = formatX64DbgScript([
        `init "${this.target.path}"`,
        "symlist",
        "stop",
      ]);
    } else if (operation === "procedure_address") {
      const proc = parameters.procedure ?? "main";
      script = formatX64DbgScript([
        `init "${this.target.path}"`,
        `eval "${String(proc)}"`,
        "stop",
      ]);
    } else {
      script = formatX64DbgScript([`init "${this.target.path}"`, "stop"]);
    }

    const runResult = await this.runner.runScript(script, targetExe, options);
    if (!runResult.ok) {
      return err(runResult.error);
    }

    const execution = createAnalysisExecution(
      runResult.value,
      X64DBG_PROVIDER_IDENTITY,
      {
        limitations: [
          "Observations were produced via x64dbg/x32dbg batch script execution.",
        ],
      },
    );

    return ok(execution);
  }

  async close(): Promise<Result<null, AnalysisError>> {
    return ok(null);
  }
}
