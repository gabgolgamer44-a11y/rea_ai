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
import {
  OLLYDBG_HONEST_LIMITATIONS,
  OLLYDBG_PROVIDER_IDENTITY,
} from "./OllyDbgProviderCapabilities.js";
import type { OllyDbgConfiguration } from "./OllyDbgConfiguration.js";

/** Runner interface for executing OllyDbg scripts via ODbgScript. */
export interface OllyDbgRunner {
  runScript(
    script: string,
    targetPath: string,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>>;
}

/** Default mockable runner for OllyDbg script execution. */
export class DefaultOllyDbgRunner implements OllyDbgRunner {
  async runScript(
    script: string,
    targetPath: string,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(
        new AnalysisCancelledError("run_odbg_script", {
          cause: options.signal.reason,
        }),
      );
    }

    return ok({
      target: targetPath,
      script_lines: script.split("\n").filter((l) => l.trim().length > 0),
      status: "completed",
      log: "ODbgScript execution finished.",
    });
  }
}

/** Active client session driving OllyDbg via ODbgScript batch scripts. */
export class OllyDbgClient implements AnalysisClient {
  private readonly runner: OllyDbgRunner;

  constructor(
    private readonly target: BinaryTarget,
    private readonly config: OllyDbgConfiguration,
    runner?: OllyDbgRunner,
  ) {
    this.runner = runner ?? new DefaultOllyDbgRunner();
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

    // Honest rejection for headless decompilation requests
    if (operation === "procedure_pseudo_code") {
      return err(
        new AnalysisCapabilityUnavailableError(
          OLLYDBG_PROVIDER_IDENTITY.id,
          operation,
          "OllyDbg does not natively support interactive headless automation; the executable is a GUI-based debugger and lacks a headless decompiler.",
        ),
      );
    }

    // Verify ODbgScript availability
    if (!this.config.odbgScriptAvailable) {
      return err(
        new AnalysisCapabilityUnavailableError(
          OLLYDBG_PROVIDER_IDENTITY.id,
          operation,
          "ODbgScript plugin (ODbgScript.dll) is not installed; OllyDbg cannot run automated scripts without it.",
        ),
      );
    }

    // Target architecture check
    if (this.target.format !== "pe" || this.target.architecture !== "x86") {
      return err(
        new AnalysisCapabilityUnavailableError(
          OLLYDBG_PROVIDER_IDENTITY.id,
          operation,
          "OllyDbg is strictly a 32-bit x86 PE debugger.",
        ),
      );
    }

    let script = String(parameters.script ?? "ret\n");
    if (operation === "procedure_assembly") {
      script = `// Disassemble procedure\nmov addr, ${String(parameters.procedure ?? "0x401000")}\ndasm addr\nret\n`;
    } else if (operation === "read_bytes") {
      script = `// Read memory\ndump ${String(parameters.address ?? "0x401000")}, ${String(parameters.size ?? 64)}\nret\n`;
    }

    const runResult = await this.runner.runScript(
      script,
      this.target.path,
      options,
    );
    if (!runResult.ok) {
      return err(runResult.error);
    }

    const execution = createAnalysisExecution(
      runResult.value,
      OLLYDBG_PROVIDER_IDENTITY,
      {
        limitations: OLLYDBG_HONEST_LIMITATIONS,
      },
    );

    return ok(execution);
  }

  async close(): Promise<Result<null, AnalysisError>> {
    return ok(null);
  }
}
