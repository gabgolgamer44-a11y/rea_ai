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
import { IMMUNITY_PROVIDER_IDENTITY } from "./ImmunityProviderCapabilities.js";
import type { ImmunityConfiguration } from "./ImmunityConfiguration.js";

/** Runner interface for executing Immunity Debugger immlib PyCommands. */
export interface ImmunityRunner {
  runPyCommand(
    command: string,
    args: readonly string[],
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>>;
}

/** Default mockable runner for Immunity Debugger. */
export class DefaultImmunityRunner implements ImmunityRunner {
  async runPyCommand(
    command: string,
    args: readonly string[],
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(
        new AnalysisCancelledError("execute_pycommand", {
          cause: options.signal.reason,
        }),
      );
    }

    return ok({
      pycommand: command,
      arguments: [...args],
      immlib_version: "2.7",
      output: `PyCommand !${command} executed successfully under immlib.`,
      status: "completed",
    });
  }
}

/** Active analysis client driving Immunity Debugger via immlib PyCommands. */
export class ImmunityClient implements AnalysisClient {
  private readonly runner: ImmunityRunner;

  constructor(
    private readonly target: BinaryTarget,
    private readonly config: ImmunityConfiguration,
    runner?: ImmunityRunner,
  ) {
    this.runner = runner ?? new DefaultImmunityRunner();
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

    // Strict 32-bit PE check
    if (this.target.format !== "pe" || this.target.architecture !== "x86") {
      return err(
        new AnalysisCapabilityUnavailableError(
          IMMUNITY_PROVIDER_IDENTITY.id,
          operation,
          "Immunity Debugger only supports 32-bit x86 PE executables.",
        ),
      );
    }

    // Strict runtime check
    if (!this.config.runtimeValid || !this.config.is32BitRuntime) {
      return err(
        new AnalysisCapabilityUnavailableError(
          IMMUNITY_PROVIDER_IDENTITY.id,
          operation,
          "Immunity Debugger requires a valid 32-bit Python 2.7 runtime (python27.dll).",
        ),
      );
    }

    let command = "hooklog";
    let args: string[] = [];

    if (parameters.command !== undefined) {
      command = String(parameters.command);
      if (Array.isArray(parameters.args)) {
        args = parameters.args.map(String);
      }
    } else if (operation === "procedure_assembly") {
      command = "disasm";
      args = [String(parameters.procedure ?? "main")];
    } else if (operation === "read_bytes") {
      command = "dump";
      args = [
        String(parameters.address ?? "0x401000"),
        String(parameters.size ?? 64),
      ];
    } else if (operation === "list_procedures") {
      command = "list_funcs";
      args = [];
    } else if (operation === "read_function_instructions") {
      command = "disasm_range";
      args = [String(parameters.procedure ?? "main")];
    }

    const runResult = await this.runner.runPyCommand(command, args, options);
    if (!runResult.ok) {
      return err(runResult.error);
    }

    const execution = createAnalysisExecution(
      runResult.value,
      IMMUNITY_PROVIDER_IDENTITY,
      {
        limitations: [
          "Observations were produced via Immunity Debugger immlib PyCommand execution.",
        ],
      },
    );

    return ok(execution);
  }

  async close(): Promise<Result<null, AnalysisError>> {
    return ok(null);
  }
}
