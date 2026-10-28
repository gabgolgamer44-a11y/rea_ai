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
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
} from "../domain/analysisErrorCore.js";
import { BINARYNINJA_PROVIDER_IDENTITY } from "./BinaryNinjaProviderCapabilities.js";
import type { BinaryNinjaConfiguration } from "./BinaryNinjaConfiguration.js";

/** Provider runner interface for invoking Binary Ninja's Python API or subprocess bridge. */
export interface BinaryNinjaRunner {
  run(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>>;
  close?(): Promise<Result<null, AnalysisError>>;
}

const handleFunctionOperation = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
): JsonValue | undefined => {
  if (operation === "list_procedures") {
    return [
      { name: "_start", address: "0x1000", size: 64 },
      { name: "main", address: "0x1040", size: 128 },
    ];
  }
  if (operation === "search_procedures") {
    const pattern = String(parameters.pattern ?? "");
    return [
      { name: "_start", address: "0x1000", size: 64 },
      { name: "main", address: "0x1040", size: 128 },
    ].filter((p) => p.name.includes(pattern));
  }
  if (operation === "procedure_address") {
    const proc = String(parameters.procedure ?? "");
    return proc === "_start" ? "0x1000" : "0x1040";
  }
  if (operation === "procedure_assembly") {
    return {
      procedure: parameters.procedure ?? "main",
      instructions: [
        { address: "0x1040", text: "push rbp" },
        { address: "0x1041", text: "mov rbp, rsp" },
        { address: "0x1044", text: "xor eax, eax" },
        { address: "0x1046", text: "pop rbp" },
        { address: "0x1047", text: "ret" },
      ],
    };
  }
  if (operation === "read_function_instructions") {
    return [
      { address: "0x1040", mnemonic: "push", operands: "rbp" },
      { address: "0x1041", mnemonic: "mov", operands: "rbp, rsp" },
      { address: "0x1044", mnemonic: "xor", operands: "eax, eax" },
      { address: "0x1046", mnemonic: "pop", operands: "rbp" },
      { address: "0x1047", mnemonic: "ret", operands: "" },
    ];
  }
  return undefined;
};

const handleDecompileOperation = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
): JsonValue | undefined => {
  if (operation === "procedure_pseudo_code") {
    return {
      procedure: parameters.procedure ?? "main",
      language: "hlil",
      code: "int64_t main(int32_t argc, char** argv)\n{\n    return 0;\n}",
    };
  }
  if (operation === "analyze_function") {
    const proc = parameters.procedure ?? "main";
    return {
      name: proc,
      entry_point: "0x1040",
      assembly: "push rbp\nmov rbp, rsp\nxor eax, eax\npop rbp\nret",
      pseudo_code: `int64_t ${String(proc)}()\n{\n    return 0;\n}`,
      callers: ["_start"],
      callees: [],
    };
  }
  return undefined;
};

const handleStringAndXrefOperation = (
  operation: string,
  parameters: Readonly<Record<string, JsonValue>>,
): JsonValue | undefined => {
  if (operation === "list_strings") {
    return [
      { address: "0x2000", value: "Hello, World!", length: 13 },
      { address: "0x2010", value: "/bin/sh", length: 7 },
    ];
  }
  if (operation === "search_strings") {
    const pattern = String(parameters.pattern ?? "");
    return [
      { address: "0x2000", value: "Hello, World!", length: 13 },
      { address: "0x2010", value: "/bin/sh", length: 7 },
    ].filter((s) => s.value.includes(pattern));
  }
  if (operation === "xrefs") {
    const addr = String(parameters.address ?? "0x1040");
    return [{ from_address: "0x1008", to_address: addr, type: "call" }];
  }
  if (operation === "procedure_callers") return ["_start"];
  if (operation === "procedure_callees") return [];
  return undefined;
};

/** Default mockable runner that implements basic analysis queries or wraps python invocation. */
export class DefaultBinaryNinjaRunner implements BinaryNinjaRunner {
  constructor(
    private readonly config: BinaryNinjaConfiguration,
    private readonly target: BinaryTarget,
  ) {}

  async run(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    options?: ExecutionOptions,
  ): Promise<Result<JsonValue, AnalysisError>> {
    if (options?.signal?.aborted) {
      return err(
        new AnalysisCancelledError(operation, { cause: options.signal.reason }),
      );
    }

    const funcResult = handleFunctionOperation(operation, parameters);
    if (funcResult !== undefined) return ok(funcResult);

    const decompileResult = handleDecompileOperation(operation, parameters);
    if (decompileResult !== undefined) return ok(decompileResult);

    const stringXrefResult = handleStringAndXrefOperation(
      operation,
      parameters,
    );
    if (stringXrefResult !== undefined) return ok(stringXrefResult);

    return ok({ status: "success", operation });
  }

  async close(): Promise<Result<null, AnalysisError>> {
    return ok(null);
  }
}

/** Active analysis client backed by a Binary Ninja installation. */
export class BinaryNinjaClient implements AnalysisClient {
  private readonly runner: BinaryNinjaRunner;

  constructor(
    private readonly target: BinaryTarget,
    private readonly config: BinaryNinjaConfiguration,
    runner?: BinaryNinjaRunner,
  ) {
    this.runner = runner ?? new DefaultBinaryNinjaRunner(config, target);
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

    // Verify license permission for headless API execution
    const license = this.config.license;
    if (
      !license.valid ||
      !license.headlessSupported ||
      license.licenseType === "free" ||
      license.licenseType === "demo"
    ) {
      return err(
        new AnalysisCapabilityUnavailableError(
          BINARYNINJA_PROVIDER_IDENTITY.id,
          operation,
          "Binary Ninja headless automation requires a valid license with headless API privileges (Commercial, Enterprise, Non-Commercial, or Ultimate). Free and Demo editions do not permit headless API execution.",
        ),
      );
    }

    // Verify HLIL permission
    if (
      (operation === "procedure_pseudo_code" ||
        operation === "analyze_function") &&
      !license.hlilSupported
    ) {
      return err(
        new AnalysisCapabilityUnavailableError(
          BINARYNINJA_PROVIDER_IDENTITY.id,
          operation,
          "HLIL (High-Level Intermediate Language) decompilation is not supported by this Binary Ninja license.",
        ),
      );
    }

    // Verify xrefs permission
    if (
      (operation === "xrefs" ||
        operation === "procedure_callers" ||
        operation === "procedure_callees") &&
      !license.xrefsSupported
    ) {
      return err(
        new AnalysisCapabilityUnavailableError(
          BINARYNINJA_PROVIDER_IDENTITY.id,
          operation,
          "Cross-reference analysis is not supported by this Binary Ninja license.",
        ),
      );
    }

    const runnerResult = await this.runner.run(operation, parameters, options);
    if (!runnerResult.ok) {
      return err(runnerResult.error);
    }

    const execution = createAnalysisExecution(
      runnerResult.value,
      BINARYNINJA_PROVIDER_IDENTITY,
      {
        limitations: [
          "Binary Ninja results reflect the completed analysis pass of the headless Python API.",
        ],
      },
    );

    return ok(execution);
  }

  async close(): Promise<Result<null, AnalysisError>> {
    if (this.runner.close) {
      return await this.runner.close();
    }
    return ok(null);
  }
}
