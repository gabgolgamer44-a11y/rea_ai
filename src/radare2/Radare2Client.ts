import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
  type ExecutionOptions,
} from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
} from "../domain/analysisSearch.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  executeRadare2Command,
  runRadare2JsonCommand,
  type Radare2ProcessLauncher,
} from "./Radare2Command.js";
import {
  RADARE2_PROVIDER_IDENTITY,
  type Radare2Configuration,
} from "./Radare2Configuration.js";

/** Function entry discovered by radare2 aflj. */
export interface Radare2Function {
  readonly offset: number;
  readonly name: string;
  readonly size: number;
  readonly realsz?: number | undefined;
  readonly noreturn?: boolean | undefined;
  readonly stackframe?: number | undefined;
  readonly calltype?: string | undefined;
  readonly cost?: number | undefined;
  readonly cc?: number | undefined;
  readonly bits?: number | undefined;
  readonly type?: string | undefined;
  readonly nbbs?: number | undefined;
  readonly edges?: number | undefined;
  readonly ebbs?: number | undefined;
  readonly minbound?: number | undefined;
  readonly maxbound?: number | undefined;
  readonly callrefs?: readonly unknown[] | undefined;
  readonly datarefs?: readonly unknown[] | undefined;
  readonly codexrefs?: readonly unknown[] | undefined;
  readonly dataxrefs?: readonly unknown[] | undefined;
}

/** String entry discovered by radare2 izj. */
export interface Radare2String {
  readonly vaddr: number;
  readonly paddr: number;
  readonly ordinal?: number | undefined;
  readonly size?: number | undefined;
  readonly length?: number | undefined;
  readonly section?: string | undefined;
  readonly type?: string | undefined;
  readonly string: string;
}

/** Import entry discovered by radare2 iij. */
export interface Radare2Import {
  readonly name: string;
  readonly flagname?: string | undefined;
  readonly ordinal?: number | undefined;
  readonly bind?: string | undefined;
  readonly type?: string | undefined;
  readonly classname?: string | undefined;
  readonly descriptor?: string | undefined;
  readonly plt?: number | undefined;
}

/** Export or symbol entry discovered by radare2 isj. */
export interface Radare2Export {
  readonly name: string;
  readonly flagname?: string | undefined;
  readonly realname?: string | undefined;
  readonly ordinal?: number | undefined;
  readonly bind?: string | undefined;
  readonly type?: string | undefined;
  readonly size?: number | undefined;
  readonly vaddr?: number | undefined;
  readonly paddr?: number | undefined;
  readonly is_imported?: boolean | undefined;
}

/** Cross reference entry discovered by radare2 axtj. */
export interface Radare2Xref {
  readonly from: number;
  readonly type: string;
  readonly opcode?: string | undefined;
  readonly fcn_addr?: number | undefined;
  readonly fcn_name?: string | undefined;
  readonly ref?: number | undefined;
}

/** Disassembled instruction from radare2 pdfj. */
export interface Radare2Instruction {
  readonly offset: number;
  readonly size: number;
  readonly bytes: string;
  readonly opcode: string;
  readonly type?: string | undefined;
}

/** Function disassembly from radare2 pdfj. */
export interface Radare2Disassembly {
  readonly name?: string | undefined;
  readonly size?: number | undefined;
  readonly addr?: number | undefined;
  readonly ops: readonly Radare2Instruction[];
}

/** Binary metadata from radare2 ij. */
export interface Radare2BinaryInfo {
  readonly core?: {
    readonly file?: string | undefined;
    readonly size?: number | undefined;
    readonly format?: string | undefined;
    readonly type?: string | undefined;
  } | undefined;
  readonly bin?: {
    readonly os?: string | undefined;
    readonly arch?: string | undefined;
    readonly bits?: number | undefined;
    readonly endian?: string | undefined;
    readonly bclass?: string | undefined;
    readonly baddr?: number | undefined;
    readonly entry?: number | undefined;
    readonly canaries?: boolean | undefined;
    readonly nx?: boolean | undefined;
    readonly pic?: boolean | undefined;
    readonly relocs?: boolean | undefined;
    readonly stripped?: boolean | undefined;
    readonly compiler?: string | undefined;
    readonly lang?: string | undefined;
  } | undefined;
}

/** Standard limitations reported by radare2 analysis. */
export const RADARE2_LIMITATIONS = Object.freeze([
  "Radare2 static analysis: procedure boundaries, basic blocks, and cross-references depend on radare2 static analysis depth.",
  "Decompilation relies on external plugins (r2ghidra or r2dec) and represents reconstructed C pseudocode, never original source bytes.",
]);

/** Format integer address as lowercase 0x-prefixed hex string. */
export const normalizeAddress = (addr: number | string): string => {
  if (typeof addr === "number") {
    return `0x${addr.toString(16)}`;
  }
  if (addr.startsWith("0x") || addr.startsWith("0X")) {
    return addr.toLowerCase();
  }
  const parsed = Number.parseInt(addr, 16);
  if (Number.isSafeInteger(parsed)) {
    return `0x${parsed.toString(16)}`;
  }
  return addr;
};

interface ExecutionContext {
  readonly locations: readonly EvidenceLocation[];
  readonly limitations: readonly string[];
  readonly analysisProfile?: AnalysisProfileCommitment;
}

/**
 * Radare2 analysis client bound to a target binary, implementing REA's
 * AnalysisClient interface and specific radare2 inspection commands.
 */
export class Radare2Client implements AnalysisClient {
  #closed = false;
  readonly #config: Radare2Configuration;
  readonly #target: BinaryTarget;
  readonly #profile: AnalysisProfileCommitment | undefined;
  readonly #launcher: Radare2ProcessLauncher | undefined;

  constructor(
    config: Radare2Configuration,
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment | undefined,
    launcher?: Radare2ProcessLauncher | undefined,
  ) {
    this.#config = config;
    this.#target = target;
    this.#profile = profile;
    this.#launcher = launcher;
  }

  get config(): Radare2Configuration {
    return this.#config;
  }

  get target(): BinaryTarget {
    return this.#target;
  }

  /** Run ij to query binary information. */
  async getBinaryInfo(
    options: ExecutionOptions = {},
  ): Promise<Result<Radare2BinaryInfo, AnalysisError>> {
    return runRadare2JsonCommand<Radare2BinaryInfo>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["ij"],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "binary_info",
      launcher: this.#launcher,
    });
  }

  /** Run aflj to query analyzed functions. */
  async getFunctions(
    options: ExecutionOptions = {},
  ): Promise<Result<readonly Radare2Function[], AnalysisError>> {
    return runRadare2JsonCommand<readonly Radare2Function[]>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["aa", "aflj"],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "list_procedures",
      launcher: this.#launcher,
    });
  }

  /** Run izj to query strings from data sections. */
  async getStrings(
    options: ExecutionOptions = {},
  ): Promise<Result<readonly Radare2String[], AnalysisError>> {
    return runRadare2JsonCommand<readonly Radare2String[]>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["izj"],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "list_strings",
      launcher: this.#launcher,
    });
  }

  /** Run iij to query imports. */
  async getImports(
    options: ExecutionOptions = {},
  ): Promise<Result<readonly Radare2Import[], AnalysisError>> {
    return runRadare2JsonCommand<readonly Radare2Import[]>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["iij"],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "inspect_pe_imports",
      launcher: this.#launcher,
    });
  }

  /** Run isj to query exports and symbols. */
  async getExports(
    options: ExecutionOptions = {},
  ): Promise<Result<readonly Radare2Export[], AnalysisError>> {
    return runRadare2JsonCommand<readonly Radare2Export[]>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["isj"],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "inspect_native_exports",
      launcher: this.#launcher,
    });
  }

  /** Run axtj to query cross references to a given address. */
  async getXrefs(
    address: string,
    options: ExecutionOptions = {},
  ): Promise<Result<readonly Radare2Xref[], AnalysisError>> {
    return runRadare2JsonCommand<readonly Radare2Xref[]>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: ["aa", `axtj @ ${address}`],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "xrefs",
      launcher: this.#launcher,
    });
  }

  /** Run pdfj to query disassembly of a function or address. */
  async getDisassembly(
    addressOrName: string,
    options: ExecutionOptions = {},
  ): Promise<Result<Radare2Disassembly, AnalysisError>> {
    return runRadare2JsonCommand<Radare2Disassembly>({
      r2Path: this.#config.r2Command,
      targetPath: this.#target.path,
      commands: [`pdfj @ ${addressOrName}`],
      signal: options.signal,
      timeoutMs: this.#config.timeoutMs,
      maxBufferBytes: this.#config.maxBufferBytes,
      operation: "procedure_assembly",
      launcher: this.#launcher,
    });
  }

  /**
   * Run pdgj to decompile a function, conditioned on decompiler plugin presence.
   */
  async getDecompilation(
    addressOrName: string,
    options: ExecutionOptions = {},
  ): Promise<Result<string, AnalysisError>> {
    if (this.#config.hasDecompilerPlugin === false) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "radare2",
          "procedure_pseudo_code",
          "Decompiler plugin (e.g. r2ghidra or r2dec) is not installed in radare2",
          {
            userMessage:
              "Install r2ghidra or r2dec plugin for radare2 to enable decompilation.",
          },
        ),
      );
    }

    try {
      const res = await executeRadare2Command({
        r2Path: this.#config.r2Command,
        targetPath: this.#target.path,
        commands: [`pdgj @ ${addressOrName}`],
        signal: options.signal,
        timeoutMs: this.#config.timeoutMs,
        maxBufferBytes: this.#config.maxBufferBytes,
        operation: "procedure_pseudo_code",
        launcher: this.#launcher,
      });

      const trimmed = res.stdout.trim();
      if (trimmed === "" || res.stderr.includes("Cannot find")) {
        const fallback = await executeRadare2Command({
          r2Path: this.#config.r2Command,
          targetPath: this.#target.path,
          commands: [`pdg @ ${addressOrName}`],
          signal: options.signal,
          timeoutMs: this.#config.timeoutMs,
          maxBufferBytes: this.#config.maxBufferBytes,
          operation: "procedure_pseudo_code",
          launcher: this.#launcher,
        });
        const fbTrimmed = fallback.stdout.trim();
        if (fbTrimmed !== "") {
          return ok(fbTrimmed);
        }
        return err(
          new AnalysisCapabilityUnavailableError(
            "radare2",
            "procedure_pseudo_code",
            `Decompilation failed or returned empty output for ${addressOrName}`,
          ),
        );
      }

      try {
        const parsed = JSON.parse(trimmed) as unknown;
        if (
          typeof parsed === "object" &&
          parsed !== null &&
          "code" in parsed &&
          typeof (parsed as { code: unknown }).code === "string"
        ) {
          return ok((parsed as { code: string }).code);
        }
      } catch {
        // Output was plain text rather than JSON
      }

      return ok(trimmed);
    } catch (cause: unknown) {
      if (cause instanceof AnalysisError) {
        return err(cause);
      }
      return err(
        new AnalysisOutputError(
          "procedure_pseudo_code",
          `Decompilation failed: ${cause instanceof Error ? cause.message : String(cause)}`,
          { cause },
        ),
      );
    }
  }

  /**
   * Execute an analysis operation against radare2, returning normalized
   * AnalysisExecution facts.
   */
  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions = {},
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closed) {
      return err(
        new AnalysisCapabilityUnavailableError(
          "radare2",
          operation,
          "This radare2 session is closed.",
        ),
      );
    }

    if (options.signal?.aborted === true) {
      return err(
        new AnalysisCancelledError(operation, {
          cause: options.signal.reason,
        }),
      );
    }

    const document = parameters.document;
    if (document !== undefined && document !== this.#target.path) {
      return err(
        new AnalysisInputError(operation, undefined, [
          {
            path: ["document"],
            reason: "invalid_value",
            expected: this.#target.path,
            observed: document,
            message:
              "radare2 session analyzes one target; omit document or match the target path.",
          },
        ]),
      );
    }

    const context: ExecutionContext = {
      locations: [{ kind: "artifact-path", path: this.#target.path }],
      limitations: RADARE2_LIMITATIONS,
      ...(this.#profile === undefined
        ? {}
        : { analysisProfile: this.#profile }),
    };

    switch (operation) {
      case "health":
        return this.#handleHealth(context);
      case "list_procedures":
      case "search_procedures":
        return this.#handleProcedures(operation, parameters, options, context);
      case "procedure_address":
        return this.#handleProcedureAddress(parameters, options, context);
      case "address_name":
        return this.#handleAddressName(parameters, options, context);
      case "list_strings":
      case "search_strings":
        return this.#handleStrings(operation, parameters, options, context);
      case "procedure_assembly":
        return this.#handleAssembly(parameters, options, context);
      case "procedure_pseudo_code":
        return this.#handlePseudocode(parameters, options, context);
      case "xrefs":
        return this.#handleXrefs(parameters, options, context);
      case "read_binary_inventory_summary":
        return this.#handleInventorySummary(options, context);
      case "inspect_native_load_image":
        return this.#handleLoadImage(options, context);
      default:
        return err(
          new AnalysisCapabilityUnavailableError(
            "radare2",
            operation,
            `radare2 provider does not support operation ${operation}`,
          ),
        );
    }
  }

  async executeIfReady(
    _operation: AnalysisOperation,
    _parameters: Readonly<Record<string, JsonValue>>,
    _options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError> | undefined> {
    return undefined;
  }

  async close(): Promise<Result<null, AnalysisError>> {
    this.#closed = true;
    return ok(null);
  }

  #handleHealth(context: ExecutionContext) {
    return ok(
      createAnalysisExecution(
        {
          ready: true,
          provider: "radare2",
          r2Command: this.#config.r2Command,
          rabin2Command: this.#config.rabin2Command,
          hasDecompilerPlugin: this.#config.hasDecompilerPlugin ?? false,
        },
        RADARE2_PROVIDER_IDENTITY,
        context,
      ),
    );
  }

  async #handleProcedures(
    operation: "list_procedures" | "search_procedures",
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const funcsResult = await this.getFunctions(options);
    if (!funcsResult.ok) return funcsResult;

    const items = funcsResult.value.map((fn) => ({
      address: normalizeAddress(fn.offset),
      value: fn.name,
      procedure: {
        external: fn.type === "imp",
        thunk: false,
        thunk_target: null,
      },
    }));

    if (operation === "search_procedures") {
      const parsedQuery = analysisSearchQuerySchema.safeParse(parameters);
      if (!parsedQuery.success) {
        return err(
          new AnalysisInputError(operation, { cause: parsedQuery.error }),
        );
      }
      const predicate = analysisSearchPredicate(parsedQuery.data);
      const filtered = items.filter(({ value }) => predicate(value));
      return ok(
        createAnalysisExecution(
          filtered,
          RADARE2_PROVIDER_IDENTITY,
          context,
        ),
      );
    }

    return ok(
      createAnalysisExecution(items, RADARE2_PROVIDER_IDENTITY, context),
    );
  }

  async #handleProcedureAddress(
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const procedureParam = parameters.procedure;
    if (typeof procedureParam !== "string" || procedureParam.trim() === "") {
      return err(
        new AnalysisInputError("procedure_address", undefined, [
          {
            path: ["procedure"],
            reason: "missing_argument",
            message: "procedure must be a non-empty string",
          },
        ]),
      );
    }

    const funcsResult = await this.getFunctions(options);
    if (!funcsResult.ok) return funcsResult;

    const match = funcsResult.value.find(
      (fn) =>
        fn.name === procedureParam ||
        normalizeAddress(fn.offset) === normalizeAddress(procedureParam),
    );

    if (match === undefined) {
      return err(
        new AnalysisInputError("procedure_address", {
          userMessage: `Procedure ${procedureParam} was not found in radare2 inventory.`,
        }),
      );
    }

    const addr = normalizeAddress(match.offset);
    return ok(
      createAnalysisExecution(addr, RADARE2_PROVIDER_IDENTITY, {
        ...context,
        locations: [...context.locations, { kind: "address", address: addr }],
      }),
    );
  }

  async #handleAddressName(
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const addressParam = parameters.address;
    if (typeof addressParam !== "string" || addressParam.trim() === "") {
      return err(
        new AnalysisInputError("address_name", undefined, [
          {
            path: ["address"],
            reason: "missing_argument",
            message: "address must be a valid hex address",
          },
        ]),
      );
    }

    const funcsResult = await this.getFunctions(options);
    if (!funcsResult.ok) return funcsResult;

    const match = funcsResult.value.find(
      (fn) =>
        normalizeAddress(fn.offset) === normalizeAddress(addressParam),
    );

    const name = match !== undefined ? match.name : null;
    return ok(
      createAnalysisExecution(name, RADARE2_PROVIDER_IDENTITY, {
        ...context,
        locations: [
          ...context.locations,
          { kind: "address", address: normalizeAddress(addressParam) },
        ],
      }),
    );
  }

  async #handleStrings(
    operation: "list_strings" | "search_strings",
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const stringsResult = await this.getStrings(options);
    if (!stringsResult.ok) return stringsResult;

    const items = stringsResult.value.map((s) => ({
      address: normalizeAddress(s.vaddr),
      value: s.string,
      string: {
        encoding: s.type ?? "ascii",
        termination: "present_or_not_required" as const,
        byte_length: s.size ?? s.length ?? s.string.length,
      },
    }));

    if (operation === "search_strings") {
      const parsedQuery = analysisSearchQuerySchema.safeParse(parameters);
      if (!parsedQuery.success) {
        return err(
          new AnalysisInputError(operation, { cause: parsedQuery.error }),
        );
      }
      const predicate = analysisSearchPredicate(parsedQuery.data);
      const filtered = items.filter(({ value }) => predicate(value));
      return ok(
        createAnalysisExecution(
          filtered,
          RADARE2_PROVIDER_IDENTITY,
          context,
        ),
      );
    }

    return ok(
      createAnalysisExecution(items, RADARE2_PROVIDER_IDENTITY, context),
    );
  }

  async #handleAssembly(
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const procParam =
      typeof parameters.procedure === "string"
        ? parameters.procedure
        : typeof parameters.address === "string"
          ? parameters.address
          : undefined;

    if (procParam === undefined) {
      return err(
        new AnalysisInputError("procedure_assembly", undefined, [
          {
            path: ["procedure"],
            reason: "missing_argument",
            message: "procedure or address must be specified",
          },
        ]),
      );
    }

    const disasmResult = await this.getDisassembly(procParam, options);
    if (!disasmResult.ok) return disasmResult;

    const lines = disasmResult.value.ops.map(
      (op) => `${normalizeAddress(op.offset)}: ${op.opcode}`,
    );

    const assemblyText = lines.join("\n");
    const addr =
      disasmResult.value.addr !== undefined
        ? normalizeAddress(disasmResult.value.addr)
        : normalizeAddress(procParam);

    return ok(
      createAnalysisExecution(assemblyText, RADARE2_PROVIDER_IDENTITY, {
        ...context,
        locations: [...context.locations, { kind: "address", address: addr }],
      }),
    );
  }

  async #handlePseudocode(
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const procParam =
      typeof parameters.procedure === "string"
        ? parameters.procedure
        : typeof parameters.address === "string"
          ? parameters.address
          : undefined;

    if (procParam === undefined) {
      return err(
        new AnalysisInputError("procedure_pseudo_code", undefined, [
          {
            path: ["procedure"],
            reason: "missing_argument",
            message: "procedure or address must be specified",
          },
        ]),
      );
    }

    const decompileResult = await this.getDecompilation(procParam, options);
    if (!decompileResult.ok) return decompileResult;

    return ok(
      createAnalysisExecution(
        decompileResult.value,
        RADARE2_PROVIDER_IDENTITY,
        context,
      ),
    );
  }

  async #handleXrefs(
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const addressParam = parameters.address;
    if (typeof addressParam !== "string" || addressParam.trim() === "") {
      return err(
        new AnalysisInputError("xrefs", undefined, [
          {
            path: ["address"],
            reason: "missing_argument",
            message: "address must be a valid hex address",
          },
        ]),
      );
    }

    const xrefsResult = await this.getXrefs(addressParam, options);
    if (!xrefsResult.ok) return xrefsResult;

    const addresses = xrefsResult.value.map((x) =>
      normalizeAddress(x.from),
    );

    return ok(
      createAnalysisExecution(addresses, RADARE2_PROVIDER_IDENTITY, {
        ...context,
        locations: [
          ...context.locations,
          { kind: "address", address: normalizeAddress(addressParam) },
        ],
      }),
    );
  }

  async #handleInventorySummary(
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const funcsResult = await this.getFunctions(options);
    const stringsResult = await this.getStrings(options);

    const procedureCount = funcsResult.ok ? funcsResult.value.length : 0;
    const stringCount = stringsResult.ok ? stringsResult.value.length : 0;

    const summary = {
      document: this.#target.path,
      procedure_count: procedureCount,
      string_count: stringCount,
      segments: [],
    };

    return ok(
      createAnalysisExecution(
        summary,
        RADARE2_PROVIDER_IDENTITY,
        context,
      ),
    );
  }

  async #handleLoadImage(
    options: ExecutionOptions,
    context: ExecutionContext,
  ) {
    const infoResult = await this.getBinaryInfo(options);
    if (!infoResult.ok) return infoResult;

    const bin = infoResult.value.bin;
    const core = infoResult.value.core;

    const loadImage = {
      path: this.#target.path,
      format: bin?.bclass ?? core?.format ?? "unknown",
      architecture: bin?.arch ?? "unknown",
      bits: bin?.bits ?? 0,
      endian: bin?.endian ?? "unknown",
      entry_point:
        bin?.entry !== undefined ? normalizeAddress(bin.entry) : null,
      base_address:
        bin?.baddr !== undefined ? normalizeAddress(bin.baddr) : null,
    };

    return ok(
      createAnalysisExecution(
        loadImage,
        RADARE2_PROVIDER_IDENTITY,
        context,
      ),
    );
  }
}
