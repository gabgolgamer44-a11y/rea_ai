import type {
  AnalysisClient,
  AnalysisClientContext,
  AnalysisProfileResolution,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  AnalysisProviderInspectionOptions,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderIdentity,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  executeRadare2Command,
  probeDecompilerPlugins,
  type Radare2ProcessLauncher,
} from "./Radare2Command.js";
import {
  RADARE2_PROVIDER_IDENTITY,
  RADARE2_REMEDIATION,
  readRadare2Configuration,
  resolveRadare2Configuration,
  type Radare2Configuration,
  type Radare2ConfigurationOptions,
} from "./Radare2Configuration.js";
import { Radare2Client, RADARE2_LIMITATIONS } from "./Radare2Client.js";

/** Supported REA operations advertised by the Radare2 provider. */
export const RADARE2_SUPPORTED_OPERATIONS = Object.freeze([
  "list_procedures",
  "search_procedures",
  "procedure_address",
  "address_name",
  "list_strings",
  "search_strings",
  "procedure_assembly",
  "procedure_pseudo_code",
  "xrefs",
  "read_binary_inventory_summary",
  "inspect_native_load_image",
] as const);

/** Common effect flags for all read-only Radare2 capabilities. */
const RADARE2_EFFECTS = Object.freeze({
  mutatesArtifact: false,
  launchesProcess: true,
  mayShowUi: false,
  mayAccessNetwork: false,
  mayWriteFilesystem: false,
  changesPermissions: false,
  requiresRoot: false,
});

/**
 * Radare2 analysis provider candidate for REA AI, implementing
 * AnalysisProviderCandidate with dynamic decompiler plugin probing.
 */
export class Radare2Provider implements AnalysisProviderCandidate {
  #config: Radare2Configuration;
  #version: string | null = null;
  #hasDecompilerPlugin: boolean | undefined;
  readonly #launcher?: Radare2ProcessLauncher | undefined;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #platform: NodeJS.Platform;

  constructor(
    configOptions?: Radare2ConfigurationOptions,
    options?: {
      readonly launcher?: Radare2ProcessLauncher | undefined;
      readonly environment?: Readonly<NodeJS.ProcessEnv> | undefined;
      readonly platform?: NodeJS.Platform | undefined;
      readonly hasDecompilerPlugin?: boolean | undefined;
      readonly version?: string | undefined;
    },
  ) {
    this.#environment = options?.environment ?? process.env;
    this.#platform = options?.platform ?? process.platform;
    this.#launcher = options?.launcher;
    this.#hasDecompilerPlugin =
      options?.hasDecompilerPlugin ?? configOptions?.hasDecompilerPlugin;
    this.#version = options?.version ?? null;

    this.#config = readRadare2Configuration(
      this.#environment,
      {
        ...configOptions,
        hasDecompilerPlugin: this.#hasDecompilerPlugin,
      },
      this.#platform,
    );
  }

  identity(): ProviderIdentity {
    return {
      ...RADARE2_PROVIDER_IDENTITY,
      version: this.#version,
    };
  }

  /**
   * Return capability descriptors for all radare2 operations.
   * `procedure_pseudo_code` announces availability conditioned on whether
   * a decompiler plugin (r2ghidra or r2dec) is installed.
   */
  capabilities(): readonly CapabilityDescriptor[] {
    const decompilerAvailable = this.#hasDecompilerPlugin === true;

    return Object.freeze(
      RADARE2_SUPPORTED_OPERATIONS.map((operation): CapabilityDescriptor => {
        if (operation === "procedure_pseudo_code") {
          if (decompilerAvailable) {
            return Object.freeze({
              provider: this.identity(),
              operation,
              available: true,
              reason: null,
              effects: RADARE2_EFFECTS,
              limitations: RADARE2_LIMITATIONS,
            });
          }
          return Object.freeze({
            provider: this.identity(),
            operation,
            available: false,
            reason:
              "Decompilation plugin (e.g. r2ghidra or r2dec) is not installed.",
            effects: RADARE2_EFFECTS,
            limitations: RADARE2_LIMITATIONS,
          });
        }

        return Object.freeze({
          provider: this.identity(),
          operation,
          available: true,
          reason: null,
          effects: RADARE2_EFFECTS,
          limitations: RADARE2_LIMITATIONS,
        });
      }),
    );
  }

  /**
   * Check radare2 availability on the host and probe decompiler plugins.
   */
  async inspectAvailability(
    options?: AnalysisProviderInspectionOptions,
  ): Promise<ProviderAvailability> {
    if (options?.signal?.aborted === true) {
      return {
        status: "unavailable",
        code: "runtime_unavailable",
        reason: "Inspection cancelled",
        diagnostics: { reason: "cancelled" },
      };
    }

    try {
      this.#config = await resolveRadare2Configuration(
        this.#environment,
        this.#platform,
        options?.signal,
        {
          r2Command: this.#config.r2Command,
          rabin2Command: this.#config.rabin2Command,
          hasDecompilerPlugin: this.#hasDecompilerPlugin,
        },
      );

      // Probe version via r2 -v
      if (this.#version === null) {
        try {
          let stdout = "";
          if (this.#launcher !== undefined) {
            const verRes = await this.#launcher(
              this.#config.r2Command,
              ["-v"],
              {
                signal: options?.signal,
                env: this.#environment,
              },
            );
            stdout = verRes.stdout;
          } else {
            const verRes = await executeRadare2Command({
              r2Path: this.#config.r2Command,
              targetPath: "",
              commands: [],
              extraArgs: ["-v"],
              signal: options?.signal,
              env: this.#environment,
              timeoutMs: 5000,
            });
            stdout = verRes.stdout;
          }
          const match = /radare2\s+([0-9a-zA-Z._-]+)/iu.exec(stdout);
          if (match !== null && match[1] !== undefined) {
            this.#version = match[1];
          }
        } catch {
          // Version probe failure can happen if r2 is absent or non-executable
        }
      }

      // Probe decompiler plugins if not explicitly configured
      if (this.#hasDecompilerPlugin === undefined) {
        const probe = await probeDecompilerPlugins(this.#config.r2Command, {
          launcher: this.#launcher,
          signal: options?.signal,
          env: this.#environment,
        });
        this.#hasDecompilerPlugin = probe.anyDecompiler;
      }

      // If we got here or have a mock launcher, confirm availability
      if (this.#launcher !== undefined || this.#version !== null) {
        return {
          status: "available",
          code: null,
          reason: null,
          diagnostics: {
            r2_command: this.#config.r2Command,
            rabin2_command: this.#config.rabin2Command,
            version: this.#version ?? "unknown",
            decompiler_available: this.#hasDecompilerPlugin,
          },
        };
      }

      return {
        status: "unavailable",
        code: "executable_missing",
        reason: `radare2 executable (${this.#config.r2Command}) was not found or failed version probe.`,
        diagnostics: {
          r2_command: this.#config.r2Command,
          remediation: RADARE2_REMEDIATION,
        },
      };
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason: `radare2 inspection failed: ${cause instanceof Error ? cause.message : String(cause)}`,
        diagnostics: {
          r2_command: this.#config.r2Command,
          remediation: RADARE2_REMEDIATION,
        },
      };
    }
  }

  /**
   * Verify if the provided binary target is supported by radare2.
   */
  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    if (target.kind !== "executable") {
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `radare2 supports executable target files; received target kind '${target.kind}'`,
        diagnostics: { kind: target.kind, path: target.path },
      };
    }

    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics: {
        path: target.path,
        kind: target.kind,
        format: "format" in target ? target.format : "unknown",
        architecture: "architecture" in target ? target.architecture : "unknown",
      },
    };
  }

  /**
   * Resolve an immutable analysis profile commitment for the given target.
   */
  async resolveAnalysisProfile(
    target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    if (options?.signal?.aborted === true) {
      return err(
        new AnalysisCancelledError("resolve_analysis_profile", {
          cause: options.signal.reason,
        }),
      );
    }

    const profile = createAnalysisProfile(
      {
        id: RADARE2_PROVIDER_IDENTITY.id,
        name: RADARE2_PROVIDER_IDENTITY.name,
        version: this.#version ?? "unknown",
      },
      {
        target_sha256: target.sha256,
        r2_command: this.#config.r2Command,
        decompiler_plugin:
          this.#hasDecompilerPlugin === true ? "available" : "unavailable",
      },
    );

    return ok({
      profile,
      createClient: (t, p) => this.createClient(t, p),
    });
  }

  /**
   * Instantiate an active radare2 analysis client for a binary target.
   */
  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
    _context?: AnalysisClientContext,
  ): AnalysisClient {
    return new Radare2Client(
      {
        ...this.#config,
        hasDecompilerPlugin: this.#hasDecompilerPlugin,
      },
      target,
      profile,
      this.#launcher,
    );
  }

  hasPendingOwnedResources(): boolean {
    return false;
  }

  async closeOwnedResources(): Promise<Result<null, AnalysisError>> {
    return ok(null);
  }
}
