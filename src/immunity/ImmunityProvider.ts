import type {
  AnalysisClient,
  AnalysisClientContext,
  AnalysisProfileResolution,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  CapabilityDescriptor,
  ProviderAvailability,
  ProviderIdentity,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { ok, type Result } from "../domain/result.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  IMMUNITY_PROVIDER_IDENTITY,
  immunityCapabilities,
} from "./ImmunityProviderCapabilities.js";
import {
  resolveImmunityConfiguration,
  type ImmunityConfiguration,
} from "./ImmunityConfiguration.js";
import { ImmunityClient, type ImmunityRunner } from "./ImmunityClient.js";

/** Deep provider candidate for Immunity Debugger on Windows. */
export class ImmunityProvider implements AnalysisProviderCandidate {
  private config: ImmunityConfiguration | undefined;
  private readonly runner: ImmunityRunner | undefined;

  constructor(
    config?: ImmunityConfiguration,
    runner?: ImmunityRunner,
    private readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {
    this.config = config;
    this.runner = runner;
  }

  identity(): ProviderIdentity {
    return IMMUNITY_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return immunityCapabilities();
  }

  inspectAvailability(): ProviderAvailability {
    const diagnostics = {
      platform: this.platform,
      install_dir: this.config?.installDir ?? null,
      executable_path: this.config?.executablePath ?? null,
      python27_dll: this.config?.python27DllPath ?? null,
      is_32bit_runtime: this.config?.is32BitRuntime ?? null,
    };

    if (this.platform !== "win32") {
      return {
        status: "unavailable",
        code: "unsupported_host",
        reason: `Immunity Debugger requires a Windows host (running on ${this.platform}).`,
        diagnostics,
      };
    }

    if (!this.config) {
      const resolved = resolveImmunityConfiguration(this.environment, {
        platform: this.platform,
      });
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        const message = resolved.error.message;
        const code = message.includes("python27.dll")
          ? message.includes("64-bit")
            ? "runtime_unavailable"
            : "runtime_missing"
          : "executable_missing";

        return {
          status: "unavailable",
          code,
          reason: message,
          diagnostics,
        };
      }
    }

    if (!this.config.runtimeValid || !this.config.is32BitRuntime) {
      return {
        status: "unavailable",
        code: "runtime_unavailable",
        reason:
          "Immunity Debugger requires a valid 32-bit Python 2.7 runtime (python27.dll) for immlib support.",
        diagnostics,
      };
    }

    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        platform: this.platform,
        install_dir: this.config.installDir,
        executable_path: this.config.executablePath,
        python27_dll: this.config.python27DllPath,
        is_32bit_runtime: this.config.is32BitRuntime,
      },
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.architecture ?? null,
    };

    if (target.kind !== "executable") {
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Immunity Debugger only supports executable targets (received ${target.kind}).`,
        diagnostics,
      };
    }

    if (target.format !== "pe") {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason: `Immunity Debugger only supports Windows PE executables (received ${target.format}).`,
        diagnostics,
      };
    }

    if (target.architecture === "x86_64") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Immunity Debugger is a 32-bit debugger and cannot analyze 64-bit PE binaries.",
        diagnostics,
      };
    }

    if (target.architecture !== "x86") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `Immunity Debugger only supports 32-bit x86 PE targets (received ${target.architecture ?? "unknown"}).`,
        diagnostics,
      };
    }

    return {
      status: "supported",
      code: null,
      reason: null,
      diagnostics,
    };
  }

  async resolveAnalysisProfile(
    target: BinaryTarget,
    _options?: AnalysisProfileResolutionOptions,
  ): Promise<Result<AnalysisProfileResolution, AnalysisError>> {
    const profile = createAnalysisProfile(
      {
        id: IMMUNITY_PROVIDER_IDENTITY.id,
        name: IMMUNITY_PROVIDER_IDENTITY.name,
        version: IMMUNITY_PROVIDER_IDENTITY.version ?? "1",
      },
      {
        target_path: target.path,
        target_sha256: target.sha256,
        format: target.format,
        architecture: target.architecture ?? "unknown",
      },
    );

    return ok({
      profile,
      createClient: (t, p, c) => this.createClient(t, p, c),
    });
  }

  createClient(
    target: BinaryTarget,
    _profile?: AnalysisProfileCommitment,
    _context?: AnalysisClientContext,
  ): AnalysisClient {
    if (!this.config) {
      const resolved = resolveImmunityConfiguration(this.environment, {
        platform: this.platform,
      });
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        this.config = {
          installDir:
            "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger",
          executablePath:
            "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\ImmunityDebugger.exe",
          python27DllPath:
            "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\python27.dll",
          pyCommandsDir:
            "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\PyCommands",
          is32BitRuntime: true,
          runtimeValid: true,
        };
      }
    }

    return new ImmunityClient(target, this.config, this.runner);
  }
}
