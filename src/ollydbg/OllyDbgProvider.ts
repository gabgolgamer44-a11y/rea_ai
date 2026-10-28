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
  OLLYDBG_PROVIDER_IDENTITY,
  ollyDbgCapabilities,
} from "./OllyDbgProviderCapabilities.js";
import {
  resolveOllyDbgConfiguration,
  type OllyDbgConfiguration,
} from "./OllyDbgConfiguration.js";
import { OllyDbgClient, type OllyDbgRunner } from "./OllyDbgClient.js";

/** Deep provider candidate for OllyDbg (v1.10 / v2.01) on Windows. */
export class OllyDbgProvider implements AnalysisProviderCandidate {
  private config: OllyDbgConfiguration | undefined;
  private readonly runner: OllyDbgRunner | undefined;

  constructor(
    config?: OllyDbgConfiguration,
    runner?: OllyDbgRunner,
    private readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {
    this.config = config;
    this.runner = runner;
  }

  identity(): ProviderIdentity {
    return OLLYDBG_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return ollyDbgCapabilities(this.config);
  }

  inspectAvailability(): ProviderAvailability {
    const diagnostics = {
      platform: this.platform,
      executable_path: this.config?.executablePath ?? null,
      version: this.config?.version ?? null,
      odbg_script_available: this.config?.odbgScriptAvailable ?? null,
    };

    if (this.platform !== "win32") {
      return {
        status: "unavailable",
        code: "unsupported_host",
        reason: `OllyDbg integration requires a Windows host (running on ${this.platform}).`,
        diagnostics,
      };
    }

    if (!this.config) {
      const resolved = resolveOllyDbgConfiguration(this.environment, {
        platform: this.platform,
      });
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        return {
          status: "unavailable",
          code: "executable_missing",
          reason: resolved.error.message,
          diagnostics,
        };
      }
    }

    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: {
        platform: this.platform,
        executable_path: this.config.executablePath,
        version: this.config.version,
        plugin_dir: this.config.pluginDir,
        odbg_script_available: this.config.odbgScriptAvailable,
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
        reason: `OllyDbg only debugs executable targets (received ${target.kind}).`,
        diagnostics,
      };
    }

    if (target.format !== "pe") {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason: `OllyDbg only supports Windows PE executables (received ${target.format}).`,
        diagnostics,
      };
    }

    if (target.architecture === "x86_64") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "OllyDbg is a 32-bit debugger and cannot analyze 64-bit PE binaries.",
        diagnostics,
      };
    }

    if (target.architecture !== "x86") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `OllyDbg only supports 32-bit x86 PE targets (received ${target.architecture ?? "unknown"}).`,
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
        id: OLLYDBG_PROVIDER_IDENTITY.id,
        name: OLLYDBG_PROVIDER_IDENTITY.name,
        version: OLLYDBG_PROVIDER_IDENTITY.version ?? "1",
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
      const resolved = resolveOllyDbgConfiguration(this.environment, {
        platform: this.platform,
      });
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        this.config = {
          executablePath: "C:\\OllyDbg\\OLLYDBG.EXE",
          version: "1.10",
          pluginDir: "C:\\OllyDbg\\plugins",
          odbgScriptPath: "C:\\OllyDbg\\plugins\\ODbgScript.dll",
          odbgScriptAvailable: true,
        };
      }
    }

    return new OllyDbgClient(target, this.config, this.runner);
  }
}
