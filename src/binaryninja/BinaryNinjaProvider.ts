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
  BINARYNINJA_PROVIDER_IDENTITY,
  binaryNinjaCapabilities,
} from "./BinaryNinjaProviderCapabilities.js";
import {
  resolveBinaryNinjaConfiguration,
  type BinaryNinjaConfiguration,
} from "./BinaryNinjaConfiguration.js";
import {
  BinaryNinjaClient,
  type BinaryNinjaRunner,
} from "./BinaryNinjaClient.js";

/** Deep analysis provider candidate for Binary Ninja headless automation. */
export class BinaryNinjaProvider implements AnalysisProviderCandidate {
  private config: BinaryNinjaConfiguration | undefined;
  private readonly runner: BinaryNinjaRunner | undefined;

  constructor(
    config?: BinaryNinjaConfiguration,
    runner?: BinaryNinjaRunner,
    private readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    this.config = config;
    this.runner = runner;
  }

  identity(): ProviderIdentity {
    return BINARYNINJA_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return binaryNinjaCapabilities(this.config?.license);
  }

  inspectAvailability(): ProviderAvailability {
    if (!this.config) {
      const resolved = resolveBinaryNinjaConfiguration(this.environment);
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        return {
          status: "unavailable",
          code: "executable_missing",
          reason: resolved.error.message,
          diagnostics: {
            configured: false,
          },
        };
      }
    }

    const license = this.config.license;
    const diagnostics = {
      install_path: this.config.installPath,
      binary_path: this.config.binaryPath,
      python_path: this.config.pythonPath,
      license_type: license.licenseType,
      headless_supported: license.headlessSupported,
      hlil_supported: license.hlilSupported,
    };

    if (
      !license.valid ||
      !license.headlessSupported ||
      license.licenseType === "free" ||
      license.licenseType === "demo"
    ) {
      return {
        status: "unavailable",
        code: "runtime_unavailable",
        reason:
          "Binary Ninja installed license does not permit headless API automation. A Commercial, Enterprise, Non-Commercial, or Ultimate license is required.",
        diagnostics,
      };
    }

    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics,
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
      architecture: target.architecture ?? null,
    };

    if (target.kind !== "executable" && target.kind !== "database") {
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason: `Binary Ninja cannot directly analyze ${target.kind} targets.`,
        diagnostics,
      };
    }

    // Format support
    if (target.format === "gamecube-dol") {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          "Binary Ninja cannot load GameCube DOL targets without an external community loader.",
        diagnostics,
      };
    }

    if (target.format === "dos-com" || target.format === "dos-mz") {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          "Binary Ninja does not natively provide full analysis for legacy 16-bit DOS targets.",
        diagnostics,
      };
    }

    // Architecture support
    if (target.architecture === "hexagon") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason:
          "Binary Ninja does not support Qualcomm Hexagon DSP architecture.",
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
        id: BINARYNINJA_PROVIDER_IDENTITY.id,
        name: BINARYNINJA_PROVIDER_IDENTITY.name,
        version: BINARYNINJA_PROVIDER_IDENTITY.version ?? "1",
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
      const resolved = resolveBinaryNinjaConfiguration(this.environment);
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        // Fallback default config with invalid license
        this.config = {
          installPath: "/opt/binaryninja",
          binaryPath: "/opt/binaryninja/binaryninja",
          pythonPath: "/usr/bin/python3",
          license: {
            licenseType: "unknown",
            valid: false,
            headlessSupported: false,
            hlilSupported: false,
            xrefsSupported: false,
          },
          version: "4.0",
        };
      }
    }

    return new BinaryNinjaClient(target, this.config, this.runner);
  }
}
