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
  X64DBG_PROVIDER_IDENTITY,
  x64DbgCapabilities,
} from "./X64DbgProviderCapabilities.js";
import {
  resolveX64DbgConfiguration,
  type X64DbgConfiguration,
} from "./X64DbgConfiguration.js";
import { X64DbgClient } from "./X64DbgClient.js";
import type { X64DbgRunner } from "./X64DbgBridge.js";

/** Deep provider candidate for x64dbg and x32dbg Windows debuggers. */
export class X64DbgProvider implements AnalysisProviderCandidate {
  private config: X64DbgConfiguration | undefined;
  private readonly runner: X64DbgRunner | undefined;

  constructor(
    config?: X64DbgConfiguration,
    runner?: X64DbgRunner,
    private readonly environment: Readonly<NodeJS.ProcessEnv> = process.env,
    private readonly platform: NodeJS.Platform = process.platform,
  ) {
    this.config = config;
    this.runner = runner;
  }

  identity(): ProviderIdentity {
    return X64DBG_PROVIDER_IDENTITY;
  }

  capabilities(): readonly CapabilityDescriptor[] {
    return x64DbgCapabilities();
  }

  inspectAvailability(): ProviderAvailability {
    const diagnostics = {
      platform: this.platform,
      install_dir: this.config?.installDir ?? null,
      x32_path: this.config?.x32ExePath ?? null,
      x64_path: this.config?.x64ExePath ?? null,
    };

    if (this.platform !== "win32") {
      return {
        status: "unavailable",
        code: "unsupported_host",
        reason: `x64dbg integration is supported on Windows hosts only (running on ${this.platform}).`,
        diagnostics,
      };
    }

    if (!this.config) {
      const resolved = resolveX64DbgConfiguration(this.environment, {
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

    if (!this.config.x32ExePath && !this.config.x64ExePath) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason:
          "Neither x32dbg.exe nor x64dbg.exe was located in the configured installation.",
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
        x32_path: this.config.x32ExePath,
        x64_path: this.config.x64ExePath,
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
        reason: `x64dbg only debugs executable targets (received ${target.kind}).`,
        diagnostics,
      };
    }

    if (target.format !== "pe") {
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason: `x64dbg is a Windows PE debugger and cannot analyze ${target.format} targets.`,
        diagnostics,
      };
    }

    if (target.architecture !== "x86" && target.architecture !== "x86_64") {
      return {
        status: "unsupported",
        code: "architecture_unsupported",
        reason: `x64dbg only supports x86 (32-bit) and x86_64 (64-bit) architectures (received ${target.architecture ?? "unknown"}).`,
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
        id: X64DBG_PROVIDER_IDENTITY.id,
        name: X64DBG_PROVIDER_IDENTITY.name,
        version: X64DBG_PROVIDER_IDENTITY.version ?? "1",
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
      const resolved = resolveX64DbgConfiguration(this.environment, {
        platform: this.platform,
      });
      if (resolved.ok) {
        this.config = resolved.value;
      } else {
        this.config = {
          installDir: "C:\\x64dbg\\release",
          x32ExePath: "C:\\x64dbg\\release\\x32\\x32dbg.exe",
          x64ExePath: "C:\\x64dbg\\release\\x64\\x64dbg.exe",
          launcherPath: null,
          ipcPipeName: "\\\\.\\pipe\\x64dbg",
          mode: "script",
        };
      }
    }

    return new X64DbgClient(target, this.config, this.runner);
  }
}
