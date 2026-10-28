import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import type { OllyDbgConfiguration } from "./OllyDbgConfiguration.js";

export const OLLYDBG_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "ollydbg",
  name: "OllyDbg",
  version: "1",
});

export const OLLYDBG_OPERATIONS = Object.freeze([
  "procedure_assembly",
  "read_bytes",
  "read_function_instructions",
  "procedure_pseudo_code",
] as const);

export type OllyDbgOperation = (typeof OLLYDBG_OPERATIONS)[number];

export const OLLYDBG_HONEST_LIMITATIONS = Object.freeze([
  "OllyDbg does not natively support interactive headless automation; the executable is a graphical debugger. Automated execution is restricted to batch scripts via plugins such as ODbgScript.",
  "OllyDbg is strictly a 32-bit x86 debugger; 64-bit binaries and non-PE targets are not supported.",
]);

/**
 * Declares capabilities for OllyDbg with an honest statement that native
 * interactive headless automation is unavailable in the executable.
 */
export const ollyDbgCapabilities = (
  config?: OllyDbgConfiguration,
): readonly CapabilityDescriptor[] => {
  const effects = Object.freeze({
    mutatesArtifact: false,
    launchesProcess: true,
    mayShowUi: true,
    mayAccessNetwork: false,
    mayWriteFilesystem: false,
    changesPermissions: false,
    requiresRoot: false,
  });

  const odbgScriptAvailable = config?.odbgScriptAvailable ?? false;

  return Object.freeze(
    OLLYDBG_OPERATIONS.map((operation): CapabilityDescriptor => {
      if (operation === "procedure_pseudo_code") {
        return Object.freeze({
          provider: OLLYDBG_PROVIDER_IDENTITY,
          operation,
          available: false,
          reason:
            "OllyDbg does not natively support interactive headless automation; the executable is a GUI-based debugger and lacks a headless decompiler.",
          effects,
          limitations: OLLYDBG_HONEST_LIMITATIONS,
        });
      }

      if (!odbgScriptAvailable) {
        return Object.freeze({
          provider: OLLYDBG_PROVIDER_IDENTITY,
          operation,
          available: false,
          reason:
            "ODbgScript plugin (ODbgScript.dll) is not installed; OllyDbg cannot execute automated scripts without ODbgScript.",
          effects,
          limitations: OLLYDBG_HONEST_LIMITATIONS,
        });
      }

      return Object.freeze({
        provider: OLLYDBG_PROVIDER_IDENTITY,
        operation,
        available: true,
        reason: null,
        effects,
        limitations: OLLYDBG_HONEST_LIMITATIONS,
      });
    }),
  );
};
