import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";
import type { OfficialToolName } from "../contracts/officialToolContracts.js";
import type { BinaryNinjaLicenseInfo } from "./BinaryNinjaConfiguration.js";

/** Public identity committed by every Binary Ninja observation. */
export const BINARYNINJA_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "binaryninja",
  name: "Binary Ninja",
  version: "1",
});

/** Operations supported by Binary Ninja's Python API and headless runner. */
export const BINARYNINJA_OPERATIONS = Object.freeze([
  "list_procedures",
  "search_procedures",
  "procedure_address",
  "procedure_assembly",
  "procedure_pseudo_code",
  "analyze_function",
  "list_strings",
  "search_strings",
  "xrefs",
  "procedure_callers",
  "procedure_callees",
  "read_function_instructions",
] as const satisfies readonly (OfficialToolName | "analyze_function")[]);

export type BinaryNinjaOperation = (typeof BINARYNINJA_OPERATIONS)[number];

const HLIL_OPERATIONS: ReadonlySet<BinaryNinjaOperation> = new Set([
  "procedure_pseudo_code",
  "analyze_function",
]);

const XREF_OPERATIONS: ReadonlySet<BinaryNinjaOperation> = new Set([
  "xrefs",
  "procedure_callers",
  "procedure_callees",
]);

/**
 * Build honest capability descriptors reflecting the user's actual license tier.
 * Only announces features (HLIL, functions, strings, xrefs) that the active
 * Binary Ninja license permits for headless execution.
 */
export const binaryNinjaCapabilities = (
  license?: BinaryNinjaLicenseInfo,
): readonly CapabilityDescriptor[] => {
  const isHeadlessAllowed =
    license !== undefined &&
    license.valid &&
    license.headlessSupported &&
    license.licenseType !== "free" &&
    license.licenseType !== "demo";

  return Object.freeze(
    BINARYNINJA_OPERATIONS.map((operation): CapabilityDescriptor => {
      const effects = Object.freeze({
        mutatesArtifact: false,
        launchesProcess: true,
        mayShowUi: false,
        mayAccessNetwork: false,
        mayWriteFilesystem: false,
        changesPermissions: false,
        requiresRoot: false,
      });

      const limitations = Object.freeze([
        "Observations depend on Binary Ninja's completed background analysis pass.",
        ...(HLIL_OPERATIONS.has(operation)
          ? [
              "Decompilation pseudocode is derived from Binary Ninja High-Level IL (HLIL).",
            ]
          : []),
        ...(XREF_OPERATIONS.has(operation)
          ? [
              "Cross-references represent code and data references identified by the Vector35 analysis engine.",
            ]
          : []),
      ]);

      if (!isHeadlessAllowed) {
        return Object.freeze({
          provider: BINARYNINJA_PROVIDER_IDENTITY,
          operation,
          available: false,
          reason:
            "Binary Ninja headless execution requires a valid license with headless API privileges (Commercial, Enterprise, Non-Commercial, or Ultimate). Free and Demo editions do not permit headless automation.",
          effects,
          limitations,
        });
      }

      if (HLIL_OPERATIONS.has(operation) && !license.hlilSupported) {
        return Object.freeze({
          provider: BINARYNINJA_PROVIDER_IDENTITY,
          operation,
          available: false,
          reason:
            "HLIL (High-Level Intermediate Language) decompilation is not supported or licensed in this Binary Ninja installation.",
          effects,
          limitations,
        });
      }

      if (XREF_OPERATIONS.has(operation) && !license.xrefsSupported) {
        return Object.freeze({
          provider: BINARYNINJA_PROVIDER_IDENTITY,
          operation,
          available: false,
          reason:
            "Cross-reference analysis is not supported by this Binary Ninja license.",
          effects,
          limitations,
        });
      }

      return Object.freeze({
        provider: BINARYNINJA_PROVIDER_IDENTITY,
        operation,
        available: true,
        reason: null,
        effects,
        limitations,
      });
    }),
  );
};
