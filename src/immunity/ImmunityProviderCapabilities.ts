import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const IMMUNITY_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "immunity",
  name: "Immunity Debugger",
  version: "1",
});

export const IMMUNITY_OPERATIONS = Object.freeze([
  "procedure_assembly",
  "read_bytes",
  "read_function_instructions",
  "list_procedures",
] as const);

export type ImmunityOperation = (typeof IMMUNITY_OPERATIONS)[number];

export const immunityCapabilities = (): readonly CapabilityDescriptor[] => {
  const effects = Object.freeze({
    mutatesArtifact: false,
    launchesProcess: true,
    mayShowUi: true,
    mayAccessNetwork: false,
    mayWriteFilesystem: false,
    changesPermissions: false,
    requiresRoot: false,
  });

  const limitations = Object.freeze([
    "Immunity Debugger is strictly restricted to 32-bit PE binaries on Windows.",
    "Automation relies on 32-bit Python 2.7 (immlib) PyCommands.",
    "Target execution launches ImmunityDebugger.exe GUI.",
  ]);

  return Object.freeze(
    IMMUNITY_OPERATIONS.map((operation): CapabilityDescriptor =>
      Object.freeze({
        provider: IMMUNITY_PROVIDER_IDENTITY,
        operation,
        available: true,
        reason: null,
        effects,
        limitations,
      }),
    ),
  );
};
