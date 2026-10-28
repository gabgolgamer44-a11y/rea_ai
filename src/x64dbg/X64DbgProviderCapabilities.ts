import type {
  CapabilityDescriptor,
  ProviderIdentity,
} from "../application/AnalysisProvider.js";

export const X64DBG_PROVIDER_IDENTITY: ProviderIdentity = Object.freeze({
  id: "x64dbg",
  name: "x64dbg",
  version: "1",
});

export const X64DBG_OPERATIONS = Object.freeze([
  "procedure_assembly",
  "read_bytes",
  "read_function_instructions",
  "list_procedures",
  "procedure_address",
] as const);

export type X64DbgOperation = (typeof X64DBG_OPERATIONS)[number];

export const x64DbgCapabilities = (): readonly CapabilityDescriptor[] => {
  const effects = Object.freeze({
    mutatesArtifact: false,
    launchesProcess: true,
    mayShowUi: true,
    mayAccessNetwork: false,
    mayWriteFilesystem: true,
    changesPermissions: false,
    requiresRoot: false,
  });

  const limitations = Object.freeze([
    "x64dbg is an interactive Windows debugger; execution launches a GUI process or runs batch scripts (-s).",
    "Analysis and breakpoint execution are limited to 32-bit (x32dbg) and 64-bit (x64dbg) PE executables.",
  ]);

  return Object.freeze(
    X64DBG_OPERATIONS.map((operation): CapabilityDescriptor =>
      Object.freeze({
        provider: X64DBG_PROVIDER_IDENTITY,
        operation,
        available: true,
        reason: null,
        effects,
        limitations,
      }),
    ),
  );
};
