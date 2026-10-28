import { describe, expect, it } from "vitest";
import { pe } from "../../../../src/domain/binaryTarget.fixture.js";
import {
  isPe32BitMachine,
  resolveImmunityConfiguration,
  type ImmunityConfiguration,
} from "../../../../src/immunity/ImmunityConfiguration.js";
import { ImmunityProvider } from "../../../../src/immunity/ImmunityProvider.js";
import { ImmunityClient } from "../../../../src/immunity/ImmunityClient.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

const makeConfig = (
  overrides: Partial<ImmunityConfiguration> = {},
): ImmunityConfiguration => ({
  installDir: "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger",
  executablePath:
    "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\ImmunityDebugger.exe",
  python27DllPath:
    "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\python27.dll",
  pyCommandsDir:
    "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger\\PyCommands",
  is32BitRuntime: true,
  runtimeValid: true,
  ...overrides,
});

const makeTarget = (
  architecture: "x86" | "x86_64" = "x86",
  format: "pe" | "elf" = "pe",
): BinaryTarget =>
  ({
    path: `C:\\targets\\binary_${architecture}.exe`,
    sha256: "f".repeat(64),
    kind: "executable",
    format,
    architecture,
    availableArchitectures: [architecture],
  }) as BinaryTarget;

describe("Immunity Debugger Strict 32-bit Runtime & Connector", () => {
  it("correctly identifies 32-bit x86 PE vs 64-bit PE in isPe32BitMachine", () => {
    // 0x014c is 32-bit x86
    const pe32 = pe(0x014c);
    expect(isPe32BitMachine(pe32)).toBe(true);

    // 0x8664 is 64-bit x86_64
    const pe64 = pe(0x8664);
    expect(isPe32BitMachine(pe64)).toBe(false);
  });

  it("strictly validates 32-bit python27.dll and fails if a 64-bit DLL is supplied", () => {
    const pe64Bytes = pe(0x8664);
    const res = resolveImmunityConfiguration(
      {},
      {
        installDir: "C:\\Immunity",
        executablePath: "C:\\Immunity\\ImmunityDebugger.exe",
        python27DllPath: "C:\\Immunity\\python27.dll",
        fileExists: () => true,
        readBuffer: () => pe64Bytes,
      },
    );

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure for 64-bit python27.dll");
    expect(res.error.message).toContain("64-bit DLL was found");
  });

  it("fails closed when python27.dll is missing", () => {
    const res = resolveImmunityConfiguration(
      {},
      {
        installDir: "C:\\Immunity",
        executablePath: "C:\\Immunity\\ImmunityDebugger.exe",
        python27DllPath: "C:\\Immunity\\python27.dll",
        fileExists: (p) => p.endsWith("ImmunityDebugger.exe"),
      },
    );

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure when python27.dll missing");
    expect(res.error.message).toContain("requires python27.dll");
  });

  it("succeeds when python27.dll is verified 32-bit", () => {
    const pe32Bytes = pe(0x014c);
    const res = resolveImmunityConfiguration(
      {},
      {
        installDir: "C:\\Immunity",
        executablePath: "C:\\Immunity\\ImmunityDebugger.exe",
        python27DllPath: "C:\\Immunity\\python27.dll",
        fileExists: () => true,
        readBuffer: () => pe32Bytes,
      },
    );

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected resolution");
    expect(res.value.is32BitRuntime).toBe(true);
    expect(res.value.runtimeValid).toBe(true);
  });

  it("inspects availability honestly based on platform and runtime", () => {
    const winProvider = new ImmunityProvider(
      makeConfig(),
      undefined,
      {},
      "win32",
    );
    expect(winProvider.inspectAvailability().status).toBe("available");

    const linuxProvider = new ImmunityProvider(
      makeConfig(),
      undefined,
      {},
      "linux",
    );
    expect(linuxProvider.inspectAvailability().status).toBe("unavailable");
    expect(linuxProvider.inspectAvailability().code).toBe("unsupported_host");
  });

  it("STRICTLY restricts target support to 32-bit x86 PE targets", () => {
    const provider = new ImmunityProvider(makeConfig(), undefined, {}, "win32");

    // 32-bit PE is supported
    expect(
      provider.inspectTargetSupport(makeTarget("x86", "pe")),
    ).toMatchObject({
      status: "supported",
    });

    // 64-bit PE is explicitly declined with architecture_unsupported
    const x64Support = provider.inspectTargetSupport(
      makeTarget("x86_64", "pe"),
    );
    expect(x64Support).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining("cannot analyze 64-bit PE binaries"),
    });

    // Non-PE is declined with target_format_unsupported
    const elfSupport = provider.inspectTargetSupport(makeTarget("x86", "elf"));
    expect(elfSupport).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
  });

  it("executes immlib commands through ImmunityClient", async () => {
    const client = new ImmunityClient(makeTarget("x86", "pe"), makeConfig());
    const res = await client.execute("procedure_assembly", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    expect(res.value.provider.id).toBe("immunity");
    const payload = res.value.result as {
      immlib_version: string;
      output: string;
    };
    expect(payload.immlib_version).toBe("2.7");
    expect(payload.output).toContain("immlib");
  });

  it("rejects 64-bit PE execution in ImmunityClient", async () => {
    const client = new ImmunityClient(makeTarget("x86_64", "pe"), makeConfig());
    const res = await client.execute("procedure_assembly", {
      procedure: "main",
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error.message).toContain("only supports 32-bit x86 PE");
  });
});
