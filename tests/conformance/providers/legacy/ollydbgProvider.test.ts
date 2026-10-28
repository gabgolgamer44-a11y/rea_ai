import { describe, expect, it } from "vitest";
import {
  resolveOllyDbgConfiguration,
  type OllyDbgConfiguration,
} from "../../../../src/ollydbg/OllyDbgConfiguration.js";
import { OllyDbgProvider } from "../../../../src/ollydbg/OllyDbgProvider.js";
import { OllyDbgClient } from "../../../../src/ollydbg/OllyDbgClient.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

const makeConfig = (
  overrides: Partial<OllyDbgConfiguration> = {},
): OllyDbgConfiguration => ({
  executablePath: "C:\\OllyDbg\\OLLYDBG.EXE",
  version: "1.10",
  pluginDir: "C:\\OllyDbg\\plugins",
  odbgScriptPath: "C:\\OllyDbg\\plugins\\ODbgScript.dll",
  odbgScriptAvailable: true,
  ...overrides,
});

const makeTarget = (
  architecture: "x86" | "x86_64" = "x86",
  format: "pe" | "elf" = "pe",
): BinaryTarget =>
  ({
    path: `C:\\targets\\binary_${architecture}.exe`,
    sha256: "a".repeat(64),
    kind: "executable",
    format,
    architecture,
    availableArchitectures: [architecture],
  }) as BinaryTarget;

describe("OllyDbg (v1.10 / v2.01) Connector & Honest Capabilities", () => {
  it("resolves v1.10 vs v2.01 configuration and detects ODbgScript plugin", () => {
    const v1Res = resolveOllyDbgConfiguration(
      {},
      {
        executablePath: "C:\\OllyDbg\\OLLYDBG.EXE",
        pluginDir: "C:\\OllyDbg\\plugins",
        fileExists: (p) =>
          p.endsWith("ODbgScript.dll") || p.endsWith("OLLYDBG.EXE"),
      },
    );

    expect(v1Res.ok).toBe(true);
    if (!v1Res.ok) throw new Error("expected v1");
    expect(v1Res.value.version).toBe("1.10");
    expect(v1Res.value.odbgScriptAvailable).toBe(true);

    const v2Res = resolveOllyDbgConfiguration(
      {},
      {
        executablePath: "C:\\tools\\ollydbg2\\ollydbg.exe",
        pluginDir: "C:\\tools\\ollydbg2\\plugins",
        fileExists: (p) => p.endsWith("ollydbg.exe"),
      },
    );

    expect(v2Res.ok).toBe(true);
    if (!v2Res.ok) throw new Error("expected v2");
    expect(v2Res.value.version).toBe("2.01");
    expect(v2Res.value.odbgScriptAvailable).toBe(false);
  });

  it("HONESTLY declares that native interactive headless automation does NOT exist in the executable", () => {
    const provider = new OllyDbgProvider(makeConfig(), undefined, {}, "win32");
    const capabilities = provider.capabilities();

    // Assert UI and process launch effects
    for (const cap of capabilities) {
      expect(cap.effects.mayShowUi).toBe(true);
      expect(cap.effects.launchesProcess).toBe(true);
      expect(cap.limitations).toContain(
        "OllyDbg does not natively support interactive headless automation; the executable is a graphical debugger. Automated execution is restricted to batch scripts via plugins such as ODbgScript.",
      );
    }

    // Interactive headless decompilation operation MUST be declared unavailable
    const pseudoCap = capabilities.find(
      (c) => c.operation === "procedure_pseudo_code",
    );
    expect(pseudoCap?.available).toBe(false);
    expect(pseudoCap?.reason).toContain(
      "OllyDbg does not natively support interactive headless automation",
    );
  });

  it("declares script operations unavailable when ODbgScript is not installed", () => {
    const provider = new OllyDbgProvider(
      makeConfig({ odbgScriptAvailable: false }),
      undefined,
      {},
      "win32",
    );
    const capabilities = provider.capabilities();

    const asmCap = capabilities.find(
      (c) => c.operation === "procedure_assembly",
    );
    expect(asmCap?.available).toBe(false);
    expect(asmCap?.reason).toContain(
      "ODbgScript plugin (ODbgScript.dll) is not installed",
    );
  });

  it("declares script operations available when ODbgScript is present", () => {
    const provider = new OllyDbgProvider(
      makeConfig({ odbgScriptAvailable: true }),
      undefined,
      {},
      "win32",
    );
    const capabilities = provider.capabilities();

    const asmCap = capabilities.find(
      (c) => c.operation === "procedure_assembly",
    );
    expect(asmCap?.available).toBe(true);
    expect(asmCap?.reason).toBeNull();
  });

  it("restricts target support to 32-bit x86 PE targets", () => {
    const provider = new OllyDbgProvider(makeConfig(), undefined, {}, "win32");

    expect(
      provider.inspectTargetSupport(makeTarget("x86", "pe")),
    ).toMatchObject({
      status: "supported",
    });

    const x64Support = provider.inspectTargetSupport(
      makeTarget("x86_64", "pe"),
    );
    expect(x64Support).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining(
        "32-bit debugger and cannot analyze 64-bit PE",
      ),
    });

    const elfSupport = provider.inspectTargetSupport(makeTarget("x86", "elf"));
    expect(elfSupport).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });
  });

  it("executes batch scripts through OllyDbgClient when ODbgScript is installed", async () => {
    const client = new OllyDbgClient(makeTarget("x86", "pe"), makeConfig());
    const res = await client.execute("procedure_assembly", {
      procedure: "0x401000",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    expect(res.value.provider.id).toBe("ollydbg");
    const payload = res.value.result as { status: string; log: string };
    expect(payload.status).toBe("completed");
  });

  it("honestly rejects headless decompilation in OllyDbgClient", async () => {
    const client = new OllyDbgClient(makeTarget("x86", "pe"), makeConfig());
    const res = await client.execute("procedure_pseudo_code", {
      procedure: "0x401000",
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error.message).toContain(
      "OllyDbg does not natively support interactive headless automation",
    );
  });

  it("rejects execution in OllyDbgClient when ODbgScript is absent", async () => {
    const client = new OllyDbgClient(
      makeTarget("x86", "pe"),
      makeConfig({ odbgScriptAvailable: false }),
    );
    const res = await client.execute("procedure_assembly", {
      procedure: "0x401000",
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error.message).toContain("ODbgScript plugin");
  });
});
