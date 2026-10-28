import { describe, expect, it } from "vitest";
import {
  resolveX64DbgConfiguration,
  selectX64DbgExecutable,
  type X64DbgConfiguration,
} from "../../../../src/x64dbg/X64DbgConfiguration.js";
import { buildBreakAndDumpScript } from "../../../../src/x64dbg/X64DbgBridge.js";
import { X64DbgProvider } from "../../../../src/x64dbg/X64DbgProvider.js";
import { X64DbgClient } from "../../../../src/x64dbg/X64DbgClient.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

const makeConfig = (
  overrides: Partial<X64DbgConfiguration> = {},
): X64DbgConfiguration => ({
  installDir: "C:\\x64dbg\\release",
  x32ExePath: "C:\\x64dbg\\release\\x32\\x32dbg.exe",
  x64ExePath: "C:\\x64dbg\\release\\x64\\x64dbg.exe",
  launcherPath: "C:\\x64dbg\\release\\x96dbg.exe",
  ipcPipeName: "\\\\.\\pipe\\x64dbg",
  mode: "script",
  ...overrides,
});

const peTarget = (architecture: "x86" | "x86_64"): BinaryTarget =>
  ({
    path: `C:\\targets\\app_${architecture}.exe`,
    sha256: "d".repeat(64),
    kind: "executable",
    format: "pe",
    executableRole: "application",
    managed: false,
    architecture,
    availableArchitectures: [architecture],
  }) as unknown as BinaryTarget;

describe("x64dbg / x32dbg Windows Debugger Connector", () => {
  it("resolves configuration from installation paths", () => {
    const res = resolveX64DbgConfiguration(
      {},
      {
        installDir: "C:\\x64dbg\\release",
        x32ExePath: "C:\\x64dbg\\release\\x32\\x32dbg.exe",
        x64ExePath: "C:\\x64dbg\\release\\x64\\x64dbg.exe",
      },
    );
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected resolution");
    expect(res.value.x32ExePath).toContain("x32dbg.exe");
    expect(res.value.x64ExePath).toContain("x64dbg.exe");
  });

  it("selects x32dbg for 32-bit PE binaries and x64dbg for 64-bit PE binaries", () => {
    const config = makeConfig();

    const x32 = selectX64DbgExecutable(config, peTarget("x86"));
    expect(x32.ok).toBe(true);
    if (!x32.ok) throw new Error("expected x32");
    expect(x32.value).toBe("C:\\x64dbg\\release\\x32\\x32dbg.exe");

    const x64 = selectX64DbgExecutable(config, peTarget("x86_64"));
    expect(x64.ok).toBe(true);
    if (!x64.ok) throw new Error("expected x64");
    expect(x64.value).toBe("C:\\x64dbg\\release\\x64\\x64dbg.exe");
  });

  it("fails closed when 32-bit target is requested but x32dbg is missing", () => {
    const config = makeConfig({ x32ExePath: null });
    const sel = selectX64DbgExecutable(config, peTarget("x86"));
    expect(sel.ok).toBe(false);
    if (sel.ok) throw new Error("expected failure");
    expect(sel.error.message).toContain("x32dbg.exe was not found");
  });

  it("inspects availability honestly on Windows vs non-Windows hosts", () => {
    const winProvider = new X64DbgProvider(
      makeConfig(),
      undefined,
      {},
      "win32",
    );
    const winAvail = winProvider.inspectAvailability();
    expect(winAvail.status).toBe("available");

    const linuxProvider = new X64DbgProvider(
      makeConfig(),
      undefined,
      {},
      "linux",
    );
    const linuxAvail = linuxProvider.inspectAvailability();
    expect(linuxAvail.status).toBe("unavailable");
    expect(linuxAvail.code).toBe("unsupported_host");
  });

  it("supports PE x86 and x86_64, but declines non-PE formats and other architectures", () => {
    const provider = new X64DbgProvider(makeConfig(), undefined, {}, "win32");

    expect(provider.inspectTargetSupport(peTarget("x86"))).toMatchObject({
      status: "supported",
    });
    expect(provider.inspectTargetSupport(peTarget("x86_64"))).toMatchObject({
      status: "supported",
    });

    const elfTarget = {
      path: "/tmp/sample.elf",
      sha256: "e".repeat(64),
      kind: "executable",
      format: "elf",
      architecture: "x86_64",
      availableArchitectures: ["x86_64"],
    } as unknown as BinaryTarget;

    expect(provider.inspectTargetSupport(elfTarget)).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
    });

    const armPeTarget = {
      path: "C:\\sample_arm.exe",
      sha256: "e".repeat(64),
      kind: "executable",
      format: "pe",
      architecture: "arm64",
      availableArchitectures: ["arm64"],
    } as unknown as BinaryTarget;

    expect(provider.inspectTargetSupport(armPeTarget)).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
    });
  });

  it("generates formatted batch scripts for breakpoint and memory dumps (-s)", () => {
    const script = buildBreakAndDumpScript(
      "C:\\test.exe",
      "0x401000",
      "0x402000",
      128,
    );
    expect(script).toContain('init "C:\\test.exe"');
    expect(script).toContain("bp 0x401000");
    expect(script).toContain("run");
    expect(script).toContain("dump 0x402000, 128");
    expect(script).toContain("stop");
    expect(script.endsWith("\r\n")).toBe(true);
  });

  it("executes operations via X64DbgClient", async () => {
    const client = new X64DbgClient(peTarget("x86_64"), makeConfig());
    const res = await client.execute("procedure_assembly", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    expect(res.value.provider.id).toBe("x64dbg");
    const payload = res.value.result as {
      status: string;
      registers: Record<string, string>;
    };
    expect(payload.status).toBe("completed");
    expect(payload.registers.rip).toBe("0x00007ff712341040");
  });

  it("X64DbgClient honors AbortSignal", async () => {
    const controller = new AbortController();
    controller.abort(new Error("aborted"));

    const client = new X64DbgClient(peTarget("x86_64"), makeConfig());
    const res = await client.execute(
      "procedure_assembly",
      {},
      { signal: controller.signal },
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected abort");
    expect(res.error._tag).toBe("AnalysisCancelledError");
  });
});
