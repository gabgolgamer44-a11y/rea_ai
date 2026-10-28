import { execSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisOutputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../../../../src/domain/analysisErrorCore.js";
import {
  DEFAULT_RADARE2_MAX_BUFFER_BYTES,
  DEFAULT_RADARE2_TIMEOUT_MS,
  readRadare2Configuration,
} from "../../../../src/radare2/Radare2Configuration.js";
import {
  executeRadare2Command,
  probeDecompilerPlugins,
  runRadare2JsonCommand,
  type Radare2CommandResult,
  type Radare2ProcessLauncher,
} from "../../../../src/radare2/Radare2Command.js";
import { Radare2Client } from "../../../../src/radare2/Radare2Client.js";
import { Radare2Provider } from "../../../../src/radare2/Radare2Provider.js";

// --- Mock Fixture Data ---

const MOCK_IJ = {
  core: {
    file: "/tmp/sample.elf",
    size: 16384,
    format: "elf64",
    type: "EXEC",
  },
  bin: {
    os: "linux",
    arch: "x86",
    bits: 64,
    endian: "little",
    bclass: "elf64",
    baddr: 4194304,
    entry: 4198400,
    canaries: true,
    nx: true,
    pic: false,
    relocs: false,
    stripped: false,
    compiler: "gcc",
  },
};

const MOCK_AFLJ = [
  {
    offset: 4198400, // 0x401000
    name: "main",
    size: 64,
    realsz: 64,
    noreturn: false,
    stackframe: 16,
    calltype: "amd64",
    cost: 15,
    cc: 1,
    bits: 64,
    type: "fcn",
    nbbs: 2,
    edges: 1,
    ebbs: 2,
  },
  {
    offset: 4198500, // 0x401064
    name: "helper_function",
    size: 32,
    realsz: 32,
    noreturn: false,
    stackframe: 8,
    calltype: "amd64",
    cost: 8,
    cc: 1,
    bits: 64,
    type: "fcn",
    nbbs: 1,
    edges: 0,
    ebbs: 1,
  },
];

const MOCK_IZJ = [
  {
    vaddr: 4202496, // 0x402000
    paddr: 2048,
    ordinal: 1,
    size: 14,
    length: 13,
    section: ".rodata",
    type: "ascii",
    string: "Hello, Radare!",
  },
  {
    vaddr: 4202520, // 0x402018
    paddr: 2072,
    ordinal: 2,
    size: 19,
    length: 18,
    section: ".rodata",
    type: "ascii",
    string: "Target reached OK",
  },
];

const MOCK_IIJ = [
  {
    name: "puts",
    flagname: "sym.imp.puts",
    ordinal: 1,
    bind: "GLOBAL",
    type: "FUNC",
    plt: 4198352,
  },
  {
    name: "exit",
    flagname: "sym.imp.exit",
    ordinal: 2,
    bind: "GLOBAL",
    type: "FUNC",
    plt: 4198368,
  },
];

const MOCK_ISJ = [
  {
    name: "main",
    flagname: "sym.main",
    realname: "main",
    ordinal: 1,
    bind: "GLOBAL",
    type: "FUNC",
    size: 64,
    vaddr: 4198400,
    paddr: 4096,
    is_imported: false,
  },
  {
    name: "_start",
    flagname: "entry0",
    realname: "_start",
    ordinal: 2,
    bind: "GLOBAL",
    type: "FUNC",
    size: 32,
    vaddr: 4198380,
    paddr: 4076,
    is_imported: false,
  },
];

const MOCK_AXTJ = [
  {
    from: 4198432, // 0x401020
    type: "CALL",
    opcode: "call sym.helper_function",
    fcn_addr: 4198400,
    fcn_name: "main",
    ref: 4198500,
  },
];

const MOCK_PDFJ = {
  name: "main",
  size: 64,
  addr: 4198400,
  ops: [
    {
      offset: 4198400,
      size: 1,
      bytes: "55",
      opcode: "push rbp",
      type: "upush",
    },
    {
      offset: 4198401,
      size: 3,
      bytes: "4889e5",
      opcode: "mov rbp, rsp",
      type: "mov",
    },
    {
      offset: 4198404,
      size: 5,
      bytes: "e85b000000",
      opcode: "call sym.helper_function",
      type: "call",
    },
    {
      offset: 4198409,
      size: 1,
      bytes: "c3",
      opcode: "ret",
      type: "ret",
    },
  ],
};

const MOCK_PDGJ = {
  code: "int main(void) {\n    helper_function();\n    return 0;\n}",
};

/** Create a mock launcher routing radare2 command strings to canned fixtures. */
const createMockLauncher = (options?: {
  readonly hasDecompilerPlugin?: boolean;
}): Radare2ProcessLauncher => {
  const decompiler = options?.hasDecompilerPlugin ?? true;

  return async (
    _executable,
    args,
    launcherOpts,
  ): Promise<Radare2CommandResult> => {
    if (launcherOpts.signal?.aborted === true) {
      throw new AnalysisCancelledError("launcher", {
        cause: launcherOpts.signal.reason,
      });
    }


    if (args.includes("-v")) {
      return {
        exitCode: 0,
        stdout: "radare2 5.9.0 0 @ linux-x86-64 git.5.9.0\n",
        stderr: "",
      };
    }

    if (args.includes("-L")) {
      return {
        exitCode: 0,
        stdout: decompiler
          ? "core r2ghidra Ghidra decompiler plugin for radare2\ncore r2dec Decompiler plugin for radare2\n"
          : "core standard radare2 core plugin\n",
        stderr: "",
      };
    }

    // Inspect command flag
    const cIdx = args.indexOf("-c");
    const cmd = cIdx !== -1 ? args[cIdx + 1] : "";

    if (cmd?.includes("iij")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_IIJ),
        stderr: "",
      };
    }

    if (cmd?.includes("isj")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_ISJ),
        stderr: "",
      };
    }

    if (cmd?.includes("izj")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_IZJ),
        stderr: "",
      };
    }

    if (cmd?.includes("aflj")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_AFLJ),
        stderr: "",
      };
    }

    if (cmd?.includes("ij")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_IJ),
        stderr: "",
      };
    }

    if (cmd?.includes("axtj")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_AXTJ),
        stderr: "",
      };
    }

    if (cmd?.includes("pdfj")) {
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_PDFJ),
        stderr: "",
      };
    }

    if (cmd?.includes("pdgj") || cmd?.includes("pdg")) {
      if (!decompiler) {
        return {
          exitCode: 1,
          stdout: "",
          stderr: "Cannot find r2ghidra plugin\n",
        };
      }
      return {
        exitCode: 0,
        stdout: JSON.stringify(MOCK_PDGJ),
        stderr: "",
      };
    }

    return {
      exitCode: 0,
      stdout: "{}",
      stderr: "",
    };
  };
};

const createMockTarget = (): BinaryTarget => ({
  path: "/tmp/sample.elf",
  sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  kind: "executable",
  format: "elf",
  architecture: "x86_64",
  availableArchitectures: ["x86_64"],
});

// --- Test Suites ---

describe("Radare2Configuration", () => {
  it("resolves default configuration values", () => {
    const config = readRadare2Configuration({});
    expect(config.timeoutMs).toBe(DEFAULT_RADARE2_TIMEOUT_MS);
    expect(config.maxBufferBytes).toBe(DEFAULT_RADARE2_MAX_BUFFER_BYTES);
    expect(config.r2CommandSource).toBe("path");
    expect(config.rabin2CommandSource).toBe("path");
  });

  it("reads configuration from environment variables", () => {
    const env = {
      REA_RADARE2_COMMAND: "/opt/radare2/bin/r2",
      REA_RABIN2_COMMAND: "/opt/radare2/bin/rabin2",
      REA_RADARE2_TIMEOUT_MS: "45000",
      REA_RADARE2_MAX_BUFFER_BYTES: "67108864",
    };
    const config = readRadare2Configuration(env);
    expect(config.r2Command).toBe("/opt/radare2/bin/r2");
    expect(config.r2CommandSource).toBe("environment");
    expect(config.rabin2Command).toBe("/opt/radare2/bin/rabin2");
    expect(config.rabin2CommandSource).toBe("environment");
    expect(config.timeoutMs).toBe(45000);
    expect(config.maxBufferBytes).toBe(67108864);
  });

  it("respects explicit configuration options overrides", () => {
    const config = readRadare2Configuration(
      {},
      {
        r2Command: "/custom/r2",
        rabin2Command: "/custom/rabin2",
        timeoutMs: 15000,
        maxBufferBytes: 1048576,
        hasDecompilerPlugin: true,
      },
    );
    expect(config.r2Command).toBe("/custom/r2");
    expect(config.r2CommandSource).toBe("custom");
    expect(config.rabin2Command).toBe("/custom/rabin2");
    expect(config.timeoutMs).toBe(15000);
    expect(config.maxBufferBytes).toBe(1048576);
    expect(config.hasDecompilerPlugin).toBe(true);
  });
});

describe("Radare2Command", () => {
  it("executes command via launcher and returns stdout", async () => {
    const launcher = createMockLauncher();
    const result = await executeRadare2Command({
      r2Path: "r2",
      targetPath: "/tmp/sample.elf",
      commands: ["ij"],
      launcher,
    });
    expect(result.exitCode).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject(MOCK_IJ);
  });

  it("throws AnalysisCancelledError when AbortSignal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("User cancelled"));

    await expect(
      executeRadare2Command({
        r2Path: "r2",
        targetPath: "/tmp/sample.elf",
        commands: ["ij"],
        signal: controller.signal,
        launcher: createMockLauncher(),
      }),
    ).rejects.toBeInstanceOf(AnalysisCancelledError);
  });

  it("parses valid JSON with runRadare2JsonCommand", async () => {
    const launcher = createMockLauncher();
    const result = await runRadare2JsonCommand<typeof MOCK_IJ>({
      r2Path: "r2",
      targetPath: "/tmp/sample.elf",
      commands: ["ij"],
      launcher,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.bin?.arch).toBe("x86");
      expect(result.value.bin?.bits).toBe(64);
    }
  });

  it("returns AnalysisOutputError on malformed JSON", async () => {
    const badLauncher: Radare2ProcessLauncher = async () => ({
      exitCode: 0,
      stdout: "not-json-content",
      stderr: "",
    });

    const result = await runRadare2JsonCommand({
      r2Path: "r2",
      targetPath: "/tmp/sample.elf",
      commands: ["ij"],
      launcher: badLauncher,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(AnalysisOutputError);
    }
  });

  it("propagates AnalysisTimeoutError when timeout occurs", async () => {
    const timeoutLauncher: Radare2ProcessLauncher = async () => {
      throw new AnalysisTimeoutError("ij", 1000);
    };

    const res = await runRadare2JsonCommand({
      r2Path: "r2",
      targetPath: "/tmp/sample.elf",
      commands: ["ij"],
      launcher: timeoutLauncher,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBeInstanceOf(AnalysisTimeoutError);
    }
  });

  it("propagates AnalysisResourceConstraintError when buffer limit is exceeded", async () => {
    const overflowLauncher: Radare2ProcessLauncher = async () => {
      throw new AnalysisResourceConstraintError(
        "ij",
        "capacity",
        "Output buffer exceeded allowance",
        null,
        { retryable: false },
      );
    };

    const res = await runRadare2JsonCommand({
      r2Path: "r2",
      targetPath: "/tmp/sample.elf",
      commands: ["ij"],
      launcher: overflowLauncher,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBeInstanceOf(AnalysisResourceConstraintError);
    }
  });

  it("probes decompiler plugins correctly", async () => {
    const launcherWithGhidra = createMockLauncher({
      hasDecompilerPlugin: true,
    });
    const probeYes = await probeDecompilerPlugins("r2", {
      launcher: launcherWithGhidra,
    });
    expect(probeYes.r2ghidra).toBe(true);
    expect(probeYes.anyDecompiler).toBe(true);

    const launcherNoGhidra = createMockLauncher({
      hasDecompilerPlugin: false,
    });
    const probeNo = await probeDecompilerPlugins("r2", {
      launcher: launcherNoGhidra,
    });
    expect(probeNo.r2ghidra).toBe(false);
    expect(probeNo.anyDecompiler).toBe(false);
  });
});

describe("Radare2Client", () => {
  const target = createMockTarget();
  const config = readRadare2Configuration({}, { hasDecompilerPlugin: true });
  const launcher = createMockLauncher({ hasDecompilerPlugin: true });
  const client = new Radare2Client(config, target, undefined, launcher);

  it("queries binary info via ij", async () => {
    const res = await client.getBinaryInfo();
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.bin?.arch).toBe("x86");
      expect(res.value.bin?.entry).toBe(4198400);
    }
  });

  it("queries functions via aflj", async () => {
    const res = await client.getFunctions();
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.length).toBe(2);
      expect(res.value[0]?.name).toBe("main");
      expect(res.value[1]?.name).toBe("helper_function");
    }
  });

  it("queries strings via izj", async () => {
    const res = await client.getStrings();
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.length).toBe(2);
      expect(res.value[0]?.string).toBe("Hello, Radare!");
    }
  });

  it("queries imports (iij) and exports (isj)", async () => {
    const imports = await client.getImports();
    expect(imports.ok).toBe(true);
    if (imports.ok) {
      expect(imports.value.length).toBe(2);
      expect(imports.value[0]?.name).toBe("puts");
    }

    const exports = await client.getExports();
    expect(exports.ok).toBe(true);
    if (exports.ok) {
      expect(exports.value.length).toBe(2);
      expect(exports.value[0]?.name).toBe("main");
    }
  });

  it("queries cross references via axtj", async () => {
    const res = await client.getXrefs("0x401064");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.length).toBe(1);
      expect(res.value[0]?.fcn_name).toBe("main");
    }
  });

  it("queries disassembly via pdfj", async () => {
    const res = await client.getDisassembly("main");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.name).toBe("main");
      expect(res.value.ops.length).toBe(4);
      expect(res.value.ops[0]?.opcode).toBe("push rbp");
    }
  });

  it("queries decompilation via pdgj when plugin is available", async () => {
    const res = await client.getDecompilation("main");
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value).toContain("int main(void)");
    }
  });

  it("fails decompilation when plugin is absent", async () => {
    const clientNoDec = new Radare2Client(
      readRadare2Configuration({}, { hasDecompilerPlugin: false }),
      target,
      undefined,
      createMockLauncher({ hasDecompilerPlugin: false }),
    );
    const res = await clientNoDec.getDecompilation("main");
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    }
  });
});

describe("Radare2Client standard operations", () => {
  const target = createMockTarget();
  const config = readRadare2Configuration({}, { hasDecompilerPlugin: true });
  const launcher = createMockLauncher({ hasDecompilerPlugin: true });
  const client = new Radare2Client(config, target, undefined, launcher);

  // REA standard execute() operations
  it("executes list_procedures operation", async () => {
    const res = await client.execute("list_procedures", {});
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(Array.isArray(res.value.result)).toBe(true);
      expect(res.value.result).toEqual([
        {
          address: "0x401000",
          value: "main",
          procedure: { external: false, thunk: false, thunk_target: null },
        },
        {
          address: "0x401064",
          value: "helper_function",
          procedure: { external: false, thunk: false, thunk_target: null },
        },
      ]);
    }
  });

  it("executes search_procedures operation with regex", async () => {
    const res = await client.execute("search_procedures", {
      pattern: "^main$",
      mode: "regex",
      case_sensitive: true,
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.result).toEqual([
        {
          address: "0x401000",
          value: "main",
          procedure: { external: false, thunk: false, thunk_target: null },
        },
      ]);
    }
  });

  it("executes procedure_address and address_name", async () => {
    const addr = await client.execute("procedure_address", {
      procedure: "main",
    });
    expect(addr.ok).toBe(true);
    if (addr.ok) {
      expect(addr.value.result).toBe("0x401000");
    }

    const name = await client.execute("address_name", {
      address: "0x401000",
    });
    expect(name.ok).toBe(true);
    if (name.ok) {
      expect(name.value.result).toBe("main");
    }
  });

  it("executes list_strings and search_strings", async () => {
    const strings = await client.execute("list_strings", {});
    expect(strings.ok).toBe(true);
    if (strings.ok) {
      expect(Array.isArray(strings.value.result)).toBe(true);
      expect((strings.value.result as unknown[]).length).toBe(2);
    }

    const search = await client.execute("search_strings", {
      pattern: "Radare",
      mode: "literal",
      case_sensitive: true,
    });
    expect(search.ok).toBe(true);
    if (search.ok) {
      expect((search.value.result as unknown[]).length).toBe(1);
    }
  });

  it("executes procedure_assembly", async () => {
    const res = await client.execute("procedure_assembly", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(typeof res.value.result).toBe("string");
      expect(res.value.result as string).toContain("0x401000: push rbp");
      expect(res.value.result as string).toContain("0x401009: ret");
    }
  });

  it("executes procedure_pseudo_code", async () => {
    const res = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(typeof res.value.result).toBe("string");
      expect(res.value.result as string).toContain("int main(void)");
    }
  });

  it("executes xrefs operation", async () => {
    const res = await client.execute("xrefs", {
      address: "0x401064",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.result).toEqual(["0x401020"]);
    }
  });

  it("executes read_binary_inventory_summary", async () => {
    const res = await client.execute("read_binary_inventory_summary", {});
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.result).toMatchObject({
        document: target.path,
        procedure_count: 2,
        string_count: 2,
      });
    }
  });

  it("executes inspect_native_load_image", async () => {
    const res = await client.execute("inspect_native_load_image", {});
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.result).toMatchObject({
        path: target.path,
        architecture: "x86",
        bits: 64,
        endian: "little",
        entry_point: "0x401000",
      });
    }
  });

  it("executes health operation", async () => {
    const res = await client.execute("health", {});
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.value.result).toMatchObject({
        ready: true,
        provider: "radare2",
        hasDecompilerPlugin: true,
      });
    }
  });

  it("fails execution when client is closed", async () => {
    const tempClient = new Radare2Client(config, target, undefined, launcher);
    await tempClient.close();
    const res = await tempClient.execute("health", {});
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    }
  });
});

describe("Radare2Provider Candidate & Discovery", () => {
  const launcherWithDecompiler = createMockLauncher({
    hasDecompilerPlugin: true,
  });
  const launcherWithoutDecompiler = createMockLauncher({
    hasDecompilerPlugin: false,
  });

  it("reports provider identity", () => {
    const provider = new Radare2Provider(undefined, {
      launcher: launcherWithDecompiler,
      version: "5.9.0",
    });
    expect(provider.identity()).toEqual({
      id: "radare2",
      name: "radare2",
      version: "5.9.0",
    });
  });

  it("announces decompilation capability only when plugin is available", () => {
    const providerWith = new Radare2Provider(
      { hasDecompilerPlugin: true },
      { launcher: launcherWithDecompiler },
    );
    const capsWith = providerWith.capabilities();
    const decompileWith = capsWith.find(
      (c) => c.operation === "procedure_pseudo_code",
    );
    expect(decompileWith?.available).toBe(true);
    expect(decompileWith?.reason).toBeNull();

    const providerWithout = new Radare2Provider(
      { hasDecompilerPlugin: false },
      { launcher: launcherWithoutDecompiler },
    );
    const capsWithout = providerWithout.capabilities();
    const decompileWithout = capsWithout.find(
      (c) => c.operation === "procedure_pseudo_code",
    );
    expect(decompileWithout?.available).toBe(false);
    expect(decompileWithout?.reason).toContain("Decompilation plugin");
  });

  it("inspects availability and returns available when executable is present", async () => {
    const provider = new Radare2Provider(undefined, {
      launcher: launcherWithDecompiler,
    });
    const availability = await provider.inspectAvailability();
    expect(availability.status).toBe("available");
    expect(availability.code).toBeNull();
  });

  it("inspects availability and returns unavailable when r2 is missing", async () => {
    const provider = new Radare2Provider({
      r2Command: "/nonexistent/path/to/r2_missing",
    });
    const availability = await provider.inspectAvailability();
    expect(availability.status).toBe("unavailable");
    expect(availability.code).toBe("executable_missing");
  });

  it("inspects target support rejecting non-executable target kinds", () => {
    const provider = new Radare2Provider(undefined, {
      launcher: launcherWithDecompiler,
    });
    const supported = provider.inspectTargetSupport(createMockTarget());
    expect(supported.status).toBe("supported");

    const unsupported = provider.inspectTargetSupport({
      path: "/tmp/bundle",
      sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      kind: "bundle",
    } as unknown as BinaryTarget);
    expect(unsupported.status).toBe("unsupported");
    expect(unsupported.code).toBe("target_kind_unsupported");
  });

  it("resolves analysis profile with sha256 digest commitment", async () => {
    const provider = new Radare2Provider(undefined, {
      launcher: launcherWithDecompiler,
      version: "5.9.0",
      hasDecompilerPlugin: true,
    });
    const target = createMockTarget();
    const profileRes = await provider.resolveAnalysisProfile(target);
    expect(profileRes.ok).toBe(true);
    if (profileRes.ok) {
      const profile = profileRes.value.profile;
      if (profile) {
        expect(profile.provider.id).toBe("radare2");
        expect(profile.digest).toMatch(/^[0-9a-f]{64}$/u);
        expect(profileRes.value.createClient).toBeDefined();

        const created = profileRes.value.createClient?.(target, profile);
        expect(created).toBeDefined();
      }
    }
  });
});

describe("Real Execution (Host Radare2)", () => {
  // Check if r2 is actually on PATH on the test system
  let hasRealR2 = false;
  try {
    const cmd = process.platform === "win32" ? "where.exe r2" : "which r2";
    execSync(cmd, { stdio: "ignore" });
    hasRealR2 = true;
  } catch {
    hasRealR2 = false;
  }

  it.runIf(hasRealR2)(
    "performs real execution against target when r2 is on host PATH",
    async () => {
      const realProvider = new Radare2Provider();
      const availability = await realProvider.inspectAvailability();
      expect(availability.status).toBe("available");

      const target = createMockTarget();
      const client = realProvider.createClient(target);
      const health = await client.execute("health", {});
      expect(health.ok).toBe(true);
    },
  );

  it.skipIf(hasRealR2)(
    "reports missing executable correctly when r2 is absent from host PATH",
    async () => {
      const provider = new Radare2Provider();
      const availability = await provider.inspectAvailability();
      expect(availability.status).toBe("unavailable");
      expect(availability.code).toBe("executable_missing");
    },
  );
});
