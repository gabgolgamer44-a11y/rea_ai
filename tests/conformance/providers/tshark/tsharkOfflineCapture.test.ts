import { describe, expect, it, onTestFinished } from "vitest";
import { writeFile, chmod } from "node:fs/promises";
import { join } from "node:path";
import {
  TsharkCaptureProvider,
  tsharkHostSupported,
  tsharkOfflineCaptureSupported,
  tsharkLiveCaptureSupported,
} from "../../../../src/captures/TsharkCaptureProvider.js";
import { PacketCaptureService } from "../../../../src/application/captures/PacketCaptureService.js";
import { packetCaptureSchema } from "../../../../src/domain/captures/packetCapture.js";
import { packetFieldsCatalogSchema } from "../../../../src/domain/captures/packetFields.js";
import { PrivateRuntimeRoot } from "../../../../src/process/PrivateRuntimeRoot.js";
import {
  spawnOwnedProviderProcess,
  type OwnedProviderProcessSpawnOptions,
} from "../../../../src/process/ProviderProcess.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { readStableArtifact } from "../../../../src/artifacts/readStableArtifact.js";

interface FixtureOptions {
  readonly platform?: NodeJS.Platform;
  readonly mode?: "ok" | "empty" | "filtered";
}

const createTsharkFixture = async (options: FixtureOptions = {}) => {
  const platform = options.platform ?? "win32";
  const mode = options.mode ?? "ok";
  const directory = await createTestTempDirectory("rea-tshark-conformance-");
  const pcapPath = join(directory, "traffic.pcap");
  const pcapngPath = join(directory, "traffic.pcapng");
  await writeFile(pcapPath, "pcap-binary-data");
  await writeFile(pcapngPath, "pcapng-binary-data");

  const capturedSpawnOptions: OwnedProviderProcessSpawnOptions[] = [];

  const script = join(directory, "tshark-producer.mjs");
  await writeFile(
    script,
    `import { readFileSync } from 'node:fs';
if (process.argv.includes('--version')) {
  console.log('TShark (Wireshark) 4.6.6 (REA conformance stub)');
} else if (process.argv.includes('-G')) {
  console.log([
    'P\\tInternet Protocol\\tip',
    'F\\tSource IP Address\\tip.src\\tFT_IPv4\\tip\\tBASE_NONE\\t0x0\\tIPv4 source',
    'F\\tDestination IP Address\\tip.dst\\tFT_IPv4\\tip\\tBASE_NONE\\t0x0\\tIPv4 destination',
    'P\\tDomain Name System\\tdns',
    'F\\tQuery Name\\tdns.qry.name\\tFT_STRING\\tdns\\tBASE_NONE\\t0x0\\tDNS query domain'
  ].join('\\n'));
} else {
  const mode = ${JSON.stringify(mode)};
  if (mode === 'empty') {
    console.log('[]');
  } else if (mode === 'filtered') {
    console.log(JSON.stringify([
      {
        _source: {
          layers: {
            "frame.number": ["2"],
            "ip.src": ["10.0.0.1"],
            "ip.dst": ["10.0.0.2"],
            "dns.qry.name": ["secure.example.org"]
          }
        }
      }
    ]));
  } else {
    console.log(JSON.stringify([
      {
        _source: {
          layers: {
            "frame.number": ["1"],
            "ip.src": ["192.168.1.100"],
            "ip.dst": ["8.8.8.8"],
            "dns.qry.name": ["api.example.com"]
          }
        }
      },
      {
        _source: {
          layers: {
            "frame.number": ["2"],
            "ip.src": ["192.168.1.100", "192.168.1.101"],
            "ip.dst": ["1.1.1.1"],
            "dns.qry.name": ["gateway.example.com"]
          }
        }
      }
    ]));
  }
}
`,
  );
  await chmod(script, 0o700);

  const provider = new TsharkCaptureProvider(
    {
      ...process.env,
      REA_TSHARK_COMMAND: script,
      ...(platform === "linux"
        ? { REA_TSHARK_PRLIMIT_COMMAND: script }
        : {}),
    },
    async (spawnInput) => {
      capturedSpawnOptions.push(spawnInput);
      return spawnOwnedProviderProcess({
        ...spawnInput,
        command: process.execPath,
        arguments: [script, ...spawnInput.arguments],
        expectedCommand: process.execPath,
      });
    },
    async () => {
      const root = await PrivateRuntimeRoot.create({
        parent: directory,
        prefix: "tshark-workspace-",
      });
      return {
        path: root.path,
        close: async () => root.close(),
      };
    },
    platform,
    readStableArtifact,
    async (limits) => ({
      ...limits,
      address_space_bytes: 1073741824,
      file_bytes: 67108864,
      cpu_seconds: 30,
    }),
  );

  onTestFinished(async () => {
    await provider.close();
  });

  const service = new PacketCaptureService(provider);
  return {
    service,
    provider,
    directory,
    pcapPath,
    pcapngPath,
    capturedSpawnOptions: () => capturedSpawnOptions,
  };
};

describe("TShark Offline Host Support & Decoupling", () => {
  it("admits offline capture analysis on Windows and Linux", () => {
    expect(tsharkHostSupported("linux")).toBe(true);
    expect(tsharkHostSupported("win32")).toBe(true);
    expect(tsharkOfflineCaptureSupported("linux")).toBe(true);
    expect(tsharkOfflineCaptureSupported("win32")).toBe(true);
  });

  it("refuses unsupported hosts before launch or workspace allocation", () => {
    expect(tsharkHostSupported("darwin")).toBe(false);
    expect(tsharkHostSupported("freebsd")).toBe(false);
    expect(tsharkOfflineCaptureSupported("darwin")).toBe(false);
  });

  it("separates user-space offline analysis from driver-dependent live capture", () => {
    // Offline capture never requires Npcap/WinPcap
    expect(tsharkOfflineCaptureSupported("win32")).toBe(true);
    // Live capture on Windows requires Npcap driver
    expect(tsharkLiveCaptureSupported("win32", false)).toBe(false);
    expect(tsharkLiveCaptureSupported("win32", true)).toBe(true);
    // Live capture on Linux uses OS capture capabilities
    expect(tsharkLiveCaptureSupported("linux")).toBe(true);
  });

  it("throws capability unavailable on unsupported platforms", async () => {
    const provider = new TsharkCaptureProvider(
      { REA_TSHARK_COMMAND: process.execPath },
      async () => {
        throw new Error("Must not launch");
      },
      async () => {
        throw new Error("Must not allocate workspace");
      },
      "darwin",
    );
    const service = new PacketCaptureService(provider);
    onTestFinished(() => service.close());

    const result = await service.inspect({
      path: "/dummy.pcap",
      fields: ["frame.number"],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error._tag).toBe("AnalysisCapabilityUnavailableError");
      expect((result.error as { reason?: string }).reason).toContain("Linux");
    }
  });
});

describe("Windows Offline Capture Analysis (platform = win32)", () => {
  it("runs offline analysis without requiring prlimit", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src", "ip.dst"],
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);

    // On Windows, resource_limiter is null because no prlimit binary is used
    expect(report.resource_limiter).toBeNull();
    // Limits are reported and conform to REA native bounded producer profile
    expect(report.limits).toMatchObject({
      input_bytes: 33554432,
      output_bytes: 4194304,
      command_timeout_ms: 30000,
      address_space_bytes: 1073741824,
      file_bytes: 67108864,
      cpu_seconds: 30,
    });
    // Packets are decoded accurately
    expect(report.packets).toHaveLength(2);
    expect(report.packets[0]?.["frame.number"]).toEqual(["1"]);
    expect(report.packets[0]?.["ip.src"]).toEqual(["192.168.1.100"]);
    expect(report.packets[0]?.["ip.dst"]).toEqual(["8.8.8.8"]);
  });

  it("applies native REA memory bound (Job Object) to owned process spawn", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
    });

    if (!result.ok) throw result.error;
    const spawns = f.capturedSpawnOptions();
    // Spawns happened (version probe + inspection)
    expect(spawns.length).toBeGreaterThanOrEqual(2);
    // Every spawn on Windows receives memoryLimitBytes = 1 GiB
    for (const spawn of spawns) {
      expect(spawn.memoryLimitBytes).toBe(1073741824);
    }
  });

  it("includes Windows user-space and Job Object limitations in the report", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
    });

    if (!result.ok) throw result.error;
    const limitations = result.value.limitations;
    expect(
      limitations.some(
        (text) =>
          text.includes("Windows offline capture analysis runs in user space") &&
          text.includes("without requiring Npcap or WinPcap") &&
          text.includes("Job Object committed memory (1 GiB)"),
      ),
    ).toBe(true);
  });
});

describe("Wireshark Display Filter (-Y)", () => {
  it("passes -Y <display_filter> to TShark CLI arguments", async () => {
    const f = await createTsharkFixture({
      platform: "win32",
      mode: "filtered",
    });
    const filter = "dns.qry.name == 'secure.example.org'";
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["dns.qry.name", "ip.src"],
      display_filter: filter,
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);

    // Verify tool arguments contain the display filter
    expect(report.tool.arguments).toContain("-Y");
    const yIndex = report.tool.arguments.indexOf("-Y");
    expect(report.tool.arguments[yIndex + 1]).toBe(filter);

    // Verify filtered output
    expect(report.selection.display_filter).toBe(filter);
    expect(report.packets).toHaveLength(1);
    expect(report.packets[0]?.["dns.qry.name"]).toEqual([
      "secure.example.org",
    ]);
  });

  it("omits -Y when display_filter is null", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
      display_filter: null,
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);
    expect(report.tool.arguments).not.toContain("-Y");
  });

  it("handles filter matching zero packets cleanly", async () => {
    const f = await createTsharkFixture({
      platform: "win32",
      mode: "empty",
    });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
      display_filter: "ip.addr == 10.254.254.254",
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);
    expect(report.packets).toEqual([]);
    expect(report.output_window.matching_packets).toBe(0);
    expect(report.output_window.returned_packets).toBe(0);
    expect(report.output_window.has_more).toBe(false);
  });
});

describe("Structured Field Extraction (-T json / -e <field>)", () => {
  it("structures multi-field extraction into typed string arrays", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src", "ip.dst", "dns.qry.name"],
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);

    // Verify CLI arguments include -T json and -e for each field
    expect(report.tool.arguments).toContain("-T");
    expect(report.tool.arguments).toContain("json");
    expect(report.tool.arguments).toContain("--no-duplicate-keys");
    expect(report.tool.arguments).toContain("-e");
    expect(report.tool.arguments).toContain("frame.number");
    expect(report.tool.arguments).toContain("ip.src");
    expect(report.tool.arguments).toContain("ip.dst");
    expect(report.tool.arguments).toContain("dns.qry.name");

    // Verify frame.number is always present
    expect(report.packets[0]?.["frame.number"]).toEqual(["1"]);
    expect(report.packets[1]?.["frame.number"]).toEqual(["2"]);

    // Verify repeated field preservation (ip.src in frame 2 has 2 addresses)
    expect(report.packets[1]?.["ip.src"]).toEqual([
      "192.168.1.100",
      "192.168.1.101",
    ]);
  });

  it("supports two-pass analysis flag (-2) and packet limit (-c)", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
      two_pass: true,
      packet_limit: 100,
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);
    expect(report.tool.arguments).toContain("-2");
    expect(report.tool.arguments).toContain("-c");
    expect(report.tool.arguments).toContain("100");
  });
});

describe("Linux Offline Capture Conformance (platform = linux)", () => {
  it("uses prlimit and populates resource_limiter on Linux", async () => {
    const f = await createTsharkFixture({ platform: "linux" });
    const result = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
    });

    if (!result.ok) throw result.error;
    const report = packetCaptureSchema.parse(result.value.normalized_result);

    // On Linux, resource_limiter is present and populated
    expect(report.resource_limiter).not.toBeNull();
    expect(report.resource_limiter?.path).toBeDefined();
    expect(report.resource_limiter?.arguments).toContain("--as=1073741824:1073741824");
    expect(report.resource_limiter?.arguments).toContain("--fsize=67108864:67108864");
    expect(report.resource_limiter?.arguments).toContain("--core=0:0");
  });
});

describe("PCAP and PCAPNG Format Parity", () => {
  it("analyzes .pcap files identically to .pcapng files", async () => {
    const f = await createTsharkFixture({ platform: "win32" });

    const pcapResult = await f.service.inspect({
      path: f.pcapPath,
      fields: ["ip.src"],
    });
    const pcapngResult = await f.service.inspect({
      path: f.pcapngPath,
      fields: ["ip.src"],
    });

    if (!pcapResult.ok) throw pcapResult.error;
    if (!pcapngResult.ok) throw pcapngResult.error;

    const pcapReport = packetCaptureSchema.parse(pcapResult.value.normalized_result);
    const pcapngReport = packetCaptureSchema.parse(pcapngResult.value.normalized_result);

    expect(pcapReport.packets).toEqual(pcapngReport.packets);
    expect(pcapReport.output_window).toEqual(pcapngReport.output_window);
    expect(pcapReport.read_scope).toBe("to-eof");
    expect(pcapngReport.read_scope).toBe("to-eof");
  });
});

describe("TShark Field Definition Discovery (-G fields)", () => {
  it("discovers installed protocol and field definitions on Windows without capture", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspectFields({
      kind: "protocols",
    });

    if (!result.ok) throw result.error;
    const report = packetFieldsCatalogSchema.parse(result.value.normalized_result);

    expect(report.resource_limiter).toBeNull();
    expect(report.records.length).toBeGreaterThan(0);
    expect(report.records[0]?.kind).toBe("protocol");
    expect(report.records[0]?.abbreviation).toBe("ip");
  });

  it("discovers field registrations with filtering on Windows", async () => {
    const f = await createTsharkFixture({ platform: "win32" });
    const result = await f.service.inspectFields({
      kind: "fields",
      query: "ip.src",
    });

    if (!result.ok) throw result.error;
    const report = packetFieldsCatalogSchema.parse(result.value.normalized_result);

    expect(report.records).toHaveLength(1);
    expect(report.records[0]?.abbreviation).toBe("ip.src");
    expect(report.records[0]?.parent_protocol).toBe("ip");
  });
});
