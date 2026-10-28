import { describe, expect, it } from "vitest";
import { BinaryNinjaClient } from "../../../../src/binaryninja/BinaryNinjaClient.js";
import type { BinaryNinjaConfiguration } from "../../../../src/binaryninja/BinaryNinjaConfiguration.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import { ok } from "../../../../src/domain/result.js";

const makeConfig = (
  overrides: Partial<BinaryNinjaConfiguration["license"]> = {},
): BinaryNinjaConfiguration => ({
  installPath: "/opt/binaryninja",
  binaryPath: "/opt/binaryninja/binaryninja",
  pythonPath: "/usr/bin/python3",
  version: "4.0",
  license: {
    licenseType: "commercial",
    valid: true,
    headlessSupported: true,
    hlilSupported: true,
    xrefsSupported: true,
    ...overrides,
  },
});

const makeTarget = (): BinaryTarget =>
  ({
    path: "/tmp/sample.elf",
    sha256: "c".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  }) as BinaryTarget;

describe("Binary Ninja Client Operations", () => {
  it("executes list_procedures and returns structured procedure inventory", async () => {
    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const res = await client.execute("list_procedures", {});
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    expect(res.value.provider.id).toBe("binaryninja");
    const procs = res.value.result as Array<{ name: string; address: string }>;
    expect(procs.some((p) => p.name === "main")).toBe(true);
    expect(procs.some((p) => p.name === "_start")).toBe(true);
  });

  it("executes procedure_pseudo_code and returns HLIL decompilation", async () => {
    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const res = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    const hlil = res.value.result as {
      procedure: string;
      language: string;
      code: string;
    };
    expect(hlil.procedure).toBe("main");
    expect(hlil.language).toBe("hlil");
    expect(hlil.code).toContain("int64_t main");
  });

  it("executes analyze_function and returns unified function dossier", async () => {
    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const res = await client.execute("analyze_function", {
      procedure: "main",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");

    const dossier = res.value.result as {
      name: string;
      entry_point: string;
      assembly: string;
      pseudo_code: string;
    };
    expect(dossier.name).toBe("main");
    expect(dossier.pseudo_code).toContain("main()");
  });

  it("executes list_strings and search_strings", async () => {
    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const listRes = await client.execute("list_strings", {});
    expect(listRes.ok).toBe(true);
    if (!listRes.ok) throw new Error("expected success");
    const strings = listRes.value.result as Array<{ value: string }>;
    expect(strings.some((s) => s.value === "Hello, World!")).toBe(true);

    const searchRes = await client.execute("search_strings", {
      pattern: "Hello",
    });
    expect(searchRes.ok).toBe(true);
    if (!searchRes.ok) throw new Error("expected success");
    const found = searchRes.value.result as Array<{ value: string }>;
    expect(found).toHaveLength(1);
    expect(found[0]?.value).toBe("Hello, World!");
  });

  it("executes xrefs and procedure caller/callee inspection", async () => {
    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const xrefsRes = await client.execute("xrefs", { address: "0x1040" });
    expect(xrefsRes.ok).toBe(true);
    if (!xrefsRes.ok) throw new Error("expected success");
    const xrefs = xrefsRes.value.result as Array<{
      from_address: string;
      type: string;
    }>;
    expect(xrefs[0]?.type).toBe("call");

    const callersRes = await client.execute("procedure_callers", {
      procedure: "main",
    });
    expect(callersRes.ok).toBe(true);
    if (!callersRes.ok) throw new Error("expected success");
    expect(callersRes.value.result).toEqual(["_start"]);
  });

  it("rejects execution with AnalysisCapabilityUnavailableError when headless execution is not licensed", async () => {
    const client = new BinaryNinjaClient(
      makeTarget(),
      makeConfig({
        licenseType: "free",
        headlessSupported: false,
      }),
    );
    const res = await client.execute("list_procedures", {});
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(res.error.message).toContain("headless API privileges");
  });

  it("rejects HLIL decompilation when HLIL is not supported by license", async () => {
    const client = new BinaryNinjaClient(
      makeTarget(),
      makeConfig({
        hlilSupported: false,
      }),
    );
    const res = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(res.error.message).toContain("HLIL");
  });

  it("honors AbortSignal and aborts immediately", async () => {
    const controller = new AbortController();
    controller.abort(new Error("Analysis cancelled by user"));

    const client = new BinaryNinjaClient(makeTarget(), makeConfig());
    const res = await client.execute(
      "list_procedures",
      {},
      { signal: controller.signal },
    );
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected cancellation");
    expect(res.error._tag).toBe("AnalysisCancelledError");
  });

  it("supports custom injected BinaryNinjaRunner", async () => {
    const customRunner = {
      run: async (op: string) => ok({ custom_result: `executed ${op}` }),
    };

    const client = new BinaryNinjaClient(
      makeTarget(),
      makeConfig(),
      customRunner,
    );
    const res = await client.execute("procedure_assembly", {
      procedure: "foo",
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected success");
    expect(res.value.result).toEqual({
      custom_result: "executed procedure_assembly",
    });
  });
});
