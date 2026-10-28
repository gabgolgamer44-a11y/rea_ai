import { describe, expect, it } from "vitest";
import { BinaryNinjaProvider } from "../../../../src/binaryninja/BinaryNinjaProvider.js";
import type { BinaryNinjaConfiguration } from "../../../../src/binaryninja/BinaryNinjaConfiguration.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";

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

const makeTarget = (overrides: Partial<BinaryTarget> = {}): BinaryTarget =>
  ({
    path: "/tmp/sample.elf",
    sha256: "b".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
    ...overrides,
  }) as BinaryTarget;

describe("Binary Ninja Provider & Capability Reflection", () => {
  it("reports available when configured with a valid headless commercial license", () => {
    const provider = new BinaryNinjaProvider(makeConfig());
    const avail = provider.inspectAvailability();
    expect(avail.status).toBe("available");
    expect(avail.code).toBeNull();
  });

  it("reports runtime_unavailable when installed license is Free edition lacking headless rights", () => {
    const provider = new BinaryNinjaProvider(
      makeConfig({
        licenseType: "free",
        headlessSupported: false,
      }),
    );
    const avail = provider.inspectAvailability();
    expect(avail.status).toBe("unavailable");
    expect(avail.code).toBe("runtime_unavailable");
    expect(avail.reason).toContain("headless API automation");
  });

  it("reports runtime_unavailable when installed license is Demo edition", () => {
    const provider = new BinaryNinjaProvider(
      makeConfig({
        licenseType: "demo",
        headlessSupported: false,
      }),
    );
    const avail = provider.inspectAvailability();
    expect(avail.status).toBe("unavailable");
    expect(avail.code).toBe("runtime_unavailable");
  });

  it("announces all features (HLIL, functions, strings, xrefs) when fully licensed", () => {
    const provider = new BinaryNinjaProvider(makeConfig());
    const capabilities = provider.capabilities();

    const hlilCap = capabilities.find(
      (c) => c.operation === "procedure_pseudo_code",
    );
    expect(hlilCap?.available).toBe(true);
    expect(hlilCap?.reason).toBeNull();

    const analyzeCap = capabilities.find(
      (c) => c.operation === "analyze_function",
    );
    expect(analyzeCap?.available).toBe(true);

    const procsCap = capabilities.find(
      (c) => c.operation === "list_procedures",
    );
    expect(procsCap?.available).toBe(true);

    const stringsCap = capabilities.find((c) => c.operation === "list_strings");
    expect(stringsCap?.available).toBe(true);

    const xrefsCap = capabilities.find((c) => c.operation === "xrefs");
    expect(xrefsCap?.available).toBe(true);
  });

  it("declares HLIL operations unavailable when HLIL is not licensed", () => {
    const provider = new BinaryNinjaProvider(
      makeConfig({
        hlilSupported: false,
      }),
    );
    const capabilities = provider.capabilities();

    const hlilCap = capabilities.find(
      (c) => c.operation === "procedure_pseudo_code",
    );
    expect(hlilCap?.available).toBe(false);
    expect(hlilCap?.reason).toContain("HLIL");

    // Functions and strings should remain available
    const procsCap = capabilities.find(
      (c) => c.operation === "list_procedures",
    );
    expect(procsCap?.available).toBe(true);
    const stringsCap = capabilities.find((c) => c.operation === "list_strings");
    expect(stringsCap?.available).toBe(true);
  });

  it("declares xrefs operations unavailable when xrefs are unsupported", () => {
    const provider = new BinaryNinjaProvider(
      makeConfig({
        xrefsSupported: false,
      }),
    );
    const capabilities = provider.capabilities();

    const xrefsCap = capabilities.find((c) => c.operation === "xrefs");
    expect(xrefsCap?.available).toBe(false);
    expect(xrefsCap?.reason).toContain("Cross-reference");

    const callersCap = capabilities.find(
      (c) => c.operation === "procedure_callers",
    );
    expect(callersCap?.available).toBe(false);
  });

  it("declares all operations unavailable when license is Free edition", () => {
    const provider = new BinaryNinjaProvider(
      makeConfig({
        licenseType: "free",
        headlessSupported: false,
      }),
    );
    const capabilities = provider.capabilities();
    expect(capabilities.every((c) => !c.available)).toBe(true);
    expect(capabilities[0]?.reason).toContain("headless API privileges");
  });

  it("supports standard executable target formats (ELF, PE, Mach-O, raw-binary)", () => {
    const provider = new BinaryNinjaProvider(makeConfig());

    expect(
      provider.inspectTargetSupport(makeTarget({ format: "elf" })),
    ).toMatchObject({
      status: "supported",
    });
    expect(
      provider.inspectTargetSupport(makeTarget({ format: "pe" })),
    ).toMatchObject({
      status: "supported",
    });
    expect(
      provider.inspectTargetSupport(makeTarget({ format: "mach-o" })),
    ).toMatchObject({
      status: "supported",
    });
    expect(
      provider.inspectTargetSupport(makeTarget({ format: "raw-binary" })),
    ).toMatchObject({
      status: "supported",
    });
  });

  it("declines GameCube DOL targets with format rejection", () => {
    const provider = new BinaryNinjaProvider(makeConfig());
    const support = provider.inspectTargetSupport(
      makeTarget({ format: "gamecube-dol", architecture: "powerpc" }),
    );
    expect(support).toMatchObject({
      status: "unsupported",
      code: "target_format_unsupported",
      reason: expect.stringContaining("GameCube DOL"),
    });
  });

  it("declines Hexagon architecture targets", () => {
    const provider = new BinaryNinjaProvider(makeConfig());
    const support = provider.inspectTargetSupport(
      makeTarget({ format: "elf", architecture: "hexagon" }),
    );
    expect(support).toMatchObject({
      status: "unsupported",
      code: "architecture_unsupported",
      reason: expect.stringContaining("Hexagon"),
    });
  });

  it("resolves analysis profile with committed identity", async () => {
    const provider = new BinaryNinjaProvider(makeConfig());
    const target = makeTarget();
    const resolution = await provider.resolveAnalysisProfile(target);
    expect(resolution.ok).toBe(true);
    if (!resolution.ok) throw new Error("expected resolution");
    expect(resolution.value.profile?.provider.id).toBe("binaryninja");
  });
});
