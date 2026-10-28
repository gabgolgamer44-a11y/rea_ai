import { describe, expect, it } from "vitest";
import {
  parseBinaryNinjaLicense,
  resolveBinaryNinjaConfiguration,
} from "../../../../src/binaryninja/BinaryNinjaConfiguration.js";

describe("Binary Ninja Configuration & License Parser", () => {
  it("parses commercial license JSON with headless and HLIL support", () => {
    const raw = JSON.stringify({
      product: "Binary Ninja Commercial",
      type: "commercial",
      serial: "BN-COMM-12345",
      name: "Acme Corp",
      valid: true,
      headlessSupported: true,
      hlilSupported: true,
      xrefsSupported: true,
    });
    const license = parseBinaryNinjaLicense(raw);
    expect(license.valid).toBe(true);
    expect(license.licenseType).toBe("commercial");
    expect(license.headlessSupported).toBe(true);
    expect(license.hlilSupported).toBe(true);
    expect(license.xrefsSupported).toBe(true);
    expect(license.serial).toBe("BN-COMM-12345");
  });

  it("parses enterprise and ultimate licenses with headless support", () => {
    const enterprise = parseBinaryNinjaLicense(
      '{"product": "Binary Ninja Enterprise"}',
    );
    expect(enterprise.licenseType).toBe("enterprise");
    expect(enterprise.headlessSupported).toBe(true);
    expect(enterprise.hlilSupported).toBe(true);

    const ultimate = parseBinaryNinjaLicense(
      '{"product": "Binary Ninja Ultimate"}',
    );
    expect(ultimate.licenseType).toBe("ultimate");
    expect(ultimate.headlessSupported).toBe(true);
    expect(ultimate.hlilSupported).toBe(true);
  });

  it("identifies Free and Demo licenses as lacking headless API authorization", () => {
    const freeLic = parseBinaryNinjaLicense('{"product": "Binary Ninja Free"}');
    expect(freeLic.licenseType).toBe("free");
    expect(freeLic.headlessSupported).toBe(false);

    const demoLic = parseBinaryNinjaLicense("Binary Ninja Demo Edition");
    expect(demoLic.licenseType).toBe("demo");
    expect(demoLic.headlessSupported).toBe(false);
  });

  it("handles empty or invalid license input safely", () => {
    const empty = parseBinaryNinjaLicense("");
    expect(empty.valid).toBe(false);
    expect(empty.headlessSupported).toBe(false);
    expect(empty.licenseType).toBe("unknown");
  });

  it("resolves configuration from custom options and file probes", () => {
    const res = resolveBinaryNinjaConfiguration(
      {},
      {
        installPath: "/opt/binaryninja",
        pythonPath: "/usr/bin/python3",
        licenseOverride: {
          licenseType: "commercial",
          valid: true,
          headlessSupported: true,
          hlilSupported: true,
          xrefsSupported: true,
        },
        fileExists: (p) => p === "/opt/binaryninja",
      },
    );

    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("expected resolution");
    expect(res.value.installPath).toBe("/opt/binaryninja");
    expect(res.value.license.headlessSupported).toBe(true);
    expect(res.value.license.licenseType).toBe("commercial");
  });

  it("fails closed when installation path is not found", () => {
    const res = resolveBinaryNinjaConfiguration(
      {},
      {
        installPath: "/nonexistent/binaryninja",
        fileExists: () => false,
      },
    );

    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("expected failure");
    expect(res.error.message).toContain("not found");
  });
});
