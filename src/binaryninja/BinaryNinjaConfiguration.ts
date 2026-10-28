import { constants, accessSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "../domain/result.js";
import { ConfigurationError } from "../domain/configurationErrors.js";

/** Binary Ninja commercial / non-commercial license tiers. */
export type BinaryNinjaLicenseType =
  | "commercial"
  | "enterprise"
  | "non-commercial"
  | "ultimate"
  | "free"
  | "demo"
  | "unknown";

/** Verified facts regarding the installed Binary Ninja license. */
export interface BinaryNinjaLicenseInfo {
  readonly licenseType: BinaryNinjaLicenseType;
  readonly serial?: string | undefined;
  readonly name?: string | undefined;
  readonly valid: boolean;
  /** Whether this license admits headless Python API / CLI automation. */
  readonly headlessSupported: boolean;
  /** Whether the HLIL (High-Level Intermediate Language) decompiler is licensed. */
  readonly hlilSupported: boolean;
  /** Whether cross-reference analysis is supported. */
  readonly xrefsSupported: boolean;
  readonly expirationDate?: string | undefined;
}

/** Resolved configuration for Binary Ninja and its Python integration. */
export interface BinaryNinjaConfiguration {
  readonly installPath: string;
  readonly binaryPath: string;
  readonly pythonPath: string;
  readonly license: BinaryNinjaLicenseInfo;
  readonly version: string | null;
  readonly channel?: string | undefined;
}

export interface BinaryNinjaResolveOptions {
  readonly installPath?: string | undefined;
  readonly pythonPath?: string | undefined;
  readonly licenseDatPath?: string | undefined;
  readonly licenseOverride?: Partial<BinaryNinjaLicenseInfo> | undefined;
  readonly platform?: NodeJS.Platform | undefined;
  readonly fileExists?: ((path: string) => boolean) | undefined;
  readonly readFile?: ((path: string) => string) | undefined;
}

/** Standard installation paths across supported platforms. */
export const DEFAULT_BINARYNINJA_INSTALL_PATHS: Record<
  string,
  readonly string[]
> = {
  win32: [
    "C:\\Program Files\\Vector35\\BinaryNinja",
    "C:\\Users\\User\\AppData\\Local\\Programs\\Vector35\\BinaryNinja",
  ],
  darwin: [
    "/Applications/Binary Ninja.app/Contents/MacOS",
    "/Applications/BinaryNinja.app/Contents/MacOS",
  ],
  linux: ["/opt/binaryninja", "/usr/local/binaryninja"],
};

const parseTierFromText = (text: string): BinaryNinjaLicenseType => {
  const lower = text.toLowerCase();
  if (lower.includes("enterprise")) return "enterprise";
  if (lower.includes("ultimate")) return "ultimate";
  if (lower.includes("commercial")) return "commercial";
  if (lower.includes("non-commercial") || lower.includes("student"))
    return "non-commercial";
  if (lower.includes("free")) return "free";
  if (lower.includes("demo")) return "demo";
  return "unknown";
};

const parseJsonLicense = (
  parsed: Record<string, unknown>,
): BinaryNinjaLicenseInfo => {
  const typeStr = String(
    parsed.licenseType ?? parsed.type ?? parsed.product ?? "",
  );
  const licenseType = parseTierFromText(typeStr);
  const isFreeOrDemo = licenseType === "free" || licenseType === "demo";

  const explicitHeadless =
    typeof parsed.headlessSupported === "boolean"
      ? parsed.headlessSupported
      : !isFreeOrDemo && licenseType !== "unknown";

  const explicitHlil =
    typeof parsed.hlilSupported === "boolean"
      ? parsed.hlilSupported
      : !isFreeOrDemo;

  return {
    licenseType,
    serial: typeof parsed.serial === "string" ? parsed.serial : undefined,
    name: typeof parsed.name === "string" ? parsed.name : undefined,
    valid: parsed.valid !== false,
    headlessSupported: explicitHeadless,
    hlilSupported: explicitHlil,
    xrefsSupported: parsed.xrefsSupported !== false,
    expirationDate:
      typeof parsed.expirationDate === "string"
        ? parsed.expirationDate
        : undefined,
  };
};

const parseTextLicense = (raw: string): BinaryNinjaLicenseInfo => {
  const licenseType = parseTierFromText(raw);
  const isFreeOrDemo = licenseType === "free" || licenseType === "demo";
  const headlessSupported = !isFreeOrDemo && licenseType !== "unknown";

  return {
    licenseType,
    valid: true,
    headlessSupported,
    hlilSupported: !isFreeOrDemo,
    xrefsSupported: !isFreeOrDemo,
  };
};

/**
 * Inspect raw license data (e.g. from license.dat or license string)
 * to determine license tier and headless automation rights.
 */
export const parseBinaryNinjaLicense = (
  rawContent: string,
): BinaryNinjaLicenseInfo => {
  const trimmed = rawContent.trim();
  if (trimmed.length === 0) {
    return {
      licenseType: "unknown",
      valid: false,
      headlessSupported: false,
      hlilSupported: false,
      xrefsSupported: false,
    };
  }

  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    return parseJsonLicense(parsed);
  } catch {
    return parseTextLicense(trimmed);
  }
};

const findBinaryNinjaInstallDir = (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: BinaryNinjaResolveOptions,
  platform: NodeJS.Platform,
  fileExists: (p: string) => boolean,
): string | undefined => {
  const candidate =
    options.installPath ??
    environment.BINARYNINJA_PATH ??
    environment.BN_INSTALL_DIR;

  if (candidate !== undefined) {
    return fileExists(candidate) ? candidate : undefined;
  }

  const defaults = DEFAULT_BINARYNINJA_INSTALL_PATHS[platform] ?? [];
  for (const dir of defaults) {
    if (fileExists(dir)) return dir;
  }

  return undefined;
};

interface LicenseContext {
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly options: BinaryNinjaResolveOptions;
  readonly installDir: string;
  readonly fileExists: (p: string) => boolean;
  readonly readFile: (p: string) => string;
}

const readLicenseContent = (ctx: LicenseContext): string | null => {
  if (ctx.environment.BN_LICENSE) {
    return ctx.environment.BN_LICENSE;
  }

  const candidateLicensePaths: string[] = [];
  if (ctx.options.licenseDatPath) {
    candidateLicensePaths.push(ctx.options.licenseDatPath);
  }
  if (ctx.environment.BINARYNINJA_LICENSE_PATH) {
    candidateLicensePaths.push(ctx.environment.BINARYNINJA_LICENSE_PATH);
  }
  candidateLicensePaths.push(join(ctx.installDir, "license.dat"));

  const home =
    ctx.environment.USERPROFILE ??
    ctx.environment.HOME ??
    ctx.environment.APPDATA;
  if (home) {
    candidateLicensePaths.push(join(home, ".binaryninja", "license.dat"));
    candidateLicensePaths.push(
      join(home, "AppData", "Roaming", "Binary Ninja", "license.dat"),
    );
  }

  for (const licPath of candidateLicensePaths) {
    if (!ctx.fileExists(licPath)) continue;
    try {
      return ctx.readFile(licPath);
    } catch {
      // best-effort read
    }
  }

  return null;
};

const resolveLicenseInfo = (ctx: LicenseContext): BinaryNinjaLicenseInfo => {
  if (ctx.options.licenseOverride) {
    return {
      licenseType: ctx.options.licenseOverride.licenseType ?? "commercial",
      valid: ctx.options.licenseOverride.valid ?? true,
      headlessSupported: ctx.options.licenseOverride.headlessSupported ?? true,
      hlilSupported: ctx.options.licenseOverride.hlilSupported ?? true,
      xrefsSupported: ctx.options.licenseOverride.xrefsSupported ?? true,
      serial: ctx.options.licenseOverride.serial,
      name: ctx.options.licenseOverride.name,
      expirationDate: ctx.options.licenseOverride.expirationDate,
    };
  }

  const licenseContent = readLicenseContent(ctx);
  if (licenseContent !== null) {
    return parseBinaryNinjaLicense(licenseContent);
  }

  return {
    licenseType: "unknown",
    valid: false,
    headlessSupported: false,
    hlilSupported: false,
    xrefsSupported: false,
  };
};

/**
 * Resolve Binary Ninja configuration by probing installation paths,
 * Python environment, and headless license permissions.
 */
export const resolveBinaryNinjaConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: BinaryNinjaResolveOptions = {},
): Result<BinaryNinjaConfiguration, ConfigurationError> => {
  const platform = options.platform ?? process.platform;
  const fileExists =
    options.fileExists ??
    ((p: string) => {
      try {
        accessSync(p, constants.F_OK);
        return true;
      } catch {
        return false;
      }
    });
  const readFile =
    options.readFile ??
    ((p: string) => {
      return readFileSync(p, "utf8");
    });

  const installDir = findBinaryNinjaInstallDir(
    environment,
    options,
    platform,
    fileExists,
  );

  if (installDir === undefined) {
    return err(
      new ConfigurationError(
        "Binary Ninja installation directory not found. Set BINARYNINJA_PATH or install to a standard location.",
        {
          settings: [
            {
              setting: "BINARYNINJA_PATH",
              constraint:
                "must point to a valid Binary Ninja installation directory",
            },
          ],
          remediationAction:
            "Install Binary Ninja or specify the directory using the BINARYNINJA_PATH environment variable.",
        },
      ),
    );
  }

  const binaryName = platform === "win32" ? "binaryninja.exe" : "binaryninja";
  const binaryPath = join(installDir, binaryName);

  const pythonPath =
    options.pythonPath ??
    environment.BINARYNINJA_PYTHON ??
    environment.PYTHONPATH ??
    (platform === "win32"
      ? join(installDir, "plugins", "python")
      : join(installDir, "python"));

  const license = resolveLicenseInfo({
    environment,
    options,
    installDir,
    fileExists,
    readFile,
  });

  return ok({
    installPath: installDir,
    binaryPath,
    pythonPath,
    license,
    version: "4.0",
    channel: "stable",
  });
};
