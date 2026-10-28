import { constants, accessSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "../domain/result.js";
import { ConfigurationError } from "../domain/configurationErrors.js";

/** Resolved configuration for Immunity Debugger with verified 32-bit Python 2.7 runtime. */
export interface ImmunityConfiguration {
  readonly installDir: string;
  readonly executablePath: string;
  readonly python27DllPath: string;
  readonly pyCommandsDir: string;
  readonly is32BitRuntime: boolean;
  readonly runtimeValid: boolean;
}

export interface ImmunityResolveOptions {
  readonly installDir?: string | undefined;
  readonly executablePath?: string | undefined;
  readonly python27DllPath?: string | undefined;
  readonly platform?: NodeJS.Platform | undefined;
  readonly fileExists?: ((path: string) => boolean) | undefined;
  readonly readBuffer?: ((path: string) => Buffer) | undefined;
}

export const DEFAULT_IMMUNITY_INSTALL_DIRS: readonly string[] = [
  "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger",
  "C:\\Program Files\\Immunity Inc\\Immunity Debugger",
  "C:\\Immunity Debugger",
];

/** Inspect a PE file buffer to verify if it is a 32-bit x86 binary (machine === 0x014c). */
export const isPe32BitMachine = (buffer: Buffer): boolean => {
  if (buffer.length < 64) return false;
  // Check MZ signature
  if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) return false;

  const peOffset = buffer.readUInt32LE(0x3c);
  if (buffer.length < peOffset + 6) return false;

  // Check PE signature
  if (
    buffer[peOffset] !== 0x50 ||
    buffer[peOffset + 1] !== 0x45 ||
    buffer[peOffset + 2] !== 0 ||
    buffer[peOffset + 3] !== 0
  ) {
    return false;
  }

  const machine = buffer.readUInt16LE(peOffset + 4);
  return machine === 0x014c; // IMAGE_FILE_MACHINE_I386
};

const verifyPython27Dll = (
  candidateDll: string,
  fileExists: (p: string) => boolean,
  readBuffer: (p: string) => Buffer,
): Result<null, ConfigurationError> => {
  if (!fileExists(candidateDll)) {
    return err(
      new ConfigurationError(
        "Immunity Debugger requires python27.dll in its installation directory for immlib scripting support.",
        {
          settings: [
            {
              setting: "python27DllPath",
              constraint:
                "python27.dll must be present in Immunity Debugger directory",
            },
          ],
          remediationAction:
            "Ensure python27.dll is placed in the Immunity Debugger directory.",
        },
      ),
    );
  }

  try {
    const dllBytes = readBuffer(candidateDll);
    const is32Bit = isPe32BitMachine(dllBytes);

    if (!is32Bit) {
      return err(
        new ConfigurationError(
          "Immunity Debugger requires a 32-bit Python 2.7 runtime (python27.dll) for immlib support; a 64-bit DLL was found.",
          {
            settings: [
              {
                setting: "python27DllPath",
                constraint: "python27.dll must be a 32-bit x86 PE binary",
              },
            ],
            remediationAction:
              "Replace python27.dll with the 32-bit x86 release required by Immunity Debugger.",
          },
        ),
      );
    }
  } catch (cause) {
    return err(
      new ConfigurationError(
        `Failed to read python27.dll to verify 32-bit architecture: ${cause instanceof Error ? cause.message : String(cause)}`,
      ),
    );
  }

  return ok(null);
};

/**
 * Resolve Immunity Debugger configuration, enforcing strict verification of
 * python27.dll (must exist and must be 32-bit x86).
 */
export const resolveImmunityConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: ImmunityResolveOptions = {},
): Result<ImmunityConfiguration, ConfigurationError> => {
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

  const readBuffer =
    options.readBuffer ??
    ((p: string) => {
      return readFileSync(p);
    });

  let installDir: string | undefined =
    options.installDir ??
    environment.IMMUNITY_PATH ??
    environment.IMMUNITY_INSTALL_DIR;

  if (installDir === undefined) {
    for (const dir of DEFAULT_IMMUNITY_INSTALL_DIRS) {
      if (fileExists(dir)) {
        installDir = dir;
        break;
      }
    }
  }

  const resolvedDir =
    installDir ?? "C:\\Program Files (x86)\\Immunity Inc\\Immunity Debugger";
  const defaultExe = join(resolvedDir, "ImmunityDebugger.exe");
  const executablePath = options.executablePath ?? defaultExe;

  if (!fileExists(executablePath)) {
    return err(
      new ConfigurationError(
        "Immunity Debugger executable not found. Set IMMUNITY_PATH or install Immunity Debugger.",
        {
          settings: [
            {
              setting: "IMMUNITY_PATH",
              constraint: "must point to valid Immunity Debugger directory",
            },
          ],
          remediationAction:
            "Install Immunity Debugger 32-bit or set IMMUNITY_PATH to its installation folder.",
        },
      ),
    );
  }

  const candidateDll =
    options.python27DllPath ?? join(resolvedDir, "python27.dll");

  const dllCheck = verifyPython27Dll(candidateDll, fileExists, readBuffer);
  if (!dllCheck.ok) {
    return err(dllCheck.error);
  }

  const pyCommandsDir = join(resolvedDir, "PyCommands");

  return ok({
    installDir: resolvedDir,
    executablePath,
    python27DllPath: candidateDll,
    pyCommandsDir,
    is32BitRuntime: true,
    runtimeValid: true,
  });
};
