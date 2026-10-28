import { constants, accessSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "../domain/result.js";
import { ConfigurationError } from "../domain/configurationErrors.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";

/** Resolved configuration for x64dbg / x32dbg installation on Windows. */
export interface X64DbgConfiguration {
  readonly installDir: string;
  readonly x32ExePath: string | null;
  readonly x64ExePath: string | null;
  readonly launcherPath: string | null;
  readonly ipcPipeName: string;
  readonly mode: "script" | "ipc";
}

export interface X64DbgResolveOptions {
  readonly installDir?: string | undefined;
  readonly x32ExePath?: string | undefined;
  readonly x64ExePath?: string | undefined;
  readonly mode?: ("script" | "ipc") | undefined;
  readonly ipcPipeName?: string | undefined;
  readonly platform?: NodeJS.Platform | undefined;
  readonly fileExists?: ((path: string) => boolean) | undefined;
}

/** Standard Windows installation directories for x64dbg. */
export const DEFAULT_X64DBG_INSTALL_DIRS: readonly string[] = [
  "C:\\Program Files\\x64dbg\\release",
  "C:\\Program Files (x86)\\x64dbg\\release",
  "C:\\tools\\x64dbg\\release",
  "C:\\x64dbg\\release",
];

export const DEFAULT_X64DBG_IPC_PIPE = "\\\\.\\pipe\\x64dbg";

/**
 * Resolve x64dbg/x32dbg configuration by probing environment variables and directories.
 */
export const resolveX64DbgConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: X64DbgResolveOptions = {},
): Result<X64DbgConfiguration, ConfigurationError> => {
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

  let installDir: string | undefined =
    options.installDir ??
    environment.X64DBG_PATH ??
    environment.X64DBG_INSTALL_DIR;

  if (installDir === undefined) {
    for (const dir of DEFAULT_X64DBG_INSTALL_DIRS) {
      if (fileExists(dir)) {
        installDir = dir;
        break;
      }
    }
  }

  if (installDir === undefined && !options.x32ExePath && !options.x64ExePath) {
    return err(
      new ConfigurationError(
        "x64dbg installation directory not found. Set X64DBG_PATH or install to a standard location.",
        {
          settings: [
            {
              setting: "X64DBG_PATH",
              constraint: "must point to x64dbg release directory",
            },
          ],
          remediationAction:
            "Install x64dbg or set the X64DBG_PATH environment variable to the directory containing x32 and x64 builds.",
        },
      ),
    );
  }

  const resolvedDir = installDir ?? "C:\\x64dbg\\release";
  const defaultX32 = join(resolvedDir, "x32", "x32dbg.exe");
  const defaultX64 = join(resolvedDir, "x64", "x64dbg.exe");
  const defaultLauncher = join(resolvedDir, "x96dbg.exe");

  const x32ExePath =
    options.x32ExePath ?? (fileExists(defaultX32) ? defaultX32 : null);
  const x64ExePath =
    options.x64ExePath ?? (fileExists(defaultX64) ? defaultX64 : null);
  const launcherPath = fileExists(defaultLauncher) ? defaultLauncher : null;

  return ok({
    installDir: resolvedDir,
    x32ExePath,
    x64ExePath,
    launcherPath,
    ipcPipeName: options.ipcPipeName ?? DEFAULT_X64DBG_IPC_PIPE,
    mode: options.mode ?? "script",
  });
};

/**
 * Select the appropriate executable (x32dbg vs x64dbg) based on the target PE architecture.
 */
export const selectX64DbgExecutable = (
  config: X64DbgConfiguration,
  target: BinaryTarget,
): Result<string, ConfigurationError> => {
  if (target.format !== "pe") {
    return err(
      new ConfigurationError(
        `x64dbg only supports PE binaries; target format is ${target.format}.`,
      ),
    );
  }

  if (target.architecture === "x86") {
    if (!config.x32ExePath) {
      return err(
        new ConfigurationError(
          "Target is a 32-bit PE binary, but x32dbg.exe was not found in the x64dbg installation.",
          {
            settings: [
              {
                setting: "x32ExePath",
                constraint: "x32dbg.exe must be present",
              },
            ],
            remediationAction:
              "Ensure the x32 directory exists within your x64dbg installation.",
          },
        ),
      );
    }
    return ok(config.x32ExePath);
  }

  if (target.architecture === "x86_64") {
    if (!config.x64ExePath) {
      return err(
        new ConfigurationError(
          "Target is a 64-bit PE binary, but x64dbg.exe was not found in the x64dbg installation.",
          {
            settings: [
              {
                setting: "x64ExePath",
                constraint: "x64dbg.exe must be present",
              },
            ],
            remediationAction:
              "Ensure the x64 directory exists within your x64dbg installation.",
          },
        ),
      );
    }
    return ok(config.x64ExePath);
  }

  return err(
    new ConfigurationError(
      `x64dbg does not support architecture ${target.architecture ?? "unknown"}. Only x86 and x86_64 are supported.`,
    ),
  );
};
