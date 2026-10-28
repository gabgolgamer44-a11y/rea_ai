import { constants, accessSync } from "node:fs";
import { join } from "node:path";
import { err, ok, type Result } from "../domain/result.js";
import { ConfigurationError } from "../domain/configurationErrors.js";

export type OllyDbgVersion = "1.10" | "2.01";

/** Resolved configuration for OllyDbg (v1.10 or v2.01) with plugin inventory. */
export interface OllyDbgConfiguration {
  readonly executablePath: string;
  readonly version: OllyDbgVersion;
  readonly pluginDir: string;
  readonly odbgScriptPath: string | null;
  readonly odbgScriptAvailable: boolean;
}

export interface OllyDbgResolveOptions {
  readonly executablePath?: string | undefined;
  readonly pluginDir?: string | undefined;
  readonly version?: OllyDbgVersion | undefined;
  readonly platform?: NodeJS.Platform | undefined;
  readonly fileExists?: ((path: string) => boolean) | undefined;
}

export const DEFAULT_OLLYDBG_PATHS: readonly string[] = [
  "C:\\tools\\ollydbg\\OLLYDBG.EXE",
  "C:\\Program Files (x86)\\OllyDbg\\OLLYDBG.EXE",
  "C:\\OllyDbg\\OLLYDBG.EXE",
  "C:\\tools\\ollydbg2\\ollydbg.exe",
  "C:\\Program Files (x86)\\OllyDbg2\\ollydbg.exe",
];

/**
 * Resolve OllyDbg configuration and check for the ODbgScript plugin.
 */
export const resolveOllyDbgConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
  options: OllyDbgResolveOptions = {},
): Result<OllyDbgConfiguration, ConfigurationError> => {
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

  let candidateExe: string | undefined =
    options.executablePath ??
    environment.OLLYDBG_PATH ??
    environment.OLLYDBG_EXE;

  if (candidateExe === undefined) {
    for (const exe of DEFAULT_OLLYDBG_PATHS) {
      if (fileExists(exe)) {
        candidateExe = exe;
        break;
      }
    }
  }

  if (candidateExe === undefined || !fileExists(candidateExe)) {
    return err(
      new ConfigurationError(
        "OllyDbg executable not found. Set OLLYDBG_PATH or install OllyDbg v1.10 or v2.01.",
        {
          settings: [
            {
              setting: "OLLYDBG_PATH",
              constraint:
                "must point to a valid OLLYDBG.EXE or ollydbg.exe binary",
            },
          ],
          remediationAction:
            "Install OllyDbg (v1.10 or v2.01) or set OLLYDBG_PATH to its executable path.",
        },
      ),
    );
  }

  // Detect version
  let version: OllyDbgVersion = options.version ?? "1.10";
  if (!options.version) {
    const lower = candidateExe.toLowerCase();
    if (lower.includes("ollydbg2") || lower.includes("v2")) {
      version = "2.01";
    } else {
      version = "1.10";
    }
  }

  // Detect plugin directory and ODbgScript.dll
  const exeDir = candidateExe.slice(
    0,
    Math.max(0, candidateExe.lastIndexOf("\\")),
  );
  const pluginDir =
    options.pluginDir ??
    (fileExists(join(exeDir, "plugins"))
      ? join(exeDir, "plugins")
      : join(exeDir, "plugin"));

  const candidateScriptDll = join(pluginDir, "ODbgScript.dll");
  const odbgScriptAvailable = fileExists(candidateScriptDll);
  const odbgScriptPath = odbgScriptAvailable ? candidateScriptDll : null;

  return ok({
    executablePath: candidateExe,
    version,
    pluginDir,
    odbgScriptPath,
    odbgScriptAvailable,
  });
};
