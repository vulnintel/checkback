import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { sha256 } from "./secrets.js";

/** `<appdata>/checkback` — never inside the scanned project. */
export function defaultAppDir(): string {
  if (process.platform === "win32") return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "checkback");
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "checkback");
  return join(process.env.XDG_DATA_HOME ?? join(homedir(), ".local", "share"), "checkback");
}

/** Per-project key: hash of the absolute (realpath) project path; case-folded on Windows. */
export function projectKey(absPath: string): string {
  return sha256(process.platform === "win32" ? absPath.toLowerCase() : absPath).slice(0, 32);
}

export async function readJson<T>(file: string, fallback: T): Promise<T> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return fallback;
  }
}

/** Write via temp file + rename so a crash never leaves a half-written file. */
export async function writeJson(file: string, data: unknown): Promise<void> {
  await mkdir(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  await rename(tmp, file);
}
