import { randomBytes } from "node:crypto";
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
  // Unique per call: two writes of the same file in one process must not share a temp file.
  const tmp = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  await rename(tmp, file);
}

export const CONSENT_VERSION = 1;

/** `<appdata>/checkback/config.json` — shared by GUI, MCP and CLI. Written with mode 600. */
export interface LocalConfig {
  consent?: { at: string; version: number };
  lang?: "ko" | "en";
  /** External lookups, each on by default once consent is given (§3-1). */
  external?: { osv?: boolean; registry?: boolean; vulnintel?: boolean };
  api_key?: string;
}

export async function readConfig(appDir: string): Promise<LocalConfig> {
  const c = await readJson<unknown>(join(appDir, "config.json"), {});
  return typeof c === "object" && c !== null ? (c as LocalConfig) : {};
}

let configQueue: Promise<unknown> = Promise.resolve();

/**
 * Read-modify-write, serialized within the process: concurrent updates (GUI consent, then a language
 * change) each see the previous write, so none is lost.
 * shortcut: no cross-process lock (GUI and MCP running at once can still race); add a lock file if that shows up.
 */
export function updateConfig(appDir: string, patch: Partial<LocalConfig>): Promise<LocalConfig> {
  const run = configQueue.then(async () => {
    const next = { ...(await readConfig(appDir)), ...patch };
    await writeJson(join(appDir, "config.json"), next);
    return next;
  });
  configQueue = run.catch(() => undefined);
  return run;
}

export const hasConsent = (c: LocalConfig): boolean => (c.consent?.version ?? 0) >= CONSENT_VERSION;

/** Environment variable first, then the config file (§10-4). */
export const apiKeyOf = (c: LocalConfig): string | undefined => process.env.VULNINTEL_API_KEY || c.api_key || undefined;

/**
 * Per-install HMAC key for value hashes. Value hashes end up in appdata (ignores, snapshots);
 * a keyed hash keeps low-entropy secrets (weak DB passwords) from being brute-forced from them.
 */
export async function installKey(appDir: string): Promise<Buffer> {
  const file = join(appDir, "install.key");
  try {
    const k = await readFile(file);
    if (k.length === 32) return k;
  } catch {
    // create below
  }
  await mkdir(appDir, { recursive: true });
  const key = randomBytes(32);
  try {
    await writeFile(file, key, { flag: "wx", mode: 0o600 });
    return key;
  } catch {
    return readFile(file); // another process created it first
  }
}
