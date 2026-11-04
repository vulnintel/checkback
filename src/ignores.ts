import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { defaultAppDir, projectKey, readJson, writeJson } from "./appdata.js";

export interface IgnoreEntry {
  /** Finding id (fingerprint). */
  id: string;
  reason: string;
  at: string;
}

async function ignoreFile(cwd: string, appDir: string): Promise<string> {
  return join(appDir, "ignores", `${projectKey(await realpath(resolve(cwd)))}.json`);
}

export async function listIgnores(cwd: string, appDir = defaultAppDir()): Promise<IgnoreEntry[]> {
  const list = await readJson<unknown>(await ignoreFile(cwd, appDir), []);
  return Array.isArray(list) ? list.filter((e): e is IgnoreEntry => typeof e?.id === "string") : [];
}

export async function addIgnore(cwd: string, id: string, reason: string, appDir = defaultAppDir()): Promise<void> {
  const list = (await listIgnores(cwd, appDir)).filter((e) => e.id !== id);
  list.push({ id, reason: reason.slice(0, 500), at: new Date().toISOString() });
  await writeJson(await ignoreFile(cwd, appDir), list);
}

export async function removeIgnore(cwd: string, id: string, appDir = defaultAppDir()): Promise<void> {
  const list = (await listIgnores(cwd, appDir)).filter((e) => e.id !== id);
  await writeJson(await ignoreFile(cwd, appDir), list);
}
