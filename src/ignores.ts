import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { defaultAppDir, projectKey, readJson, writeJson } from "./appdata.js";
import { readLastScan } from "./recheck.js";
import type { Finding } from "./types.js";

export interface IgnoreEntry {
  /** Finding id (fingerprint). */
  id: string;
  reason: string;
  at: string;
  /** "title — package@version · file:line" from the last scan, so the list says what was ignored. Absent in older entries. */
  label?: string;
}

async function ignoreFile(cwd: string, appDir: string): Promise<string> {
  return join(appDir, "ignores", `${projectKey(await realpath(resolve(cwd)))}.json`);
}

/** Title, package@version and file:line; missing parts are left out. Never a value. */
export function findingLabel(f: Pick<Finding, "title" | "package" | "version" | "location">): string {
  const pkg = f.package ? `${f.package}${f.version ? `@${f.version}` : ""}` : "";
  const where = f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "";
  const tail = [pkg, where].filter(Boolean).join(" · ");
  return tail ? `${f.title} — ${tail}` : f.title;
}

export async function listIgnores(cwd: string, appDir = defaultAppDir()): Promise<IgnoreEntry[]> {
  const list = await readJson<unknown>(await ignoreFile(cwd, appDir), []);
  return Array.isArray(list) ? list.filter((e): e is IgnoreEntry => typeof e?.id === "string") : [];
}

export async function addIgnore(cwd: string, id: string, reason: string, appDir = defaultAppDir()): Promise<void> {
  const list = (await listIgnores(cwd, appDir)).filter((e) => e.id !== id);
  const f = (await readLastScan(cwd, appDir))?.findings.find((x) => x.id === id);
  list.push({ id, reason: reason.slice(0, 500), at: new Date().toISOString(), ...(f && { label: findingLabel(f) }) });
  await writeJson(await ignoreFile(cwd, appDir), list);
}

export async function removeIgnore(cwd: string, id: string, appDir = defaultAppDir()): Promise<void> {
  const list = (await listIgnores(cwd, appDir)).filter((e) => e.id !== id);
  await writeJson(await ignoreFile(cwd, appDir), list);
}
