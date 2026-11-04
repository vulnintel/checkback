import { NetError, requestJson, type Http } from "./http.js";

// §8-2. Every helper returns "error" instead of throwing so one failure never stops the scan;
// 429 waits Retry-After once.

export type Exists = "ok" | "missing" | "error" | "offline";

async function get<T>(http: Http, url: string, accept?: string): Promise<{ s: Exists; body?: T }> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return { s: "ok", body: await requestJson<T>(http, url, accept ? { headers: { Accept: accept } } : {}) };
    } catch (e) {
      const err = e as NetError;
      if (err.kind === "offline") return { s: "offline" };
      if (err.kind === "http" && err.status === 404) return { s: "missing" };
      if (err.kind === "http" && err.status === 429 && attempt === 0) {
        await http.sleep(err.retryAfterMs || 1000);
        continue;
      }
      return { s: "error" };
    }
  }
  return { s: "error" };
}

const npmPath = (name: string): string => name.replace("/", "%2F");

export interface NpmAbbrev {
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, { hasInstallScript?: boolean }>;
}

export const npmAbbrev = (http: Http, name: string): Promise<{ s: Exists; body?: NpmAbbrev }> =>
  get<NpmAbbrev>(http, `https://registry.npmjs.org/${npmPath(name)}`, "application/vnd.npm.install-v1+json");

/** Full document — only for edit-distance candidates (has `time.created`). */
export async function npmCreated(http: Http, name: string): Promise<string | null> {
  const r = await get<{ time?: { created?: string } }>(http, `https://registry.npmjs.org/${npmPath(name)}`);
  return r.body?.time?.created ?? null;
}

/** Weekly downloads; 404 / no stats → 0 (U15). */
export async function npmWeeklyDownloads(http: Http, name: string): Promise<number | null> {
  const r = await get<{ downloads?: number }>(http, `https://api.npmjs.org/downloads/point/last-week/${name}`);
  if (r.s === "missing") return 0;
  return r.s === "ok" ? (r.body?.downloads ?? 0) : null;
}

export const pypiExists = async (http: Http, name: string): Promise<Exists> =>
  (await get(http, `https://pypi.org/pypi/${encodeURIComponent(name)}/json`)).s;
