import { NetError, requestJson, type Http } from "./http.js";

// §8-2. Every helper returns "error" instead of throwing so one failure never stops the scan;
// 429 waits Retry-After once.

export type Exists = "ok" | "missing" | "error" | "offline";

// Registry metadata of big packages is large (npm abbreviated `next` ≈ 26 MB), above the 4 MiB default cap.
const REGISTRY_MAX_BYTES = 64 * 1024 * 1024;

async function get<T>(http: Http, url: string, accept?: string): Promise<{ s: Exists; body?: T }> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return { s: "ok", body: await requestJson<T>(http, url, { maxBytes: REGISTRY_MAX_BYTES, ...(accept && { headers: { Accept: accept } }) }) };
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

// npm name rule (legacy names may have capitals). Lock names are untrusted: anything else is not looked up.
const NPM_NAME = /^(@[a-z0-9~-][a-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
const npmPath = (name: string): string => encodeURIComponent(name).replace(/^%40/, "@");

export interface NpmAbbrev {
  "dist-tags"?: Record<string, string>;
  versions?: Record<string, { hasInstallScript?: boolean }>;
}

export const npmAbbrev = async (http: Http, name: string): Promise<{ s: Exists; body?: NpmAbbrev }> =>
  NPM_NAME.test(name) ? get<NpmAbbrev>(http, `https://registry.npmjs.org/${npmPath(name)}`, "application/vnd.npm.install-v1+json") : { s: "error" };

/** Full document — only for edit-distance candidates (has `time.created`). */
export async function npmCreated(http: Http, name: string): Promise<string | null> {
  if (!NPM_NAME.test(name)) return null;
  const r = await get<{ time?: { created?: string } }>(http, `https://registry.npmjs.org/${npmPath(name)}`);
  return r.body?.time?.created ?? null;
}

/** Weekly downloads; 404 / no stats → 0 (U15). */
export async function npmWeeklyDownloads(http: Http, name: string): Promise<number | null> {
  if (!NPM_NAME.test(name)) return null;
  const r = await get<{ downloads?: number }>(http, `https://api.npmjs.org/downloads/point/last-week/${name}`);
  if (r.s === "missing") return 0;
  return r.s === "ok" ? (r.body?.downloads ?? 0) : null;
}

export const pypiExists = async (http: Http, name: string): Promise<Exists> =>
  (await get(http, `https://pypi.org/pypi/${encodeURIComponent(name)}/json`)).s;

/**
 * When `version` was published (npm `time[version]`, PyPI first upload), from the same name-only
 * documents as the checks above; null when unknown.
 */
export async function releasedAt(http: Http, eco: "npm" | "PyPI", name: string, version: string): Promise<string | null> {
  if (eco === "npm") {
    if (!NPM_NAME.test(name)) return null;
    const r = await get<{ time?: Record<string, string> }>(http, `https://registry.npmjs.org/${npmPath(name)}`);
    return r.body?.time?.[version] ?? null;
  }
  const r = await get<{ releases?: Record<string, { upload_time_iso_8601?: string }[]> }>(http, `https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  return (r.body?.releases?.[version] ?? []).flatMap((f) => f.upload_time_iso_8601 ?? []).sort()[0] ?? null;
}
