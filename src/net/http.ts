import { join } from "node:path";
import { readJson, writeJson } from "../appdata.js";

export const VERSION = "0.0.0";
export const USER_AGENT = `checkback/${VERSION} (+https://github.com/vulnintel/checkback)`;
export type Fetch = typeof fetch;

/** Network failure: "offline" (DNS/connect), "timeout", or an HTTP status. */
export class NetError extends Error {
  constructor(
    readonly kind: "offline" | "timeout" | "http",
    readonly status = 0,
    readonly body: unknown = undefined,
    readonly retryAfterMs = 0,
  ) {
    super(kind === "http" ? `HTTP ${status}` : kind);
  }
}

export interface Http {
  fetch: Fetch;
  /** Injected clock/sleep for tests. */
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

export const defaultHttp = (f: Fetch = globalThis.fetch): Http => ({
  fetch: f,
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: Date.now,
});

const retryAfter = (h: string | null): number => {
  if (!h) return 0;
  const s = Number(h);
  if (Number.isFinite(s)) return Math.min(s, 120) * 1000;
  const t = Date.parse(h);
  return Number.isFinite(t) ? Math.max(0, Math.min(t - Date.now(), 120_000)) : 0;
};

/** One request. Throws NetError for network failures and non-2xx (body parsed as JSON when possible). */
export async function requestJson<T>(http: Http, url: string, init: RequestInit & { timeoutMs?: number } = {}): Promise<T> {
  let res: Response;
  try {
    res = await http.fetch(url, {
      ...init,
      headers: { "User-Agent": USER_AGENT, Accept: "application/json", ...(init.headers as Record<string, string>) },
      signal: AbortSignal.timeout(init.timeoutMs ?? 30_000),
    });
  } catch (e) {
    throw new NetError((e as Error).name === "TimeoutError" || (e as Error).name === "AbortError" ? "timeout" : "offline");
  }
  const text = await res.text().catch(() => "");
  let body: unknown = undefined;
  try {
    body = text ? JSON.parse(text) : undefined;
  } catch {
    body = undefined;
  }
  if (!res.ok) throw new NetError("http", res.status, body, retryAfter(res.headers.get("retry-after")));
  return body as T;
}

/** Run `fn` over items with at most `n` in flight (§8-2: 4). */
export async function mapLimit<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]!);
      }
    }),
  );
  return out;
}

/** Small JSON-file cache per namespace under `<appdata>/checkback/cache/`. */
export class Cache {
  private data: Record<string, { t: number; v: unknown }> = {};
  private dirty = false;
  private constructor(private readonly file: string) {}

  static async open(appDir: string, ns: string): Promise<Cache> {
    const c = new Cache(join(appDir, "cache", `${ns}.json`));
    const d = await readJson<unknown>(c.file, {});
    if (typeof d === "object" && d !== null) c.data = d as Cache["data"];
    return c;
  }

  get<T>(key: string, maxAgeMs: number, now: number): T | undefined {
    const e = this.data[key];
    return e && now - e.t < maxAgeMs ? (e.v as T) : undefined;
  }

  set(key: string, v: unknown, now: number): void {
    this.data[key] = { t: now, v };
    this.dirty = true;
  }

  async save(maxAgeMs: number, now: number): Promise<void> {
    if (!this.dirty) return;
    for (const [k, e] of Object.entries(this.data)) if (now - e.t >= maxAgeMs) delete this.data[k];
    await writeJson(this.file, this.data);
  }
}
