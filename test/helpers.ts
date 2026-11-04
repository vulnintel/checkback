import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll } from "vitest";
import { loadDefaultTemplate, scan, type Finding, type ScanResult, type Template } from "../src/index.js";

const made: string[] = [];
afterAll(() => {
  for (const d of made) rmSync(d, { recursive: true, force: true });
});

export function tempDir(): string {
  const d = mkdtempSync(join(tmpdir(), "checkback-"));
  made.push(d);
  return d;
}

/** Create a project. `files` values are file contents (string = UTF-8). */
export function project(files: Record<string, string | Buffer>, root = tempDir()): string {
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, content);
  }
  return root;
}

export function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", ...args], {
    cwd,
    encoding: "utf8",
  });
}

export function gitRepo(cwd: string): string {
  git(cwd, "init", "-q");
  return cwd;
}

export async function scanDefault(
  cwd: string,
  opts: { lang?: "ko" | "en"; appDir?: string; fetch?: typeof fetch; now?: () => number } = {},
): Promise<ScanResult> {
  return scan(cwd, await loadDefaultTemplate(), { appDir: opts.appDir ?? tempDir(), ...opts });
}

/** App data folder with first-run consent given (external lookups allowed). */
export async function consentedAppDir(external?: { osv?: boolean; registry?: boolean; vulnintel?: boolean }): Promise<string> {
  const { updateConfig } = await import("../src/appdata.js");
  const d = tempDir();
  await updateConfig(d, { consent: { at: "2026-11-04T00:00:00Z", version: 1 }, ...(external && { external }) });
  return d;
}

export interface NpmMock {
  missing?: boolean;
  latest?: string;
  versions?: Record<string, { hasInstallScript?: boolean }>;
  created?: string;
  weekly?: number;
}

export interface NetMock {
  /** "npm:name@version" → vuln ids */
  osv?: Record<string, string[]>;
  vulns?: Record<string, unknown>;
  npm?: Record<string, NpmMock>;
  pypi?: Record<string, boolean>;
  /** id → response data, or an HTTP status */
  vi?: Record<string, Record<string, unknown> | number>;
  /** Statuses returned by successive querybatch calls before normal answers. */
  osvFail?: number[];
  offline?: boolean;
}

export interface Call {
  method: string;
  url: string;
  body?: string;
}

/** Fake fetch for OSV / npm / PyPI / VulnIntel that records every request. */
export function mockNet(m: NetMock): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
    new Response(body === undefined ? "" : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
  const f = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = String(input);
    calls.push({ method: init?.method ?? "GET", url, ...(typeof init?.body === "string" && { body: init.body }) });
    if (m.offline) throw new TypeError("fetch failed");
    const u = new URL(url);
    if (u.host === "api.osv.dev" && u.pathname === "/v1/querybatch") {
      const st = m.osvFail?.shift();
      if (st) return json({ message: "fail" }, st);
      const q = JSON.parse(init!.body as string) as { queries: { package: { ecosystem: string; name: string }; version: string }[] };
      return json({
        results: q.queries.map((x) => {
          const ids = m.osv?.[`${x.package.ecosystem}:${x.package.name}@${x.version}`] ?? [];
          return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
        }),
      });
    }
    if (u.host === "api.osv.dev" && u.pathname.startsWith("/v1/vulns/")) {
      const id = decodeURIComponent(u.pathname.slice("/v1/vulns/".length));
      return m.vulns?.[id] ? json({ modified: "2026-01-01T00:00:00Z", ...(m.vulns[id] as object) }) : json({ message: "nf" }, 404);
    }
    if (u.host === "registry.npmjs.org") {
      const name = decodeURIComponent(u.pathname.slice(1));
      const p = m.npm?.[name];
      if (!p || p.missing) return json({ error: "Not found" }, 404);
      return json({
        name,
        "dist-tags": { latest: p.latest ?? "1.0.0" },
        versions: p.versions ?? { [p.latest ?? "1.0.0"]: {} },
        ...(!(init?.headers as Record<string, string>)?.Accept?.includes("install-v1") && { time: { created: p.created ?? "2015-01-01T00:00:00Z" } }),
      });
    }
    if (u.host === "api.npmjs.org") {
      const name = decodeURIComponent(u.pathname.split("/last-week/")[1]!);
      return json({ downloads: m.npm?.[name]?.weekly ?? 1_000_000 });
    }
    if (u.host === "pypi.org") {
      const name = decodeURIComponent(u.pathname.split("/")[2]!);
      return m.pypi?.[name] === false ? json({ message: "nf" }, 404) : json({ info: { name } });
    }
    if (u.host === "api.vulnintelapp.com") {
      const id = decodeURIComponent(u.pathname.split("/vulnerabilities/")[1] ?? "");
      const v = m.vi?.[id];
      if (typeof v === "number") return json({ error: "x" }, v, v === 429 ? { "retry-after": "60" } : {});
      return v ? json({ success: true, data: v }) : json({ detail: "not found" }, 404);
    }
    return json({ error: "unexpected" }, 599);
  };
  return { fetch: f as typeof fetch, calls };
}

export const byRule = (r: ScanResult, id: string): Finding[] => r.findings.filter((f) => f.rule_id === id);

export function withRules(t: Template, enabled: string[]): Template {
  return { ...t, rules: t.rules.map((r) => ({ ...r, enabled: enabled.includes(r.id) })) };
}

// ---------- secret fixtures, assembled at run time (AC7: no raw keys in the repository) ----------

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWYZabcdefghijkmnopqrstuvwyz0123456789"; // no x/X: avoids "xxx" placeholders
let seed = 7;
/** Deterministic pseudo-random alphanumerics. */
export function rnd(n: number, alphabet = ALNUM): string {
  let s = "";
  for (let i = 0; i < n; i++) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    s += alphabet[seed % alphabet.length];
  }
  return s;
}

const b64u = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");
export const jwt = (claims: Record<string, unknown>): string =>
  [b64u({ alg: "HS256", typ: "JWT" }), b64u({ iss: "supabase", ...claims }), rnd(43)].join(".");

export const K = {
  openai: () => ["sk", "proj", rnd(60)].join("-"),
  anthropic: () => ["sk", "ant", "api03", rnd(93) + "AA"].join("-"),
  serviceRoleJwt: () => jwt({ role: "service_role", ref: rnd(20).toLowerCase() }),
  anonJwt: () => jwt({ role: "anon", ref: rnd(20).toLowerCase() }),
  sbSecret: () => ["sb", "secret", rnd(32)].join("_"),
  sbPublishable: () => ["sb", "publishable", rnd(32)].join("_"),
  sbPat: () => ["sbp", rnd(40, "abcdef0123456789")].join("_"),
  aws: () => ["AK", "IA", rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWYZ234567")].join(""),
  stripe: () => ["sk", "live", rnd(24)].join("_"),
  stripePk: () => ["pk", "live", rnd(24)].join("_"),
  github: () => ["ghp", rnd(36)].join("_"),
  google: () => ["AI", "za", rnd(35)].join(""),
  vulnintel: () => ["vi", "live", rnd(32)].join("_"),
  pem: () => ["-----BEGIN ", "PRIVATE KEY-----\n", rnd(64), "\n", rnd(64), "\n-----END ", "PRIVATE KEY-----\n"].join(""),
};
