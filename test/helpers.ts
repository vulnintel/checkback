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

export async function scanDefault(cwd: string, opts: { lang?: "ko" | "en"; appDir?: string } = {}): Promise<ScanResult> {
  return scan(cwd, await loadDefaultTemplate(), { appDir: opts.appDir ?? tempDir(), ...opts });
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
