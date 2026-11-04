import { createHash } from "node:crypto";
import { readFileSync, rmSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { addIgnore, loadDefaultTemplate, scan, type Finding, type ScanResult } from "../src/index.js";
import { lastScanFile, lockLooksHandEdited, recordFixRequest, snapshotFile, type LockState } from "../src/recheck.js";
import { byRule, consentedAppDir, git, gitRepo, K, mockNet, project, tempDir } from "./helpers.js";

const NOW = Date.UTC(2026, 10, 4);

async function rescan(dir: string, appDir: string, o: { fetch?: typeof fetch; template?: Awaited<ReturnType<typeof loadDefaultTemplate>> } = {}): Promise<ScanResult> {
  return scan(dir, o.template ?? (await loadDefaultTemplate()), { appDir, now: () => NOW, ...(o.fetch && { fetch: o.fetch }) });
}

/** Scan, request a fix for every fix item, return the baseline result. */
async function baseline(dir: string, appDir: string, fetch?: typeof fetch): Promise<ScanResult> {
  const r = await rescan(dir, appDir, { ...(fetch && { fetch }) });
  await recordFixRequest(dir, r.findings.filter((f) => f.confidence !== "info").map((f) => f.id), appDir, NOW);
  return r;
}

const status = (r: ScanResult, rule: string): [string | undefined, string | undefined, string][] =>
  byRule(r, rule).map((f) => [f.recheck, f.location?.file, f.confidence]);

describe("AC67 recheck against the fix-request snapshot", () => {
  it("(a) secret line deleted → resolved + revocation check; (b) unchanged → remaining; (c) new key → new", async () => {
    const appDir = tempDir();
    const [k1, k2] = [K.openai(), K.openai()];
    const dir = project({ "src/a.ts": `const a = "${k1}";\n`, "src/b.ts": `const b = "${k2}";\n` });
    const base = await baseline(dir, appDir);
    project({ "src/a.ts": "const a = process.env.OPENAI_API_KEY;\n", "src/c.ts": `const c = "${K.github()}";\n` }, dir);
    const r = await rescan(dir, appDir);
    expect(r.compare).toMatchObject({ baseline: "fix_request", counts: { resolved: 1, remaining: 1, new: 1 } });
    expect(r.compare!.resolved).toEqual([{ id: base.findings.find((f) => f.location?.file === "src/a.ts")!.id, rule_id: "secret-openai", title: "OpenAI key exposed", location: { file: "src/a.ts", line: 1 }, confirm_revocation: true }]);
    expect(status(r, "secret-openai")).toEqual([["remaining", "src/b.ts", "confirmed"]]);
    expect(status(r, "secret-github")).toEqual([["new", "src/c.ts", "confirmed"]]);
    expect(r.compare!.requested).toHaveLength(2);
  });

  it("(d) same key moved to another source file → one 'same key' card, still a fix item", async () => {
    const appDir = tempDir();
    const k = K.stripe();
    const dir = project({ "src/pay.ts": `stripe("${k}")\n` });
    await baseline(dir, appDir);
    rmSync(join(dir, "src/pay.ts"));
    project({ "src/config/keys.ts": `export const s = "${k}";\n` }, dir);
    const r = await rescan(dir, appDir);
    expect(status(r, "secret-stripe-live")).toEqual([["same_key", "src/config/keys.ts", "confirmed"]]);
    expect(byRule(r, "secret-stripe-live")[0]!.recheck_note).toBe("same_key_remains");
    expect(r.compare!.counts).toMatchObject({ same_key: 1, resolved: 0 });
  });

  it("(e) same key moved into a gitignored, untracked .env.local → 'same key' (not resolved)", async () => {
    const appDir = tempDir();
    const k = K.openai();
    const dir = gitRepo(project({ "src/ai.ts": `const k = "${k}";\n`, ".gitignore": ".env*.local\n" }));
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "a");
    await baseline(dir, appDir);
    project({ "src/ai.ts": "const k = process.env.OPENAI_API_KEY;\n", ".env.local": `OPENAI_API_KEY=${k}\n` }, dir);
    const r = await rescan(dir, appDir);
    const f = byRule(r, "secret-openai");
    expect(f).toMatchObject([{ recheck: "same_key", location: { file: ".env.local" }, confidence: "confirmed", notes: ["local_only_env"] }]);
    expect(r.compare!.counts.resolved).toBe(0);
  });

  it("(f) CORS wildcard moved to another file → moved; (g) moved into tests/ → downgraded, keeps confirmed", async () => {
    const appDir = tempDir();
    const line = "res.setHeader('Access-Control-Allow-Origin', '*');\n";
    let dir = project({ "api/a.ts": line });
    await baseline(dir, appDir);
    rmSync(join(dir, "api/a.ts"));
    project({ "server/h.ts": line }, dir);
    expect(status(await rescan(dir, appDir), "cors-wildcard")).toEqual([["moved", "server/h.ts", "confirmed"]]);

    const appDir2 = tempDir();
    dir = project({ "api/a.ts": line });
    await baseline(dir, appDir2);
    rmSync(join(dir, "api/a.ts"));
    project({ "tests/h.ts": line }, dir);
    const r = await rescan(dir, appDir2);
    expect(status(r, "cors-wildcard")).toEqual([["downgraded", "tests/h.ts", "confirmed"]]);
  });

  it("(h) tracked key file renamed → paired by content hash as 'same key'", async () => {
    const appDir = tempDir();
    const dir = gitRepo(project({ "certs/server.key": K.pem(), ".gitignore": ".env\n" }));
    git(dir, "add", ".");
    git(dir, "commit", "-q", "-m", "a");
    await baseline(dir, appDir);
    git(dir, "mv", "certs/server.key", "certs/prod.key");
    git(dir, "commit", "-q", "-m", "b");
    const r = await rescan(dir, appDir);
    expect(status(r, "key-file-committed")).toEqual([["same_key", "certs/prod.key", "confirmed"]]);
  });

  it("(i) rule turned off → 'not checked', nothing counted as resolved", async () => {
    const appDir = tempDir();
    const dir = project({ "app.py": "app.run(debug=True)\n" });
    await baseline(dir, appDir);
    const tpl = await loadDefaultTemplate();
    const off = { ...tpl, rules: tpl.rules.map((r) => (r.id === "debug-flask" ? { ...r, enabled: false } : r)) };
    const r = await rescan(dir, appDir, { template: off });
    expect(r.compare!.counts).toMatchObject({ not_checked: 1, resolved: 0 });
    expect(byRule(r, "debug-flask")).toMatchObject([{ recheck: "not_checked", carried: true }]);
  });

  it("(j) .env in history stays 'remaining' after the working tree is cleaned", async () => {
    const appDir = tempDir();
    const dir = gitRepo(project({ ".env": `OPENAI_API_KEY=${K.openai()}\n` }));
    git(dir, "add", ".env");
    git(dir, "commit", "-q", "-m", "a");
    await baseline(dir, appDir);
    project({ ".env": "OPENAI_API_KEY=\n", ".gitignore": ".env\n" }, dir);
    git(dir, "rm", "-q", "--cached", ".env");
    git(dir, "add", ".gitignore");
    git(dir, "commit", "-q", "-m", "b");
    const r = await rescan(dir, appDir);
    expect(byRule(r, "env-committed")).toMatchObject([{ recheck: "remaining", location: { file: ".env" } }]);
  });

  it("(k) vulnerable version bumped by hand in package-lock (integrity kept) → 'lock mismatch', not resolved", async () => {
    const appDir = await consentedAppDir({ vulnintel: false, registry: false });
    const net = mockNet({
      osv: { "npm:lodash@4.17.20": ["GHSA-35jh-r3h4-6jhm"] },
      vulns: { "GHSA-35jh-r3h4-6jhm": { id: "GHSA-35jh-r3h4-6jhm", database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] } },
    });
    const lockText = (v: string, integrity: string, url: string): string =>
      JSON.stringify({ name: "a", lockfileVersion: 3, packages: { "": { name: "a", dependencies: { lodash: "^4.17.20" } }, "node_modules/lodash": { version: v, resolved: url, integrity } } });
    const dir = project({
      "package.json": JSON.stringify({ name: "a", dependencies: { lodash: "^4.17.20" } }),
      "package-lock.json": lockText("4.17.20", "sha512-OLD", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"),
    });
    await baseline(dir, appDir, net.fetch);
    project({ "package-lock.json": lockText("4.17.21", "sha512-OLD", "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz") }, dir);
    const r = await rescan(dir, appDir, { fetch: net.fetch });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ recheck: "lock_mismatch", carried: true, package: "lodash", version: "4.17.20" }]);
    expect(r.compare!.counts.resolved).toBe(0);
    // A real upgrade (new integrity + matching URL) resolves it.
    project({ "package-lock.json": lockText("4.17.21", "sha512-NEW", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz") }, dir);
    expect((await rescan(dir, appDir, { fetch: net.fetch })).compare!.counts).toMatchObject({ resolved: 1, lock_mismatch: 0 });
  });

  it("(l)(m) lock consistency rules", () => {
    const st = (p: Partial<LockState>): LockState => ({ path: "package-lock.json", lockHash: "1", manifestHash: "m", manifestDeps: null, root: null, entries: {}, ...p });
    const base = st({ entries: { a: [{ version: "1.0.0", integrity: "sha512-A" }] } });
    expect(lockLooksHandEdited(base, st({ lockHash: "2", entries: { a: [{ version: "1.0.0", integrity: "sha512-B" }] } }))).toBe(true); // (l)
    expect(lockLooksHandEdited(base, st({ lockHash: "2", entries: { a: [{ version: "1.0.1" }] } }))).toBe(true); // (4) no integrity
    expect(lockLooksHandEdited(base, st({ lockHash: "2", entries: { a: [{ version: "1.0.1", integrity: "sha512-C" }] } }))).toBe(false);
    expect(lockLooksHandEdited(base, st({ lockHash: "2", manifestDeps: { a: "^1" }, root: { deps: { a: "^1", ghost: "1.0.0" }, versions: { a: "1.0.0" } } }))).toBe(true); // (m)
    expect(lockLooksHandEdited(base, st({ lockHash: "2", manifestDeps: { a: "^2" }, root: { deps: { a: "^2" }, versions: { a: "1.0.0" } } }))).toBe(true); // range broken
    expect(lockLooksHandEdited(base, st({}))).toBe(false); // unchanged lock & manifest are not re-checked
  });

  it("(n) three rechecks after a snapshot keep the same baseline; without a snapshot → 'previous'", async () => {
    const appDir = tempDir();
    const dir = project({ "app.py": "app.run(debug=True)\n" });
    let r = await rescan(dir, appDir);
    expect(r.compare).toBeUndefined();
    r = await rescan(dir, appDir);
    expect(r.compare).toMatchObject({ baseline: "previous", counts: { remaining: 1 } });
    await recordFixRequest(dir, [r.findings[0]!.id], appDir, NOW);
    project({ "app.py": "app.run()\n" }, dir);
    const runs = [await rescan(dir, appDir), await rescan(dir, appDir), await rescan(dir, appDir)];
    for (const x of runs) expect(x.compare).toEqual(runs[0]!.compare);
    expect(runs[0]!.compare).toMatchObject({ baseline: "fix_request", baseline_at: new Date(NOW).toISOString(), counts: { resolved: 1 } });
  });

  it("AC45: ignored items are not counted in any recheck state", async () => {
    const appDir = tempDir();
    const dir = project({ "app.py": "app.run(debug=True)\n", "main.py": "FastAPI(debug=True)\n" });
    const r0 = await baseline(dir, appDir);
    await addIgnore(dir, byRule(r0, "debug-flask")[0]!.id, "dev only", appDir);
    project({ "app.py": "app.run()\n" }, dir);
    const r = await rescan(dir, appDir);
    expect(r.compare!.counts).toMatchObject({ resolved: 0, remaining: 1 });
  });

  it("snapshot follows the M5 rule: same scan → ids added; new scan → new snapshot", async () => {
    const appDir = tempDir();
    const dir = project({ "app.py": "app.run(debug=True)\n", "main.py": "FastAPI(debug=True)\n" });
    const r = await rescan(dir, appDir);
    const [a, b] = r.findings.map((f) => f.id);
    await recordFixRequest(dir, [a!], appDir, NOW);
    expect((await recordFixRequest(dir, [b!], appDir, NOW + 1)).requested).toEqual([a, b]);
    await rescan(dir, appDir);
    const s = await recordFixRequest(dir, [b!], appDir, NOW + 2);
    expect(s.requested).toEqual([b]);
    await expect(recordFixRequest(dir, ["nope"], appDir)).rejects.toThrow(/unknown finding id/);
  });
});

describe("value hashes are per-install HMAC (no plain sha256 anywhere)", () => {
  it("HMAC differs from sha256 and between installs, stable within one; files hold no values", async () => {
    const k = K.openai();
    const dir = project({ "src/a.ts": `const k = "${k}";\n` });
    const [d1, d2] = [tempDir(), tempDir()];
    const f1: Finding = byRule(await rescan(dir, d1), "secret-openai")[0]!;
    const f1b: Finding = byRule(await rescan(dir, d1), "secret-openai")[0]!;
    const f2: Finding = byRule(await rescan(dir, d2), "secret-openai")[0]!;
    expect(f1.value_hash).toBe(f1b.value_hash);
    expect(f1.value_hash).not.toBe(f2.value_hash);
    expect(f1.value_hash).not.toBe(createHash("sha256").update(k).digest("hex"));
    expect(readFileSync(join(d1, "install.key"))).toHaveLength(32);
    if (process.platform !== "win32") expect(statSync(join(d1, "install.key")).mode & 0o077).toBe(0);
    await recordFixRequest(dir, [f1.id], d1);
    for (const f of [await lastScanFile(d1, dir), await snapshotFile(d1, dir)]) {
      const text = readFileSync(f, "utf8");
      expect(text).not.toContain(k);
      expect(text).not.toContain(k.slice(0, 12));
      expect(text).not.toContain("••••"); // no masked values either
    }
  });
});

