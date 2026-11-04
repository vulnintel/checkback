import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { apiKeyOf, updateConfig } from "../src/appdata.js";
import { parseViResult } from "../src/builtins/vi-scan.js";
import { ignoreCommand, parseSelection, trackCommand, watchCommand } from "../src/commands.js";
import { createMcpHandler, listIgnores, type McpScan } from "../src/index.js";
import { byRule, consentedAppDir, mockNet, project, scanDefault, tempDir, tty, type NetMock } from "./helpers.js";

const NOW = Date.UTC(2026, 10, 4);
const now = (): number => NOW;
const KEY = ["vi", "live", "Q".repeat(32)].join("_");
const json = (b: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json", ...headers } });

const lockOf = (deps: Record<string, string>, extra: Record<string, object> = {}): string =>
  JSON.stringify({
    name: "a",
    lockfileVersion: 3,
    packages: {
      "": { name: "a", dependencies: deps },
      ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split("/").pop()}-${v}.tgz`, integrity: `sha512-${n}${v}` }])),
      ...extra,
    },
  });

const projectFiles = (lodash = "4.17.20"): Record<string, string> => ({
  "package.json": JSON.stringify({ name: "a", dependencies: { lodash, minimist: "1.2.0", "@acme/ui": "1.0.0" } }),
  "package-lock.json": lockOf(
    { lodash, minimist: "1.2.0" },
    { "node_modules/@acme/ui": { version: "1.0.0", resolved: "https://npm.acme.dev/@acme/ui/-/ui-1.0.0.tgz", integrity: "sha512-p" } },
  ),
  ".npmrc": "@acme:registry=https://npm.acme.dev/\n",
});

const RESULT = {
  summary: { total_packages: 2 },
  packages: [
    {
      purl: "pkg:npm/lodash@4.17.20", ecosystem: "npm", name: "lodash", version: "4.17.20",
      vulnerabilities: [{ id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], cve_id: "CVE-2021-23337", severity: "HIGH", cvss: { score: 7.2, version: "3.1" }, kev: true, fixed_versions: ["4.17.21"] }],
      unknown_vulnerabilities: [],
    },
    { purl: "pkg:npm/minimist@1.2.0", ecosystem: "npm", name: "minimist", version: "1.2.0", vulnerabilities: [], unknown_vulnerabilities: [{ id: "GHSA-xvch-5gv4-984h", severity: "UNKNOWN", fixed_versions: ["1.2.6"] }] },
  ],
};

interface ViServer {
  uploads: string[];
  polls: number;
  net: ReturnType<typeof mockNet>;
}

/** Fake VulnIntel key API: upload → poll sequence. */
function viServer(o: { upload?: () => Response; polls?: (() => Response)[]; extra?: NetMock } = {}): ViServer {
  const s: ViServer = { uploads: [], polls: 0, net: undefined as never };
  const polls = o.polls ?? [() => json({ job_id: "job-1", status: "running", progress: { phase: "matching", percent: 40 } }), () => json({ job_id: "job-1", status: "completed", result: RESULT })];
  s.net = mockNet({
    npm: { lodash: {}, minimist: {} },
    ...o.extra,
    custom: async (u, init) => {
      if (u.host !== "api.vulnintelapp.com" || !u.pathname.startsWith("/api/v1/scan/jobs")) return undefined;
      expect((init?.headers as Record<string, string>)["X-Api-Key"]).toBe(KEY);
      if (init?.method === "POST") {
        const form = init.body as FormData;
        expect(form.get("kind")).toBe("sbom");
        expect(form.get("scan_depth")).toBe("precise");
        s.uploads.push(await (form.get("file") as Blob).text());
        return o.upload?.() ?? json({ job_id: "job-1", status: "queued", status_url: "/api/v1/scan/jobs/job-1" }, 202, { "x-quota-remaining": "97" });
      }
      const r = polls[Math.min(s.polls, polls.length - 1)]!();
      s.polls++;
      return r;
    },
  });
  return s;
}

describe("AC27 key mode: SBOM upload → poll → VulnIntel result", () => {
  it("uploads the public-only SBOM once, polls, and builds findings from result.packages", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const srv = viServer({ polls: [() => json({ job_id: "job-1", status: "completed", result: RESULT })] });
    const r = await scanDefault(project(projectFiles()), { appDir, fetch: srv.net.fetch, now, lang: "ko" });
    expect(srv.uploads).toHaveLength(1);
    const sbom = srv.uploads[0]!;
    expect(sbom).not.toContain("acme"); // private scope never uploaded
    expect(sbom).not.toContain("package-lock"); // no lockfile names
    expect(JSON.parse(sbom).components.map((c: { name: string }) => c.name)).toEqual(["lodash", "minimist"]);
    const v = byRule(r, "vulnerable-deps");
    expect(v.map((f) => [f.package, f.severity, f.confidence, f.kev, f.fixed_version, f.source])).toEqual([
      ["lodash", "critical", "confirmed", true, "4.17.21", "vulnintel"],
      ["minimist", "medium", "review", false, "1.2.6", "vulnintel"],
    ]);
    expect(r.vulnintel).toMatchObject({ status: "ok", job_id: "job-1", history_url: "https://www.vulnintelapp.com/ko/scan?tab=history&job=job-1", quota_remaining: 97 });
    expect(srv.net.calls.some((c) => c.url.includes("api.osv.dev/v1/vulns/"))).toBe(false); // no OSV details in key mode
    expect(srv.net.calls.some((c) => c.url.endsWith("/v1/querybatch"))).toBe(true); // OSV still checks MAL-
  });

  it("AC30: same lock → no upload and no poll; one changed line → exactly one upload", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const dir = project(projectFiles());
    let srv = viServer({ polls: [() => json({ job_id: "job-1", status: "completed", result: RESULT })] });
    await scanDefault(dir, { appDir, fetch: srv.net.fetch, now });
    srv = viServer();
    const again = await scanDefault(dir, { appDir, fetch: srv.net.fetch, now });
    expect(srv.uploads).toHaveLength(0);
    expect(srv.polls).toBe(0);
    expect(again.vulnintel).toMatchObject({ status: "cached" });
    expect(byRule(again, "vulnerable-deps")).toHaveLength(2);
    project(projectFiles("4.17.21"), dir);
    srv = viServer({ polls: [() => json({ job_id: "job-2", status: "completed", result: { packages: [] } })] });
    await scanDefault(dir, { appDir, fetch: srv.net.fetch, now });
    expect(srv.uploads).toHaveLength(1);
  });

  it("AC31: the uploaded SBOM bytes are identical for the same lock", async () => {
    const files = projectFiles();
    const a = viServer({ polls: [() => json({ job_id: "j", status: "completed", result: RESULT })] });
    const b = viServer({ polls: [() => json({ job_id: "j", status: "completed", result: RESULT })] });
    await scanDefault(project(files), { appDir: await consentedAppDir({}, KEY), fetch: a.net.fetch, now });
    await scanDefault(project(files), { appDir: await consentedAppDir({}, KEY), fetch: b.net.fetch, now });
    expect(a.uploads[0]).toBe(b.uploads[0]);
  });

  it("a job still running at the deadline is resumed on the next scan without a new upload", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const dir = project(projectFiles());
    let srv = viServer({ polls: [() => json({ job_id: "job-1", status: "running" })] });
    const first = await scanDefault(dir, { appDir, fetch: srv.net.fetch, now, deadlineMs: 50 });
    expect(first.vulnintel).toMatchObject({ status: "pending", job_id: "job-1" });
    expect(byRule(first, "vulnerable-deps")).toEqual([]); // OSV fallback (mock OSV has no vulns)
    srv = viServer({ polls: [() => json({ job_id: "job-1", status: "completed", result: RESULT })] });
    const second = await scanDefault(dir, { appDir, fetch: srv.net.fetch, now });
    expect(srv.uploads).toHaveLength(0);
    expect(second.vulnintel).toMatchObject({ status: "ok", job_id: "job-1" });
  });
});

describe("AC32 key-mode failures fall back to OSV", () => {
  const osv = { osv: { "npm:lodash@4.17.20": ["GHSA-35jh-r3h4-6jhm"] }, vulns: { "GHSA-35jh-r3h4-6jhm": { id: "GHSA-35jh-r3h4-6jhm", database_specific: { severity: "HIGH" } } } };

  it("402 → OSV results + quota notice, no automatic upload again this month; refresh forces one", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const dir = project(projectFiles());
    let srv = viServer({ upload: () => json({ error: { error: "monthly_quota_exceeded" } }, 402, { "x-quota-reset": "2026-12-01T00:00:00Z" }), extra: osv });
    const r = await scanDefault(dir, { appDir, fetch: srv.net.fetch, now, lang: "ko" });
    expect(r.vulnintel).toMatchObject({ status: "fallback", reason: "quota_exceeded", quota_reset: "2026-12-01T00:00:00Z" });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ package: "lodash", source: "osv" }]);
    project(projectFiles("4.17.19"), dir);
    srv = viServer({ extra: osv });
    expect((await scanDefault(dir, { appDir, fetch: srv.net.fetch, now })).vulnintel).toMatchObject({ reason: "quota_blocked" });
    expect(srv.uploads).toHaveLength(0);
    srv = viServer({ polls: [() => json({ job_id: "j", status: "completed", result: RESULT })] });
    await scanDefault(dir, { appDir, fetch: srv.net.fetch, now, refreshVulnIntel: true });
    expect(srv.uploads).toHaveLength(1);
  });

  it.each([
    ["401 invalid key", () => json({ detail: "x" }, 401), "invalid_key"],
    ["413 too large", () => json({ detail: "x" }, 413), "too_large"],
    ["400 bad request", () => json({ detail: "x" }, 400), "bad_request"],
  ])("%s → fallback", async (_, upload, reason) => {
    const srv = viServer({ upload, extra: osv });
    const r = await scanDefault(project(projectFiles()), { appDir: await consentedAppDir({ vulnintel: false }, KEY), fetch: srv.net.fetch, now });
    expect(r.vulnintel).toMatchObject({ status: "fallback", reason });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ source: "osv" }]);
  });

  it("429 → waits Retry-After once; still 429 → fallback", async () => {
    let n = 0;
    const srv = viServer({ upload: () => (n++, json({}, 429, { "retry-after": "1" })), extra: osv });
    const r = await scanDefault(project(projectFiles()), { appDir: await consentedAppDir({ vulnintel: false }, KEY), fetch: srv.net.fetch, now });
    expect(srv.uploads).toHaveLength(2);
    expect(r.vulnintel).toMatchObject({ status: "fallback", reason: "rate_limited" });
  });

  it("job failed → fallback; unreadable result (old/unknown server shape) → fallback, never a crash", async () => {
    let srv = viServer({ polls: [() => json({ job_id: "job-1", status: "failed", error: { code: "parse_error", message: "x" } })], extra: osv });
    let r = await scanDefault(project(projectFiles()), { appDir: await consentedAppDir({ vulnintel: false }, KEY), fetch: srv.net.fetch, now });
    expect(r.vulnintel).toMatchObject({ status: "fallback", reason: "job_failed" });
    srv = viServer({ polls: [() => json({ job_id: "job-1", status: "completed", result: { something: "else" } })], extra: osv });
    r = await scanDefault(project(projectFiles()), { appDir: await consentedAppDir({ vulnintel: false }, KEY), fetch: srv.net.fetch, now });
    expect(r.vulnintel).toMatchObject({ status: "fallback", reason: "bad_result" });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ source: "osv" }]);
  });

  it("result parser tolerates missing fields and reads B1 fields when present", () => {
    expect(parseViResult({ packages: [{ name: "x", vulnerabilities: [{ id: "GHSA-1" }, { nope: 1 }] }] })).toEqual([
      { ecosystem: "", name: "x", version: null, vulns: [{ id: "GHSA-1", aliases: [], kev: false, fixed: [], unknown: false }] },
    ]);
    expect(parseViResult({ packages: [{ name: "x", version: "1", vulnerabilities: [{ id: "a", vpi_level: 5, epss_score: "0.3" }] }] })![0]!.vulns[0]).toMatchObject({ vpi: 5, epss: 0.3 });
    expect(parseViResult(null)).toBeNull();
  });
});

describe("§10-4 key storage", () => {
  it("environment variable wins over the config file; config is written with mode 600", async () => {
    const d = tempDir();
    await updateConfig(d, { api_key: "from-file" });
    const prev = process.env.VULNINTEL_API_KEY;
    process.env.VULNINTEL_API_KEY = "from-env";
    try {
      expect(apiKeyOf({ api_key: "from-file" })).toBe("from-env");
    } finally {
      if (prev === undefined) delete process.env.VULNINTEL_API_KEY;
      else process.env.VULNINTEL_API_KEY = prev;
    }
    expect(apiKeyOf({ api_key: "from-file" })).toBe(prev ?? "from-file");
    if (process.platform !== "win32") expect(statSync(join(d, "config.json")).mode & 0o077).toBe(0);
    expect(readFileSync(join(d, "config.json"), "utf8")).toContain("from-file");
  });
});

describe("AC55 checkback watch (person only)", () => {
  const subServer = (handler: (body: { ecosystem: string; target_value: string; target_type: string }) => Response): { net: ReturnType<typeof mockNet>; bodies: Record<string, unknown>[] } => {
    const bodies: Record<string, unknown>[] = [];
    const net = mockNet({
      custom: (u, init) => {
        if (u.pathname !== "/api/v1/subscriptions") return undefined;
        const b = JSON.parse(init!.body as string);
        bodies.push(b);
        return handler(b);
      },
    });
    return { net, bodies };
  };
  const watchProject = (): string => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 14; i++) deps[`pkg-${String(i).padStart(2, "0")}`] = "1.0.0";
    return project({
      "package.json": JSON.stringify({ name: "a", dependencies: deps }),
      "package-lock.json": lockOf(deps, { "node_modules/transitive-x": { version: "2.0.0", resolved: "https://registry.npmjs.org/transitive-x/-/transitive-x-2.0.0.tgz" } }),
    });
  };

  it("non-interactive → refused, nothing sent; no key → key notice", async () => {
    const t = tty([], false);
    const net = mockNet({});
    expect(await watchCommand(t.io, { cwd: watchProject(), appDir: await consentedAppDir({}, KEY), lang: "en", fetch: net.fetch })).toBe(1);
    expect(t.err()).toMatch(/non-interactive run refused/);
    expect(net.calls).toEqual([]);
    const t2 = tty([""]);
    expect(await watchCommand(t2.io, { cwd: watchProject(), appDir: await consentedAppDir(), lang: "ko", fetch: net.fetch })).toBe(1);
    expect(t2.out()).toContain("api-keys?src=checkback");
  });

  it("default = up to 10 direct deps; body has ecosystem + name only; 201/409/404 counted", async () => {
    const srv = subServer((b) => (b.target_value === "pkg-01" ? json({}, 409) : b.target_value === "pkg-02" ? json({ detail: "nf" }, 404) : json({ id: 1 }, 201)));
    const t = tty([""]);
    const code = await watchCommand(t.io, { cwd: watchProject(), appDir: await consentedAppDir({}, KEY), lang: "en", fetch: srv.net.fetch });
    expect(code).toBe(0);
    expect(srv.bodies).toHaveLength(10);
    expect(srv.bodies.every((b) => Object.keys(b).sort().join() === "ecosystem,target_type,target_value" && b.target_type === "package")).toBe(true);
    expect(srv.bodies.map((b) => b.target_value)).not.toContain("transitive-x");
    expect(JSON.stringify(srv.bodies)).not.toMatch(/1\.0\.0|package-lock|node_modules/);
    expect(t.out()).toMatch(/Now watching 8 · already 1 · no data 1 · not done 0/);
  });

  it("400 subscription_limit_exceeded stops the rest; 429 waits Retry-After once", async () => {
    let n = 0;
    const srv = subServer(() => {
      n++;
      if (n === 1) return json({}, 429, { "retry-after": "1" });
      if (n <= 3) return json({ id: n }, 201);
      return json({ error: { error: "subscription_limit_exceeded", limit: 10 }, request_id: "r" }, 400);
    });
    const t = tty(["1-5"]);
    await watchCommand(t.io, { cwd: watchProject(), appDir: await consentedAppDir({}, KEY), lang: "en", fetch: srv.net.fetch });
    expect(srv.bodies).toHaveLength(4); // 429 + retry, 1 more created, then the limit
    expect(t.out()).toMatch(/Now watching 2 · already 0 · no data 0 · not done 3/);
    expect(t.out()).toMatch(/Subscription limit \(10\) reached/);
  });

  it("403 (key path: package targets only) stops", async () => {
    const srv = subServer(() => json({ error: { error: "api_key_package_only" } }, 403));
    const t = tty(["1"]);
    expect(await watchCommand(t.io, { cwd: watchProject(), appDir: await consentedAppDir({}, KEY), lang: "en", fetch: srv.net.fetch })).toBe(1);
    expect(t.out()).toMatch(/Stopped: forbidden/);
  });

  it("selection parser", () => {
    expect(parseSelection("1,3, 5-7 9-8 x 99", 10)).toEqual([0, 2, 4, 5, 6, 7, 8]);
  });
});

describe("AC29 checkback track", () => {
  it("one list call per 100 CVEs, registers only unregistered CVEs with the fixed note, GHSA-only not offered", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const dir = project(projectFiles());
    await scanDefault(dir, { appDir, fetch: viServer({ polls: [() => json({ job_id: "j", status: "completed", result: RESULT })] }).net.fetch, now });
    const puts: { url: string; body: unknown }[] = [];
    let lists = 0;
    const net = mockNet({
      custom: (u, init) => {
        if (u.pathname === "/api/v1/remediations") {
          lists++;
          expect(u.searchParams.getAll("cve_id")).toEqual(["CVE-2021-23337"]);
          return json({ success: true, data: [], meta: { total: 0 } });
        }
        if (u.pathname.startsWith("/api/v1/remediations/")) {
          puts.push({ url: u.pathname, body: JSON.parse(init!.body as string) });
          return json({ success: true });
        }
        return undefined;
      },
    });
    const t = tty(["all"]);
    expect(await trackCommand(t.io, { cwd: dir, appDir, lang: "en", fetch: net.fetch })).toBe(0);
    expect(lists).toBe(1);
    expect(puts).toEqual([{ url: "/api/v1/remediations/CVE-2021-23337", body: { status: "open", note: "checkback: lodash@4.17.20" } }]);
    expect(t.out()).not.toContain("GHSA-xvch"); // GHSA-only item is not offered
  });

  it("already registered → not overwritten", async () => {
    const appDir = await consentedAppDir({ vulnintel: false }, KEY);
    const dir = project(projectFiles());
    await scanDefault(dir, { appDir, fetch: viServer({ polls: [() => json({ job_id: "j", status: "completed", result: RESULT })] }).net.fetch, now });
    let puts = 0;
    const net = mockNet({
      custom: (u) =>
        u.pathname === "/api/v1/remediations" ? json({ data: [{ cve_id: "CVE-2021-23337", status: "open" }] }) : u.pathname.startsWith("/api/v1/remediations/") ? (puts++, json({})) : undefined,
    });
    const t = tty(["all"]);
    await trackCommand(t.io, { cwd: dir, appDir, lang: "en", fetch: net.fetch });
    expect(puts).toBe(0);
    expect(t.out()).toMatch(/CVE-2021-23337 · lodash@4\.17\.20 · registered/);
  });
});

describe("checkback ignore (person only, not an MCP tool)", () => {
  it("non-interactive refused; interactive ignore + reason, then --remove", async () => {
    const appDir = tempDir();
    const dir = project({ "app.py": "app.run(debug=True)\n" });
    await scanDefault(dir, { appDir });
    expect(await ignoreCommand(tty([], false).io, { cwd: dir, appDir, lang: "en" })).toBe(1);
    expect(await listIgnores(dir, appDir)).toEqual([]);
    expect(await ignoreCommand(tty(["1", "dev server only"]).io, { cwd: dir, appDir, lang: "en" })).toBe(0);
    expect(await listIgnores(dir, appDir)).toMatchObject([{ reason: "dev server only" }]);
    expect(byRule(await scanDefault(dir, { appDir }), "debug-flask")).toEqual([]);
    expect(await ignoreCommand(tty(["1"]).io, { cwd: dir, appDir, lang: "en", remove: true })).toBe(0);
    expect(await listIgnores(dir, appDir)).toEqual([]);
  });
});

describe("MCP scan response time (deadline) with a large lock", () => {
  it("returns near the deadline with partial lookups marked; the next scan continues from cache", async () => {
    const deps: Record<string, string> = {};
    for (let i = 0; i < 400; i++) deps[`dep-${i}`] = "1.0.0";
    const dir = project({ "package.json": JSON.stringify({ name: "big", dependencies: deps }), "package-lock.json": lockOf(deps) });
    const appDir = await consentedAppDir({ vulnintel: false });
    const net = mockNet({ latencyMs: 25, npm: Object.fromEntries(Object.keys(deps).map((d) => [d, {}])) });
    const h = createMcpHandler({ cwd: dir, appDir, fetch: net.fetch, deadlineMs: 800 });
    const t0 = Date.now();
    const res = (await h({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "scan", arguments: {} } })) as { result: { content: { text: string }[] } };
    const ms = Date.now() - t0;
    const s = JSON.parse(res.result.content[0]!.text) as McpScan;
    expect(ms).toBeLessThan(800 + 2500);
    expect(s.checked.find((c) => c.rule_id === "hallucinated-package")).toMatchObject({ ran: false, reason: "timeout_partial" });
    expect(s.notice).toMatch(/(다음 scan에서 이어서|the next scan continues)/);
    const before = net.calls.filter((c) => c.url.startsWith("https://registry.npmjs.org/")).length;
    expect(before).toBeLessThan(400);
    await h({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "scan", arguments: {} } });
    const after = net.calls.filter((c) => c.url.startsWith("https://registry.npmjs.org/")).length;
    expect(after - before).toBeLessThan(400); // cached names are not asked again
    expect(new Set(net.calls.filter((c) => c.url.startsWith("https://registry.npmjs.org/")).map((c) => c.url)).size).toBe(after); // no name twice
  }, 30_000);
});
