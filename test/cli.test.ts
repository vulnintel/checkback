// CLI parsing, help, readable scan report, --fail-on gate, and the single version source.

import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { request } from "node:http";
import { describe, expect, it } from "vitest";
import { closest, depsUncheckedWarning, failOnCount, failOnMessage, formatScan, parseCli, usage } from "../src/commands.js";
import { startGui } from "../src/gui/server.js";
import { USER_AGENT, VERSION } from "../src/net/http.js";
import { clearSnapshot, createMcpHandler, loadDefaultTemplate, recordFixRequest } from "../src/index.js";
import { consentedAppDir, git, gitRepo, K, mockNet, project, scanDefault, tempDir } from "./helpers.js";

const NL = "\n";
const PKG_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version as string;

describe("version comes from package.json", () => {
  it("VERSION, User-Agent, MCP serverInfo, scan engine_version and GUI state all match", async () => {
    expect(PKG_VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(VERSION).toBe(PKG_VERSION);
    expect(USER_AGENT).toContain(`checkback/${PKG_VERSION} `);

    const cwd = project({ "a.txt": "" });
    const h = createMcpHandler({ cwd, appDir: tempDir() });
    const init = (await h({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } })) as {
      result: { serverInfo: { version: string } };
    };
    expect(init.result.serverInfo.version).toBe(PKG_VERSION);
    expect((await scanDefault(cwd)).engine_version).toBe(PKG_VERSION);

    const g = await startGui({ cwd, appDir: tempDir() });
    try {
      const origin = `http://127.0.0.1:${g.port}`;
      const send = (method: string, path: string, headers: Record<string, string>, body?: string) =>
        new Promise<{ headers: Record<string, unknown>; text: string }>((resolve, reject) => {
          const r = request({ host: "127.0.0.1", port: g.port, method, path, headers: { host: `127.0.0.1:${g.port}`, origin, ...headers } }, (res) => {
            let text = "";
            res.setEncoding("utf8");
            res.on("data", (c) => (text += c));
            res.on("end", () => resolve({ headers: res.headers, text }));
          });
          r.on("error", reject);
          r.end(body);
        });
      const token = g.url.split("#t=")[1]!;
      const s = await send("POST", "/api/session", { "content-type": "application/json", "x-checkback-token": token }, "{}");
      const cookie = String(s.headers["set-cookie"]).split(";")[0]!;
      const state = JSON.parse((await send("GET", "/api/state", { cookie, "x-checkback-token": token })).text) as { version: string };
      expect(state.version).toBe(PKG_VERSION);
    } finally {
      await g.close();
    }
  });
});

describe("parseCli", () => {
  it("help and version anywhere, help as a command", () => {
    for (const a of [["-h"], ["--help"], ["help"], ["scan", "--help"]]) expect(parseCli(a)).toEqual({ kind: "help" });
    for (const a of [["-v"], ["--version"]]) expect(parseCli(a)).toEqual({ kind: "version" });
  });

  it("no command or a leading option means gui", () => {
    expect(parseCli([])).toEqual({ kind: "run", cmd: "gui", opts: {} });
    expect(parseCli(["--no-open"])).toEqual({ kind: "run", cmd: "gui", opts: { "--no-open": true } });
  });

  it("scan options, both `--x v` and `--x=v`", () => {
    expect(parseCli(["scan", "--lang", "ko", "--fail-on=high", "--json", "--template", "t.yaml"])).toEqual({
      kind: "run",
      cmd: "scan",
      opts: { "--lang": "ko", "--fail-on": "high", "--json": true, "--template": "t.yaml" },
    });
  });

  it("errors with a suggestion for unknown commands and options", () => {
    expect(parseCli(["scna"])).toEqual({ kind: "error", message: 'unknown command "scna". Did you mean "scan"?' });
    expect(parseCli(["sca"])).toMatchObject({ message: expect.stringContaining('Did you mean "scan"?') });
    expect(parseCli(["frobnicate"])).toEqual({ kind: "error", message: 'unknown command "frobnicate".' });
    expect(parseCli(["scan", "--fail-of", "high"])).toMatchObject({ kind: "error", message: expect.stringContaining('Did you mean "--fail-on"?') });
    expect(parseCli(["sbom", "--lang", "ko"])).toMatchObject({ kind: "error", message: expect.stringContaining('unknown option "--lang" for "sbom"') });
    expect(parseCli(["scan", "extra"])).toMatchObject({ kind: "error" });
  });

  it("rejects missing and invalid values", () => {
    expect(parseCli(["scan", "--fail-on"])).toMatchObject({ kind: "error", message: expect.stringContaining("needs a value") });
    expect(parseCli(["scan", "--fail-on", "--json"])).toMatchObject({ kind: "error", message: expect.stringContaining("needs a value") });
    expect(parseCli(["scan", "--fail-on", "huge"])).toMatchObject({ kind: "error", message: expect.stringContaining("critical, high, medium, low") });
    expect(parseCli(["scan", "--lang", "fr"])).toMatchObject({ kind: "error" });
    expect(parseCli(["sbom", "--upload=yes"])).toMatchObject({ kind: "error", message: expect.stringContaining("does not take a value") });
  });

  it("closest only suggests near matches", () => {
    expect(closest("gu", ["gui", "scan"])).toBe("gui");
    expect(closest("xyzzy", ["gui", "scan"])).toBeUndefined();
  });

  it("usage lists every command and the version", () => {
    const u = usage("9.9.9");
    expect(u).toMatch(/^checkback 9\.9\.9/);
    expect(u).toContain("usage: checkback");
    for (const c of ["gui", "scan", "sbom", "mcp", "consent", "ignore", "watch", "track", "--fail-on", "--json"]) expect(u).toContain(c);
  });
});

describe("failOnCount", () => {
  const fs = [
    { severity: "critical", confidence: "confirmed" },
    { severity: "high", confidence: "review" },
    { severity: "medium", confidence: "confirmed" },
    { severity: "critical", confidence: "info" },
  ] as const;
  it("counts confirmed findings at the threshold or above", () => {
    expect(failOnCount([...fs], "critical")).toBe(1);
    expect(failOnCount([...fs], "high")).toBe(1);
    expect(failOnCount([...fs], "medium")).toBe(2);
    expect(failOnCount([...fs], "low")).toBe(2);
    expect(failOnCount([], "low")).toBe(0);
  });

  it("A3: the threshold message follows --lang", () => {
    expect(failOnMessage(7, "high")).toBe("checkback: 7 things to fix at high or above (--fail-on high)");
    expect(failOnMessage(1, "low")).toBe("checkback: 1 thing to fix at any severity (--fail-on low)");
    expect(failOnMessage(7, "high", "ko")).toBe("checkback: 높음 이상 고칠 일 7개 (--fail-on high)");
    expect(failOnMessage(2, "low", "ko")).toBe("checkback: 심각도와 관계없이 고칠 일 2개 (--fail-on low)");
  });
});

describe("formatScan", () => {
  const SECRET = ["sk", "proj", "CliTestFakeKeyNotReal000011112222333344445555666677778888QzWx"].join("-");
  const dir = (): string => {
    const cwd = gitRepo(project({ "src/ai.ts": `export const k = "${SECRET}";\n`, "server.js": "const app = require('express')();\napp.use(require('cors')());\n", ".env.example": "OPENAI_API_KEY=your-key-here\n" }));
    git(cwd, "add", "-A");
    git(cwd, "commit", "-qm", "i");
    return cwd;
  };

  it("summary, items with location and description, next steps; no secret or masked value", async () => {
    const r = await scanDefault(dir(), { lang: "en" });
    const out = formatScan(r, await loadDefaultTemplate(), "en", false);
    expect(out).toMatch(/^\d+ things? to fix {3}CRITICAL \d+ · HIGH \d+ · MEDIUM \d+/);
    expect(out).toContain("To fix");
    expect(out).toMatch(/ {2}CRITICAL {2}\S.*\n {12}src\/ai\.ts:1\n {12}An OpenAI API key/);
    expect(out).toContain("npx checkback ");
    expect(out).toContain("Passing is not 'safe'");
    expect(out).not.toContain(SECRET);
    expect(out).not.toContain(SECRET.slice(-4));
    expect(out).not.toContain("•");
    expect(out).not.toContain("\x1b[");
  });

  it("Korean labels and color codes when asked", async () => {
    const r = await scanDefault(dir(), { lang: "ko" });
    const out = formatScan(r, await loadDefaultTemplate(), "ko", true);
    expect(out).toContain("고칠 일");
    expect(out).toContain("긴급");
    expect(out).toContain("\x1b[");
  });

  // N1/N2: what could not be checked is said first; dependency items name the package and the upgrade.
  const depsProject = (): string => {
    const lock = JSON.stringify({
      name: "app",
      lockfileVersion: 3,
      packages: { "": { name: "app", dependencies: { lodash: "4.17.15" } }, "node_modules/lodash": { version: "4.17.15", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz", integrity: "sha512-x" } },
    });
    return project({ "package.json": JSON.stringify({ name: "app", dependencies: { lodash: "4.17.15" } }), "package-lock.json": lock, "web/package-lock.json": lock, "web/package.json": JSON.stringify({ name: "web", dependencies: { lodash: "4.17.15" } }) });
  };

  it("N1: offline dependency lookups are announced at the top, and --fail-on gets a warning", async () => {
    const r = await scanDefault(depsProject(), { appDir: await consentedAppDir(), fetch: mockNet({ offline: true }).fetch });
    const out = formatScan(r, await loadDefaultTemplate(), "en", false);
    const notice = out.indexOf("! An external lookup failed");
    expect(notice).toBeGreaterThan(0);
    expect(notice).toBeLessThan(out.indexOf("Next"));
    expect(out.split(NL)[3]).toMatch(/^! /); // right under the summary
    expect(depsUncheckedWarning(r)).toMatch(/dependency check did not fully run \(offline.*--fail-on does not cover it/);
    expect(depsUncheckedWarning(r, "ko")).toMatch(/^checkback: 의존성 검사가 끝까지 실행되지 않아\(offline.*--fail-on 판정에 들어가지 않았습니다/);
    const ko = formatScan(r, await loadDefaultTemplate(), "ko", false);
    expect(ko).toContain("! 외부 조회에 실패해 의존성 검사 일부를 하지 못했습니다");
  });

  it("N1: no consent → consent notice at the top; partial (time budget) → the same notice as GUI/MCP", async () => {
    let r = await scanDefault(depsProject());
    expect(formatScan(r, await loadDefaultTemplate(), "en", false).split(NL)[3]).toMatch(/^! External lookups are off until consent/);
    expect(depsUncheckedWarning(r)).toMatch(/no_consent/);
    r = await scanDefault(depsProject(), { appDir: await consentedAppDir(), fetch: mockNet({}).fetch, deadlineMs: 0 });
    expect(formatScan(r, await loadDefaultTemplate(), "en", false)).toContain("! Some external lookups did not finish in time");
    expect(depsUncheckedWarning(r)).toMatch(/timeout_partial/);
  });

  it("N2: a vulnerable package shows name, version, upgrade target and every lock with it", async () => {
    const net = mockNet({
      osv: { "npm:lodash@4.17.15": ["GHSA-35jh-r3h4-6jhm"] },
      vulns: { "GHSA-35jh-r3h4-6jhm": { id: "GHSA-35jh-r3h4-6jhm", aliases: [], database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] } },
      npm: { lodash: {} },
    });
    const r = await scanDefault(depsProject(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch });
    const out = formatScan(r, await loadDefaultTemplate(), "en", false);
    expect(out).toContain(
      [
        "  HIGH      Package with known vulnerabilities",
        "            lodash 4.17.15 → upgrade to 4.17.21 or later",
        "            package-lock.json +1 more: web/package-lock.json",
      ].join(NL),
    );
    expect(formatScan(r, await loadDefaultTemplate(), "ko", false)).toContain("lodash 4.17.15 → 4.17.21 이상으로 올리기");
    expect(depsUncheckedWarning(r)).toBeNull();
  });

  it("A4: re-check summary, resolved items and tags on changed states only", async () => {
    const appDir = tempDir();
    const [a, b, c] = [K.openai(), K.openai(), K.openai()];
    const cwd = project({ "src/a.ts": `export const a = "${a}";\n`, "src/b.ts": `export const b = "${b}";\n`, "src/c.ts": `export const c = "${c}";\n` });
    const tpl = await loadDefaultTemplate();
    const first = await scanDefault(cwd, { appDir, lang: "ko" });
    await recordFixRequest(cwd, first.findings.filter((f) => f.confidence === "confirmed").map((f) => f.id), appDir);
    // a's key removed, b's key moved to another file, c left alone
    writeFileSync(join(cwd, "src/a.ts"), "export const a = process.env.A;\n");
    rmSync(join(cwd, "src/b.ts"));
    writeFileSync(join(cwd, "src/b2.ts"), `export const b = "${b}";\n`);
    let r = await scanDefault(cwd, { appDir, lang: "ko" });
    const ko = formatScan(r, tpl, "ko", false);
    expect(ko).toMatch(/\n재검사\(수정 요청 기준\): 해결됨 1 · 아직 남음 1 · 같은 키 남음 1 · 새로 생김 0\n {2}해결됨 {2}\S.* · src\/a\.ts:1\n/);
    expect(ko).not.toContain("옮겨짐 의심");
    expect(ko).toMatch(/긴급 {2}\S.*\[같은 키 남음\]\n {8}src\/b2\.ts:1/);
    expect(ko.match(/\[[^\]]+\]/g)).toEqual(["[같은 키 남음]"]); // "still there" gets no tag
    const en = formatScan(r, tpl, "en", false);
    expect(en).toContain("Re-check (against the fix request): Resolved 1 · Still there 1 · Same key remains 1 · New 0");
    expect(en).toContain("[Same key remains]");
    for (const k of [a, b, c]) for (const out of [ko, en]) expect(out).not.toContain(k.slice(-6));
    await clearSnapshot(cwd, appDir);
    r = await scanDefault(cwd, { appDir, lang: "ko" });
    expect(formatScan(r, tpl, "ko", false)).toContain("재검사(직전 검사 기준): 해결됨 0 · 아직 남음 2 · 같은 키 남음 0 · 새로 생김 0");
    // no baseline → no re-check block
    expect(formatScan(await scanDefault(cwd, { lang: "ko" }), tpl, "ko", false)).not.toContain("재검사");
  });

  it("clean project says so", async () => {
    const r = await scanDefault(project({ "a.txt": "hello\n" }));
    expect(formatScan(r, await loadDefaultTemplate(), "en", false)).toContain("0 things to fix");
  });
});
