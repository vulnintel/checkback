// Clean-room end-to-end check of an installed checkback package (run inside docker/e2e/Dockerfile).
// Usage: node e2e.mjs online|offline
//   online  — default network, no consent: local rules only (deterministic, no external calls).
//   offline — run with `docker run --network none`; consent is given so external lookups are
//             attempted and must fail soft ("offline") while local rules, SBOM, MCP and GUI keep working.
// Every check runs and reports; the exit code is 1 if any check failed. Nothing is skipped.
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { connect } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";

const MODE = process.argv[2] === "offline" ? "offline" : "online";
// CHECKBACK_JS=<path to dist/cli.js> runs a local build instead of the installed `checkback` bin.
const BIN = process.env.CHECKBACK_JS ? [process.execPath, process.env.CHECKBACK_JS] : ["checkback"];
const PKG_DIR = process.env.CHECKBACK_JS
  ? dirname(dirname(realpathSync(process.env.CHECKBACK_JS)))
  : spawnSync("npm", ["root", "-g"], { encoding: "utf8" }).stdout.trim() + "/checkback";
const VERSION = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf8")).version;

// ---------- result bookkeeping
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok     ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL   ${name}\n       ${String(e?.message ?? e).split("\n").join("\n       ")}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const eq = (actual, expected, what) => assert(JSON.stringify(actual) === JSON.stringify(expected), `${what}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);

// ---------- fixture: obviously fake keys, assembled at run time so no secret-shaped string is committed
const SECRETS = {
  openai: ["sk", "proj", "E2eFakeKeyNotReal0000111122223333444455556666777788889999QzWx"].join("-"),
  github: ["ghp", "E2eFakeTokenNotReal0000111122223QzWv"].join("_"),
};
const TAILS = Object.values(SECRETS).map((s) => s.slice(-4)); // GUI masking shows the last 4; MCP/CLI must not

const home = mkdtempSync(join(tmpdir(), "cb-home-"));
const project = mkdtempSync(join(tmpdir(), "cb-proj-"));
const ENV = { ...process.env, HOME: home, XDG_DATA_HOME: join(home, "data"), APPDATA: join(home, "data"), LANG: "C.UTF-8", NO_COLOR: "1" };
const APP_DIR = join(home, "data", "checkback"); // XDG_DATA_HOME (Linux) / APPDATA (Windows)

function write(rel, body) {
  mkdirSync(dirname(join(project, rel)), { recursive: true });
  writeFileSync(join(project, rel), body);
}
write("package.json", JSON.stringify({ name: "e2e-app", version: "1.0.0", private: true, dependencies: { lodash: "4.17.20" } }, null, 2));
write(
  "package-lock.json",
  JSON.stringify(
    {
      name: "e2e-app",
      version: "1.0.0",
      lockfileVersion: 3,
      requires: true,
      packages: {
        "": { name: "e2e-app", version: "1.0.0", dependencies: { lodash: "4.17.20" } },
        "node_modules/lodash": {
          version: "4.17.20",
          resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
          integrity: "sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==",
        },
      },
    },
    null,
    2,
  ),
);
write(".gitignore", "node_modules/\n"); // no .env rule
write(".env", `GITHUB_TOKEN=${SECRETS.github}\n`); // committed below
write(".env.example", "OPENAI_API_KEY=your-key-here\n"); // placeholder: must not be reported
write("src/lib/ai.ts", `import OpenAI from "openai";\nexport const client = new OpenAI({ apiKey: "${SECRETS.openai}" });\n`);
write("server.js", `const express = require("express");\nconst cors = require("cors");\nconst app = express();\napp.use(cors());\napp.listen(3000);\n`);
write("backend/settings/production.py", "DEBUG = True\nALLOWED_HOSTS = ['*']\n");
write("firestore.rules", "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if true;\n    }\n  }\n}\n");
write("supabase/migrations/0001_init.sql", "create table public.notes (\n  id bigint primary key,\n  body text\n);\n");
const git = (...a) => spawnSync("git", ["-c", "user.name=e2e", "-c", "user.email=e2e@localhost", ...a], { cwd: project, encoding: "utf8" });
assert(git("init", "-q").status === 0, "git init failed (is git installed?)");
git("add", "-A");
assert(git("commit", "-q", "-m", "init").status === 0, "git commit failed");

// [rule_id, severity, confidence, file]
const EXPECTED = [
  ["secret-openai", "critical", "confirmed", "src/lib/ai.ts"],
  ["secret-github", "critical", "confirmed", ".env"],
  ["env-committed", "critical", "confirmed", ".env"],
  ["gitignore-env-missing", "high", "confirmed", ".gitignore"],
  ["firebase-rules", "critical", "confirmed", "firestore.rules"],
  ["supabase-rls", "high", "confirmed", "supabase/migrations/0001_init.sql"],
  ["debug-django", "high", "confirmed", "backend/settings/production.py"],
  ["cors-wildcard", "medium", "review", "server.js"],
];
function expectFindings(findings, where) {
  const got = findings.map((f) => `${f.rule_id}|${f.severity}|${f.confidence}|${f.location?.file ?? ""}`);
  const missing = EXPECTED.map((e) => e.join("|")).filter((e) => !got.includes(e));
  assert(missing.length === 0, `${where}: missing ${JSON.stringify(missing)}\n got ${JSON.stringify(got)}`);
  const onExample = findings.filter((f) => f.location?.file === ".env.example" && f.confidence !== "info");
  assert(onExample.length === 0, `${where}: placeholder in .env.example reported: ${JSON.stringify(onExample.map((f) => f.rule_id))}`);
}
function noSecrets(text, where, { tails = true } = {}) {
  for (const s of Object.values(SECRETS)) assert(!text.includes(s), `${where}: raw secret value present`);
  if (tails) {
    assert(!text.includes("••••"), `${where}: masked value present`);
    for (const t of TAILS) assert(!text.includes(t), `${where}: last 4 chars of a secret present (${t})`);
  }
}
function externalReason(checked, where) {
  const want = MODE === "offline" ? "offline" : "no_consent";
  for (const id of ["vulnerable-deps", "hallucinated-package"]) {
    const c = checked.find((x) => x.rule_id === id);
    assert(c, `${where}: ${id} missing from checked`);
    assert(c.reason === want, `${where}: ${id} reason expected ${want}, got ${JSON.stringify(c)}`);
  }
}

// ---------- process helpers
function run(args, { timeoutMs = 120_000, input } = {}) {
  const r = spawnSync(BIN[0], [...BIN.slice(1), ...args], { cwd: project, env: ENV, encoding: "utf8", timeout: timeoutMs, input: input ?? "" });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "", error: r.error };
}

if (MODE === "offline") {
  mkdirSync(APP_DIR, { recursive: true });
  writeFileSync(join(APP_DIR, "config.json"), JSON.stringify({ consent: { at: new Date().toISOString(), version: 1 } }));
}

console.log(`checkback ${VERSION} · node ${process.version} · mode ${MODE}`);

// ① CLI basics
await check("cli: --help prints usage and exits 0", () => {
  const r = run(["--help"], { timeoutMs: 15_000 });
  assert(/usage: checkback/.test(r.out + r.err), `no usage text (stdout=${JSON.stringify(r.out.slice(0, 200))})`);
  eq(r.code, 0, "exit code");
});
await check("cli: --version prints the package version", () => {
  const r = run(["--version"], { timeoutMs: 15_000 });
  assert(r.out.trim() === VERSION, `expected stdout ${JSON.stringify(VERSION)}, got stdout=${JSON.stringify(r.out.slice(0, 120))} stderr=${JSON.stringify(r.err.slice(0, 120))} code=${r.code}`);
  eq(r.code, 0, "exit code");
});
await check("cli: unknown command prints usage to stderr and exits 2", () => {
  const r = run(["no-such-command"], { timeoutMs: 15_000 });
  eq(r.code, 2, "exit code");
  assert(/usage: checkback/.test(r.err), "no usage on stderr");
});
await check("cli: a typo gets the closest command / option suggested, exit 2", () => {
  const c = run(["scna"], { timeoutMs: 15_000 });
  eq(c.code, 2, "exit code (command)");
  assert(/Did you mean "scan"\?/.test(c.err), `no command suggestion: ${JSON.stringify(c.err.slice(0, 200))}`);
  const o = run(["scan", "--fail-of", "high"], { timeoutMs: 15_000 });
  eq(o.code, 2, "exit code (option)");
  assert(/Did you mean "--fail-on"\?/.test(o.err), `no option suggestion: ${JSON.stringify(o.err.slice(0, 200))}`);
  eq(run(["scan", "--fail-on", "huge"], { timeoutMs: 15_000 }).code, 2, "exit code (bad value)");
});
if (MODE === "online") {
  await check("cli: consent is refused without a TTY and nothing is stored (AC37)", () => {
    const r = run(["consent"], { timeoutMs: 15_000 });
    assert(r.code !== 0, `exit code 0`);
    let cfg = {};
    try {
      cfg = JSON.parse(readFileSync(join(APP_DIR, "config.json"), "utf8"));
    } catch {}
    assert(!cfg.consent, "consent was stored");
  });
}

// ②③ scan + outputs
let cliFindings = [];
await check("cli: scan finds the planted problems with expected severity/confidence", () => {
  const t0 = Date.now();
  const r = run(["scan"], { timeoutMs: 90_000 });
  eq(r.code, 0, `exit code (stderr ${r.err.slice(0, 300)})`);
  const j = JSON.parse(r.out);
  cliFindings = j.findings;
  expectFindings(j.findings, "scan");
  externalReason(j.checked, "scan");
  console.log(`       ${j.findings.length} findings in ${Date.now() - t0} ms`);
});
await check("cli: scan JSON has no secret values or masked values", () => {
  const r = run(["scan"], { timeoutMs: 90_000 });
  noSecrets(r.out, "scan");
  assert(!r.out.includes("masked_match"), "masked_match field present");
});
await check("cli: scan --lang ko returns Korean titles", () => {
  const j = JSON.parse(run(["scan", "--lang", "ko"], { timeoutMs: 90_000 }).out);
  assert(j.findings.some((f) => /[가-힣]/.test(f.title)), "no Hangul title");
});
await check("cli: scan --text prints a readable report without secrets, masked values or colors", () => {
  const r = run(["scan", "--text"], { timeoutMs: 90_000 });
  eq(r.code, 0, `exit code (stderr ${r.err.slice(0, 300)})`);
  assert(/^\d+ things? to fix {3}CRITICAL \d+ · HIGH \d+ · MEDIUM \d+/.test(r.out), `no summary: ${JSON.stringify(r.out.slice(0, 200))}`);
  for (const s of ["To fix", "src/lib/ai.ts:2", "firestore.rules", "npx checkback"]) assert(r.out.includes(s), `missing ${JSON.stringify(s)}`);
  // N1: what was not checked is said at the top, never a silent "safe"-looking report.
  const top = MODE === "offline" ? "! An external lookup failed" : "! External lookups are off until consent";
  assert(r.out.split("\n")[3]?.startsWith(top), `no ${JSON.stringify(top)} notice under the summary: ${JSON.stringify(r.out.slice(0, 400))}`);
  assert(!r.out.includes("\x1b["), "ANSI color codes in non-TTY output");
  noSecrets(r.out, "scan --text");
  const ko = run(["scan", "--text", "--lang", "ko"], { timeoutMs: 90_000 });
  assert(/^고칠 일 \d+개/.test(ko.out) && ko.out.includes("긴급"), `no Korean report: ${JSON.stringify(ko.out.slice(0, 200))}`);
});
await check("cli: scan --fail-on high exits 1 with a reason on stderr, JSON on stdout", () => {
  const r = run(["scan", "--fail-on", "high"], { timeoutMs: 90_000 });
  eq(r.code, 1, "exit code");
  assert(/things? to fix at high or above \(--fail-on high\)/.test(r.err), `no reason on stderr: ${JSON.stringify(r.err.slice(0, 200))}`);
  assert(r.err.includes(`dependency check did not fully run (${MODE === "offline" ? "offline" : "no_consent"}`), `no unchecked-dependency warning: ${JSON.stringify(r.err.slice(0, 300))}`);
  expectFindings(JSON.parse(r.out).findings, "scan --fail-on");
  noSecrets(r.out, "scan --fail-on");
});
await check("cli: sbom is CycloneDX >= 1.4 with the locked package as a purl", () => {
  const r = run(["sbom"], { timeoutMs: 30_000 });
  eq(r.code, 0, "exit code");
  const bom = JSON.parse(r.out);
  eq(bom.bomFormat, "CycloneDX", "bomFormat");
  assert(Number(bom.specVersion) >= 1.4, `specVersion ${bom.specVersion}`);
  assert((bom.components ?? []).some((c) => c.purl === "pkg:npm/lodash@4.17.20"), "lodash purl missing");
  noSecrets(r.out, "sbom");
});
await check("cli: sbom --upload is valid CycloneDX JSON", () => {
  const r = run(["sbom", "--upload"], { timeoutMs: 30_000 });
  eq(r.code, 0, "exit code");
  eq(JSON.parse(r.out).bomFormat, "CycloneDX", "bomFormat");
});

// ④ MCP over stdio
function mcp() {
  const p = spawn(BIN[0], [...BIN.slice(1), "mcp"], { cwd: project, env: ENV, stdio: ["pipe", "pipe", "pipe"] });
  let buf = "";
  const waiting = new Map();
  const extra = [];
  p.stdout.setEncoding("utf8");
  p.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      const w = waiting.get(msg.id);
      if (w) waiting.delete(msg.id), w(msg);
      else extra.push(msg);
    }
  });
  let next = 1;
  const call = (method, params, timeoutMs = 60_000) =>
    new Promise((resolve, reject) => {
      const id = next++;
      const t = setTimeout(() => reject(new Error(`MCP ${method} timed out`)), timeoutMs);
      waiting.set(id, (m) => (clearTimeout(t), resolve(m)));
      p.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, ...(params && { params }) })}\n`);
    });
  const notify = (method) => p.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", method })}\n`);
  const tool = async (name, args = {}) => {
    const m = await call("tools/call", { name, arguments: args });
    return { m, text: m.result?.content?.[0]?.text ?? "", isError: !!m.result?.isError };
  };
  return { p, call, notify, tool, extra, close: () => p.stdin.end() };
}
{
  const s = mcp();
  await check("mcp: initialize returns server info with the package version", async () => {
    const m = await s.call("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "0" } });
    eq(m.result?.protocolVersion, "2025-06-18", "protocolVersion");
    eq(m.result?.serverInfo?.name, "checkback", "serverInfo.name");
    eq(m.result?.serverInfo?.version, VERSION, "serverInfo.version");
    s.notify("notifications/initialized");
  });
  await check("mcp: tools/list is exactly the five tools (AC36)", async () => {
    const m = await s.call("tools/list");
    eq((m.result?.tools ?? []).map((t) => t.name).sort(), ["ai_check_prompt", "explain", "export_sbom", "fix_prompts", "scan"], "tools");
  });
  let found = [];
  await check("mcp: scan returns the planted problems, no secrets or masked values (AC6, AC38)", async () => {
    const { text, isError } = await s.tool("scan");
    assert(!isError, `tool error: ${text}`);
    const j = JSON.parse(text);
    eq(Object.keys(j).filter((k) => !["findings", "checked", "compare", "notice"].includes(k)), [], "unexpected top-level keys");
    found = j.findings;
    expectFindings(j.findings, "mcp scan");
    externalReason(j.checked, "mcp scan");
    noSecrets(text, "mcp scan");
    const howto = /External lookups are off until consent|외부 조회는 아직 꺼져/;
    assert(/Passing is not 'safe'|통과는 '안전'이 아닙니다/.test(j.notice ?? ""), "disclaimer missing from notice");
    if (MODE === "online") assert(howto.test(j.notice), "consent how-to missing before consent");
    else assert(!howto.test(j.notice), "consent how-to shown after consent");
    eq(
      cliFindings.map((f) => f.id).sort(),
      j.findings.map((f) => f.id).sort(),
      "MCP and CLI finding ids",
    );
  });
  await check("mcp: explain and fix_prompts work and carry no secret values", async () => {
    const f = found.find((x) => x.rule_id === "secret-openai");
    assert(f, "no secret-openai finding to explain");
    const ex = await s.tool("explain", { finding_id: f.id });
    assert(!ex.isError && JSON.parse(ex.text).description, `explain failed: ${ex.text.slice(0, 200)}`);
    noSecrets(ex.text, "explain");
    const fp = await s.tool("fix_prompts", { finding_ids: [f.id] });
    assert(!fp.isError && /revoke|폐기/i.test(fp.text), `fix_prompts failed: ${fp.text.slice(0, 200)}`);
    noSecrets(fp.text, "fix_prompts");
  });
  await check("mcp: fix_prompts refuses 11 ids; unknown tool is an error", async () => {
    const ids = Array.from({ length: 11 }, (_, i) => found[i % found.length]?.id ?? `x${i}`);
    assert((await s.tool("fix_prompts", { finding_ids: ids })).isError, "11 ids accepted");
    const m = await s.call("tools/call", { name: "ignore", arguments: {} });
    eq(m.error?.code, -32602, "unknown tool error code");
  });
  await check("mcp: export_sbom and ai_check_prompt answer", async () => {
    eq(JSON.parse((await s.tool("export_sbom")).text).bomFormat, "CycloneDX", "export_sbom bomFormat");
    const a = await s.tool("ai_check_prompt");
    assert(!a.isError && a.text.length > 100, "ai_check_prompt empty");
    noSecrets(a.text, "ai_check_prompt");
  });
  s.close();
  await new Promise((r) => (s.p.exitCode !== null ? r() : s.p.once("exit", r)));
  await check("mcp: exits cleanly when stdin closes, no stray stdout", () => {
    eq(s.p.exitCode, 0, "exit code");
    eq(s.extra, [], "unexpected stdout messages");
  });
}

// ⑤ GUI server (--no-open)
function http(port, { method = "GET", path = "/", host = `127.0.0.1:${port}`, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, method, path, headers: { Host: host, ...headers, ...(body !== undefined && { "Content-Type": "application/json" }) } }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (d) => (data += d));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}
{
  const p = spawn(BIN[0], [...BIN.slice(1), "--no-open"], { cwd: project, env: ENV, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout.setEncoding("utf8");
  p.stdout.on("data", (d) => (out += d));
  const m = await new Promise((resolve) => {
    const t0 = Date.now();
    const tick = setInterval(() => {
      const hit = /http:\/\/127\.0\.0\.1:(\d+)\/#t=([0-9a-f]+)/.exec(out);
      if (hit || Date.now() - t0 > 20_000 || p.exitCode !== null) clearInterval(tick), resolve(hit);
    }, 100);
  });
  const port = Number(m?.[1]);
  const token = m?.[2] ?? "";
  const self = `http://127.0.0.1:${port}`;
  let cookie = "";
  const all = [];
  const h = async (o) => {
    const r = await http(port, o);
    all.push(r);
    return r;
  };
  await check("gui: --no-open prints a loopback URL with a 64-hex token", () => {
    assert(m, `no URL printed: ${JSON.stringify(out)}`);
    eq(token.length, 64, "token length");
  });
  if (m) {
    await check("gui: page is served with CSP and nosniff (AC4)", async () => {
      const r = await h({});
      eq(r.status, 200, "status");
      assert(/text\/html/.test(r.headers["content-type"]), "content-type");
      assert(/frame-ancestors 'none'/.test(r.headers["content-security-policy"] ?? ""), "CSP");
      eq(r.headers["x-content-type-options"], "nosniff", "nosniff");
      const js = await h({ path: "/app.js" });
      eq(js.status, 200, "/app.js status");
    });
    await check("gui: API without token/cookie is 401 (AC2)", async () => {
      eq((await h({ path: "/api/state" })).status, 401, "GET /api/state");
      eq((await h({ method: "POST", path: "/api/session", headers: { Origin: self, "X-Checkback-Token": "0".repeat(64) }, body: {} })).status, 401, "wrong token");
    });
    await check("gui: foreign Host / Origin are 403 (AC3)", async () => {
      eq((await h({ host: `evil.example:${port}` })).status, 403, "Host evil.example");
      eq((await h({ method: "POST", path: "/api/session", headers: { Origin: "https://evil.example", "X-Checkback-Token": token }, body: {} })).status, 403, "Origin evil");
      eq((await h({ method: "POST", path: "/api/session", headers: { Origin: `http://127.0.0.1:${port + 1}`, "X-Checkback-Token": token }, body: {} })).status, 403, "Origin other port");
      eq((await h({ method: "POST", path: "/api/session", headers: { "X-Checkback-Token": token }, body: {} })).status, 403, "POST without Origin");
    });
    await check("gui: session cookie is HttpOnly, SameSite=Strict, named after the port (AC4)", async () => {
      const r = await h({ method: "POST", path: "/api/session", headers: { Origin: self, "X-Checkback-Token": token }, body: {} });
      eq(r.status, 204, "status");
      const c = String(r.headers["set-cookie"] ?? "");
      assert(c.startsWith(`checkback_s_${port}=`) && /HttpOnly/.test(c) && /SameSite=Strict/.test(c), `cookie ${c}`);
      cookie = c.split(";")[0];
      eq((await h({ path: "/api/state", headers: { Cookie: cookie } })).status, 401, "cookie without token header");
      const st = await h({ path: "/api/state", headers: { Cookie: cookie, "X-Checkback-Token": token } });
      eq(st.status, 200, "cookie + token");
      eq(JSON.parse(st.body).consent, MODE === "offline", "consent state");
    });
    await check("gui: scan through the API finds the planted problems; no raw secrets in the result", async () => {
      const auth = { Cookie: cookie, "X-Checkback-Token": token, Origin: self };
      eq((await h({ method: "POST", path: "/api/scan", headers: auth, body: { template: "default" } })).status, 200, "POST /api/scan");
      const t0 = Date.now();
      let s;
      do {
        await new Promise((r) => setTimeout(r, 200));
        s = JSON.parse((await h({ path: "/api/scan", headers: auth })).body);
      } while (s.running && Date.now() - t0 < 90_000);
      assert(!s.running && !s.error, `scan state ${JSON.stringify(s)}`);
      const r = await h({ path: "/api/result", headers: auth });
      eq(r.status, 200, "GET /api/result");
      const j = JSON.parse(r.body);
      expectFindings(j.findings, "gui result");
      noSecrets(r.body, "gui result", { tails: false }); // the GUI may show prefix••••last4 (§10-3)
      const nr = Object.fromEntries(j.not_run.map((x) => [x.rule_id, x.reason]));
      const want = MODE === "offline" ? "offline" : "no_consent";
      eq([nr["vulnerable-deps"], nr["hallucinated-package"]], [want, want], "external rules not_run reasons");
    });
    await check("gui: no CORS headers on any response (AC3)", () => {
      const bad = all.filter((r) => Object.keys(r.headers).some((k) => k.startsWith("access-control-")));
      eq(bad.length, 0, "responses with Access-Control-*");
    });
    await check("gui: port is not reachable on non-loopback interfaces (AC1)", async () => {
      const ips = Object.values(networkInterfaces()).flat().filter((i) => i && !i.internal && i.family === "IPv4").map((i) => i.address);
      if (ips.length === 0) console.log("       (no non-loopback interface in this network mode)");
      for (const ip of ips) {
        const reached = await new Promise((resolve) => {
          const s = connect({ host: ip, port }, () => (s.destroy(), resolve(true)));
          s.on("error", () => resolve(false));
          s.setTimeout(2000, () => (s.destroy(), resolve(false)));
        });
        assert(!reached, `reachable on ${ip}:${port}`);
      }
    });
  }
  p.kill("SIGTERM");
  await new Promise((r) => (p.exitCode !== null || p.signalCode !== null ? r() : p.once("exit", r)));
}

console.log(failed ? `\n${failed} check(s) failed (mode ${MODE}, node ${process.version})` : `\nall checks passed (mode ${MODE}, node ${process.version})`);
process.exit(failed ? 1 : 0);
