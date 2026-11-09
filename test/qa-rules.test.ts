// Release QA fixes on rules, file collection and CLI (QA 2026-11-09 B2·B5·B10·B11·B13, audit #16).

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { readConfig, updateConfig } from "../src/appdata.js";
import { parseCli } from "../src/commands.js";
import { isTestPath, isVendorPath } from "../src/files.js";
import { DATA_TABLE } from "../src/notice.js";
import { needsRevoke } from "../src/prompts.js";
import { envHasOnlyPublicValues } from "../src/refine.js";
import { ProjectDirError } from "../src/scan.js";
import { byRule, git, gitRepo, K, project, scanDefault, tempDir } from "./helpers.js";

describe("B2 Supabase anon key is public, not a service key", () => {
  it("legacy anon JWT: own rule, info, no revoke step; service_role JWT and sb_secret_ stay critical", async () => {
    const dir = project({
      "src/integrations/supabase/client.ts": `export const supabase = createClient(URL, "${K.anonJwt()}");`,
      "server/admin.ts": `const a = "${K.serviceRoleJwt()}";\nconst b = "${K.sbSecret()}";`,
      "src/pub.ts": `createClient(URL, "${K.sbPublishable()}")`,
    });
    const r = await scanDefault(dir);
    const anon = byRule(r, "supabase-anon-key");
    expect(anon).toMatchObject([{ severity: "medium", confidence: "info", location: { file: "src/integrations/supabase/client.ts" }, notes: ["legacy_anon_key"] }]);
    expect(anon[0]!.secret_kind).toBeUndefined();
    expect(needsRevoke(anon[0]!)).toBe(false);
    expect(byRule(r, "secret-supabase-service-role").map((f) => [f.location!.file, f.severity, f.confidence])).toEqual([
      ["server/admin.ts", "critical", "confirmed"],
      ["server/admin.ts", "critical", "confirmed"],
    ]);
    expect(r.findings.filter((f) => f.location?.file === "src/pub.ts")).toEqual([]);
  });

  it("anon rule text keeps the key in the browser (ko/en)", async () => {
    const { loadDefaultTemplate } = await import("../src/index.js");
    const rule = (await loadDefaultTemplate()).rules.find((x) => x.id === "supabase-anon-key")!;
    if (rule.type !== "pattern") throw new Error("type");
    expect(rule.name!.ko).toContain("브라우저에 있어도 정상");
    for (const lang of ["ko", "en"] as const) {
      expect(rule.description![lang]).toMatch(/RLS/);
      expect(rule.fix_prompt![lang]).not.toMatch(/폐기|재발급|revoke|reissue|rotate/i);
    }
  });
});

describe("B5 file collection skips other checkouts and gitignored copies", () => {
  it("nested worktrees, .claude/worktrees and gitignored folders are skipped; build output and local .env are kept", async () => {
    const key = K.openai();
    const dir = gitRepo(
      project({
        ".gitignore": "dist-ignored/\ndist/\n.env\n",
        "src/a.ts": `const k = "${key}";`,
        ".claude/worktrees/feat-x/.git": "gitdir: ../../../.git/worktrees/feat-x\n",
        ".claude/worktrees/feat-x/src/a.ts": `const k = "${key}";`,
        ".claude/worktrees/feat-y/src/a.ts": `const k = "${key}";`,
        "tools/sub/.git": "gitdir: ../../.git/modules/sub\n",
        "tools/sub/a.ts": `const k = "${key}";`,
        "dist-ignored/x.js": `const k = "${key}";`,
        "dist/app.js": `const k = "${key}";`,
        ".env": `OPENAI_API_KEY=${K.openai()}\n`,
      }),
    );
    const r = await scanDefault(dir);
    const hits = byRule(r, "secret-openai").map((f) => [f.location!.file, f.confidence, f.notes ?? []]);
    expect(hits).toEqual([
      ["src/a.ts", "confirmed", ["in_build_output"]],
      [".env", "info", ["local_only_env"]],
    ]);
  });

  it(".claude/worktrees is skipped outside git too", async () => {
    const dir = project({ ".claude/worktrees/w/a.ts": `const k = "${K.openai()}";`, "a.txt": "" });
    expect(byRule(await scanDefault(dir), "secret-openai")).toEqual([]);
  });
});

describe("B10 .env with only non-secret values", () => {
  it("URL and token-type values are public; a real token is not", () => {
    expect(envHasOnlyPublicValues({ VITE_GITLAB_URL: "https://gitlab.com", VITE_GITLAB_TOKEN_TYPE: "personal-access-token", OPENAI_API_KEY: "", LOG_LEVEL: "debug" })).toBe(true);
    expect(envHasOnlyPublicValues({ VITE_GITLAB_TOKEN_TYPE: K.github() })).toBe(false);
    expect(envHasOnlyPublicValues({ GITLAB_TOKEN: "glpat-abcdefghijklmnopqrst" })).toBe(false);
    expect(envHasOnlyPublicValues({ DB_PASSWORD: "hunter2" })).toBe(false);
    expect(envHasOnlyPublicValues({ ADMIN_PASS: "letmein" })).toBe(false);
  });

  it("committed .env.production with empty keys is info public_values_only", async () => {
    const dir = gitRepo(project({ ".env.production": "VITE_GITLAB_URL=https://gitlab.com\nVITE_GITLAB_TOKEN_TYPE=personal-access-token\nVITE_OPENAI_API_KEY=\n" }));
    git(dir, "add", ".");
    git(dir, "commit", "-qm", "init");
    expect(byRule(await scanDefault(dir), "env-committed")).toMatchObject([{ confidence: "info", notes: ["public_values_only"] }]);
  });
});

describe("B11 placeholder passwords in DB URLs", () => {
  it("pass / password / <password> / ${...} are placeholders; a real password is reported", async () => {
    const dir = project({
      "ARCHITECTURE.md": [
        "mongodb+srv://user:pass@cluster0.abcde.mongodb.net/app",
        "postgresql://admin:password@db.prod-host.io:5432/app",
        "postgres://app:<password>@db.prod-host.io/app",
        "postgres://app:${DB_PASS}@db.prod-host.io/app",
        "postgres://app:Xk92jfQ0pzLm@db.prod-host.io/app",
      ].join("\n"),
    });
    expect(byRule(await scanDefault(dir), "secret-db-url").map((f) => f.location!.line)).toEqual([5]);
  });
});

describe("B13 development and vendor paths", () => {
  it("path classes", () => {
    for (const p of ["scripts/stress-test/setup/mock_openai_server.py", "src/__mocks__/api.ts", "e2e/server.py", "api/mock.server.py"]) expect(isTestPath(p)).toBe(true);
    for (const p of ["src/app.py", "mockingbird/app.py", "src/hammock.py"]) expect(isTestPath(p)).toBe(false);
    for (const p of ["static/redoc.standalone.js", "public/vendor/x.js", "assets/jquery.min.js"]) expect(isVendorPath(p)).toBe(true);
    expect(isVendorPath("src/main.js")).toBe(false);
  });

  it("mock server debug=True is review; library sourcemaps are not production findings", async () => {
    const dir = project({
      "scripts/stress-test/setup/mock_openai_server.py": "app.run(port=5001, debug=True)\n",
      "app.py": "app.run(debug=True)\n",
      "vite.config.ts": "export default { build: { sourcemap: true } }",
      "packages/ui/vite.config.ts": "export default { build: { lib: { entry: 'src/index.ts' }, sourcemap: true } }",
      "sdks/node/vite.config.ts": "export default { build: { sourcemap: true } }",
    });
    const r = await scanDefault(dir);
    expect(byRule(r, "debug-flask").map((f) => [f.location!.file, f.confidence])).toEqual([
      ["app.py", "confirmed"],
      ["scripts/stress-test/setup/mock_openai_server.py", "review"],
    ]);
    expect(byRule(r, "sourcemap-vite").map((f) => [f.location!.file, f.confidence])).toEqual([
      ["vite.config.ts", "confirmed"],
      ["sdks/node/vite.config.ts", "review"],
      ["packages/ui/vite.config.ts", "info"],
    ]);
  });

  it("vendored bundles and private Python modules are not import names", async () => {
    const dir = project({
      "package.json": '{"name":"app","dependencies":{}}',
      "static/redoc.standalone.js": 'var a=require("null"),b=require("ajv");',
      "src/a.ts": 'import x from "left-pad";',
      "requirements.txt": "flask==3.0.0\n",
      "conftest.py": "from _pytest.config import Config\n",
    });
    const names = byRule(await scanDefault(dir), "hallucinated-package").map((f) => f.package);
    expect(names).toContain("left-pad");
    expect(names).not.toContain("null");
    expect(names).not.toContain("ajv");
    expect(names.some((n) => n?.startsWith("-") || n?.startsWith("_"))).toBe(false);
  });
});

describe("plugin folder guard", () => {
  it("refuses the Claude Code plugin cache and checkback's own plugin bundle", async () => {
    const cache = join(tempDir(), ".claude", "plugins", "cache", "vulnintel", "checkback", "0.1.0");
    mkdirSync(cache, { recursive: true });
    writeFileSync(join(cache, "a.txt"), "");
    await expect(scanDefault(cache)).rejects.toThrow(ProjectDirError);
    const bundle = project({ ".claude-plugin/plugin.json": '{"name":"checkback"}', ".mcp.json": '{"mcpServers":{"checkback":{"command":"npx","args":["checkback","mcp"]}}}' });
    await expect(scanDefault(bundle, { lang: "ko" })).rejects.toThrow(/프로젝트 폴더를 알 수 없음/);
    // A project that merely has a plugin manifest is still scanned.
    const other = project({ ".claude-plugin/plugin.json": '{"name":"mine"}', "a.txt": "" });
    await expect(scanDefault(other)).resolves.toBeTruthy();
  });
});

describe("config writes", () => {
  it("concurrent updates keep every field", async () => {
    const d = tempDir();
    await Promise.all([
      updateConfig(d, { consent: { at: "2026-11-09T00:00:00Z", version: 1 } }),
      updateConfig(d, { lang: "ko" }),
      updateConfig(d, { external: { osv: false } }),
    ]);
    expect(await readConfig(d)).toEqual({ consent: { at: "2026-11-09T00:00:00Z", version: 1 }, lang: "ko", external: { osv: false } });
  });
});

describe("notice and CLI", () => {
  it("data table says no server receives code or paths, consistently in ko/en", () => {
    expect(DATA_TABLE.en.split("\n")[0]).toMatch(/never sent to any server/);
    expect(DATA_TABLE.ko.split("\n")[0]).toMatch(/어떤 서버로도/);
    expect(DATA_TABLE.en).not.toMatch(/never sent anywhere/);
  });

  it("sbom --upload-preview, with --upload kept as an alias", () => {
    expect(parseCli(["sbom", "--upload-preview"])).toEqual({ kind: "run", cmd: "sbom", opts: { "--upload-preview": true } });
    expect(parseCli(["sbom", "--upload"])).toEqual({ kind: "run", cmd: "sbom", opts: { "--upload": true } });
  });
});
