import { describe, expect, it } from "vitest";
import { foldIds, safeFix } from "../src/builtins/deps.js";
import { findingDescription, namedKindText } from "../src/builtins/text.js";
import { loadDefaultTemplate } from "../src/index.js";
import { fixPromptText } from "../src/prompts.js";
import { ViBudget } from "../src/net/budget.js";
import { defaultHttp } from "../src/net/http.js";
import { createSubscription, keyError, putRemediation, uploadSbom } from "../src/net/vulnintel.js";
import { NetError } from "../src/net/http.js";
import { cmpVersion, cvss3Score, satisfies } from "../src/versions.js";
import { byRule, consentedAppDir, mockNet, project, scanDefault, tempDir } from "./helpers.js";

const NOW = Date.UTC(2026, 10, 4);
const now = (): number => NOW;
const pj = (o: object): string => JSON.stringify(o);
const kinds = (fs: { kind?: string; severity: string; confidence: string }[]): string[][] => fs.map((f) => [f.kind!, f.severity, f.confidence]);

describe("AC14 supabase-rls", () => {
  const sb = { "package.json": pj({ name: "app", dependencies: { "@supabase/supabase-js": "^2" } }) };

  it("table without RLS → high·confirmed; folder missing → Advisor info only", async () => {
    let r = await scanDefault(project({ ...sb, "supabase/migrations/001_init.sql": "create table public.notes (id int);\ncreate table todos (id int);\nalter table todos enable row level security;\n" }));
    expect(kinds(byRule(r, "supabase-rls"))).toEqual([
      ["rls_disabled", "high", "confirmed"],
      ["advisor", "medium", "info"],
    ]);
    expect(byRule(r, "supabase-rls")[0]!.location).toEqual({ file: "supabase/migrations/001_init.sql", line: 1 });
    r = await scanDefault(project(sb));
    expect(kinds(byRule(r, "supabase-rls"))).toEqual([["advisor", "medium", "info"]]);
  });

  it("RLS disabled later, dropped table, comments and $$ bodies are handled", async () => {
    const r = await scanDefault(
      project({
        ...sb,
        "supabase/migrations/001.sql": "create table a (id int);\nalter table a enable row level security;\n-- create table ghost (id int);\ncreate function f() returns void as $$ create table inner_t (x int); $$ language sql;\n",
        "supabase/migrations/002.sql": "alter table a disable row level security;\ncreate table b (id int);\ndrop table b;\n",
      }),
    );
    expect(byRule(r, "supabase-rls").filter((f) => f.kind === "rls_disabled").map((f) => f.location)).toEqual([{ file: "supabase/migrations/001.sql", line: 1 }]);
  });

  it("always-true write policy → high·review, select → info, dropped later → none", async () => {
    const r = await scanDefault(
      project({
        ...sb,
        "supabase/migrations/001.sql": [
          "create table t (id int);",
          "alter table t enable row level security;",
          'create policy "upd" on public.t for update using (true);',
          'create policy "read" on t for select using (true);',
          'create policy "ins" on t for insert with check (true);',
        ].join("\n"),
        "supabase/migrations/002.sql": 'drop policy if exists "ins" on t;\n',
      }),
    );
    expect(kinds(byRule(r, "supabase-rls")).filter(([k]) => k !== "advisor")).toEqual([
      ["always_true_write", "high", "review"],
      ["public_read", "medium", "info"],
    ]);
  });

  it("B1: items name their table (and policy) in the description and fix prompt; ids and titles unchanged", async () => {
    const r = await scanDefault(
      project({
        ...sb,
        "supabase/migrations/001.sql": [
          "create table public.orders (id int);",
          "create table notes (id int);",
          "alter table notes enable row level security;",
          'create policy "Anyone can\nedit" on public.notes for update using (true);',
          'create policy "read all" on notes for select using (true);',
        ].join("\n"),
      }),
    );
    const [off, write, read] = ["rls_disabled", "always_true_write", "public_read"].map((k) => byRule(r, "supabase-rls").find((f) => f.kind === k)!);
    expect([off.table, write.table, write.policy, read.policy]).toEqual(["public.orders", "public.notes", "Anyone can edit", "read all"]);
    expect(off.title).toBe("Table without Row Level Security");
    expect(findingDescription(off, "ko")).toMatch(/^저장소 마이그레이션 기준으로 public\.orders 테이블에 행 수준 보안/);
    expect(findingDescription(write, "en")).toMatch(/^The "Anyone can edit" policy on public\.notes uses true/);
    expect(findingDescription(read, "ko")).toMatch(/^public\.notes 테이블의 "read all" select 정책/);
    const tpl = await loadDefaultTemplate();
    const p = fixPromptText([off], tpl, "ko").text;
    expect(p).toContain("1) 무엇이 문제인가: 저장소 마이그레이션 기준으로 public.orders 테이블에");
    expect(p).toContain("3) 코드 수정: 새 마이그레이션에서 alter table public.orders enable row level security 를 추가하고, public.orders 테이블에");
    expect(fixPromptText([write], tpl, "en").text).toContain('3) Code change: Write a new migration that replaces the condition of the "Anyone can edit" policy on public.notes');
    // A stored finding from before (no table) keeps the generic text.
    const { table: _t, ...old } = off;
    expect(namedKindText(old)?.description.ko).toMatch(/이 테이블에/);
  });

  it("SQL outside supabase/migrations lists the paths; EXECUTE format → dynamic SQL info", async () => {
    const r = await scanDefault(
      project({
        ...sb,
        "db/security/policies.sql": 'create policy "x" on t for all using (auth.uid() = owner);\n',
        "drizzle.config.ts": "export default {}",
        "supabase/migrations/001.sql": "create table t (id int);\nalter table t enable row level security;\ndo $$ begin execute format('create table %I (x int)', 'dyn'); end $$;\n",
      }),
    );
    const f = byRule(r, "supabase-rls");
    expect(f.find((x) => x.kind === "migrations_elsewhere")).toMatchObject({ confidence: "info", related: ["db/security/policies.sql", "drizzle.config.ts"] });
    expect(f.find((x) => x.kind === "dynamic_sql")).toMatchObject({ confidence: "info", location: { file: "supabase/migrations/001.sql" } });
  });

  it("service_role variable read in client code: review; with a leaked service key: critical", async () => {
    const files = { ...sb, "src/lib/admin.ts": "export const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;", "app/api/admin/route.ts": "process.env.SUPABASE_SERVICE_ROLE_KEY" };
    let r = await scanDefault(project(files));
    expect(kinds(byRule(r, "supabase-rls").filter((f) => f.kind === "service_role_client"))).toEqual([["service_role_client", "high", "review"]]);
    const jwt = ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role: "service_role", iss: "supabase" })).toString("base64url"), "c2lnbmF0dXJlLXZhbHVlLXg"].join(".");
    r = await scanDefault(project({ ...files, "scripts/seed.ts": `const k = "${jwt}";` }));
    expect(byRule(r, "supabase-rls").find((f) => f.kind === "service_role_client")).toMatchObject({ severity: "critical", confidence: "confirmed" });
  });

  it("only Supabase service keys count as service_role_client; a Stripe secret in client code goes to secret-public-env-prefix", async () => {
    const jwt = ["eyJhbGciOiJIUzI1NiJ9", Buffer.from(JSON.stringify({ role: "service_role", iss: "supabase" })).toString("base64url"), "c2lnbmF0dXJlLXZhbHVlLXg"].join(".");
    const r = await scanDefault(
      project({
        ...sb,
        "scripts/seed.ts": `const k = "${jwt}";`, // a service_role hit elsewhere must not upgrade non-Supabase names
        "app/checkout/page.tsx": '"use client";\nconst a = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;\nconst b = process.env.STRIPE_SECRET_KEY;\nconst c = process.env.NEXT_PUBLIC_API_SECRET_KEY;',
        "src/lib/admin.ts": "const d = process.env.SUPABASE_SERVICE_ROLE_KEY;\nconst e = import.meta.env.VITE_SUPABASE_SECRET_KEY;\nconst f = process.env.SERVICE_ROLE_KEY;",
      }),
    );
    const src = byRule(r, "supabase-rls").filter((f) => f.kind === "service_role_client");
    expect(src.map((f) => [f.location!.file, f.location!.line, f.severity, f.confidence])).toEqual([
      ["src/lib/admin.ts", 1, "critical", "confirmed"],
      ["src/lib/admin.ts", 2, "critical", "confirmed"],
      ["src/lib/admin.ts", 3, "critical", "confirmed"],
    ]);
    // The Stripe/other public secrets are still caught — by the variable-name rule.
    expect(byRule(r, "secret-public-env-prefix").filter((f) => f.location!.file === "app/checkout/page.tsx").map((f) => [f.location!.line, f.severity, f.confidence])).toEqual([
      [2, "high", "review"],
      [4, "high", "review"],
    ]);
  });

  it("not a Supabase project → nothing", async () => {
    expect(byRule(await scanDefault(project({ "a.sql": "create table x (id int);" })), "supabase-rls")).toEqual([]);
  });
});

describe("AC15 firebase-rules", () => {
  it.each([
    ["allow read, write: if true;", [["open_rules", "critical", "confirmed"]]],
    ["allow read, write;", [["open_rules", "critical", "confirmed"]]],
    ["allow read, write: if request.time < timestamp.date(2027, 1, 1);", [["test_mode", "high", "confirmed"]]],
    ["allow read, write: if request.time < timestamp.date(2025, 1, 1);", [["test_mode_expired", "high", "info"]]],
    ["allow read: if request.auth != null;", [["auth_only", "medium", "review"]]],
    ["allow read: if request.auth.uid == userId;", []],
    ["// allow read, write: if true;\nallow read: if request.auth.uid == u;", []],
  ])("firestore.rules: %s", async (rule, want) => {
    const r = await scanDefault(project({ "firestore.rules": `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{db}/documents {\n    match /{d=**} {\n      ${rule}\n    }\n  }\n}\n` }), { now });
    expect(kinds(byRule(r, "firebase-rules"))).toEqual(want);
  });

  it("RTDB root .read/.write true → critical; firebase.json without rules → info", async () => {
    let r = await scanDefault(project({ "database.rules.json": pj({ rules: { ".read": true, ".write": "auth != null" } }) }));
    expect(kinds(byRule(r, "firebase-rules"))).toEqual([["rtdb_open", "critical", "confirmed"]]);
    r = await scanDefault(project({ "firebase.json": "{}" }));
    expect(kinds(byRule(r, "firebase-rules"))).toEqual([["rules_missing", "medium", "info"]]);
  });
});

const lock = (deps: Record<string, string>, extra: Record<string, object> = {}): string =>
  pj({
    name: "app",
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: deps },
      ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n.split("/").pop()}-${v}.tgz`, integrity: `sha512-${n}` }])),
      ...extra,
    },
  });

describe("AC16 external lookup scope — intercepted requests", () => {
  const files = (extra: Record<string, string> = {}): Record<string, string> => ({
    "package.json": pj({
      name: "app",
      dependencies: { lodash: "4.17.21", "@acme/ui": "1.0.0", "made-up-pkg": "^1.0.0", shared: "workspace:*", loc: "file:../loc", gh: "github:a/b" },
    }),
    "package-lock.json": lock({ lodash: "4.17.21", "@acme/ui": "1.0.0" }),
    "packages/shared/package.json": pj({ name: "shared" }),
    "tsconfig.json": pj({ compilerOptions: { paths: { "@app/*": ["src/*"] } } }),
    "vite.config.ts": "export default { resolve: { alias: { '~lib': '/src/lib' } } }",
    "components/button.ts": "export {}",
    "src/main.ts": [
      "import x from 'left-pad';",
      "import y from '@app/thing';",
      "import z from '~lib/z';",
      "import s from 'shared';",
      "import c from 'components/button';",
      "import fs from 'node:fs';",
      "import p from 'path';",
      "import r from 'react-dom/client';",
    ].join("\n"),
    ...extra,
  });
  const urls = (calls: { url: string; body?: string }[]): string => calls.map((c) => `${c.url} ${c.body ?? ""}`).join("\n");

  it("(a) manifest-only names and filtered bare imports are looked up; (b)(e) aliases, workspace, local folders, file:/git: are not", async () => {
    const net = mockNet({ npm: { lodash: {}, "@acme/ui": {}, "left-pad": {}, "react-dom": {} } });
    await scanDefault(project(files()), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    const u = urls(net.calls);
    expect(u).toContain("registry.npmjs.org/made-up-pkg");
    expect(u).toContain("registry.npmjs.org/left-pad");
    expect(u).toContain("registry.npmjs.org/react-dom");
    for (const no of ["@app", "~lib", "registry.npmjs.org/shared", "components", "registry.npmjs.org/loc", "registry.npmjs.org/gh", "node:fs", "registry.npmjs.org/path"]) expect(u).not.toContain(no);
  });

  it("(c) .npmrc @acme scope: @acme/* appears in no request", async () => {
    const net = mockNet({});
    await scanDefault(project(files({ ".npmrc": "@acme:registry=https://npm.acme.dev/\n", "src/b.ts": "import a from '@acme/icons';" })), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(urls(net.calls)).not.toContain("acme");
    expect(urls(net.calls)).toContain("lodash");
  });

  it("(d) default registry changed → no npm name leaves; --extra-index-url → no PyPI name leaves", async () => {
    let net = mockNet({});
    await scanDefault(project(files({ ".npmrc": "registry=https://npm.acme.dev/\n" })), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(net.calls).toEqual([]);
    net = mockNet({});
    await scanDefault(project({ "requirements.txt": "--extra-index-url https://pypi.acme.dev/simple\nrequests==2.31.0\n", "a.py": "import yaml\n" }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(net.calls).toEqual([]);
  });
});

describe("AC17–AC20 hallucinated-package", () => {
  it("AC17: OSV MAL- → critical·confirmed 'malicious', no /v1/vulns detail call", async () => {
    const net = mockNet({ osv: { "npm:discord-selfbot-v14@1.0.0": ["MAL-2022-2490"] }, npm: { "discord-selfbot-v14": { latest: "0.0.1-security" } } });
    const r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { "discord-selfbot-v14": "1.0.0" } }), "package-lock.json": lock({ "discord-selfbot-v14": "1.0.0" }) }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(byRule(r, "hallucinated-package")).toMatchObject([{ kind: "malicious", severity: "critical", confidence: "confirmed", vuln_ids: ["MAL-2022-2490"] }]);
    expect(net.calls.some((c) => c.url.includes("/v1/vulns/"))).toBe(false);
    expect(byRule(r, "vulnerable-deps")).toEqual([]);
  });

  it("AC17: npm 0.0.1-security placeholder → malicious", async () => {
    const net = mockNet({ npm: { "evil-pkg": { latest: "0.0.1-security" } } });
    const r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { "evil-pkg": "^1.0.0" } }) }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(byRule(r, "hallucinated-package")).toMatchObject([{ kind: "malicious", severity: "critical" }]);
  });

  it("AC18: package.json name missing from the registry → high·review not_found at the manifest line", async () => {
    const net = mockNet({ npm: { "react-ai-helperz": { missing: true } } });
    const r = await scanDefault(project({ "package.json": `{\n  "name": "a",\n  "dependencies": {\n    "react-ai-helperz": "^1.0.0"\n  }\n}` }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(byRule(r, "hallucinated-package")).toMatchObject([{ kind: "not_found", severity: "high", confidence: "review", location: { file: "package.json", line: 4 }, package: "react-ai-helperz" }]);
  });

  it("lock entry from the public registry that is now 404 → removed", async () => {
    const net = mockNet({ npm: { gone: { missing: true }, app: {} } });
    const r = await scanDefault(project({ "package-lock.json": lock({}, { "node_modules/gone": { version: "1.0.0", resolved: "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz" } }) }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(byRule(r, "hallucinated-package")).toMatchObject([{ kind: "removed", severity: "high", confidence: "review" }]);
  });

  it("AC19: existing undeclared import → info; near-popular new low-download name → medium·review (install script → high); full doc/downloads only for candidates", async () => {
    const recent = new Date(NOW - 10 * 86_400_000).toISOString();
    const net = mockNet({
      npm: {
        axois: { created: recent, weekly: 50 },
        expresss: { created: recent, weekly: 50, versions: { "1.0.0": { hasInstallScript: true } } },
        dayjs: {},
        "some-real-lib": {},
      },
    });
    const r = await scanDefault(
      project({ "package.json": pj({ name: "a", dependencies: { axois: "^1.0.0", expresss: "1.0.0", dayjs: "^1" } }), "src/a.ts": "import x from 'some-real-lib';" }),
      { appDir: await consentedAppDir(), fetch: net.fetch, now },
    );
    expect(kinds(byRule(r, "hallucinated-package"))).toEqual([
      ["suspicious", "high", "review"],
      ["suspicious", "medium", "review"],
      ["undeclared_import", "medium", "info"],
    ]);
    const full = net.calls.filter((c) => c.url.startsWith("https://registry.npmjs.org/") && !c.url.includes("downloads")).map((c) => c.url);
    const dl = net.calls.filter((c) => c.url.includes("api.npmjs.org/downloads")).map((c) => c.url.split("/").pop());
    expect(dl.sort()).toEqual(["axois", "expresss"]);
    // dayjs / some-real-lib: abbreviated document only (one request each)
    expect(full.filter((u) => u.endsWith("/dayjs"))).toHaveLength(1);
  });

  it("AC20: Python `import utils` (not in the map) → no PyPI request, info only; mapped import is looked up", async () => {
    const net = mockNet({});
    const r = await scanDefault(project({ "app.py": "import utils\nimport yaml\nimport os\n" }), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(net.calls.map((c) => c.url)).toEqual(["https://pypi.org/pypi/pyyaml/json"]);
    expect(byRule(r, "hallucinated-package").map((f) => [f.package, f.confidence])).toEqual([
      ["utils", "info"],
      ["pyyaml", "info"],
    ]);
  });
});

describe("vulnerable-deps (§7-3)", () => {
  const vulnProject = (): string =>
    project({
      "package.json": pj({ name: "a", dependencies: { lodash: "4.17.20", minimist: "1.2.0" } }),
      "package-lock.json": lock({ lodash: "4.17.20", minimist: "1.2.0" }),
    });
  const osvMock = {
    osv: { "npm:lodash@4.17.20": ["GHSA-35jh-r3h4-6jhm"], "npm:minimist@1.2.0": ["GHSA-xvch-5gv4-984h"] },
    vulns: {
      "GHSA-35jh-r3h4-6jhm": { id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] },
      "GHSA-xvch-5gv4-984h": { id: "GHSA-xvch-5gv4-984h", aliases: ["CVE-2021-44906"], severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }], affected: [{ package: { ecosystem: "npm", name: "minimist" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "0.2.4" }, { introduced: "1.0.0" }, { fixed: "1.2.6" }] }] }] },
    },
    npm: { lodash: {}, minimist: {} },
  };

  it("AC25: KEV CVE goes to the top with KEV/VPI; VulnIntel requests are /vulnerabilities/{id}?lang=<lang> only", async () => {
    const net = mockNet({ ...osvMock, vi: { "CVE-2021-23337": { vpi_level: 5, is_kev: true, epss_score: 0.4 }, "CVE-2021-44906": { vpi_level: 3, is_kev: false } } });
    const r = await scanDefault(vulnProject(), { appDir: await consentedAppDir(), fetch: net.fetch, now, lang: "ko" });
    const v = byRule(r, "vulnerable-deps");
    // KEV → critical; otherwise the advisory's severity: minimist CVSS 9.8 stays critical, VPI 3 is a badge only.
    expect(v.map((f) => [f.package, f.severity, f.kev, f.vpi_level, f.fixed_version])).toEqual([
      ["lodash", "critical", true, 5, "4.17.21"],
      ["minimist", "critical", false, 3, "1.2.6"],
    ]);
    expect(r.findings[0]!.package).toBe("lodash");
    const vi = net.calls.filter((c) => c.url.includes("vulnintelapp")).map((c) => c.url);
    expect(vi.sort()).toEqual([
      "https://api.vulnintelapp.com/api/v1/vulnerabilities/CVE-2021-23337?lang=ko",
      "https://api.vulnintelapp.com/api/v1/vulnerabilities/CVE-2021-44906?lang=ko",
    ]);
    expect(v[0]!.vuln_ids).toEqual(["CVE-2021-23337"]); // B3: the GHSA record is the same vulnerability
  });

  it("B2: the public lookup's description of the package's most severe vulnerability is kept for people, per language", async () => {
    const pkg = {
      "package.json": pj({ name: "a", dependencies: { lodash: "4.17.20" } }),
      "package-lock.json": lock({ lodash: "4.17.20" }),
    };
    const two = {
      osv: { "npm:lodash@4.17.20": ["GHSA-35jh-r3h4-6jhm", "GHSA-low"] },
      vulns: {
        ...osvMock.vulns,
        "GHSA-low": { id: "GHSA-low", aliases: ["CVE-2020-1"], database_specific: { severity: "LOW" }, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] },
      },
      npm: { lodash: {} },
    };
    const net = mockNet({ ...two, vi: { "CVE-2021-23337": { vpi_level: 5, is_kev: true, description: "Command\ninjection via template." }, "CVE-2020-1": { vpi_level: 2, is_kev: false, description: "Minor issue." } } });
    const appDir = await consentedAppDir();
    const f = byRule(await scanDefault(project(pkg), { appDir, fetch: net.fetch, now, lang: "ko" }), "vulnerable-deps")[0]!;
    expect(f.vuln_description).toEqual({ id: "CVE-2021-23337", text: "Command injection via template." });
    expect(findingDescription(f, "ko")).toBe("이 버전에 공개된 취약점이 있습니다. 가장 위험한 취약점 CVE-2021-23337: Command injection via template.");
    // Not in the fix prompt (external text).
    expect(fixPromptText([f], await loadDefaultTemplate(), "ko").text).not.toContain("Command injection");
    // Cached in Korean: an English scan does not re-ask and shows no Korean text.
    const en = byRule(await scanDefault(project(pkg), { appDir, fetch: net.fetch, now, lang: "en" }), "vulnerable-deps")[0]!;
    expect(en.vuln_description).toBeUndefined();
    // No description from the lookup → the generic sentence only.
    const bare = mockNet({ ...two, vi: { "CVE-2021-23337": { vpi_level: 5, is_kev: true } } });
    const g = byRule(await scanDefault(project(pkg), { appDir: await consentedAppDir(), fetch: bare.fetch, now, lang: "en" }), "vulnerable-deps")[0]!;
    expect(g.vuln_description).toBeUndefined();
    expect(findingDescription(g, "en")).toBe("This version has published vulnerabilities.");
  });

  it("B3: ids that alias each other are one vulnerability — CVE first, else GHSA, else the first id; every CVE kept", () => {
    // requests 2.31.0 without a key: OSV answers with GHSA and PYSEC records of the same CVEs.
    const ids = ["GHSA-9wx4-h78v-vm56", "GHSA-9hjg-9r4m-mvj7", "PYSEC-2024-1", "GHSA-only", "PYSEC-lone"];
    const vulns = [
      { id: "GHSA-9wx4-h78v-vm56", aliases: ["CVE-2024-35195"] },
      { id: "GHSA-9hjg-9r4m-mvj7", aliases: ["CVE-2024-47081"] },
      { id: "PYSEC-2024-1", aliases: ["GHSA-9wx4-h78v-vm56", "CVE-2024-35195"] },
      { id: "GHSA-only", aliases: ["PYSEC-x"] },
      { id: "GHSA-two", aliases: ["CVE-2030-1", "CVE-2030-2"] },
    ];
    expect(foldIds(ids, vulns)).toEqual(["CVE-2024-35195", "CVE-2024-47081", "GHSA-only", "PYSEC-lone"]);
    expect(foldIds(["GHSA-two"], vulns)).toEqual(["CVE-2030-1", "CVE-2030-2"]);
  });

  it("AC26: public lookup off → no VulnIntel request, severity from OSV/CVSS; 429 → scan completes, rest marked", async () => {
    let net = mockNet(osvMock);
    let r = await scanDefault(vulnProject(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now });
    expect(net.calls.some((c) => c.url.includes("vulnintelapp"))).toBe(false);
    expect(byRule(r, "vulnerable-deps").map((f) => [f.package, f.severity, f.cvss])).toEqual([
      ["minimist", "critical", 9.8],
      ["lodash", "high", undefined],
    ]);
    net = mockNet({ ...osvMock, vi: { "CVE-2021-23337": 429, "CVE-2021-44906": 429 } });
    r = await scanDefault(vulnProject(), { appDir: await consentedAppDir(), fetch: net.fetch, now });
    expect(byRule(r, "vulnerable-deps")).toHaveLength(2);
    expect(byRule(r, "vulnerable-deps").every((f) => f.notes?.includes("priority_failed") || f.notes?.includes("priority_pending"))).toBe(true);
    expect(net.calls.filter((c) => c.url.includes("vulnintelapp"))).toHaveLength(1); // stopped after 429
  });

  it("N4: the same advisory has the same severity whether or not its priority lookup finished; ko→en reuses the cache", async () => {
    const appDir = await consentedAppDir();
    let net = mockNet({ ...osvMock, vi: { "CVE-2021-23337": { vpi_level: 5, is_kev: false }, "CVE-2021-44906": 500 } });
    let r = await scanDefault(vulnProject(), { appDir, fetch: net.fetch, now, lang: "ko" });
    // lodash: OSV HIGH stays high with VPI 5; minimist: lookup failed → CVSS 9.8 critical, no VPI badge.
    expect(byRule(r, "vulnerable-deps").map((f) => [f.package, f.severity, f.vpi_level, f.notes?.includes("priority_failed") ?? false])).toEqual([
      ["minimist", "critical", undefined, true],
      ["lodash", "high", 5, false],
    ]);
    net = mockNet({ ...osvMock, vi: { "CVE-2021-44906": { vpi_level: 3, is_kev: false } } });
    r = await scanDefault(vulnProject(), { appDir, fetch: net.fetch, now, lang: "en" });
    expect(net.calls.filter((c) => c.url.includes("vulnintelapp")).map((c) => c.url)).toEqual(["https://api.vulnintelapp.com/api/v1/vulnerabilities/CVE-2021-44906?lang=en"]);
    expect(byRule(r, "vulnerable-deps").map((f) => [f.package, f.severity, f.vpi_level])).toEqual([
      ["minimist", "critical", 3],
      ["lodash", "high", 5],
    ]);
  });

  it("no fixed version, installed version released after the advisory (open-ended range) → review with a note", async () => {
    // PYSEC-2022-252: one hijacked release (1.8.5), range `introduced` only, so every later version matches.
    const vulns = {
      "PYSEC-2022-252": {
        id: "PYSEC-2022-252", published: "2022-06-21T00:00:00Z", database_specific: { severity: "CRITICAL" },
        affected: [{ package: { ecosystem: "PyPI", name: "deep-translator" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.8.5" }] }] }],
      },
    };
    const osv = { "PyPI:deep-translator@1.11.4": ["PYSEC-2022-252"] };
    const dir = (): string => project({ "requirements.txt": "deep-translator==1.11.4\n" });
    let net = mockNet({ osv, vulns, pypiReleases: { "deep-translator": { "1.11.4": "2023-06-04T12:00:00Z" } } });
    let f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix", severity: "critical", confidence: "review" }]);
    expect(f[0]!.notes).toContain("released_after_advisory");
    // Released before the advisory, or the date cannot be read → stays confirmed.
    net = mockNet({ osv, vulns, pypiReleases: { "deep-translator": { "1.11.4": "2022-01-01T00:00:00Z" } } });
    f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix", confidence: "confirmed" }]);
    net = mockNet({ osv, vulns, pypi: { "deep-translator": false } });
    f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix", confidence: "confirmed" }]);
    // Registry lookups off → no extra request, today's behaviour.
    net = mockNet({ osv, vulns, pypiReleases: { "deep-translator": { "1.11.4": "2023-06-04T12:00:00Z" } } });
    f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false, registry: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix", confidence: "confirmed" }]);
    expect(net.calls.some((c) => c.url.includes("pypi.org"))).toBe(false);
  });

  it("npm: the release time comes from the full document's `time[version]`", async () => {
    const vulns = { "GHSA-open": { id: "GHSA-open", published: "2022-01-01T00:00:00Z", affected: [{ package: { ecosystem: "npm", name: "left" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }] }] }] } };
    const net = mockNet({ osv: { "npm:left@2.0.0": ["GHSA-open"] }, vulns, npm: { left: { latest: "2.0.0", time: { "2.0.0": "2024-01-01T00:00:00Z" } } } });
    const dir = project({ "package.json": pj({ name: "a", dependencies: { left: "2.0.0" } }), "package-lock.json": lock({ left: "2.0.0" }) });
    const f = byRule(await scanDefault(dir, { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix", confidence: "review" }]);
    expect(f[0]!.notes).toContain("released_after_advisory");
  });

  it("caches: a second scan within 24h makes no VulnIntel/registry calls and no OSV detail calls", async () => {
    const appDir = await consentedAppDir();
    const dir = vulnProject();
    await scanDefault(dir, { appDir, fetch: mockNet({ ...osvMock, vi: { "CVE-2021-23337": { vpi_level: 4 } } }).fetch, now });
    const net = mockNet({ ...osvMock, vi: { "CVE-2021-23337": { vpi_level: 4 } } });
    await scanDefault(dir, { appDir, fetch: net.fetch, now });
    expect(net.calls.map((c) => new URL(c.url).pathname)).toEqual(["/v1/querybatch"]);
  });

  it("AC22: package.json without a lock → version_unknown medium·review (not 'no problems')", async () => {
    const r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { express: "^4" } }) }));
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ kind: "version_unknown", severity: "medium", confidence: "review", location: { file: "package.json" } }]);
  });

  it("AC23: two lockfiles, same package@version → one finding listing both locks", async () => {
    const net = mockNet(osvMock);
    const r = await scanDefault(
      project({ "a/package.json": pj({ name: "a", dependencies: { lodash: "4.17.20" } }), "a/package-lock.json": lock({ lodash: "4.17.20" }), "b/package.json": pj({ name: "b", dependencies: { lodash: "4.17.20" } }), "b/package-lock.json": lock({ lodash: "4.17.20" }) }),
      { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now },
    );
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ package: "lodash", lockfile: "a/package-lock.json", related: ["a/package-lock.json", "b/package-lock.json"] }]);
  });

  it("1c E2: fixed version escapes every known range of the package; none → no fixed version", async () => {
    // Shape of the C langchain-core case: V1 fixed in both lines, V2 only fixed in the next major,
    // and that fix (1.2.22) is still inside V1's second range [1.0.0, 1.3.3).
    const v1 = { id: "GHSA-aaaa-0001", affected: [{ package: { ecosystem: "npm", name: "chainlib" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "0.3.84" }, { introduced: "1.0.0" }, { fixed: "1.3.3" }] }] }] };
    const v2 = { id: "GHSA-aaaa-0002", affected: [{ package: { ecosystem: "npm", name: "chainlib" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "1.2.22" }] }, { type: "GIT", events: [{ introduced: "0" }, { fixed: "9badc0ffee" }] }] }] };
    const v3 = { id: "GHSA-aaaa-0003", affected: [{ package: { ecosystem: "npm", name: "chainlib" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0.3.0" }] }] }] };
    const dir = (): string => project({ "package.json": pj({ name: "a", dependencies: { chainlib: "0.3.34" } }), "package-lock.json": lock({ chainlib: "0.3.34" }) });
    let net = mockNet({ osv: { "npm:chainlib@0.3.34": [v1.id, v2.id] }, vulns: { [v1.id]: v1, [v2.id]: v2 }, npm: { chainlib: {} } });
    let f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable", fixed_version: "1.3.3" }]);
    expect(f[0]!.notes).toContain("major_upgrade");
    // An unfixed range means no version escapes all known vulns → "no fixed version", not a still-vulnerable pick.
    net = mockNet({ osv: { "npm:chainlib@0.3.34": [v1.id, v2.id, v3.id] }, vulns: { [v1.id]: v1, [v2.id]: v2, [v3.id]: v3 }, npm: { chainlib: {} } });
    f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: net.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable_no_fix" }]);
    expect(f[0]!.fixed_version).toBeUndefined();
  });

  it("1c E2: safeFix — last_affected is inclusive, same major preferred, no ranges → old per-vuln rule", () => {
    const k = "npm:x";
    expect(safeFix([{ fixed: { [k]: ["1.0.5"] }, ranges: { [k]: [{ introduced: "1.0.0", last_affected: "1.0.5" }, { introduced: "0", fixed: "1.0.5" }] } }], k, "1.0.1")).toBeUndefined();
    expect(safeFix([{ fixed: { [k]: ["1.0.9", "2.0.1"] }, ranges: { [k]: [{ introduced: "0", fixed: "1.0.9" }, { introduced: "2.0.0", fixed: "2.0.1" }] } }], k, "1.0.1")).toBe("1.0.9");
    expect(safeFix([{ fixed: { [k]: ["1.0.9", "2.0.1"] } }, { fixed: { [k]: ["1.2.0"] } }], k, "1.0.1")).toBe("1.2.0"); // VulnIntel results carry no ranges
  });

  it("1c E4: package-lock.json next to bun.lock → parsed, no extra 'version unknown'", async () => {
    const r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { x: "1.0.0" } }), "package-lock.json": lock({ x: "1.0.0" }), "bun.lock": "{}" }));
    expect(kinds(byRule(r, "vulnerable-deps"))).toEqual([["unsupported_lock", "medium", "info"]]);
  });

  it("B8: only an unsupported lock → one 'not supported yet' review item, never 'no lock file'; per ecosystem; unpinned requirements → 'not pinned'", async () => {
    const at = (r: Awaited<ReturnType<typeof scanDefault>>): (string | undefined)[][] => byRule(r, "vulnerable-deps").map((f) => [f.kind, f.confidence, f.location?.file]).sort();
    let r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { x: "1" } }), "yarn.lock": "" }));
    expect(at(r)).toEqual([["unsupported_lock", "review", "yarn.lock"]]);
    // A root poetry.lock covers member pyprojects, not a package.json (uv.lock is parsed now: test/uv.test.ts).
    r = await scanDefault(
      project({
        "poetry.lock": "",
        "pyproject.toml": '[project]\nname = "app"\ndependencies = ["fastapi"]\n',
        "server/pyproject.toml": '[project]\nname = "srv"\ndependencies = ["uvicorn"]\n',
        "web/package.json": pj({ name: "w", dependencies: { x: "1" } }),
      }),
    );
    expect(at(r)).toEqual([
      ["unsupported_lock", "review", "poetry.lock"],
      ["version_unknown", "review", "web/package.json"],
    ]);
    r = await scanDefault(project({ "requirements.txt": "PyYAML>=5.1\nflask==2.0.0\n" }));
    expect(at(r)).toEqual([["version_unpinned", "review", "requirements.txt"]]);
  });

  it("B3: a broken or old lock → 'lock could not be read' review item instead of a silent 'nothing found'", async () => {
    const at = (r: Awaited<ReturnType<typeof scanDefault>>): (string | undefined)[][] => byRule(r, "vulnerable-deps").map((f) => [f.kind, f.confidence, f.location?.file]);
    const manifest = pj({ name: "a", dependencies: { lodash: "4.17.15" } });
    expect(at(await scanDefault(project({ "package.json": manifest, "package-lock.json": lock({ lodash: "4.17.15" }).slice(0, 40) })))).toEqual([["lock_unreadable", "review", "package-lock.json"]]);
    const conflict = "lockfileVersion: '9.0'\nimporters:\n  .:\n<<<<<<< HEAD\n    dependencies: {}\n=======\n    dependencies: []\n>>>>>>> feature\n";
    expect(at(await scanDefault(project({ "package.json": manifest, "pnpm-lock.yaml": conflict })))).toEqual([["lock_unreadable", "review", "pnpm-lock.yaml"]]);
    const old = "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.15:\n    resolution: {integrity: sha512-x}\n";
    expect(at(await scanDefault(project({ "package.json": manifest, "pnpm-lock.yaml": old })))).toEqual([["lock_regenerate", "review", "pnpm-lock.yaml"]]);
  });

  it("B1: the suggested fixed version is itself asked to OSV; a vulnerable candidate brings the next fix; unasked → fix_unverified", async () => {
    const lo = (id: string, events: object[]): object => ({ id, affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "ECOSYSTEM", events }] }] });
    // 4.18.0 fixes what 4.17.15 has, but 4.18.0 itself is hit by a later vuln fixed in 4.18.1 (the QA lodash case).
    const m = {
      osv: { "npm:lodash@4.17.15": ["GHSA-lo-1"], "npm:lodash@4.18.0": ["GHSA-lo-2"] },
      vulns: { "GHSA-lo-1": lo("GHSA-lo-1", [{ introduced: "0" }, { fixed: "4.18.0" }]), "GHSA-lo-2": lo("GHSA-lo-2", [{ introduced: "4.18.0" }, { fixed: "4.18.1" }]) },
      npm: { lodash: {} },
    };
    const dir = (): string => project({ "package.json": pj({ name: "a", dependencies: { lodash: "4.17.15" } }), "package-lock.json": lock({ lodash: "4.17.15" }) });
    let f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: mockNet(m).fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable", fixed_version: "4.18.1", vuln_ids: ["GHSA-lo-1"] }]);
    expect(f[0]!.notes).not.toContain("fix_unverified");
    // OSV fails for the candidate check → the range-based pick, marked unverified.
    let batches = 0;
    const down = mockNet({ ...m, custom: (u) => (u.pathname === "/v1/querybatch" && ++batches > 1 ? new Response("{}", { status: 503 }) : undefined) });
    f = byRule(await scanDefault(dir(), { appDir: await consentedAppDir({ vulnintel: false }), fetch: down.fetch, now }), "vulnerable-deps");
    expect(f).toMatchObject([{ kind: "vulnerable", fixed_version: "4.18.0" }]);
    expect(f[0]!.notes).toContain("fix_unverified");
  });

  it("B15: requests still running at the deadline are cut there; the result is partial, not offline", async () => {
    const hang = ((_u: unknown, init?: RequestInit) => new Promise((_, rej) => init!.signal!.addEventListener("abort", () => rej(init!.signal!.reason)))) as typeof fetch;
    const t0 = Date.now();
    const r = await scanDefault(project({ "package.json": pj({ name: "a", dependencies: { lodash: "4.17.20" } }), "package-lock.json": lock({ lodash: "4.17.20" }) }), {
      appDir: await consentedAppDir({ vulnintel: false }),
      fetch: hang,
      now,
      deadlineMs: 1500,
    });
    expect(Date.now() - t0).toBeLessThan(1500 + 3000); // not requestJson's 30 s timeout
    expect(r.checked.find((c) => c.rule_id === "vulnerable-deps")).toMatchObject({ ran: false, reason: "timeout_partial" });
    expect(r.checked.find((c) => c.rule_id === "hallucinated-package")).toMatchObject({ ran: false, reason: "timeout_partial" });
  });
});

describe("AC32·AC33·AC34 failures, offline, consent", () => {
  const p = (): string => project({ "package.json": pj({ name: "a", dependencies: { lodash: "4.17.20" } }), "package-lock.json": lock({ lodash: "4.17.20" }), "src/a.ts": `const k = "${"sk-proj-" + "Q".repeat(48)}";` });

  it("AC34: no consent → zero external requests; local rules still run", async () => {
    const net = mockNet({});
    const r = await scanDefault(p(), { fetch: net.fetch, now });
    expect(net.calls).toEqual([]);
    expect(byRule(r, "secret-openai")).toHaveLength(1);
    expect(r.checked.find((c) => c.rule_id === "hallucinated-package")).toMatchObject({ ran: false, reason: "no_consent" });
  });

  it("AC34: each lookup can be turned off", async () => {
    const net = mockNet({});
    await scanDefault(p(), { appDir: await consentedAppDir({ osv: false, registry: false, vulnintel: false }), fetch: net.fetch, now });
    expect(net.calls).toEqual([]);
  });

  it("AC33: offline → local results, dependency checks 'offline' (= not checked)", async () => {
    const r = await scanDefault(p(), { appDir: await consentedAppDir(), fetch: mockNet({ offline: true }).fetch, now });
    expect(byRule(r, "secret-openai")).toHaveLength(1);
    expect(r.checked.find((c) => c.rule_id === "vulnerable-deps")).toMatchObject({ ran: false, reason: "offline" });
    expect(r.checked.find((c) => c.rule_id === "hallucinated-package")).toMatchObject({ ran: false, reason: "offline" });
  });

  it("AC32: OSV 5xx → one retry; still failing → skipped as offline. 413 → batch halved", async () => {
    let net = mockNet({ osvFail: [503], ...{ osv: { "npm:lodash@4.17.20": ["GHSA-1"] }, vulns: { "GHSA-1": { id: "GHSA-1", database_specific: { severity: "HIGH" } } } } });
    let r = await scanDefault(p(), { appDir: await consentedAppDir({ vulnintel: false, registry: false }), fetch: net.fetch, now });
    expect(byRule(r, "vulnerable-deps")).toHaveLength(1);
    net = mockNet({ osvFail: [503, 503] });
    r = await scanDefault(p(), { appDir: await consentedAppDir({ registry: false }), fetch: net.fetch, now });
    expect(r.checked.find((c) => c.rule_id === "vulnerable-deps")).toMatchObject({ ran: false, reason: "offline" });
    expect(net.calls.filter((c) => c.url.endsWith("/querybatch"))).toHaveLength(2);
    net = mockNet({ osvFail: [413], osv: { "npm:lodash@4.17.20": ["GHSA-1"] }, vulns: { "GHSA-1": { id: "GHSA-1" } } });
    const dir = project({ "package-lock.json": lock({ lodash: "4.17.20", minimist: "1.2.0" }) });
    r = await scanDefault(dir, { appDir: await consentedAppDir({ registry: false, vulnintel: false }), fetch: net.fetch, now });
    expect(net.calls.filter((c) => c.url.endsWith("/querybatch")).map((c) => (JSON.parse(c.body!) as { queries: unknown[] }).queries.length)).toEqual([2, 1, 1]);
    expect(byRule(r, "vulnerable-deps").map((f) => f.package)).toEqual(["lodash"]);
  });

  it("AC32: VulnIntel key-path error mapping (402 / 401 / 429 / subscription limit / 403)", async () => {
    const budget = new ViBudget(tempDir());
    const err = (status: number, body?: unknown, retry = 0): Promise<unknown> => keyError(new NetError("http", status, body, retry), budget);
    expect(await err(401)).toEqual({ kind: "invalid_key" });
    expect(await err(402, { error: "monthly_quota_exceeded" })).toEqual({ kind: "quota_exceeded" });
    expect(await err(403)).toEqual({ kind: "forbidden" });
    expect(await err(429, undefined, 60_000)).toEqual({ kind: "rate_limited", retryAfterMs: 60_000 });
    expect(await err(400, { error: { error: "subscription_limit_exceeded", limit: 10 }, request_id: "x" })).toEqual({ kind: "subscription_limit", limit: 10 });
    expect(await budget.take("key")).toBe(false); // 429 blocked the shared budget for a minute

    const calls: { url: string; init?: RequestInit }[] = [];
    const fake = (async (url: string, init?: RequestInit) => {
      calls.push({ url, ...(init && { init }) });
      return new Response(JSON.stringify({ error: { error: "subscription_limit_exceeded", limit: 50 } }), { status: 400, headers: { "x-quota-remaining": "7" } });
    }) as typeof fetch;
    const b2 = new ViBudget(tempDir());
    expect(await createSubscription(defaultHttp(fake), b2, "vi_live_k", "npm", "lodash")).toEqual({ ok: false, error: { kind: "subscription_limit", limit: 50 } });
    expect(JSON.parse(calls[0]!.init!.body as string)).toEqual({ target_type: "package", ecosystem: "npm", target_value: "lodash" });
    expect((calls[0]!.init!.headers as Record<string, string>)["X-Api-Key"]).toBe("vi_live_k");
    expect(await putRemediation(defaultHttp(fake), b2, "k", "GHSA-xxxx-yyyy-zzzz", "a", "1")).toEqual({ ok: false, error: { kind: "bad_request" } });
    const ok = (async () => new Response(JSON.stringify({ job_id: "j", status: "queued" }), { status: 202, headers: { "x-quota-remaining": "99" } })) as typeof fetch;
    expect(await uploadSbom(defaultHttp(ok), b2, "k", "{}")).toEqual({ ok: true, value: { job_id: "j", status: "queued" }, quotaRemaining: 99 });
  });
});

describe("AC28 VulnIntel call budget (§8-5)", () => {
  it("no 60-second window ever exceeds 50 calls, across two processes sharing the file", async () => {
    const dir = tempDir();
    let t = 1_000_000;
    const clock = (): number => t;
    const a = new ViBudget(dir, { now: clock });
    const b = new ViBudget(dir, { now: clock });
    const granted: number[] = [];
    for (let step = 0; step < 150; step++) {
      t += 1400; // 150 attempts × 2 over 210 s
      const [x, y] = await Promise.all([a.take("public"), b.take(step % 3 ? "public" : "poll")]);
      if (x) granted.push(t);
      if (y) granted.push(t);
    }
    for (const start of granted) expect(granted.filter((g) => g >= start && g < start + 60_000).length).toBeLessThanOrEqual(50);
    expect(granted.length).toBeGreaterThan(150);
  }, 60_000);

  it("with a key, public lookups leave room for key/poll calls; polling capped at 20/min", async () => {
    const dir = tempDir();
    const k = new ViBudget(dir, { now: () => 5, keyMode: true });
    let pub = 0;
    while (await k.take("public")) pub++;
    expect(pub).toBe(30);
    expect(await k.take("key")).toBe(true);
    let poll = 0;
    const d2 = new ViBudget(tempDir(), { now: () => 5 });
    while (await d2.take("poll")) poll++;
    expect(poll).toBe(20);
  });
});

describe("version helpers", () => {
  it("cmpVersion / satisfies / CVSS", () => {
    expect(["1.10.0", "1.2.0", "1.2.0-rc.1", "1.2.0.post1", "2.0.0"].sort(cmpVersion)).toEqual(["1.2.0-rc.1", "1.2.0", "1.2.0.post1", "1.10.0", "2.0.0"]);
    expect(satisfies("4.17.21", "^4.17.20")).toBe(true);
    expect(satisfies("5.0.0", "^4.17.20")).toBe(false);
    expect(satisfies("0.2.5", "^0.2.3")).toBe(true);
    expect(satisfies("0.3.0", "^0.2.3")).toBe(false);
    expect(satisfies("1.2.9", "~1.2.3")).toBe(true);
    expect(satisfies("1.3.0", "~1.2.3")).toBe(false);
    expect(satisfies("1.5.0", ">=1.0.0 <2.0.0 || ^3")).toBe(true);
    expect(satisfies("2.1.0", "1.x || 2.x")).toBe(true);
    expect(satisfies("1.0.0", "1.0.1")).toBe(false);
    expect(satisfies("1.0.0", "workspace:*")).toBe(true);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")).toBe(9.9);
    expect(cvss3Score("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N")).toBe(1.8);
    expect(cvss3Score("CVSS:4.0/AV:N")).toBeNull();
  });
});
