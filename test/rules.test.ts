import { mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { byRule, git, gitRepo, jwt, K, project, rnd, scanDefault, tempDir } from "./helpers.js";

type Expect = { severity: string; confidence: string }[];
interface Case {
  name: string;
  files: () => Record<string, string>;
  expect: Expect;
  /** Commit these paths in a fresh git repo first. */
  commit?: string[];
}

const c = (severity: string, confidence: string): Expect[number] => ({ severity, confidence });

/** AC7: positive and negative fixture per default-template engine item, expected severity·confidence. */
const RULE_CASES: Record<string, Case[]> = {
  "secret-openai": [
    { name: "project key in code", files: () => ({ "src/ai.ts": `const k = "${K.openai()}";` }), expect: [c("critical", "confirmed")] },
    { name: "placeholder", files: () => ({ "src/ai.ts": 'const k = "sk-proj-your-key-goes-here-0000000000000000000000";' }), expect: [] },
    { name: "short sk- word", files: () => ({ "src/a.ts": "const cls = 'sk-button';" }), expect: [] },
  ],
  "secret-anthropic": [
    { name: "api key", files: () => ({ "server.py": `KEY = "${K.anthropic()}"` }), expect: [c("critical", "confirmed")] },
    { name: "prefix only", files: () => ({ "server.py": 'KEY = "sk-ant-api03-..."' }), expect: [] },
  ],
  "secret-supabase-service-role": [
    { name: "service_role JWT", files: () => ({ "src/db.ts": `createClient(url, "${K.serviceRoleJwt()}")` }), expect: [c("critical", "confirmed")] },
    { name: "sb_secret_", files: () => ({ "src/db.ts": `createClient(url, "${K.sbSecret()}")` }), expect: [c("critical", "confirmed")] },
    { name: "authenticated JWT", files: () => ({ "src/db.ts": `const t = "${jwt({ role: "authenticated" })}"` }), expect: [] },
    { name: "legacy anon JWT is not a service key (B2)", files: () => ({ "src/db.ts": `createClient(url, "${K.anonJwt()}")` }), expect: [] },
  ],
  "supabase-anon-key": [
    { name: "legacy anon JWT is info only (AC8)", files: () => ({ "src/db.ts": `createClient(url, "${K.anonJwt()}")` }), expect: [c("medium", "info")] },
    { name: "service_role JWT is not the anon rule", files: () => ({ "src/db.ts": `createClient(url, "${K.serviceRoleJwt()}")` }), expect: [] },
    { name: "sb_publishable_ is allowlisted", files: () => ({ "src/db.ts": `createClient(url, "${K.sbPublishable()}")` }), expect: [] },
  ],
  "secret-supabase-pat": [
    { name: "sbp_ token", files: () => ({ ".mcp.json": `{"args": ["--access", "${K.sbPat()}"]}` }), expect: [c("critical", "confirmed")] },
    { name: "too short", files: () => ({ "a.txt": "sbp_1234abcd" }), expect: [] },
  ],
  "secret-aws": [
    { name: "access key id", files: () => ({ "deploy.sh": `AWS_ACCESS_KEY_ID=${K.aws()}` }), expect: [c("critical", "confirmed")] },
    { name: "AWS docs example", files: () => ({ "deploy.sh": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" }), expect: [] },
  ],
  "secret-stripe-live": [
    { name: "sk_live_", files: () => ({ "api/pay.ts": `stripe("${K.stripe()}")` }), expect: [c("critical", "confirmed")] },
    { name: "pk_live_ is public", files: () => ({ "src/pay.ts": `loadStripe("${K.stripePk()}")` }), expect: [] },
  ],
  "secret-github": [
    { name: "ghp_", files: () => ({ "ci.sh": `TOKEN=${K.github()}` }), expect: [c("critical", "confirmed")] },
    { name: "short", files: () => ({ "ci.sh": "TOKEN=ghp_abc" }), expect: [] },
  ],
  "secret-google-key": [
    { name: "plain key", files: () => ({ "src/maps.ts": `const key = "${K.google()}";` }), expect: [c("medium", "review")] },
    { name: "Gemini key", files: () => ({ "src/ai.ts": `const GEMINI_KEY = "${K.google()}";` }), expect: [c("high", "review")] },
    {
      name: "Firebase web config is allowed (AC8)",
      files: () => ({ "src/firebase.ts": `const firebaseConfig = {\n  apiKey: "${K.google()}",\n  authDomain: "a.firebaseapp.com",\n  projectId: "a",\n};` }),
      expect: [],
    },
  ],
  "secret-private-key": [
    { name: "PEM block", files: () => ({ "certs/k.txt": K.pem() }), expect: [c("critical", "confirmed")] },
    { name: "header string only", files: () => ({ "src/pem.ts": 'if (s.startsWith("-----BEGIN PRIVATE KEY-----")) {}' }), expect: [] },
  ],
  "secret-db-url": [
    { name: "remote host (AC24)", files: () => ({ "src/db.ts": `const u = "postgres://app:${rnd(16)}@db.prod-host.io:5432/app";` }), expect: [c("high", "confirmed")] },
    { name: "localhost default password (AC24)", files: () => ({ "src/db.ts": 'const u = "postgres://postgres:postgres@localhost/db";' }), expect: [c("medium", "review")] },
    { name: "env interpolation", files: () => ({ "src/db.ts": "const u = `postgres://app:${process.env.PW}@db/app`;" }), expect: [] },
  ],
  "secret-vulnintel": [
    { name: "vi_live_", files: () => ({ "ci.yml": `key: ${K.vulnintel()}` }), expect: [c("critical", "confirmed")] },
    { name: "short", files: () => ({ "ci.yml": "key: vi_live_short" }), expect: [] },
  ],
  "secret-public-env-prefix": [
    { name: "service role name in .env (AC8)", files: () => ({ ".env": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\n" }), expect: [c("high", "confirmed")] },
    { name: "VITE_JWT_SECRET (AC8)", files: () => ({ ".env": "VITE_JWT_SECRET=x\n" }), expect: [c("high", "confirmed")] },
    { name: "REACT_APP_PRIVATE_TOKEN (AC8)", files: () => ({ ".env": "REACT_APP_PRIVATE_TOKEN=x\n" }), expect: [c("high", "confirmed")] },
    { name: "code reference only (AC8)", files: () => ({ "src/s.ts": "const s = import.meta.env.VITE_SPOTIFY_CLIENT_SECRET;" }), expect: [c("high", "review")] },
    { name: "name in .env.example (AC8)", files: () => ({ ".env.example": "VITE_SPOTIFY_CLIENT_SECRET=\n" }), expect: [c("high", "review")] },
    {
      name: "public names are not findings (AC8)",
      files: () => ({
        ".env": [
          `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${K.sbPublishable()}`,
          `VITE_STRIPE_PUBLISHABLE_KEY=${K.stripePk()}`,
          "NEXT_PUBLIC_API_KEY=abc",
          "NEXT_PUBLIC_PUBLIC_KEY=x",
          `NEXT_PUBLIC_FIREBASE_API_KEY=${K.google()}`,
        ].join("\n"),
      }),
      expect: [],
    },
    {
      name: "Markdown docs and specs are not checked (the example line of a spec)",
      files: () => ({
        "sio/projects/spec.md": "- AC8: `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x` → high, `import.meta.env.VITE_SPOTIFY_CLIENT_SECRET` → review\n",
        "notes.mdx": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\n",
      }),
      expect: [],
    },
  ],
  "secret-in-mcp-config": [
    { name: "key value in .mcp.json", files: () => ({ ".mcp.json": `{"mcpServers":{"x":{"env":{"API_KEY":"${rnd(24)}"}}}}` }), expect: [c("high", "confirmed")] },
    { name: "env reference", files: () => ({ ".mcp.json": '{"mcpServers":{"x":{"env":{"API_KEY":"${API_KEY}"}}}}' }), expect: [] },
  ],
  "gitignore-env-missing": [
    { name: "no .gitignore", files: () => ({ ".env": "A=1\n" }), expect: [c("high", "confirmed")] },
    { name: ".gitignore without env rule", files: () => ({ ".env": "A=1\n", ".gitignore": "node_modules\n" }), expect: [c("high", "confirmed")] },
    { name: ".env*.local rule", files: () => ({ ".env.local": "A=1\n", ".gitignore": "node_modules\n.env*.local\n" }), expect: [] },
    { name: "no .env files", files: () => ({ "a.ts": "" }), expect: [] },
  ],
  "key-file-committed": [
    { name: "tracked .key", files: () => ({ "certs/server.key": "k", ".gitignore": ".env\n" }), commit: ["certs/server.key"], expect: [c("critical", "confirmed")] },
    { name: "untracked .key", files: () => ({ "certs/server.key": "k", ".gitignore": ".env\n" }), commit: [".gitignore"], expect: [] },
    { name: "tracked public key", files: () => ({ "id_rsa.pub": "ssh-rsa AAA", ".gitignore": ".env\n" }), commit: ["id_rsa.pub"], expect: [] },
  ],
  "sourcemap-in-build": [
    { name: "map in dist", files: () => ({ "dist/assets/app.js.map": "{}" }), expect: [c("medium", "confirmed")] },
    {
      name: "hidden source maps → info (AC24)",
      files: () => ({ "dist/app.js.map": "{}", "vite.config.ts": "export default { build: { sourcemap: 'hidden' } }" }),
      expect: [c("medium", "info")],
    },
    { name: "no maps", files: () => ({ "dist/app.js": "x" }), expect: [] },
  ],
  "cors-wildcard": [
    { name: "header *", files: () => ({ "api/x.ts": "res.setHeader('Access-Control-Allow-Origin', '*');" }), expect: [c("medium", "confirmed")] },
    { name: "FastAPI allow_origins=['*']", files: () => ({ "main.py": 'app.add_middleware(CORSMiddleware, allow_origins=["*"])' }), expect: [c("medium", "confirmed")] },
    { name: "app.use(cors()) (AC24)", files: () => ({ "server.js": "app.use(cors());" }), expect: [c("medium", "review")] },
    {
      name: "Supabase Edge Function (AC24)",
      files: () => ({ "supabase/functions/x/index.ts": "const h = { 'Access-Control-Allow-Origin': '*' };" }),
      expect: [c("medium", "info")],
    },
    { name: "fixed origin", files: () => ({ "server.js": "app.use(cors({ origin: 'https://a.com' }));" }), expect: [] },
    { name: "comment line", files: () => ({ "main.py": '# never use allow_origins=["*"] here' }), expect: [] },
  ],
  "cors-credentials-any": [
    { name: "origin true + credentials", files: () => ({ "server.js": "app.use(cors({ origin: true, credentials: true }));" }), expect: [c("high", "confirmed")] },
    { name: "origin '*' + credentials", files: () => ({ "server.js": "app.use(cors({ origin: '*', credentials: true }));" }), expect: [c("high", "confirmed")] },
    {
      name: "FastAPI allow_origins=['*'] + allow_credentials",
      files: () => ({ "main.py": 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)' }),
      expect: [c("high", "confirmed")],
    },
    {
      name: "all-origins regex + credentials (FastAPI, Express)",
      files: () => ({
        "main.py": 'app.add_middleware(CORSMiddleware, allow_origin_regex="https?://.*", allow_credentials=True)',
        "server.js": "app.use(cors({ origin: /.*/, credentials: true }));",
      }),
      expect: [c("high", "confirmed"), c("high", "confirmed")],
    },
    {
      name: "origin callback that always says yes + credentials",
      files: () => ({ "server.js": "app.use(cors({ origin: (o, cb) => cb(null, true), credentials: true }));" }),
      expect: [c("high", "confirmed")],
    },
    {
      name: "request Origin header copied into Allow-Origin + credentials (Express, Python)",
      files: () => ({
        "api/x.js": "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\nres.setHeader('Access-Control-Allow-Credentials', 'true');",
        "app/mw.py": 'response.headers["Access-Control-Allow-Origin"] = request.headers.get("origin")\nresponse.headers["Access-Control-Allow-Credentials"] = "true"\n',
      }),
      expect: [c("high", "confirmed"), c("high", "confirmed")],
    },
    {
      name: "settings variable + credentials is not 'any origin' (VulnIntel middleware.py)",
      files: () => ({ "main.py": "app.add_middleware(\n    CORSMiddleware,\n    allow_origins=settings.ALLOWED_ORIGINS,\n    allow_credentials=True,\n)" }),
      expect: [],
    },
    {
      name: "explicit origin list + credentials",
      files: () => ({
        "main.py": 'app.add_middleware(CORSMiddleware, allow_origins=["https://a.com", "https://b.com"], allow_credentials=True)',
        "server.js": "app.use(cors({ origin: ['https://a.com'], credentials: true }));",
      }),
      expect: [],
    },
    {
      name: "allowlist callback + credentials (Express docs pattern)",
      files: () => ({
        "server.js": "app.use(cors({ credentials: true, origin: function (origin, callback) {\n  if (allowlist.indexOf(origin) !== -1) { callback(null, true) } else { callback(new Error('no')) }\n} }));",
      }),
      expect: [],
    },
    { name: "origin true without credentials", files: () => ({ "server.js": "app.use(cors({ origin: true }));" }), expect: [] },
  ],
  "debug-django": [
    { name: "single settings.py (AC24)", files: () => ({ "proj/settings.py": "DEBUG = True\n" }), expect: [c("high", "review")] },
    {
      name: "settings/production.py (AC24)",
      files: () => ({ "proj/settings/production.py": "DEBUG = True\n", "proj/settings/dev.py": "DEBUG = False\n" }),
      expect: [c("high", "confirmed")],
    },
    {
      name: "settings/dev.py (AC24)",
      files: () => ({ "proj/settings/dev.py": "DEBUG = True\n", "proj/settings/production.py": "DEBUG = False\n" }),
      expect: [c("high", "info")],
    },
    { name: "env-driven", files: () => ({ "proj/settings.py": "DEBUG = os.environ.get('DEBUG') == '1'\n" }), expect: [c("high", "review")] },
    { name: "False", files: () => ({ "proj/settings.py": "DEBUG = False\n" }), expect: [] },
  ],
  "debug-flask": [
    { name: "app.run(debug=True)", files: () => ({ "app.py": "app.run(host='0.0.0.0', debug=True)" }), expect: [c("high", "confirmed")] },
    { name: "debug=False", files: () => ({ "app.py": "app.run(debug=False)" }), expect: [] },
  ],
  "debug-fastapi": [
    { name: "FastAPI(debug=True)", files: () => ({ "main.py": 'app = FastAPI(\n    title="x",\n    debug=True,\n)' }), expect: [c("high", "confirmed")] },
    { name: "no debug", files: () => ({ "main.py": 'app = FastAPI(title="x")' }), expect: [] },
  ],
  "debug-laravel": [
    { name: "'debug' => true", files: () => ({ "config/app.php": "<?php return ['debug' => true];" }), expect: [c("high", "confirmed")] },
    { name: "env default true", files: () => ({ "config/app.php": "<?php return ['debug' => env('APP_DEBUG', true)];" }), expect: [c("high", "review")] },
    { name: "env default false", files: () => ({ "config/app.php": "<?php return ['debug' => env('APP_DEBUG', false)];" }), expect: [] },
  ],
  "debug-spring": [
    { name: "debug=true", files: () => ({ "src/main/resources/application.properties": "debug=true\n" }), expect: [c("high", "confirmed")] },
    { name: "placeholder value", files: () => ({ "src/main/resources/application.properties": "debug=${DEBUG:false}\n" }), expect: [c("high", "review")] },
    { name: "debug=false", files: () => ({ "src/main/resources/application.yml": "debug: false\n" }), expect: [] },
  ],
  "debug-env-production": [
    { name: "DEBUG=true", files: () => ({ ".env.production": "DEBUG=true\n", ".gitignore": ".env*\n" }), expect: [c("high", "confirmed")] },
    { name: "DEBUG=false", files: () => ({ ".env.production": "DEBUG=false\n", ".gitignore": ".env*\n" }), expect: [] },
  ],
  "sourcemap-next": [
    { name: "productionBrowserSourceMaps: true", files: () => ({ "next.config.mjs": "export default { productionBrowserSourceMaps: true }" }), expect: [c("medium", "confirmed")] },
    { name: "false", files: () => ({ "next.config.mjs": "export default { productionBrowserSourceMaps: false }" }), expect: [] },
  ],
  "sourcemap-vite": [
    { name: "true", files: () => ({ "vite.config.ts": "export default { build: { sourcemap: true } }" }), expect: [c("medium", "confirmed")] },
    { name: "variable", files: () => ({ "vite.config.ts": "export default { build: { sourcemap: isDev } }" }), expect: [c("medium", "review")] },
    { name: "'hidden'", files: () => ({ "vite.config.ts": "export default { build: { sourcemap: 'hidden' } }" }), expect: [] },
  ],
};

describe("AC7 default template — positive/negative fixture per engine item", () => {
  for (const [rule, cases] of Object.entries(RULE_CASES)) {
    describe(rule, () => {
      it.each(cases.map((x) => [x.name, x] as const))("%s", async (_, x) => {
        const dir = project(x.files());
        if (x.commit) {
          gitRepo(dir);
          git(dir, "add", "--", ...x.commit);
          git(dir, "commit", "-q", "-m", "fixture");
        }
        const got = byRule(await scanDefault(dir), rule).map((f) => ({ severity: f.severity, confidence: f.confidence }));
        expect(got).toEqual(x.expect);
      });
    });
  }

  it("covers every pattern/file/config rule of the default template", async () => {
    const { loadDefaultTemplate } = await import("../src/index.js");
    const engine = (await loadDefaultTemplate()).rules.filter((r) => r.type !== "builtin" && r.type !== "ai_check").map((r) => r.id);
    expect(engine.filter((id) => id !== "env-committed" && !RULE_CASES[id])).toEqual([]); // env-committed: AC11 block
  });
});

describe("AC8 public keys and variable names", () => {
  it("allowlisted public values are counted, not reported", async () => {
    const dir = project({
      "src/firebase.ts": `export const cfg = { apiKey: "${K.google()}", authDomain: "a.firebaseapp.com", projectId: "a" };`,
      "src/sb.ts": `createClient(url, "${K.anonJwt()}")`,
    });
    const r = await scanDefault(dir);
    expect(r.stats.allowed_public_keys).toBe(1);
    expect(r.findings.filter((f) => f.confidence !== "info")).toEqual([]);
    expect(byRule(r, "secret-supabase-service-role")).toEqual([]);
    expect(byRule(r, "supabase-anon-key")[0]!.notes).toContain("legacy_anon_key");
  });

  it("anon JWT under a public env name is info only; service_role JWT under any name is critical", async () => {
    const dir = project({
      ".env": `NEXT_PUBLIC_SUPABASE_ANON_KEY=${K.anonJwt()}\nNEXT_PUBLIC_SUPABASE_KEY=${K.serviceRoleJwt()}\nSB=${K.sbSecret()}\n`,
      ".gitignore": ".env\n",
    });
    const r = await scanDefault(dir);
    const sr = byRule(r, "secret-supabase-service-role").map((f) => [f.location!.line, f.confidence]);
    // not a git repo → .env value rules are review (§5); the anon key is its own info finding (B2)
    expect(sr).toEqual([
      [2, "review"],
      [3, "review"],
    ]);
    expect(byRule(r, "supabase-anon-key").map((f) => [f.location!.line, f.confidence])).toEqual([[1, "info"]]);
    expect(byRule(r, "secret-public-env-prefix")).toEqual([]);
  });
});

describe("AC9 default excludes and build output", () => {
  it("ignores non-secret rules in node_modules/.next/dist, catches secrets in .next/static and dist", async () => {
    const key = K.openai();
    const dir = project({
      "node_modules/x/index.js": `app.use(cors()); const k="${K.openai()}";`,
      ".next/server/app.js": `const k="${K.openai()}"; app.use(cors());`,
      ".next/static/chunks/main.js": `const k="${key}";app.use(cors());`,
      "dist/app.js": `res.setHeader('Access-Control-Allow-Origin', '*'); const s="${K.stripe()}";`,
    });
    const r = await scanDefault(dir);
    expect(byRule(r, "cors-wildcard")).toEqual([]);
    expect(byRule(r, "secret-openai").map((f) => f.location!.file)).toEqual([".next/static/chunks/main.js"]);
    expect(byRule(r, "secret-stripe-live").map((f) => f.location!.file)).toEqual(["dist/app.js"]);
  });

  it("same secret in source and build output → one source finding + in_build_output", async () => {
    const key = K.openai();
    const dir = project({ "src/a.ts": `const k="${key}";`, "dist/a.js": `var k="${key}";` });
    const f = byRule(await scanDefault(dir), "secret-openai");
    expect(f.map((x) => [x.location!.file, x.notes])).toEqual([["src/a.ts", ["in_build_output"]]]);
  });
});

describe("AC10 examples, docs, placeholders, tests", () => {
  it("classifies example/doc/test paths", async () => {
    const dir = project({
      ".env.example": `OPENAI_API_KEY=your-key-here\nREAL=${K.openai()}\nDATABASE_URL=postgres://postgres:postgres@localhost:5432/app\n`,
      "README.md": "```\nDATABASE_URL=postgres://user:[PASSWORD]@host/db\n```\n",
      "tests/fixtures/keys.ts": `export const k = "${K.stripe()}";`,
      ".gitignore": ".env\n",
    });
    const r = await scanDefault(dir);
    expect(byRule(r, "secret-openai").map((f) => [f.location!.file, f.confidence])).toEqual([[".env.example", "info"]]);
    expect(byRule(r, "secret-db-url").map((f) => [f.location!.file, f.confidence])).toEqual([[".env.example", "info"]]);
    expect(byRule(r, "secret-stripe-live").map((f) => [f.location!.file, f.confidence])).toEqual([["tests/fixtures/keys.ts", "review"]]);
  });
});

describe("AC11 env-committed", () => {
  it("untracked but in history with a secret → critical", async () => {
    const dir = gitRepo(project({ ".env": `OPENAI_API_KEY=${K.openai()}\n` }));
    git(dir, "add", ".env");
    git(dir, "commit", "-q", "-m", "oops");
    git(dir, "rm", "-q", "--cached", ".env");
    project({ ".gitignore": ".env\n" }, dir);
    git(dir, "add", ".gitignore");
    git(dir, "commit", "-q", "-m", "fix");
    const r = await scanDefault(dir);
    expect(byRule(r, "env-committed")).toMatchObject([{ severity: "critical", confidence: "confirmed", location: { file: ".env" }, notes: ["history_only"] }]);
  });

  it("deleted .env that only exists in history is still reported", async () => {
    const dir = gitRepo(project({ ".env.production": `DB=postgres://a:${rnd(12)}@db.example-prod.io/x\n` }));
    git(dir, "add", ".env.production");
    git(dir, "commit", "-q", "-m", "a");
    git(dir, "rm", "-q", ".env.production");
    git(dir, "commit", "-q", "-m", "b");
    expect(byRule(await scanDefault(dir), "env-committed")).toMatchObject([{ severity: "critical", confidence: "confirmed" }]);
  });

  it("only public values → info 'public values only', gitignore-env-missing stays high", async () => {
    const dir = gitRepo(
      project({
        ".env": [
          "NEXT_PUBLIC_SUPABASE_URL=https://abcd.supabase.co",
          `NEXT_PUBLIC_SUPABASE_ANON_KEY=${K.anonJwt()}`,
          `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=${K.sbPublishable()}`,
          "SUPABASE_PROJECT_ID=abcd",
        ].join("\n"),
      }),
    );
    git(dir, "add", ".env");
    git(dir, "commit", "-q", "-m", "a");
    const r = await scanDefault(dir);
    expect(byRule(r, "env-committed")).toMatchObject([{ confidence: "info", notes: ["public_values_only"] }]);
    expect(byRule(r, "gitignore-env-missing")).toMatchObject([{ severity: "high", confidence: "confirmed" }]);
  });
});

describe("AC71 local-only .env*", () => {
  const files = (): Record<string, string> => ({
    ".env.local": `OPENAI_API_KEY=${K.openai()}\nNEXT_PUBLIC_APP_SECRET=x\n`,
    ".gitignore": ".env*.local\n",
  });

  it("gitignored, untracked, never committed → info; NEXT_PUBLIC_…SECRET stays high·confirmed", async () => {
    const dir = gitRepo(project(files()));
    git(dir, "add", ".gitignore");
    git(dir, "commit", "-q", "-m", "a");
    const r = await scanDefault(dir);
    expect(byRule(r, "secret-openai")).toMatchObject([{ confidence: "info", notes: ["local_only_env"] }]);
    expect(byRule(r, "secret-public-env-prefix")).toMatchObject([{ severity: "high", confidence: "confirmed" }]);
    expect(r.findings.filter((f) => f.confidence === "confirmed").map((f) => f.rule_id)).toEqual(["secret-public-env-prefix"]);
  });

  it("tracked → critical", async () => {
    const dir = gitRepo(project(files()));
    git(dir, "add", "-f", ".env.local", ".gitignore");
    git(dir, "commit", "-q", "-m", "a");
    expect(byRule(await scanDefault(dir), "secret-openai")).toMatchObject([{ severity: "critical", confidence: "confirmed" }]);
  });

  it("in history only → critical", async () => {
    const dir = gitRepo(project(files()));
    git(dir, "add", "-f", ".env.local", ".gitignore");
    git(dir, "commit", "-q", "-m", "a");
    git(dir, "rm", "-q", "--cached", ".env.local");
    git(dir, "commit", "-q", "-m", "b");
    expect(byRule(await scanDefault(dir), "secret-openai")).toMatchObject([{ confidence: "confirmed" }]);
  });

  it("not a git repository → review", async () => {
    expect(byRule(await scanDefault(project(files())), "secret-openai")).toMatchObject([{ confidence: "review" }]);
  });
});

describe("AC40 Windows paths, Korean folders, CRLF, BOM, UTF-16", () => {
  it("reports /-separated relative paths and correct lines", async () => {
    const key = K.openai();
    const dir = project({
      "한글 폴더/하위/a.ts": `const k = "${key}";`,
      "crlf.ts": `// a\r\n// b\r\nconst k = "${K.github()}";\r\n`,
      "bom.py": `﻿KEY = "${K.stripe()}"\n`,
      "utf16.txt": Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`KEY="${K.openai()}"`, "utf16le")]) as unknown as string,
      "utf16-nobom.txt": Buffer.from(`KEY="${K.openai()}"\n`.repeat(20), "utf16le") as unknown as string,
    });
    const r = await scanDefault(dir);
    expect(byRule(r, "secret-openai").map((f) => f.location)).toEqual([{ file: "한글 폴더/하위/a.ts", line: 1 }]);
    expect(byRule(r, "secret-github").map((f) => f.location)).toEqual([{ file: "crlf.ts", line: 3 }]);
    expect(byRule(r, "secret-stripe-live").map((f) => f.location)).toEqual([{ file: "bom.py", line: 1 }]);
    expect(r.stats.skipped.utf16).toBe(2);
    for (const f of r.findings) expect(f.location?.file ?? "").not.toContain("\\");
  });
});

describe("AC5 scan stays inside CWD", () => {
  it("does not follow a symlink/junction pointing outside CWD; paths are relative", async () => {
    const outside = project({ "secret.ts": `const k = "${K.openai()}";` });
    const dir = project({ "src/ok.ts": "export {}" });
    mkdirSync(join(dir, "linked-parent"), { recursive: true });
    symlinkSync(outside, join(dir, "linked-parent", "out"), "junction");
    const r = await scanDefault(dir);
    expect(byRule(r, "secret-openai")).toEqual([]);
    expect(r.findings.every((f) => !f.location || !/^([A-Za-z]:|\/)/.test(f.location.file))).toBe(true);
  });
});

describe("AC6 no secret values in results", () => {
  it("scan JSON carries only masked values and hashes", async () => {
    const keys = [K.openai(), K.anthropic(), K.serviceRoleJwt(), K.sbSecret(), K.aws(), K.stripe(), K.github(), K.vulnintel(), K.sbPat()];
    const dir = project({ "src/keys.ts": keys.map((k, i) => `export const k${i} = "${k}";`).join("\n") });
    const r = await scanDefault(dir);
    const json = JSON.stringify(r);
    expect(r.findings.length).toBe(keys.length);
    for (const k of keys) {
      expect(json).not.toContain(k);
      expect(json).not.toContain(k.slice(0, 20));
    }
    for (const f of r.findings) expect(f.masked_match).toMatch(/••••/);
  });
});

describe("titles follow the language option", () => {
  it("ko / en", async () => {
    const dir = project({ "a.py": "app.run(debug=True)" });
    expect(byRule(await scanDefault(dir, { lang: "ko" }), "debug-flask")[0]!.title).toBe("Flask 디버그 모드");
    expect(byRule(await scanDefault(dir), "debug-flask")[0]!.title).toBe("Flask debug mode");
  });
});

describe("checked list", () => {
  it("builtins run; dependency lookups wait for consent; git rules skipped outside a repo", async () => {
    const r = await scanDefault(project({ "a.txt": "" }));
    expect(r.checked.find((x) => x.rule_id === "supabase-rls")).toEqual({ rule_id: "supabase-rls", ran: true });
    expect(r.checked.find((x) => x.rule_id === "vulnerable-deps")).toEqual({ rule_id: "vulnerable-deps", ran: false, reason: "no_consent" });
    expect(r.checked.find((x) => x.rule_id === "env-committed")).toEqual({ rule_id: "env-committed", ran: false, reason: "not_git_repo" });
    expect(r.checked.some((x) => x.rule_id.startsWith("ai-"))).toBe(false);
    void tempDir;
  });
});
