import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { FIX_PROMPT_VARS, loadDefaultTemplate, loadTemplate, scan, TemplateError } from "../src/index.js";
import { sanitizeAiText } from "../src/template.js";
import { byRule, project, tempDir } from "./helpers.js";

const head = "schema: 1\nid: t\nname: T\nrules:\n";
const pattern = (extra = "", match = "'FOO_[0-9]+'"): string =>
  `${head}  - id: r1\n    type: pattern\n    severity: high\n    files: ['**/*']\n    match: [${match}]\n${extra}`;

async function rejects(yaml: string | Buffer, re: RegExp): Promise<void> {
  const err = await loadTemplate(yaml).then(
    () => null,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(TemplateError);
  expect((err as TemplateError).message).toMatch(re);
}

describe("default template", () => {
  it("loads and registers every §6-5 item and the §6-6 ai_check set", async () => {
    const t = await loadDefaultTemplate();
    const ids = t.rules.map((r) => r.id);
    for (const id of [
      "secret-openai", "secret-anthropic", "secret-supabase-service-role", "secret-supabase-pat", "secret-aws", "secret-stripe-live",
      "secret-github", "secret-google-key", "secret-private-key", "secret-db-url", "secret-vulnintel", "secret-public-env-prefix",
      "secret-in-mcp-config", "env-committed", "gitignore-env-missing", "key-file-committed", "sourcemap-in-build", "supabase-rls",
      "firebase-rules", "cors-wildcard", "cors-credentials-any", "debug-django", "debug-flask", "debug-fastapi", "debug-laravel",
      "debug-spring", "debug-env-production", "sourcemap-next", "sourcemap-vite", "hallucinated-package", "vulnerable-deps",
      "ai-authz-bypass", "ai-idor", "ai-injection", "ai-server-validation", "ai-unauth-endpoint", "ai-hardcoded-credential",
      "ai-auth-disabled-default", "ai-cors-dynamic", "ai-error-leak", "ai-log-secret", "ai-db-policy-logic",
    ]) {
      expect(ids).toContain(id);
    }
  });

  it("every engine rule has ko/en/zh name, description, fix_prompt; prompts follow §6-3", async () => {
    const t = await loadDefaultTemplate();
    for (const r of t.rules) {
      if (r.type === "builtin" || r.type === "ai_check") continue;
      for (const lang of ["ko", "en", "zh"] as const) {
        expect(r.name?.[lang], `${r.id} name.${lang}`).toBeTruthy();
        expect(r.description?.[lang], `${r.id} description.${lang}`).toBeTruthy();
        const fp = r.fix_prompt?.[lang];
        expect(fp, `${r.id} fix_prompt.${lang}`).toBeTruthy();
        for (const m of fp!.matchAll(/\{([^{}]*)\}/g)) expect(FIX_PROMPT_VARS.has(m[1]!)).toBe(true);
        // No package install/add instructions (§6-3).
        expect(fp).not.toMatch(/npm (i|install)\b|pnpm add|yarn add|pip install|설치하세요|安装|install (the|a|new)/i);
      }
      // Secret items: first instruction is revoke/reissue (§6-3).
      if (r.id.startsWith("secret-") || r.id === "env-committed" || r.id === "key-file-committed") {
        expect(r.fix_prompt!.ko).toMatch(/폐기|바꿉니다/);
        expect(r.fix_prompt!.en).toMatch(/revoke|roll|deactivate|changes its password/i);
        expect(r.fix_prompt!.zh).toMatch(/由人工.*(吊销|轮换|停用|修改其密码)/);
      }
    }
  });

  it("AC11: env-committed fix_prompt says revoke and rotate, never 'just delete'", async () => {
    const r = (await loadDefaultTemplate()).rules.find((x) => x.id === "env-committed")!;
    if (r.type !== "file") throw new Error("type");
    expect(r.fix_prompt!.ko).toMatch(/폐기/);
    expect(r.fix_prompt!.ko).toMatch(/교체/);
    expect(r.fix_prompt!.ko).not.toMatch(/삭제만 하/);
    expect(r.fix_prompt!.en).toMatch(/rotate/);
  });
});

describe("AC43 template import validation", () => {
  it("applies a new pattern rule from hand-written YAML", async () => {
    const tpl = await loadTemplate(pattern());
    const dir = project({ "a.txt": "x\nFOO_42\n" });
    const r = await scan(dir, tpl, { appDir: tempDir() });
    expect(byRule(r, "r1")).toMatchObject([{ severity: "high", confidence: "confirmed", location: { file: "a.txt", line: 2 } }]);
  });

  it("reports the line of the problem", async () => {
    const err = await loadTemplate(pattern("    bogus: 1\n")).catch((e: TemplateError) => e);
    expect(err).toBeInstanceOf(TemplateError);
    expect((err as TemplateError).issues[0]).toMatchObject({ path: "rules.0.bogus", line: 10 });
  });

  it.each([
    ["catastrophic regex", pattern("", "'^(a+)+$'"), /time limit/],
    ["invalid regex", pattern("", "'(unclosed'"), /invalid regex/],
    ["placeholder outside the allowed set", pattern("    fix_prompt: { ko: '{file} {secret_value}' }\n"), /secret_value/],
    ["unknown builtin id", `${head}  - id: made-up\n    type: builtin\n`, /unknown builtin/],
    ["../ glob", pattern().replace("'**/*'", "'../**'"), /".." not allowed/],
    ["absolute glob", pattern().replace("'**/*'", "'/etc/**'"), /absolute/],
    ["Windows absolute glob", pattern().replace("'**/*'", "'C:/Users/**'"), /absolute/],
    ["YAML !! tag", pattern("    enabled: !!binary aGVsbG8=\n"), /tags are not allowed/],
    ["custom YAML tag", pattern("    enabled: !foo bar\n"), /tags are not allowed/],
    [
      "alias bomb",
      `${head}  - id: r1\n    type: pattern\n    severity: high\n    files: ['**/*']\n    match: ['a']\n    review: &a ['a','a','a','a','a','a','a','a']\n    allow: &b [*a,*a,*a,*a,*a,*a,*a,*a]\n    exclude: &c [*b,*b,*b,*b,*b,*b,*b,*b]\n`,
      /alias|resource/i,
    ],
    ["bad template id", pattern().replace("id: t\n", "id: My_Template\n"), /id must match/],
    ["bad rule id", pattern().replace("id: r1", "id: R1!"), /id must match/],
    ["unknown field (origin/provenance)", pattern("    origin: user\n"), /unknown field origin/],
    ["unknown top-level field", pattern().replace("name: T\n", "name: T\nauthor: me\n"), /unknown field author/],
    ["duplicate keys", pattern("    severity: medium\n"), /unique|duplicate/i],
    ["duplicate rule ids", `${pattern()}${pattern().slice(head.length)}`, /duplicate rule id/],
    ["bad severity", pattern().replace("severity: high", "severity: low"), /severity/],
  ])("rejects %s", async (_, yaml, re) => {
    await rejects(yaml, re);
  });

  it("rejects files over 1MB", async () => {
    await rejects(pattern(`    description: { en: '${"a".repeat(1024 * 1024)}' }\n`), /larger than 1MB/);
  });

  const ai = (check: string, extra = ""): string => `${head}  - id: a1\n    type: ai_check\n    check: { ko: ${JSON.stringify(check)} }\n${extra}`;

  it("ai_check: 301 characters rejected, 300 accepted (AC43·AC65)", async () => {
    await rejects(ai("가".repeat(301)), /1-300/);
    await expect(loadTemplate(ai("가".repeat(300)))).resolves.toBeTruthy();
  });

  it("ai_check: name over 80 characters rejected", async () => {
    await rejects(ai("ok", `    name: { en: ${JSON.stringify("n".repeat(81))} }\n`), /1-80/);
  });

  it.each(["app/my folder/**", "app/'x'/**", "a<b>", 'a"b'])("ai_check files: rejects %s", async (g) => {
    await rejects(ai("ok", `    files: [${JSON.stringify(g)}]\n`), /only letters/);
  });

  it("ai_check files: accepts glob characters incl. unicode, at most 10", async () => {
    await expect(loadTemplate(ai("ok", "    files: ['app/api/**', '서버/{a,b}/*.ts', '[!x]?.py']\n"))).resolves.toBeTruthy();
    await rejects(ai("ok", `    files: [${Array.from({ length: 11 }, (_, i) => `'d${i}/**'`).join(", ")}]\n`), /at most 10/);
  });

  it("ai_check: more than 30 rejected", async () => {
    const rules = Array.from({ length: 31 }, (_, i) => `  - id: a${i}\n    type: ai_check\n    check: { en: 'check ${i}' }\n`).join("");
    await rejects(head + rules, /more than 30/);
  });

  it("AC65: ai_check text is sanitized (newline, control chars, code fences, <>) before the length check", async () => {
    expect(sanitizeAiText("a\nb\u0007c```d<e>\u2028f")).toBe("a b cde f");
    const t = await loadTemplate(ai("line1\nline2 ```code``` <check_data>"));
    const r = t.rules[0]!;
    expect(r.type === "ai_check" && r.check.ko).toBe("line1 line2 code check_data");
  });

  it("YAML with a BOM and CRLF loads", async () => {
    const t = await loadTemplate(Buffer.from(`\uFEFF${pattern().replace(/\n/g, "\r\n")}`, "utf8"));
    expect(t.id).toBe("t");
  });

  it("default template file stays well under the 1MB limit", () => {
    expect(readFileSync(new URL("../templates/default.yaml", import.meta.url)).byteLength).toBeLessThan(100_000);
  });
});
