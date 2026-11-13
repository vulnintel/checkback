// Simplified Chinese (zh): every builtin text has it, user texts fall back to English, and every
// surface (terminal report, CI gate, fix prompts, notices) speaks it.

import { describe, expect, it } from "vitest";
import { BUILTIN_NAMES, DEP_FIX, KIND_TEXT, LOCK_HAND_EDIT } from "../src/builtins/text.js";
import { depsUncheckedWarning, failOnMessage, formatScan, parseCli } from "../src/commands.js";
import { loadDefaultTemplate, loadTemplate, scan, TemplateError } from "../src/index.js";
import * as notice from "../src/notice.js";
import { aiCheckPromptText, fixPromptText } from "../src/prompts.js";
import { exportTemplate, importTemplate } from "../src/template-store.js";
import type { LocalizedText } from "../src/types.js";
import { DICTS } from "../web/src/i18n.js";
import { byRule, consentedAppDir, K, mockNet, project, tempDir } from "./helpers.js";

const HAN = /\p{Script=Han}/u;
const HANGUL = /[가-힣]/;
const placeholders = (s: string): string[] => [...new Set(s.match(/\{[a-z_]+\}/g) ?? [])].sort();

/** Every builtin text: zh is set, has the same {placeholders} as en, and is Chinese wherever ko is Korean. */
function checkText(where: string, t: LocalizedText | undefined): void {
  if (!t) return;
  expect(t.zh, where).toBeTruthy();
  expect(placeholders(t.zh!), where).toEqual(placeholders(t.en!));
  if (HANGUL.test(t.ko ?? "")) expect(t.zh, where).toMatch(HAN);
}

describe("zh builtin texts", () => {
  it("builtin judgments, dependency fixes and notices have zh with the same placeholders as en", () => {
    for (const [k, kt] of Object.entries(KIND_TEXT)) {
      for (const f of ["title", "description", "fix", "fixUv", "human"] as const) checkText(`${k}.${f}`, kt[f]);
      checkText(`${k}.named.description`, kt.named?.description);
      checkText(`${k}.named.fix`, kt.named?.fix);
    }
    for (const [k, t] of Object.entries({ ...BUILTIN_NAMES, ...DEP_FIX, LOCK_HAND_EDIT })) checkText(k, t);
    for (const k of ["DATA_TABLE", "CONSENT_HOWTO", "KEY_NOTICE", "DISCLAIMER", "PARTIAL_NOTICE", "OFFLINE_NOTICE", "SHALLOW_NOTICE"] as const) checkText(k, notice[k]);
    expect(notice.KEY_NOTICE.zh).toContain("https://www.vulnintelapp.com/zh/settings/api-keys?src=checkback");
  });

  it("default template: every rule name, description, fix prompt and AI check has zh", async () => {
    const tpl = await loadDefaultTemplate();
    let n = 0;
    for (const r of tpl.rules) {
      for (const f of ["name", "description", "fix_prompt", "check"] as const) {
        const t = (r as unknown as Record<string, LocalizedText | undefined>)[f];
        if (!t) continue;
        checkText(`${r.id}.${f}`, t);
        n++;
      }
    }
    expect(n).toBeGreaterThanOrEqual(95);
  });

  it("screen dictionary: same keys as en, every text filled and Chinese where ko is Korean", () => {
    const shape = (o: unknown): unknown =>
      typeof o === "object" && o !== null ? Object.fromEntries(Object.entries(o).sort().map(([k, v]) => [k, shape(v)])) : typeof o;
    expect(shape(DICTS.zh)).toEqual(shape(DICTS.en));
    const walk = (zh: unknown, en: unknown, ko: unknown, path: string): void => {
      if (typeof zh === "object" && zh !== null) {
        for (const k of Object.keys(zh)) walk((zh as never)[k], (en as never)[k], (ko as never)[k], `${path}.${k}`);
        return;
      }
      // Functions: call with sample arguments (numbers render in string slots too).
      const run = (v: unknown): string => (typeof v === "function" ? String(v(1, 2, 3, 4)) : String(v));
      checkText(path, { ko: run(ko), en: run(en), zh: run(zh) });
    };
    walk(DICTS.zh, DICTS.en, DICTS.ko, "zh");
  });
});

describe("zh output", () => {
  it("scan --lang zh is accepted and the terminal report is Chinese", async () => {
    expect(parseCli(["scan", "--lang", "zh"])).toEqual({ kind: "run", cmd: "scan", opts: { "--lang": "zh" } });
    const cwd = project({ "src/a.ts": `export const k = "${K.github()}";\n` });
    const tpl = await loadDefaultTemplate();
    const r = await scan(cwd, tpl, { appDir: tempDir(), lang: "zh" });
    expect(byRule(r, "secret-github")[0]!.title).toBe("GitHub 令牌泄露");
    const out = formatScan(r, tpl, "zh", false);
    expect(out).toMatch(/^待修复 1 项 {3}严重 1 · 高危 0 · 中危 0$/m);
    expect(out).toContain("  严重  GitHub 令牌泄露\n        src/a.ts:1"); // CJK labels count as double width
    expect(out).toContain("GitHub 令牌可以读取或修改你的仓库。");
    expect(out).toContain("下一步");
    expect(out).not.toMatch(HANGUL);
  });

  it("CI gate messages in zh", async () => {
    expect(failOnMessage(7, "high", "zh")).toBe("checkback: 高危及以上待修复 7 项 (--fail-on high)");
    expect(failOnMessage(2, "low", "zh")).toBe("checkback: 不限严重程度，待修复 2 项 (--fail-on low)");
    const lock = JSON.stringify({ name: "a", lockfileVersion: 3, packages: { "": { name: "a" }, "node_modules/lodash": { version: "4.17.15" } } });
    const cwd = project({ "package.json": JSON.stringify({ name: "a", dependencies: { lodash: "4.17.15" } }), "package-lock.json": lock });
    const r = await scan(cwd, await loadDefaultTemplate(), { appDir: await consentedAppDir(), fetch: mockNet({ offline: true }).fetch, lang: "zh" });
    expect(depsUncheckedWarning(r, "zh")).toMatch(/^checkback: 依赖检查没有完整运行（offline.*--fail-on 未覆盖它/);
    expect(formatScan(r, await loadDefaultTemplate(), "zh", false)).toContain("! 外部查询失败，部分依赖检查没有运行");
  });

  it("osLang: a zh locale picks zh", () => {
    expect(notice.osLang("zh-CN")).toBe("zh");
    expect(notice.osLang("zh-Hans-CN")).toBe("zh");
    expect(notice.osLang("ko-KR")).toBe("ko");
    expect(notice.osLang("en-US")).toBe("en");
    expect(notice.osLang("ja-JP")).toBe("en");
  });

  it("fix prompt in zh: the person step is split off Chinese sentences and said once; same prohibitions as en", async () => {
    const cwd = project({ "src/a.ts": `const k = "${K.openai()}";\n` });
    const tpl = await loadDefaultTemplate();
    const f = byRule(await scan(cwd, tpl, { appDir: tempDir() }), "secret-openai")[0]!;
    const t = fixPromptText([f], tpl, "zh").text.split("\n");
    expect(t[0]).toBe("[安全修复请求] OpenAI 密钥泄露");
    expect(t[2]).toBe("1) 问题是什么: 代码或构建产物中有 OpenAI API 密钥。");
    expect(t[3]).toBe("2) 先做的事: （由人工）在 OpenAI 控制台吊销此密钥并重新签发。");
    expect(t[4]).toBe("3) 代码修改: 在代码中删除该值，改为从服务端环境变量读取。不要在浏览器代码中直接调用 OpenAI，应通过你的服务器。");
    expect(t.join("\n").match(/吊销/g)).toHaveLength(1);
    expect(t.at(-2)).toContain("不要安装新的包。");
    expect(aiCheckPromptText(tpl, [], "zh")!.text).toContain("[安全审查请求 — 只读，先不要修改任何内容]");
  });
});

describe("zh in user templates", () => {
  const yaml = (name: string): string =>
    `schema: 1\nid: t\nname: T\nrules:\n  - id: r1\n    name: ${name}\n    type: pattern\n    severity: high\n    files: ['**/*']\n    match: ['FOO_[0-9]+']\n`;

  it("zh is optional: without it, zh falls back to English", async () => {
    const tpl = await loadTemplate(yaml("{ ko: 한국어 이름, en: English name }"));
    const r = await scan(project({ "a.txt": "FOO_123\n" }), tpl, { appDir: tempDir(), lang: "zh" });
    expect(r.findings[0]!.title).toBe("English name");
    expect(fixPromptText([r.findings[0]!], tpl, "zh").text.split("\n")[0]).toBe("[安全修复请求] English name");
  });

  it("zh is kept through import and export; other languages are refused", async () => {
    const appDir = tempDir();
    const { tpl } = await importTemplate(appDir, yaml("{ en: English name, zh: 中文名称 }"));
    const r = await scan(project({ "a.txt": "FOO_123\n" }), tpl, { appDir: tempDir(), lang: "zh" });
    expect(r.findings[0]!.title).toBe("中文名称");
    expect(await exportTemplate(appDir, tpl.id)).toMatch(/zh: 中文名称/);
    const err = await loadTemplate(yaml("{ en: English name, ja: 名前 }")).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TemplateError);
    expect((err as TemplateError).message).toMatch(/unknown language ja/);
  });
});
