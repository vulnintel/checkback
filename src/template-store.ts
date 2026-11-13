// User templates in `<appdata>/checkback/templates/<id>.yaml` and their local metadata in
// `<appdata>/checkback/meta/<id>.json` (§6-2). The YAML never carries provenance: "my item" is
// known only from hashes the GUI wrote to meta (M3). Shared by the GUI and the MCP server.

import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { stringify } from "yaml";
import { readJson, writeJson } from "./appdata.js";
import { VERSION } from "./net/http.js";
import { sha256 } from "./secrets.js";
import { loadDefaultTemplate, loadTemplate, TemplateError } from "./template.js";
import type { AiCheckRule, Lang, Severity, Template } from "./types.js";

const ID_RE = /^[a-z0-9-]{1,64}$/;

export interface TemplateMeta {
  /** Came in through [가져오기] (or unknown origin): every text in it is "external". */
  imported: boolean;
  /** Hashes of ai_check items written in the GUI (§6-2 M3). */
  mine: string[];
  /** Hashes of ai_check items copied from the bundled default template: neither mine nor external. */
  bundled: string[];
}

export class StoreError extends Error {
  constructor(
    readonly code: "not_found" | "read_only" | "invalid" | "not_mine",
    message: string,
    readonly issues?: TemplateError["issues"],
  ) {
    super(message);
  }
}

const tplFile = (appDir: string, id: string): string => join(appDir, "templates", `${id}.yaml`);
const metaFile = (appDir: string, id: string): string => join(appDir, "meta", `${id}.json`);

export const aiHash = (r: AiCheckRule): string => sha256(`${r.id}\0${JSON.stringify(r.check)}\0${r.files.join("\n")}`);

export async function readMeta(appDir: string, id: string): Promise<TemplateMeta> {
  const m = await readJson<Partial<TemplateMeta> | null>(metaFile(appDir, id), null);
  // A template file without meta was put there by hand: treat it as imported.
  const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  return { imported: m?.imported ?? true, mine: list(m?.mine), bundled: list(m?.bundled) };
}

/** For the AI deep-review prompt: an ai_check is external unless its hash is in meta (AC65, AC73). */
export async function aiExternal(appDir: string, tpl: Template): Promise<(r: AiCheckRule) => boolean> {
  if (tpl.id === "default") return () => false;
  const m = await readMeta(appDir, tpl.id);
  const known = new Set([...m.mine, ...m.bundled]);
  return (r) => !known.has(aiHash(r));
}

/** `default` (bundled) or a user template by id. */
export async function loadTemplateById(id: string | undefined, appDir: string): Promise<Template> {
  if (!id || id === "default") return loadDefaultTemplate();
  if (!ID_RE.test(id)) throw new StoreError("invalid", "invalid template id");
  let raw: Buffer;
  try {
    raw = await readFile(tplFile(appDir, id));
  } catch {
    throw new StoreError("not_found", `template ${id} not found`);
  }
  return loadTemplate(raw);
}

export async function listTemplates(appDir: string): Promise<{ id: string; name: string; readOnly: boolean; imported: boolean }[]> {
  const def = await loadDefaultTemplate();
  const out = [{ id: def.id, name: def.name, readOnly: true, imported: false }];
  const names = await readdir(join(appDir, "templates")).catch(() => [] as string[]);
  for (const f of names.filter((n) => n.endsWith(".yaml")).sort()) {
    const id = f.slice(0, -5);
    if (!ID_RE.test(id) || id === "default") continue;
    const t = await loadTemplateById(id, appDir).catch(() => null);
    if (t && t.id === id) out.push({ id, name: t.name, readOnly: false, imported: (await readMeta(appDir, id)).imported });
  }
  return out;
}

/** Validate through the engine loader (same rules as import), then write. */
async function save(appDir: string, tpl: Template, meta: TemplateMeta): Promise<Template> {
  const text = stringify(tpl);
  const checked = await loadTemplate(text); // throws TemplateError with line numbers
  await writeJson(metaFile(appDir, tpl.id), meta);
  await mkdir(join(appDir, "templates"), { recursive: true });
  await writeFile(tplFile(appDir, tpl.id), text, { mode: 0o600 });
  return checked;
}

async function freeId(appDir: string, base: string): Promise<string> {
  const taken = new Set((await listTemplates(appDir)).map((t) => t.id));
  const stem = base.slice(0, 56).replace(/-+$/, "") || "template";
  if (!taken.has(stem)) return stem;
  for (let i = 2; ; i++) if (!taken.has(`${stem}-${i}`)) return `${stem}-${i}`;
}

async function userTemplate(appDir: string, id: string): Promise<{ tpl: Template; meta: TemplateMeta }> {
  if (id === "default") throw new StoreError("read_only", "the default template is read-only");
  return { tpl: await loadTemplateById(id, appDir), meta: await readMeta(appDir, id) };
}

export async function duplicateTemplate(appDir: string, from: string, lang: Lang): Promise<Template> {
  const src = await loadTemplateById(from, appDir);
  const srcMeta: TemplateMeta =
    from === "default"
      ? { imported: false, mine: [], bundled: src.rules.flatMap((r) => (r.type === "ai_check" ? [aiHash(r)] : [])) }
      : await readMeta(appDir, from);
  const id = await freeId(appDir, `${src.id}-copy`);
  const name = `${src.name} ${{ ko: "(복사본)", en: "(copy)", zh: "（副本）" }[lang]}`.slice(0, 80);
  return save(appDir, { ...src, id, name, based_on: from === "default" ? `default@${VERSION}` : src.id }, srcMeta);
}

export async function setRuleEnabled(appDir: string, id: string, ruleId: string, enabled: boolean): Promise<Template> {
  const { tpl, meta } = await userTemplate(appDir, id);
  if (!tpl.rules.some((r) => r.id === ruleId)) throw new StoreError("not_found", "unknown rule");
  return save(appDir, { ...tpl, rules: tpl.rules.map((r) => (r.id === ruleId ? { ...r, enabled } : r)) }, meta);
}

export async function renameTemplate(appDir: string, id: string, name: string): Promise<Template> {
  const { tpl, meta } = await userTemplate(appDir, id);
  return save(appDir, { ...tpl, name }, meta);
}

export async function deleteTemplate(appDir: string, id: string): Promise<void> {
  await userTemplate(appDir, id);
  await rm(tplFile(appDir, id), { force: true });
  await rm(metaFile(appDir, id), { force: true });
}

/** [가져오기]: file content only (no path). Same id as an existing one → saved under a new id. */
export async function importTemplate(appDir: string, content: string): Promise<{ tpl: Template; renamed: boolean }> {
  const tpl = await loadTemplate(content);
  const id = await freeId(appDir, tpl.id);
  return { tpl: await save(appDir, { ...tpl, id }, { imported: true, mine: [], bundled: [] }), renamed: id !== tpl.id };
}

export async function exportTemplate(appDir: string, id: string): Promise<string> {
  if (id === "default") return readFile(new URL("../templates/default.yaml", import.meta.url), "utf8");
  return stringify(await loadTemplateById(id, appDir));
}

export interface AiCheckInput {
  check: string;
  severity: Severity;
  files: string[];
}

/** Add (no `ruleId`) or rewrite an ai_check the GUI wrote. Imported items can only be turned off or deleted. */
export async function saveAiCheck(appDir: string, id: string, input: AiCheckInput, lang: Lang, ruleId?: string): Promise<Template> {
  const { tpl, meta } = await userTemplate(appDir, id);
  const mine = new Set(meta.mine);
  let rules = tpl.rules;
  let newId = ruleId;
  if (ruleId) {
    const old = tpl.rules.find((r): r is AiCheckRule => r.id === ruleId && r.type === "ai_check");
    if (!old) throw new StoreError("not_found", "unknown ai_check");
    if (!mine.has(aiHash(old))) throw new StoreError("not_mine", "imported items can only be turned off or deleted");
    mine.delete(aiHash(old));
    rules = rules.filter((r) => r.id !== ruleId);
  } else {
    const ids = new Set(tpl.rules.map((r) => r.id));
    let n = 1;
    while (ids.has(`ai-mine-${n}`)) n++;
    newId = `ai-mine-${n}`;
  }
  const rule = { id: newId!, type: "ai_check" as const, enabled: true, severity: input.severity, check: { [lang]: input.check }, files: input.files };
  const at = ruleId ? tpl.rules.findIndex((r) => r.id === ruleId) : rules.length;
  const next = [...rules.slice(0, at), rule, ...rules.slice(at)];
  // Hash what the loader keeps (sanitized text), so the badge survives a reload.
  const checked = await loadTemplate(stringify({ ...tpl, rules: next }));
  const saved = checked.rules.find((r): r is AiCheckRule => r.id === newId && r.type === "ai_check")!;
  mine.add(aiHash(saved));
  return save(appDir, checked, { ...meta, mine: [...mine] });
}

export async function deleteAiCheck(appDir: string, id: string, ruleId: string): Promise<Template> {
  const { tpl, meta } = await userTemplate(appDir, id);
  const old = tpl.rules.find((r): r is AiCheckRule => r.id === ruleId && r.type === "ai_check");
  if (!old) throw new StoreError("not_found", "unknown ai_check");
  const h = aiHash(old);
  return save(appDir, { ...tpl, rules: tpl.rules.filter((r) => r.id !== ruleId) }, { ...meta, mine: meta.mine.filter((x) => x !== h), bundled: meta.bundled.filter((x) => x !== h) });
}
