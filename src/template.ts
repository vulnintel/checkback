import { readFile } from "node:fs/promises";
import { LineCounter, parseDocument, visit } from "yaml";
import { GlobError, normalizeGlob } from "./glob.js";
import { findSlowPattern } from "./regex-runner.js";
import { LANGS, type Lang, type LocalizedText, type Rule, type Severity, type Template } from "./types.js";

export const MAX_TEMPLATE_BYTES = 1024 * 1024;
export const MAX_AI_CHECKS = 30;
export const BUILTIN_IDS = ["supabase-rls", "firebase-rules", "hallucinated-package", "vulnerable-deps"] as const;
/** §6-3: the only `{…}` placeholders a fix_prompt may contain. */
export const FIX_PROMPT_VARS = new Set([
  "file", "line", "rule_name", "package", "version", "fixed_version", "vuln_ids", "lockfile", "table", "secret_kind",
]);

const ID_RE = /^[a-z0-9-]{1,64}$/;
const AI_GLOB_RE = /^[\p{L}\p{N}._\-/*?{},[\]!]+$/u;
const SEVERITIES = ["critical", "high", "medium"];
const BUILTIN_PARAMS: Record<string, Record<string, "string[]" | "number">> = {
  "supabase-rls": {},
  "firebase-rules": {},
  "hallucinated-package": { allow: "string[]", min_weekly_downloads: "number" },
  "vulnerable-deps": {},
};
const ENGINE_COMMON = ["id", "type", "enabled", "severity", "name", "description", "fix_prompt", "files", "exclude", "when"];
const ALLOWED_KEYS: Record<string, string[]> = {
  pattern: [...ENGINE_COMMON, "match", "review", "allow", "build_output", "jwt_claims", "mode"],
  file: [...ENGINE_COMMON, "expect", "git", "content_check"],
  config: [...ENGINE_COMMON, "format", "key", "equals", "review"],
  builtin: ["id", "type", "enabled", "severity", "params"],
  ai_check: ["id", "type", "enabled", "severity", "files", "name", "check"],
};

export interface TemplateIssue {
  path: string;
  line?: number;
  message: string;
}

export class TemplateError extends Error {
  constructor(readonly issues: TemplateIssue[]) {
    super(issues.map((i) => `${i.line ? `line ${i.line}: ` : ""}${i.path}: ${i.message}`).join("\n"));
  }
}

type Path = (string | number)[];
type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

/** Remove control chars/newlines, code fences and angle brackets (§6-1 ai_check sanitizing). */
export function sanitizeAiText(s: string): string {
  return s.replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, " ").replace(/```/g, "").replace(/[<>]/g, "").replace(/\s+/g, " ").trim();
}

/**
 * Parse and validate a template (§6-1, §6-2 import order). Throws TemplateError listing every
 * problem with its line when known.
 */
export async function loadTemplate(source: string | Uint8Array): Promise<Template> {
  const bytes = typeof source === "string" ? Buffer.byteLength(source, "utf8") : source.byteLength;
  if (bytes > MAX_TEMPLATE_BYTES) throw new TemplateError([{ path: "", message: "template larger than 1MB" }]);
  let text = typeof source === "string" ? source : Buffer.from(source).toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);

  const lc = new LineCounter();
  const doc = parseDocument(text, { schema: "core", lineCounter: lc, uniqueKeys: true, merge: false, prettyErrors: false });
  const issues: TemplateIssue[] = [];
  const lineOf = (offset: number | undefined): number | undefined => (offset === undefined ? undefined : lc.linePos(offset).line);
  for (const e of [...doc.errors, ...doc.warnings]) issues.push({ path: "", line: lineOf(e.pos[0]), message: e.message.split("\n")[0]! });
  visit(doc, {
    Node(_, node) {
      if (node.tag) issues.push({ path: "", line: lineOf(node.range?.[0]), message: `YAML tags are not allowed (${node.tag})` });
    },
  });
  if (issues.length) throw new TemplateError(issues);
  let data: unknown;
  try {
    data = doc.toJS({ maxAliasCount: 50 });
  } catch (e) {
    throw new TemplateError([{ path: "", message: (e as Error).message }]);
  }

  const err = (path: Path, message: string): void => {
    const node = path.length ? (doc.getIn(path, true) as { range?: [number] } | undefined) : undefined;
    issues.push({ path: path.join("."), line: lineOf(node?.range?.[0]), message });
  };
  const tpl = validateTemplate(data, err);
  if (issues.length) throw new TemplateError(issues);

  // Regex compile errors were reported above; now the time-limit test (§10-2).
  const patterns = tpl.rules.flatMap((r) =>
    r.type === "pattern" ? [...r.match, ...r.review, ...r.allow] : r.type === "config" ? r.review : [],
  );
  const slow = await findSlowPattern([...new Set(patterns)]);
  if (slow !== null) {
    const idx = tpl.rules.findIndex((r) => "match" in r && [...r.match, ...r.review, ...r.allow].includes(slow) || (r.type === "config" && r.review.includes(slow)));
    err(["rules", idx], `regex exceeds the time limit on test input: ${slow.slice(0, 80)}`);
    throw new TemplateError(issues);
  }
  return tpl;
}

let defaultTemplate: Promise<Template> | undefined;

/** The bundled read-only `default` template. */
export function loadDefaultTemplate(): Promise<Template> {
  defaultTemplate ??= readFile(new URL("../templates/default.yaml", import.meta.url)).then(loadTemplate);
  return defaultTemplate;
}

function validateTemplate(data: unknown, err: (p: Path, m: string) => void): Template {
  const empty: Template = { schema: 1, id: "", name: "", rules: [] };
  if (!isObj(data)) {
    err([], "template must be a mapping");
    return empty;
  }
  extraKeys(data, ["schema", "id", "name", "based_on", "rules"], [], err);
  if (data.schema !== 1) err(["schema"], "schema must be 1");
  const id = checkId(data.id, ["id"], err);
  const name = str(data.name, ["name"], err, { max: 80, required: true }) ?? "";
  const basedOn = str(data.based_on, ["based_on"], err, { max: 100 });
  if (!Array.isArray(data.rules)) {
    err(["rules"], "rules must be a list");
    return empty;
  }
  if (data.rules.length > 500) err(["rules"], "too many rules (max 500)");
  const rules: Rule[] = [];
  const seen = new Set<string>();
  data.rules.forEach((raw, i) => {
    const r = validateRule(raw, ["rules", i], err);
    if (!r) return;
    if (seen.has(r.id)) err(["rules", i, "id"], `duplicate rule id ${r.id}`);
    seen.add(r.id);
    rules.push(r);
  });
  if (rules.filter((r) => r.type === "ai_check").length > MAX_AI_CHECKS) err(["rules"], `more than ${MAX_AI_CHECKS} ai_check rules`);
  return { schema: 1, id, name, ...(basedOn !== undefined && { based_on: basedOn }), rules };
}

function validateRule(raw: unknown, p: Path, err: (p: Path, m: string) => void): Rule | undefined {
  if (!isObj(raw)) {
    err(p, "rule must be a mapping");
    return undefined;
  }
  const type = raw.type;
  if (typeof type !== "string" || !(type in ALLOWED_KEYS)) {
    err([...p, "type"], "type must be one of pattern, file, config, builtin, ai_check");
    return undefined;
  }
  extraKeys(raw, ALLOWED_KEYS[type]!, p, err);
  const id = checkId(raw.id, [...p, "id"], err);
  const enabled = bool(raw.enabled, [...p, "enabled"], err) ?? true;
  const sev = (key: string, required: boolean): Severity | undefined => {
    const v = raw[key];
    if (v === undefined && !required) return undefined;
    if (typeof v !== "string" || !SEVERITIES.includes(v)) err([...p, key], "severity must be critical, high or medium");
    return v as Severity;
  };

  if (type === "builtin") {
    if (!(BUILTIN_IDS as readonly string[]).includes(id)) err([...p, "id"], `unknown builtin id ${id}`);
    const severity = sev("severity", false);
    let params: Obj | undefined;
    if (raw.params !== undefined && raw.params !== null) {
      if (!isObj(raw.params)) err([...p, "params"], "params must be a mapping");
      else {
        params = raw.params;
        const spec = BUILTIN_PARAMS[id] ?? {};
        for (const [k, v] of Object.entries(params)) {
          const want = spec[k];
          if (!want) err([...p, "params", k], `unknown param ${k}`);
          else if (want === "number" ? typeof v !== "number" || v < 0 : !strList(v)) err([...p, "params", k], `${k} must be ${want}`);
        }
      }
    }
    return { type, id, enabled, ...(severity && { severity }), ...(params && { params }) };
  }

  if (type === "ai_check") {
    const check = localized(raw.check, [...p, "check"], err, { max: 300, required: true, ai: true });
    const name = localized(raw.name, [...p, "name"], err, { max: 80, ai: true });
    const files = globs(raw.files, [...p, "files"], err, { ai: true }) ?? [];
    return { type, id, enabled, severity: sev("severity", false) ?? "medium", ...(name && { name }), check: check ?? {}, files };
  }

  const base = {
    id,
    enabled,
    severity: sev("severity", true)!,
    ...optional("name", localized(raw.name, [...p, "name"], err, { max: 80 })),
    ...optional("description", localized(raw.description, [...p, "description"], err, { max: 2000 })),
    ...optional("fix_prompt", fixPrompt(raw.fix_prompt, [...p, "fix_prompt"], err)),
    files: globs(raw.files, [...p, "files"], err, { required: true }) ?? [],
    exclude: globs(raw.exclude, [...p, "exclude"], err) ?? [],
    ...optional("when", raw.when === undefined || raw.when === null ? undefined : globs([raw.when], [...p, "when"], err)?.[0]),
  };

  if (type === "pattern") {
    const match = regexes(raw.match, [...p, "match"], err, true);
    const mode = raw.mode ?? "forbid";
    if (mode !== "forbid" && mode !== "require") err([...p, "mode"], "mode must be forbid or require");
    let jwt: Record<string, string | number | boolean> | undefined;
    if (raw.jwt_claims !== undefined && raw.jwt_claims !== null) {
      if (!isObj(raw.jwt_claims) || !Object.values(raw.jwt_claims).every((v) => ["string", "number", "boolean"].includes(typeof v))) {
        err([...p, "jwt_claims"], "jwt_claims must map claim names to scalar values");
      } else jwt = raw.jwt_claims as Record<string, string | number | boolean>;
    }
    return {
      type, ...base, match,
      review: regexes(raw.review, [...p, "review"], err, false),
      allow: regexes(raw.allow, [...p, "allow"], err, false),
      build_output: bool(raw.build_output, [...p, "build_output"], err) ?? false,
      mode: mode as "forbid" | "require",
      ...(jwt && { jwt_claims: jwt }),
    };
  }
  if (type === "file") {
    if (raw.expect !== "absent" && raw.expect !== "present") err([...p, "expect"], "expect must be absent or present");
    const git = raw.git ?? "any";
    if (git !== "tracked" && git !== "any") err([...p, "git"], "git must be tracked or any");
    return {
      type, ...base,
      expect: raw.expect as "absent" | "present",
      git: git as "tracked" | "any",
      content_check: bool(raw.content_check, [...p, "content_check"], err) ?? false,
    };
  }
  if (type !== "config") return undefined;
  if (!["dotenv", "json", "yaml", "toml", "properties"].includes(raw.format as string)) {
    err([...p, "format"], "format must be dotenv, json, yaml, toml or properties");
  }
  const key = str(raw.key, [...p, "key"], err, { max: 200, required: true }) ?? "";
  if (!["string", "number", "boolean"].includes(typeof raw.equals)) err([...p, "equals"], "equals must be a scalar");
  return {
    type, ...base,
    format: raw.format as "dotenv",
    key,
    equals: raw.equals as string,
    review: regexes(raw.review, [...p, "review"], err, false),
  };
}

const optional = <K extends string, V>(k: K, v: V | undefined): { [P in K]?: V } => (v === undefined ? {} : ({ [k]: v } as { [P in K]: V }));
const strList = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string");

function extraKeys(o: Obj, allowed: string[], p: Path, err: (p: Path, m: string) => void): void {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) err([...p, k], `unknown field ${k}`);
}

function checkId(v: unknown, p: Path, err: (p: Path, m: string) => void): string {
  if (typeof v !== "string" || !ID_RE.test(v)) err(p, "id must match ^[a-z0-9-]{1,64}$");
  return typeof v === "string" ? v : "";
}

function bool(v: unknown, p: Path, err: (p: Path, m: string) => void): boolean | undefined {
  if (v === undefined) return undefined;
  if (typeof v !== "boolean") err(p, "must be true or false");
  return v === true;
}

function str(v: unknown, p: Path, err: (p: Path, m: string) => void, o: { max: number; required?: boolean }): string | undefined {
  if (v === undefined || v === null) {
    if (o.required) err(p, "required");
    return undefined;
  }
  if (typeof v !== "string" || v.length === 0 || v.length > o.max) err(p, `must be a string of 1-${o.max} characters`);
  return typeof v === "string" ? v : undefined;
}

function localized(
  v: unknown,
  p: Path,
  err: (p: Path, m: string) => void,
  o: { max: number; required?: boolean; ai?: boolean },
): LocalizedText | undefined {
  if (v === undefined || v === null) {
    if (o.required) err(p, "required");
    return undefined;
  }
  if (!isObj(v) || Object.keys(v).length === 0) {
    err(p, "must be a mapping with ko, en and/or zh");
    return undefined;
  }
  const out: LocalizedText = {};
  for (const [lang, raw] of Object.entries(v)) {
    if (!LANGS.includes(lang as Lang)) {
      err([...p, lang], `unknown language ${lang}`);
      continue;
    }
    if (typeof raw !== "string") {
      err([...p, lang], "must be a string");
      continue;
    }
    const s = o.ai ? sanitizeAiText(raw) : raw;
    const len = [...s].length;
    if (len === 0 || len > o.max) err([...p, lang], `must be 1-${o.max} characters${o.ai ? " after sanitizing" : ""}`);
    out[lang as Lang] = s;
  }
  return out;
}

function fixPrompt(v: unknown, p: Path, err: (p: Path, m: string) => void): LocalizedText | undefined {
  const t = localized(v, p, err, { max: 4000 });
  for (const [lang, s] of Object.entries(t ?? {})) {
    for (const m of s.matchAll(/\{([^{}]*)\}/g)) {
      if (!FIX_PROMPT_VARS.has(m[1]!)) err([...p, lang], `placeholder {${m[1]}} is not allowed`);
    }
  }
  return t;
}

function globs(
  v: unknown,
  p: Path,
  err: (p: Path, m: string) => void,
  o: { required?: boolean; ai?: boolean } = {},
): string[] | undefined {
  if (v === undefined || v === null) {
    if (o.required) err(p, "required");
    return undefined;
  }
  if (!strList(v) || (o.required && v.length === 0)) {
    err(p, "must be a list of glob strings");
    return undefined;
  }
  if (o.ai && v.length > 10) err(p, "at most 10 entries");
  return v.map((g, i) => {
    if (o.ai && !AI_GLOB_RE.test(g)) err([...p, i], "only letters, digits and . _ - / * ? { } , [ ] ! are allowed");
    try {
      return normalizeGlob(g);
    } catch (e) {
      if (e instanceof GlobError) err([...p, i], e.message);
      return g;
    }
  });
}

function regexes(v: unknown, p: Path, err: (p: Path, m: string) => void, required: boolean): string[] {
  if (v === undefined || v === null) {
    if (required) err(p, "required");
    return [];
  }
  if (!strList(v) || (required && v.length === 0)) {
    err(p, "must be a list of regular expressions");
    return [];
  }
  v.forEach((src, i) => {
    if (src.length === 0 || src.length > 1000) err([...p, i], "regex must be 1-1000 characters");
    try {
      new RegExp(src, "gm");
    } catch (e) {
      err([...p, i], `invalid regex: ${(e as Error).message}`);
    }
  });
  return v;
}
