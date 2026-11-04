// builtin supabase-rls and firebase-rules (§7-1). Regex-level SQL / rules reading — not parsers.

import { lineAt, type FileEntry } from "../files.js";
import type { Confidence, Finding, NoteCode, Severity } from "../types.js";

export interface BF {
  rule: string;
  kind: string;
  severity: Severity;
  confidence: Confidence;
  file: string | null;
  line: number | null;
  /** Identity of the judgment for the fingerprint (not shown anywhere). */
  value: string;
  notes?: NoteCode[];
  extra?: Partial<Finding>;
}

export interface BuiltinCtx {
  files: FileEntry[];
  text(rel: string): Promise<string | null>;
  findings: Finding[];
  now: number;
  /** package.json dependency names across the project. */
  npmDeps: Set<string>;
}

/** Replace comments and $$-bodies with spaces, keeping newlines so line numbers stay right. */
export function stripSql(t: string, keepBodies = false): string {
  const blank = (m: string): string => m.replace(/[^\n]/g, " ");
  let s = t.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/--[^\n]*/g, blank);
  if (!keepBodies) s = s.replace(/\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g, blank);
  return s;
}

const IDENT = String.raw`(?:"?(\w+)"?\.)?"?(\w+)"?`;

export async function supabaseRls(ctx: BuiltinCtx): Promise<BF[]> {
  const uses = ctx.npmDeps.has("@supabase/supabase-js") || ctx.npmDeps.has("supabase") || ctx.files.some((f) => /^supabase\//.test(f.rel));
  if (!uses) return [];
  const out: BF[] = [];
  const R = "supabase-rls";

  // service_role key used from client code
  const secretHit = ctx.findings.some((f) => f.rule_id === "secret-supabase-service-role" && f.confidence !== "info");
  for (const f of ctx.files) {
    if (f.build || !/\.(jsx?|tsx?|mjs|cjs)$/.test(f.rel)) continue;
    if (/(^|\/)api\/|route\.[jt]s$|server/i.test(f.rel)) continue;
    const t = await ctx.text(f.rel);
    if (!t) continue;
    const client = /^\s*["']use client["']/m.test(t) || /^src\//.test(f.rel) || /(^|\/)(pages|app)\//.test(f.rel);
    if (!client) continue;
    for (const m of t.matchAll(/(?:process\.env|import\.meta\.env)\.([A-Z0-9_]*(?:SERVICE_ROLE|SECRET_KEY)[A-Z0-9_]*)/g)) {
      out.push({
        rule: R, kind: "service_role_client", file: f.rel, line: lineAt(t, m.index), value: m[1]!,
        ...(secretHit ? { severity: "critical", confidence: "confirmed" } : { severity: "high", confidence: "review" }),
      });
    }
  }

  // migrations: final state after applying every file in name order
  const migs = ctx.files.filter((f) => /(^|\/)supabase\/migrations\/[^/]+\.sql$/i.test(f.rel)).sort((a, b) => (a.rel < b.rel ? -1 : 1));
  const tables = new Map<string, { file: string; line: number; rls: boolean }>();
  const policies = new Map<string, { file: string; line: number; cmd: string; alwaysTrue: boolean; table: string; name: string }>();
  const dynamic: string[] = [];
  for (const f of migs) {
    const raw = await ctx.text(f.rel);
    if (!raw) continue;
    if (/\bexecute\s+(format\s*\(|')/i.test(stripSql(raw, true))) dynamic.push(f.rel);
    const s = stripSql(raw);
    const ev: { at: number; fn: () => void }[] = [];
    const isPublic = (schema: string | undefined): boolean => !schema || schema.toLowerCase() === "public";
    for (const m of s.matchAll(new RegExp(String.raw`\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?${IDENT}`, "gi"))) {
      if (!isPublic(m[1])) continue;
      const name = m[2]!.toLowerCase();
      ev.push({ at: m.index, fn: () => tables.set(name, { file: f.rel, line: lineAt(raw, m.index), rls: false }) });
    }
    for (const m of s.matchAll(new RegExp(String.raw`\balter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?${IDENT}\s+(enable|disable)\s+row\s+level\s+security`, "gi"))) {
      const name = m[2]!.toLowerCase();
      const on = m[3]!.toLowerCase() === "enable";
      ev.push({ at: m.index, fn: () => { const t = tables.get(name); if (t) t.rls = on; } });
    }
    for (const m of s.matchAll(new RegExp(String.raw`\bdrop\s+table\s+(?:if\s+exists\s+)?${IDENT}`, "gi"))) {
      const name = m[2]!.toLowerCase();
      ev.push({ at: m.index, fn: () => tables.delete(name) });
    }
    for (const m of s.matchAll(new RegExp(String.raw`\bcreate\s+policy\s+("[^"]+"|\w+)\s+on\s+${IDENT}([^;]*)`, "gi"))) {
      const name = m[1]!.replace(/"/g, "");
      const table = m[3]!.toLowerCase();
      const body = m[4]!;
      const cmd = (/\bfor\s+(all|select|insert|update|delete)\b/i.exec(body)?.[1] ?? "all").toLowerCase();
      const alwaysTrue = /\b(using|with\s+check)\s*\(\s*true\s*\)/i.test(body);
      ev.push({ at: m.index, fn: () => policies.set(`${table}\0${name}`, { file: f.rel, line: lineAt(raw, m.index), cmd, alwaysTrue, table, name }) });
    }
    for (const m of s.matchAll(new RegExp(String.raw`\bdrop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|\w+)\s+on\s+${IDENT}`, "gi"))) {
      const key = `${m[3]!.toLowerCase()}\0${m[1]!.replace(/"/g, "")}`;
      ev.push({ at: m.index, fn: () => policies.delete(key) });
    }
    for (const e of ev.sort((a, b) => a.at - b.at)) e.fn();
  }
  for (const [name, t] of tables) {
    if (!t.rls) out.push({ rule: R, kind: "rls_disabled", severity: "high", confidence: "confirmed", file: t.file, line: t.line, value: `table:${name}` });
  }
  for (const p of policies.values()) {
    if (!p.alwaysTrue) continue;
    const write = p.cmd !== "select";
    out.push({
      rule: R, kind: write ? "always_true_write" : "public_read", severity: write ? "high" : "medium",
      confidence: write ? "review" : "info", file: p.file, line: p.line, value: `policy:${p.table}:${p.name}`,
    });
  }

  // SQL/ORM migrations outside supabase/migrations
  const elsewhere: string[] = [];
  for (const f of ctx.files) {
    if (f.build) continue;
    if (/(^|\/)drizzle\.config\.[cm]?[jt]s$/.test(f.rel)) elsewhere.push(f.rel);
    else if (/\.sql$/i.test(f.rel) && !/(^|\/)supabase\/migrations\//i.test(f.rel)) {
      const t = await ctx.text(f.rel);
      if (t && /\bcreate\s+(table|policy)\b|row\s+level\s+security/i.test(stripSql(t))) elsewhere.push(f.rel);
    }
  }
  if (elsewhere.length) {
    out.push({ rule: R, kind: "migrations_elsewhere", severity: "medium", confidence: "info", file: null, line: null, value: "elsewhere", extra: { related: elsewhere } });
  }
  for (const d of dynamic) out.push({ rule: R, kind: "dynamic_sql", severity: "medium", confidence: "info", file: d, line: null, value: `dynamic:${d}` });
  out.push({ rule: R, kind: "advisor", severity: "medium", confidence: "info", file: null, line: null, value: "advisor" });
  return out;
}

export async function firebaseRules(ctx: BuiltinCtx): Promise<BF[]> {
  const R = "firebase-rules";
  const out: BF[] = [];
  const rulesFiles = ctx.files.filter((f) => !f.build && /(^|\/)(firestore\.rules|storage\.rules|database\.rules\.json)$/.test(f.rel));
  for (const f of rulesFiles) {
    const raw = await ctx.text(f.rel);
    if (!raw) continue;
    const t = raw.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " ")).replace(/\/\/[^\n]*/g, (m) => " ".repeat(m.length));
    const add = (kind: string, severity: Severity, confidence: Confidence, index: number, notes?: NoteCode[]): void => {
      const line = lineAt(t, index);
      out.push({ rule: R, kind, severity, confidence, file: f.rel, line, value: `${kind}:${line}`, ...(notes && { notes }) });
    };
    if (f.rel.endsWith(".json")) {
      let root: unknown;
      try {
        root = (JSON.parse(t) as { rules?: unknown }).rules;
      } catch {
        root = undefined;
      }
      for (const k of [".read", ".write"]) {
        const v = (root as Record<string, unknown> | undefined)?.[k];
        if (v === true || v === "true") add("rtdb_open", "critical", "confirmed", Math.max(0, t.indexOf(`"${k}"`)));
      }
      continue;
    }
    for (const m of t.matchAll(/\ballow\s+[\w\s,]+?\s*(;|:\s*if\s+true\s*;)/g)) add("open_rules", "critical", "confirmed", m.index);
    for (const m of t.matchAll(/request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/g)) {
      const expiry = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
      if (expiry > ctx.now) add("test_mode", "high", "confirmed", m.index);
      else add("test_mode_expired", "high", "info", m.index, ["expired"]);
    }
    for (const m of t.matchAll(/\ballow\s+[\w\s,]+:\s*if\s+request\.auth\s*!=\s*null\s*;/g)) add("auth_only", "medium", "review", m.index);
  }
  if (rulesFiles.length === 0 && ctx.files.some((f) => /(^|\/)firebase\.json$/.test(f.rel))) {
    out.push({ rule: R, kind: "rules_missing", severity: "medium", confidence: "info", file: null, line: null, value: "rules_missing" });
  }
  return out;
}
