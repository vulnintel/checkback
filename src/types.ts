export type Severity = "critical" | "high" | "medium";
export type Confidence = "confirmed" | "review" | "info";
export type Lang = "ko" | "en";
export type LocalizedText = { ko?: string; en?: string };

/** Extra facts the GUI/generator turns into localized text. */
export type NoteCode =
  | "legacy_anon_key" // allowlisted Supabase legacy anon JWT — migrate to sb_publishable_
  | "public_values_only" // env-committed: only public values — no key rotation needed
  | "history_only" // file exists only in git history
  | "local_only_env" // gitignored, untracked, never committed .env*
  | "in_build_output" // same value also found in browser build output
  | "example_or_doc" // example/doc file — informational
  | "test_path" // test/fixture path — confidence lowered
  | "env_reference" // only referenced (no value present)
  | "env_driven" // value injected from environment
  | "hidden_sourcemap" // bundler emits hidden source maps
  | "dev_build"; // Next.js dev-server output (.next/static/development present), not a deploy artifact

export interface Location {
  /** CWD-relative path, always "/"-separated. */
  file: string;
  line: number | null;
}

export interface Finding {
  /** Fingerprint (see fingerprint.ts) — stable across line moves. */
  id: string;
  rule_id: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  location: Location | null;
  /** GUI-only display form. Never the raw value; MCP responses must drop it. */
  masked_match?: string;
  secret_kind?: string;
  /** sha-256 of the matched value (file rules: of file content). Used for recheck pairing. */
  value_hash: string;
  source: "local";
  notes?: NoteCode[];
}

export interface CheckedRule {
  rule_id: string;
  ran: boolean;
  reason?:
    | "disabled"
    | "not_git_repo"
    | "not_implemented" // builtin — runs from stage 4
    | "timeout" // per-rule budget exceeded — partial results
    | "timeout_partial"; // some files timed out
}

export interface ScanStats {
  files: number;
  skipped: { too_large: number; binary: number; utf16: number; long_line: number; unreadable: number; parse_error: number };
  allowed_public_keys: number;
  ignored: number;
  timed_out: { rule_id: string; file: string }[];
}

export interface ScanResult {
  engine_version: string;
  template_id: string;
  findings: Finding[];
  checked: CheckedRule[];
  stats: ScanStats;
}

// ---------- template ----------

interface RuleBase {
  id: string;
  enabled: boolean;
}

interface EngineRuleBase extends RuleBase {
  severity: Severity;
  name?: LocalizedText;
  description?: LocalizedText;
  fix_prompt?: LocalizedText;
  files: string[];
  exclude: string[];
  when?: string;
}

export interface PatternRule extends EngineRuleBase {
  type: "pattern";
  match: string[];
  review: string[];
  allow: string[];
  build_output: boolean;
  jwt_claims?: Record<string, string | number | boolean>;
  mode: "forbid" | "require";
}

export interface FileRule extends EngineRuleBase {
  type: "file";
  expect: "absent" | "present";
  git: "tracked" | "any";
  content_check: boolean;
}

export interface ConfigRule extends EngineRuleBase {
  type: "config";
  format: "dotenv" | "json" | "yaml" | "toml" | "properties";
  key: string;
  equals: string | number | boolean;
  review: string[];
}

export interface BuiltinRule extends RuleBase {
  type: "builtin";
  severity?: Severity;
  params?: Record<string, unknown>;
}

export interface AiCheckRule extends RuleBase {
  type: "ai_check";
  severity: Severity;
  name?: LocalizedText;
  check: LocalizedText;
  files: string[];
}

export type Rule = PatternRule | FileRule | ConfigRule | BuiltinRule | AiCheckRule;

export interface Template {
  schema: 1;
  id: string;
  name: string;
  based_on?: string;
  rules: Rule[];
}
