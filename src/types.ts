export type Severity = "critical" | "high" | "medium";
export type Confidence = "confirmed" | "review" | "info";
export type Lang = "ko" | "en" | "zh";
export const LANGS: readonly Lang[] = ["ko", "en", "zh"];
/** Text from users or imported templates: any language may be missing (zh falls back to en, then ko). */
export type LocalizedText = { ko?: string; en?: string; zh?: string };
/** Builtin text shipped with the engine: every language is required. */
export type FullText = Record<Lang, string>;

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
  | "dev_build" // Next.js dev-server output (.next/static/development present), not a deploy artifact
  | "dev_dependency" // development dependency
  | "major_upgrade" // fixed version is a new major — check compatibility
  | "fix_unverified" // fixed version not yet checked against OSV (offline / time budget) — confirm before upgrading
  | "severity_unknown" // no KEV/VPI/OSV severity/CVSS
  | "priority_pending" // VulnIntel priority lookup not done yet (budget) — next scan continues from cache
  | "priority_failed" // VulnIntel lookup failed — sorted by OSV severity
  | "expired"; // firebase test mode already expired

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
  source: "local" | "osv" | "registry" | "vulnintel";
  notes?: NoteCode[];
  /** Builtin sub-judgment (e.g. "rls_disabled"); texts in builtins/text.ts. */
  kind?: string;
  /** Extra CWD-relative paths the finding points to (e.g. SQL to verify, all lockfiles). */
  related?: string[];
  ecosystem?: "npm" | "PyPI";
  package?: string;
  version?: string | null;
  fixed_version?: string;
  vuln_ids?: string[];
  kev?: boolean;
  vpi_level?: number;
  epss?: number;
  cvss?: number;
  lockfile?: string;
  /**
   * Dependency items from a lock: declared directly (the manifest at or under the lock's folder and its
   * section) or reached through another package, and whether the lock also holds another major line of
   * it. The fix prompt picks the package-manager command from it.
   */
  dependency?: { direct: boolean; manifest?: string; section?: string; other_majors?: boolean };
  /** supabase-rls: the table the item is about ("public.orders") and, for policy items, the policy name (repository text). */
  table?: string;
  policy?: string;
  /**
   * vulnerable-deps: VulnIntel public lookup's description of the package's most severe vulnerability
   * (external text in the scan's language; for people only — never in a fix prompt or MCP).
   */
  vuln_description?: { id: string; text: string };
  /** Recheck status vs the baseline (§7-8). */
  recheck?: RecheckStatus;
  recheck_note?: string;
  /** Recheck Q3: the baseline version of a package re-locked at a version that is still vulnerable. */
  previous_version?: string;
  /** A baseline finding carried into this result (not found now, but not resolved: lock mismatch / not checked). */
  carried?: boolean;
  /** Recheck: the baseline finding this one was paired with when the id changed (moved / same key / version bump). */
  baseline_id?: string;
}

export type RecheckStatus = "resolved" | "remaining" | "new" | "same_key" | "moved" | "downgraded" | "lock_mismatch" | "not_checked";

export interface CheckedRule {
  rule_id: string;
  ran: boolean;
  reason?:
    | "disabled"
    | "not_git_repo"
    | "not_implemented" // builtin — runs from stage 4
    | "timeout" // per-rule budget exceeded — partial results
    | "timeout_partial" // some files timed out
    | "no_consent" // external lookups need first-run consent
    | "external_disabled" // the needed external lookup is turned off
    | "offline" // external lookup failed (offline / service error)
    | "shallow_clone"; // ran, but git history is cut off (shallow clone) — history-only files may be missed
}

export interface ScanStats {
  files: number;
  skipped: { too_large: number; binary: number; utf16: number; long_line: number; unreadable: number; parse_error: number };
  allowed_public_keys: number;
  ignored: number;
  timed_out: { rule_id: string; file: string }[];
  /** Subfolders holding their own git repository (`.git` directory) — separate projects, not scanned. */
  nested_repos: string[];
}

export interface ScanResult {
  engine_version: string;
  template_id: string;
  scan_at: string;
  findings: Finding[];
  checked: CheckedRule[];
  stats: ScanStats;
  /** Present when a baseline exists: fix-request snapshot, else the previous scan (§7-8). */
  compare?: import("./recheck.js").Compare;
  /** Key mode only: how the VulnIntel scan went (ok / cached / pending / fallback to OSV + reason). */
  vulnintel?: import("./builtins/vi-scan.js").ViScanStatus;
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
