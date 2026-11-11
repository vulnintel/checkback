// Judgments of the default-template rules that a regex alone cannot express (§6-5 tables).
// Keyed by rule id, so a cloned/exported/re-imported default template behaves the same (AC42).
// Inputs may come from any imported regex — never assume capture groups.

import { isEnvFile, isExampleOrDoc, type FileEntry } from "./files.js";
import { allowlisted, isPlaceholder } from "./secrets.js";
import type { Confidence, NoteCode, Severity } from "./types.js";

export interface RefineInput {
  file: FileEntry;
  text: string;
  value: string;
  index: number;
  lineText: string;
  severity: Severity;
  confidence: Confidence;
  files: FileEntry[];
}

export interface Refined {
  severity: Severity;
  confidence: Confidence;
  notes?: NoteCode[];
  /** Secret part of the match, if narrower than the whole match (used for hashing/masking). */
  value?: string;
  /** The matched value is a placeholder, not a key: no "revoke and reissue first" step. */
  notSecret?: boolean;
}

type Refiner = (i: RefineInput) => Refined | null;

/** Rules decided after value rules and the allowlist (§6-4 step 3); skipped on lines those already decided. */
export const LATE_RULES = new Set(["secret-public-env-prefix", "secret-in-mcp-config"]);

const LOCAL_HOSTS = /^(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]|host\.docker\.internal|db|database|postgres|postgresql|mysql|mariadb|mongo|mongodb|redis)$/i;
const DEFAULT_PASSWORDS = /^(postgres|password|root|admin|secret|pass|example|test|mysql|mongo|1234|123456|changeme)$/i;
const ENV_DRIVEN = /environ|getenv|config\(|env\(|process\.env|import\.meta\.env|\$\{/;

const around = (i: RefineInput, n: number): string => i.text.slice(Math.max(0, i.index - n), i.index + i.value.length + n);

export const REFINERS: Record<string, Refiner> = {
  "secret-google-key": (i) => ({
    severity: /GEMINI|generativelanguage/i.test(around(i, 600)) ? "high" : "medium",
    confidence: i.confidence === "confirmed" ? "review" : i.confidence,
  }),

  "secret-db-url": (i) => {
    const m = /^[a-z+]+:\/\/([^:/\s"'@]+):([^@\s"']+)@([^/:\s"'?,]+)/i.exec(i.value);
    if (!m) return { severity: i.severity, confidence: i.confidence };
    const [, , password, host] = m;
    if (/^[$%{]/.test(password!) || isPlaceholder(password!)) return null;
    return LOCAL_HOSTS.test(host!) || DEFAULT_PASSWORDS.test(password!)
      ? { severity: "medium", confidence: "review" }
      : { severity: i.severity, confidence: i.confidence };
  },

  "secret-public-env-prefix": (i) => {
    const name = i.value;
    if (!/^[A-Z0-9_]+$/.test(name)) return null;
    const rest = name.replace(/^(NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_)/, "");
    if (!/SECRET|SERVICE_ROLE|PRIVATE/.test(rest) || /ANON|PUBLISHABLE|PUBLIC|FIREBASE_API_KEY/.test(rest)) return null;
    if (/\.mdx?$/i.test(i.file.rel)) return null; // Markdown names it in prose or examples; it is never bundled
    const base = i.file.rel.slice(i.file.rel.lastIndexOf("/") + 1);
    const assign = new RegExp(`^\\s*(?:export\\s+)?${name}\\s*=\\s*(.*)$`).exec(i.lineText);
    if (base.startsWith(".env") && assign) {
      const value = dotenvValue(assign[1]!);
      // `x` / `xxx` / `your-…` / `<…>` / `changeme`: the name is the problem, there is no key to revoke.
      const notSecret = isPlaceholder(value) || /^x+$/i.test(value);
      // A value in a real .env file is bundled into the browser build — no local-only exception.
      if (isEnvFile(i.file.rel) && !isPlaceholder(value)) return { severity: "high", confidence: "confirmed", ...(notSecret && { notSecret }) };
      return { severity: "high", confidence: "review", notes: ["env_reference"], ...(notSecret && { notSecret }) };
    }
    if (isExampleOrDoc(i.file.rel)) return null;
    const ref = new RegExp(`(?:import\\.meta\\.env|process\\.env)(?:\\.${name}\\b|\\[\\s*['"]${name}['"]\\s*\\])`);
    return ref.test(i.lineText) ? { severity: "high", confidence: "review", notes: ["env_reference"] } : null;
  },

  "secret-in-mcp-config": (i) => {
    const m = /"([^"]*)"\s*$/.exec(i.value) ?? /[\s=]([^\s"'=]+)$/.exec(i.value);
    const value = m?.[1] ?? i.value;
    if (value.length < 8 || isPlaceholder(value)) return null;
    return { severity: i.severity, confidence: i.confidence, value };
  },

  "cors-wildcard": (i) =>
    /(^|\/)supabase\/functions\//.test(i.file.rel)
      ? { severity: i.severity, confidence: "info" }
      : { severity: i.severity, confidence: i.confidence },

  // Credentials anywhere in the file. `allow_origins=<variable>` (a settings list, possibly guarded
  // against "*") is not "any origin": dropped even when an older cloned template still matches it.
  "cors-credentials-any": (i) =>
    !/^allow_origins\s*=\s*[A-Za-z_]/.test(i.value) &&
    /credentials\s*:\s*true|allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|Allow-Credentials['"]?\]?\s*[:,=]\s*['"]?true/i.test(i.text)
      ? { severity: i.severity, confidence: i.confidence }
      : null,

  "debug-django": (i) => {
    const v = i.value.replace(/^DEBUG\s*=\s*/, "");
    if (ENV_DRIVEN.test(v)) return { severity: i.severity, confidence: "review", notes: ["env_driven"] };
    if (!/^True\b/.test(v)) return null;
    const split = i.files.some((f) => /(^|\/)settings\/[^/]+\.py$|(^|\/)settings[_.][^/]+\.py$/.test(f.rel) && !/__init__\.py$/.test(f.rel));
    if (!split) return { severity: i.severity, confidence: "review" };
    const b = i.file.rel.slice(i.file.rel.lastIndexOf("/") + 1);
    return /^(settings[_.])?(dev|local|base|test)/.test(b) ? { severity: i.severity, confidence: "info" } : { severity: i.severity, confidence: i.confidence };
  },

  "sourcemap-vite": (i) => {
    const v = i.value.replace(/^sourcemap\s*:\s*/, "").trim();
    if (/^(true|['"]inline['"])/.test(v)) {
      // Library builds (`build.lib`) publish to a registry, not a website; package/SDK folders often are libraries.
      if (/\blib\s*:\s*\{/.test(i.text)) return { severity: i.severity, confidence: "info" };
      if (/(^|\/)(packages|sdks?|libs?|cli)\//.test(i.file.rel)) return { severity: i.severity, confidence: "review" };
      return { severity: i.severity, confidence: "confirmed" };
    }
    if (/^(false|['"]hidden['"])/.test(v)) return null;
    return { severity: i.severity, confidence: "review", notes: ["env_driven"] };
  },
};

/** `sourcemap-in-build`: maps are expected when the bundler is set to emit hidden source maps → info. */
export function hiddenSourcemapConfig(rel: string, text: string): boolean {
  return (
    (/(^|\/)vite\.config\.[cm]?[jt]s$/.test(rel) && /sourcemap\s*:\s*['"]hidden['"]/.test(text)) ||
    (/(^|\/)webpack\.config\.[cm]?[jt]s$|(^|\/)next\.config\.[cm]?[jt]s$/.test(rel) && /devtool\s*[:=]\s*['"]hidden-/.test(text))
  );
}

const SECRET_NAME = /SECRET|PASS|PWD|TOKEN|PRIVATE|KEY|CREDENTIAL|AUTH|SALT|SIGN/i;
// Last name segment says what kind of value it is (VITE_GITLAB_TOKEN_TYPE, JWT_ALGORITHM, AUTH_URL).
const DESCRIPTOR_NAME = /_(?:TYPE|KIND|MODE|ALG|ALGORITHM|URL|URI|HOST|PORT|ENDPOINT|DOMAIN|REGION|PROVIDER|SCOPES?|ISSUER|AUDIENCE|HEADER|NAME|VERSION|ENABLED|EXPIRES?|EXPIRES_IN|TTL|LENGTH|PATH)$/i;
/** Short words joined by -_. (production, personal-access-token, HS256, us-east-1): no random key-like run. */
const plainWords = (v: string): boolean => v.length <= 64 && /^[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*$/.test(v) && v.split(/[-_.]/).every((s) => s.length <= 15);

/** `env-committed` content check (§6-5): true when every value is public or clearly not a secret. */
export function envHasOnlyPublicValues(entries: Record<string, string>): boolean {
  return Object.entries(entries).every(([k, v]) => {
    if (v === "" || /^(true|false|yes|no|on|off|\d+(\.\d+)?)$/i.test(v)) return true;
    if (allowlisted(v, k) === "public" || allowlisted(v, k) === "legacy_anon") return true;
    if (/^https?:\/\/[^\s@]*$/.test(v)) return true;
    if (SECRET_NAME.test(k)) return DESCRIPTOR_NAME.test(k) && plainWords(v);
    if (plainWords(v)) return true;
    return /URL|URI|HOST|PORT|DOMAIN|REGION|PROJECT|(^|_)ID$|ENV|MODE|NAME|LOCALE|LANG|VERSION|BUCKET/i.test(k) && /^[\w.:/-]{1,200}$/.test(v);
  });
}

/** Strip quotes / inline comment from a dotenv value. */
export function dotenvValue(raw: string): string {
  const s = raw.trim();
  const q = /^(["'`])(.*)\1/.exec(s);
  if (q) return q[2]!;
  return s.replace(/\s+#.*$/, "").trim();
}
