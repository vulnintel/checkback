import { createHash } from "node:crypto";

export const sha256 = (s: string | Uint8Array): string => createHash("sha256").update(s).digest("hex");

/** Placeholder values are never secrets (§5): `your-…`, `xxx…`, `<…>`, `[…]`, `changeme`, `example`, `${…}`. */
const PLACEHOLDER = /your[-_]|x{3,}|<[^>]*>|\[[^\]]*\]|changeme|example|placeholder|dummy|\$\{|\.{3}|\*{3}|•/i;
// The whole value is the name of the thing it stands for (docs: `postgres://user:pass@host/db`).
const PLACEHOLDER_WORD = /^(?:pass|passwd|password|pwd|secret|my_?password|db_?password)$/i;

export function isPlaceholder(value: string): boolean {
  return value.trim() === "" || PLACEHOLDER.test(value) || PLACEHOLDER_WORD.test(value.trim());
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0]!.startsWith("eyJ")) return null;
  try {
    const json: unknown = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
    return typeof json === "object" && json !== null ? (json as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export type AllowVerdict = "public" | "legacy_anon" | null;

/**
 * §6-4 value allowlist. `context` is the text around the match (for the Firebase config object).
 * Returns "public" (drop and count), "legacy_anon" (keep as info) or null (not allowlisted).
 */
export function allowlisted(value: string, context: string): AllowVerdict {
  if (/^(?:sb_publishable_|pk_live_|pk_test_)/.test(value)) return "public";
  const claims = decodeJwtPayload(value);
  if (claims?.role === "anon") return "legacy_anon";
  if (/^AIza/.test(value) && /authDomain|projectId|AUTH_DOMAIN|PROJECT_ID|FIREBASE/.test(context)) return "public";
  return null;
}

/** GUI display form (§10-3): prefix + •••• + last 4 + length. Short values show nothing of the value. */
export function mask(value: string): string {
  const n = value.length;
  if (n < 12) return `•••• (${n})`;
  const prefix = value.slice(0, Math.min(8, Math.floor(n / 4)));
  return `${prefix}••••${n >= 20 ? value.slice(-4) : ""} (${n})`;
}

/** Finding id (§5): rule + relative path + value hash; line numbers are not part of it. */
export function fingerprint(ruleId: string, file: string, valueHash: string): string {
  return sha256(`${ruleId}\0${file}\0${valueHash}`).slice(0, 32);
}
