// Key mode for vulnerable-deps (§8-3 1–3): upload the public-only CycloneDX, poll the job, read
// result.packages. Any failure falls back to OSV for this scan. The same SBOM is never uploaded
// twice: its sha-256 and the result stay in appdata (AC30); refresh only on explicit request.

import { createHash } from "node:crypto";
import type { Inventory } from "../deps/inventory.js";
import { buildSbom } from "../deps/sbom.js";
import type { ViBudget } from "../net/budget.js";
import type { Cache, Http } from "../net/http.js";
import { getJob, uploadSbom, type KeyError } from "../net/vulnintel.js";
import type { Lang } from "../types.js";

const POLL_MS = 3000;
const MAX_POLL_MS = 6 * 60_000;
const FOREVER = Number.MAX_SAFE_INTEGER;

/** One vulnerability from a VulnIntel scan result (only the fields we read; all optional). */
export interface ViVuln {
  id: string;
  aliases: string[];
  severity?: string;
  cvss?: number;
  kev: boolean;
  fixed: string[];
  vpi?: number;
  epss?: number;
  unknown: boolean;
}
export interface ViPackage {
  ecosystem: string;
  name: string;
  version: string | null;
  vulns: ViVuln[];
}

export interface ViScanStatus {
  status: "ok" | "cached" | "pending" | "fallback";
  reason?: KeyError["kind"] | "job_failed" | "bad_result" | "quota_blocked";
  job_id?: string;
  history_url?: string;
  quota_remaining?: number;
  quota_reset?: string;
}

interface Entry {
  job_id?: string;
  created?: number;
  packages?: ViPackage[];
  at?: number;
}

const num = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && v !== "" && Number.isFinite(Number(v)) ? Number(v) : undefined);

/** Tolerant reader: an older server without new fields still parses; an unknown shape → null. */
export function parseViResult(result: unknown): ViPackage[] | null {
  const pk = (result as { packages?: unknown })?.packages;
  if (!Array.isArray(pk)) return null;
  const vuln = (x: unknown, unknown: boolean): ViVuln | null => {
    const v = x as Record<string, unknown>;
    if (!v || typeof v.id !== "string") return null;
    const aliases = Array.isArray(v.aliases) ? v.aliases.filter((a): a is string => typeof a === "string") : [];
    if (typeof v.cve_id === "string" && !aliases.includes(v.cve_id)) aliases.push(v.cve_id);
    const out: ViVuln = {
      id: v.id,
      aliases,
      kev: v.kev === true,
      fixed: Array.isArray(v.fixed_versions) ? v.fixed_versions.filter((f): f is string => typeof f === "string") : [],
      unknown,
    };
    if (typeof v.severity === "string" && v.severity !== "UNKNOWN") out.severity = v.severity.toUpperCase();
    const cv = num((v.cvss as Record<string, unknown> | null)?.score);
    if (cv !== undefined) out.cvss = cv;
    const vpi = num(v.vpi_level); // B1 (optional)
    if (vpi !== undefined) out.vpi = vpi;
    const epss = num(v.epss_score);
    if (epss !== undefined) out.epss = epss;
    return out;
  };
  return pk.flatMap((p) => {
    const r = p as Record<string, unknown>;
    if (!r || typeof r.name !== "string") return [];
    const vulns = [
      ...(Array.isArray(r.vulnerabilities) ? r.vulnerabilities : []).map((x) => vuln(x, false)),
      ...(Array.isArray(r.unknown_vulnerabilities) ? r.unknown_vulnerabilities : []).map((x) => vuln(x, true)),
    ].filter((x): x is ViVuln => !!x);
    return [{ ecosystem: String(r.ecosystem ?? ""), name: r.name, version: typeof r.version === "string" ? r.version : null, vulns }];
  });
}

export interface ViScanCtx {
  http: Http;
  budget: ViBudget;
  key: string;
  lang: Lang;
  /** "vi-scan" namespace cache (per SBOM hash) */
  cache: Cache;
  now: number;
  /** Real-clock deadline (ms since epoch); polling stops there and the job is resumed next scan. */
  deadline: number;
  refresh?: boolean;
}

export async function viScan(inv: Inventory, c: ViScanCtx): Promise<{ packages: ViPackage[] | null; status: ViScanStatus }> {
  const sbom = buildSbom(inv, { forUpload: true });
  if ((JSON.parse(sbom) as { components?: unknown[] }).components?.length === 0) return { packages: [], status: { status: "ok" } };
  const hash = createHash("sha256").update(sbom).digest("hex");
  const entry = c.cache.get<Entry>(hash, FOREVER, c.now) ?? {};
  const history = (job: string): string => `https://www.vulnintelapp.com/${c.lang}/scan?tab=history&job=${encodeURIComponent(job)}`;
  if (entry.packages && !c.refresh) {
    return { packages: entry.packages, status: { status: "cached", ...(entry.job_id && { job_id: entry.job_id, history_url: history(entry.job_id) }) } };
  }
  const blocked = c.cache.get<{ until: number; reset?: string }>("quota", FOREVER, c.now);
  if (blocked && blocked.until > c.now && !c.refresh) {
    return { packages: null, status: { status: "fallback", reason: "quota_blocked", ...(blocked.reset && { quota_reset: blocked.reset }) } };
  }
  let jobId = entry.job_id && entry.created && c.now - entry.created < MAX_POLL_MS ? entry.job_id : undefined;
  let quotaRemaining: number | undefined;
  if (!jobId) {
    let up = await uploadSbom(c.http, c.budget, c.key, sbom);
    if (!up.ok && up.error.kind === "rate_limited" && Date.now() + up.error.retryAfterMs < c.deadline) {
      await c.http.sleep(up.error.retryAfterMs + 100); // the shared budget is blocked for exactly Retry-After
      up = await uploadSbom(c.http, c.budget, c.key, sbom);
    }
    if (!up.ok) {
      if (up.error.kind === "quota_exceeded") {
        // §8 table: no automatic upload again this month.
        const resetAt = up.error.reset ? Date.parse(up.error.reset) : NaN;
        const d = new Date(c.now);
        const until = Number.isFinite(resetAt) ? resetAt : Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
        c.cache.set("quota", { until, ...(up.error.reset && { reset: up.error.reset }) }, c.now);
        return { packages: null, status: { status: "fallback", reason: "quota_exceeded", ...(up.error.reset && { quota_reset: up.error.reset }) } };
      }
      return { packages: null, status: { status: "fallback", reason: up.error.kind } };
    }
    quotaRemaining = up.quotaRemaining;
    jobId = up.value.job_id;
    if (typeof jobId !== "string" || !jobId) return { packages: null, status: { status: "fallback", reason: "bad_result" } };
    entry.job_id = jobId;
    entry.created = c.now;
    c.cache.set(hash, entry, c.now);
  }
  // Poll (≤ 20/min via the budget) until done, the 6-minute cap, or the caller's deadline.
  for (let first = true; ; first = false) {
    if (!first) {
      if (Date.now() + POLL_MS > c.deadline) break;
      await c.http.sleep(POLL_MS);
    }
    const r = await getJob(c.http, c.budget, c.key, jobId);
    if (!r.ok) {
      if (r.error.kind === "budget" || r.error.kind === "rate_limited" || r.error.kind === "offline") break;
      return { packages: null, status: { status: "fallback", reason: r.error.kind, job_id: jobId } };
    }
    quotaRemaining = r.quotaRemaining ?? quotaRemaining;
    const st = r.value.status;
    if (st === "failed") {
      c.cache.set(hash, {}, c.now);
      return { packages: null, status: { status: "fallback", reason: "job_failed", job_id: jobId } };
    }
    if (st === "completed") {
      const packages = parseViResult(r.value.result);
      if (!packages) return { packages: null, status: { status: "fallback", reason: "bad_result", job_id: jobId } };
      c.cache.set(hash, { job_id: jobId, packages, at: c.now }, c.now);
      return {
        packages,
        status: { status: "ok", job_id: jobId, history_url: history(jobId), ...(quotaRemaining !== undefined && { quota_remaining: quotaRemaining }) },
      };
    }
  }
  return { packages: null, status: { status: "pending", job_id: jobId, history_url: history(jobId), ...(quotaRemaining !== undefined && { quota_remaining: quotaRemaining }) } };
}
