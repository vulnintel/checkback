import type { ViBudget } from "./budget.js";
import { NetError, requestJson, type Http } from "./http.js";

export const VI_API = "https://api.vulnintelapp.com/api/v1";

export interface PublicVuln {
  vpi_level: number | null;
  is_kev: boolean;
  epss: number | null;
  cvss: number | null;
  title: string | null;
  description: string | null;
  kev_action: string | null;
}

export type ViResult<T> = { ok: true; value: T } | { ok: false; reason: "budget" | "not_found" | "rate_limited" | "offline" | "error" };

/** §8-4 public lookup (no key). Consumes one budget slot; 429 blocks the shared bucket for a minute. */
export async function publicLookup(http: Http, budget: ViBudget, id: string, lang: "ko" | "en"): Promise<ViResult<PublicVuln>> {
  if (!(await budget.take("public"))) return { ok: false, reason: "budget" };
  try {
    const r = await requestJson<{ data?: Record<string, unknown> }>(http, `${VI_API}/vulnerabilities/${encodeURIComponent(id)}?lang=${lang}`);
    const d = r?.data ?? {};
    const num = (v: unknown): number | null => (v === null || v === undefined || Number.isNaN(Number(v)) ? null : Number(v));
    const kev = (d.kev ?? null) as Record<string, unknown> | null;
    return {
      ok: true,
      value: {
        vpi_level: num(d.vpi_level),
        is_kev: d.is_kev === true,
        epss: num(d.epss_score),
        cvss: num(d.cvss_score),
        title: typeof d.title === "string" ? d.title : null,
        description: typeof d.description === "string" ? d.description : null,
        kev_action: kev && typeof kev.required_action_label === "string" ? kev.required_action_label : kev && typeof kev.required_action === "string" ? kev.required_action : null,
      },
    };
  } catch (e) {
    return fail(e, budget);
  }
}

async function fail(e: unknown, budget: ViBudget): Promise<{ ok: false; reason: "not_found" | "rate_limited" | "offline" | "error" }> {
  const err = e as NetError;
  if (err.kind === "offline" || err.kind === "timeout") return { ok: false, reason: "offline" };
  if (err.status === 404) return { ok: false, reason: "not_found" };
  if (err.status === 429) {
    await budget.block();
    return { ok: false, reason: "rate_limited" };
  }
  return { ok: false, reason: "error" };
}

// ---------- key-mode client (§8-3). Used by stage 9; contract only, no live calls here. ----------

export type KeyError =
  | { kind: "invalid_key" } // 401
  | { kind: "quota_exceeded"; reset?: string } // 402 monthly_quota_exceeded
  | { kind: "forbidden" } // 403 (key path only allows package subscriptions)
  | { kind: "not_found" }
  | { kind: "conflict" }
  | { kind: "subscription_limit"; limit: number }
  | { kind: "rate_limited"; retryAfterMs: number }
  | { kind: "too_large" | "bad_request" | "offline" | "error" | "budget" };

export type KeyResult<T> = { ok: true; value: T; quotaRemaining?: number } | { ok: false; error: KeyError };

async function keyCall<T>(
  http: Http,
  budget: ViBudget,
  kind: "poll" | "key",
  key: string,
  path: string,
  init: RequestInit = {},
): Promise<KeyResult<T>> {
  if (!(await budget.take(kind))) return { ok: false, error: { kind: "budget" } };
  let quotaRemaining: number | undefined;
  let quotaReset: string | null = null;
  const fetchWithHeaders: typeof fetch = async (u, i) => {
    const res = await http.fetch(u, i);
    const q = res.headers.get("x-quota-remaining");
    if (q !== null && q !== "") quotaRemaining = Number(q);
    quotaReset = res.headers.get("x-quota-reset");
    return res;
  };
  try {
    const value = await requestJson<T>({ ...http, fetch: fetchWithHeaders }, `${VI_API}${path}`, {
      ...init,
      headers: { "X-Api-Key": key, ...(init.headers as Record<string, string>) },
    });
    return { ok: true, value, ...(quotaRemaining !== undefined && { quotaRemaining }) };
  } catch (e) {
    const error = await keyError(e as NetError, budget);
    if (error.kind === "quota_exceeded" && quotaReset) error.reset = quotaReset;
    return { ok: false, error };
  }
}

/** Map an HTTP failure to the §8 failure table. */
export async function keyError(err: NetError, budget: ViBudget): Promise<KeyError> {
  if (err.kind !== "http") return { kind: "offline" };
  const body = (err.body ?? {}) as Record<string, unknown>;
  // FastAPI wraps HTTPException detail as {"error": {...}} in this API.
  const inner = (typeof body.error === "object" && body.error !== null ? body.error : body.detail ?? body) as Record<string, unknown>;
  switch (err.status) {
    case 401:
      return { kind: "invalid_key" };
    case 402:
      return { kind: "quota_exceeded" };
    case 403:
      return { kind: "forbidden" };
    case 404:
      return { kind: "not_found" };
    case 409:
      return { kind: "conflict" };
    case 413:
      return { kind: "too_large" };
    case 429:
      await budget.block(err.retryAfterMs || 60_000);
      return { kind: "rate_limited", retryAfterMs: err.retryAfterMs || 60_000 };
    case 400:
      return inner?.error === "subscription_limit_exceeded" ? { kind: "subscription_limit", limit: Number(inner.limit) || 0 } : { kind: "bad_request" };
    default:
      return { kind: "error" };
  }
}

/** Key validity probe without spending a scan (§8-3-7): 404 = valid, 401 = invalid. */
export async function checkKey(http: Http, budget: ViBudget, key: string): Promise<"valid" | "invalid" | "unknown"> {
  const r = await keyCall(http, budget, "key", key, "/scan/jobs/00000000-0000-0000-0000-000000000000");
  if (r.ok) return "valid";
  return r.error.kind === "not_found" ? "valid" : r.error.kind === "invalid_key" ? "invalid" : "unknown";
}

export function uploadSbom(http: Http, budget: ViBudget, key: string, sbomJson: string): Promise<KeyResult<{ job_id: string; status: string; status_url?: string }>> {
  const form = new FormData();
  form.set("file", new Blob([sbomJson], { type: "application/json" }), "sbom.json");
  form.set("kind", "sbom");
  form.set("scan_depth", "precise");
  form.set("no_cache", "false");
  return keyCall(http, budget, "key", key, "/scan/jobs", { method: "POST", body: form });
}

export const getJob = (http: Http, budget: ViBudget, key: string, jobId: string): Promise<KeyResult<Record<string, unknown>>> =>
  keyCall(http, budget, "poll", key, `/scan/jobs/${encodeURIComponent(jobId)}`);

export function listRemediations(http: Http, budget: ViBudget, key: string, cveIds: string[]): Promise<KeyResult<Record<string, unknown>>> {
  const q = cveIds.slice(0, 100).map((c) => `cve_id=${encodeURIComponent(c)}`).join("&");
  return keyCall(http, budget, "key", key, `/remediations?${q}&per_page=100`);
}

export function putRemediation(http: Http, budget: ViBudget, key: string, cveId: string, pkg: string, version: string): Promise<KeyResult<unknown>> {
  if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) return Promise.resolve({ ok: false, error: { kind: "bad_request" } });
  return keyCall(http, budget, "key", key, `/remediations/${cveId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status: "open", note: `checkback: ${pkg}@${version}` }),
  });
}

/** Package watch (B3): key path accepts package targets only. */
export function createSubscription(http: Http, budget: ViBudget, key: string, ecosystem: "npm" | "PyPI", name: string): Promise<KeyResult<unknown>> {
  return keyCall(http, budget, "key", key, "/subscriptions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_type: "package", ecosystem, target_value: name }),
  });
}
