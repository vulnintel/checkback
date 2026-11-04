import { NetError, requestJson, type Http } from "./http.js";

export const OSV = "https://api.osv.dev";
const BATCH = 1000;

export interface OsvQuery {
  ecosystem: "npm" | "PyPI";
  name: string;
  version: string;
}

interface BatchResp {
  results?: { vulns?: { id: string; modified?: string }[]; next_page_token?: string }[];
}

export interface OsvBatchResult {
  /** Per query: vuln ids (with modified), or null when the query could not be answered. */
  results: ({ id: string; modified: string }[] | null)[];
  offline: boolean;
}

/**
 * POST /v1/querybatch (§8-1): 1,000 per request, per-query pagination via next_page_token,
 * 5xx/timeout → one retry then "not checked", oversized responses → halve the batch.
 */
export async function osvQueryBatch(http: Http, queries: OsvQuery[]): Promise<OsvBatchResult> {
  const results: OsvBatchResult["results"] = queries.map(() => []);
  let offline = false;

  async function post(idx: number[], tokens: (string | undefined)[]): Promise<void> {
    if (idx.length === 0 || offline) return;
    const body = {
      queries: idx.map((i, j) => ({
        package: { ecosystem: queries[i]!.ecosystem, name: queries[i]!.name },
        version: queries[i]!.version,
        ...(tokens[j] && { page_token: tokens[j] }),
      })),
    };
    let resp: BatchResp | undefined;
    for (let attempt = 0; attempt < 2 && !resp; attempt++) {
      try {
        resp = await requestJson<BatchResp>(http, `${OSV}/v1/querybatch`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      } catch (e) {
        const err = e as NetError;
        if (err.kind === "offline") {
          offline = true;
          for (const i of idx) results[i] = null;
          return;
        }
        // HTTP/1.1 responses are capped at 32MiB: split and retry the halves.
        if (err.kind === "http" && (err.status === 413 || err.status === 507) && idx.length > 1) {
          const h = Math.ceil(idx.length / 2);
          await post(idx.slice(0, h), tokens.slice(0, h));
          await post(idx.slice(h), tokens.slice(h));
          return;
        }
        if (attempt === 1 || (err.kind === "http" && err.status < 500)) {
          for (const i of idx) results[i] = null;
          return;
        }
      }
    }
    const more: number[] = [];
    const moreTokens: string[] = [];
    resp!.results?.forEach((r, j) => {
      const i = idx[j]!;
      for (const v of r.vulns ?? []) results[i]?.push({ id: v.id, modified: v.modified ?? "" });
      if (r.next_page_token) {
        more.push(i);
        moreTokens.push(r.next_page_token);
      }
    });
    await post(more, moreTokens);
  }

  for (let s = 0; s < queries.length; s += BATCH) {
    const idx = Array.from({ length: Math.min(BATCH, queries.length - s) }, (_, k) => s + k);
    await post(idx, []);
  }
  return { results, offline };
}

export interface OsvVuln {
  id: string;
  modified?: string;
  summary?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { ecosystem?: string; name?: string };
    ranges?: { type?: string; events?: Record<string, string>[] }[];
    database_specific?: { severity?: string };
  }[];
}

export async function osvVuln(http: Http, id: string): Promise<OsvVuln | null> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      return await requestJson<OsvVuln>(http, `${OSV}/v1/vulns/${encodeURIComponent(id)}`);
    } catch (e) {
      const err = e as NetError;
      if (err.kind === "offline" || (err.kind === "http" && err.status < 500)) return null;
    }
  }
  return null;
}
