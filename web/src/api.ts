// Session bootstrap (§10-1): the token arrives in the URL fragment, lives only in this module's
// memory, and the fragment is wiped before anything else. Reloads get it back with the HttpOnly
// session cookie. Nothing is written to localStorage / sessionStorage.

const HEADER = "X-Checkback-Token";
let token = "";

export class ApiFail extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly detail?: unknown,
  ) {
    super(code);
  }
}

export async function initSession(): Promise<boolean> {
  const m = /^#t=([a-f0-9]{64})$/.exec(location.hash);
  if (m) {
    history.replaceState(null, "", "/");
    const r = await fetch("/api/session", { method: "POST", headers: { [HEADER]: m[1]!, "Content-Type": "application/json" }, body: "{}" });
    if (!r.ok) return false;
    token = m[1]!;
    return true;
  }
  const r = await fetch("/api/token");
  if (!r.ok) return false;
  token = ((await r.json()) as { token: string }).token;
  return true;
}

export async function api<T = Record<string, unknown>>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method,
    headers: { [HEADER]: token, ...(method === "POST" && { "Content-Type": "application/json" }) },
    ...(method === "POST" && { body: JSON.stringify(body ?? {}) }),
  });
  const data = (await r.json().catch(() => ({}))) as { error?: string; detail?: unknown };
  if (!r.ok) throw new ApiFail(r.status, data.error ?? "error", data.detail);
  return data as T;
}
