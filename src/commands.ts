// Person-only actions (spec: watch, remediation tracking and ignore are never MCP tools). Until the
// GUI (stage 7) exists they are interactive terminal commands; non-interactive runs are refused
// exactly like `consent`.

import { createInterface } from "node:readline/promises";
import { join } from "node:path";
import { realpath } from "node:fs/promises";
import { resolve } from "node:path";
import { apiKeyOf, defaultAppDir, hasConsent, projectKey, readConfig, readJson, writeJson } from "./appdata.js";
import type { ConsentIO } from "./consent.js";
import { lookupScope, readInventory } from "./deps/inventory.js";
import { addIgnore, listIgnores, removeIgnore } from "./ignores.js";
import { ViBudget } from "./net/budget.js";
import { defaultHttp, type Fetch } from "./net/http.js";
import { createSubscription, listRemediations, putRemediation, type KeyError } from "./net/vulnintel.js";
import { CONSENT_HOWTO, KEY_NOTICE } from "./notice.js";
import { readLastScan } from "./recheck.js";
import type { Lang } from "./types.js";

export type TtyIO = ConsentIO;
export interface CommandOptions {
  cwd: string;
  appDir?: string;
  lang: Lang;
  fetch?: Fetch;
}

const WATCH_MAX = 50;
const WATCH_DEFAULT = 10;
const web = (lang: Lang, path: string): string => `https://www.vulnintelapp.com/${lang}${path}`;

function refuse(io: TtyIO, lang: Lang): number {
  io.error.write(
    lang === "ko"
      ? "이 명령은 사람이 터미널에서 직접 해야 합니다(비대화형 실행 거부). 아무것도 바꾸지 않았습니다.\n"
      : "This command must be run by a person in a terminal (non-interactive run refused). Nothing was changed.\n",
  );
  return 1;
}

// One readline per command: a second interface on the same stream could lose buffered answers.
const asker = (io: TtyIO): { ask: (q: string) => Promise<string>; close: () => void } => {
  const rl = createInterface({ input: io.input, output: io.output });
  return { ask: async (q) => (await rl.question(q)).trim(), close: () => rl.close() };
};

/** "1,3,5-7" → [0,2,4,5,6] (1-based input), only indexes < n. */
export function parseSelection(s: string, n: number): number[] {
  const out = new Set<number>();
  for (const part of s.split(/[,\s]+/).filter(Boolean)) {
    const m = /^(\d+)(?:-(\d+))?$/.exec(part);
    if (!m) continue;
    const a = Number(m[1]);
    const b = Number(m[2] ?? m[1]);
    for (let i = Math.min(a, b); i <= Math.max(a, b); i++) if (i >= 1 && i <= n) out.add(i - 1);
  }
  return [...out].sort((x, y) => x - y);
}

async function keyContext(io: TtyIO, o: CommandOptions): Promise<{ key: string; appDir: string } | null> {
  const appDir = o.appDir ?? defaultAppDir();
  const cfg = await readConfig(appDir);
  if (!hasConsent(cfg)) {
    io.output.write(`${CONSENT_HOWTO[o.lang]}\n`);
    return null;
  }
  const key = apiKeyOf(cfg);
  if (!key) {
    io.output.write(`${KEY_NOTICE[o.lang]}\n`);
    return null;
  }
  return { key, appDir };
}

export interface WatchResult {
  created: string[];
  already: string[];
  no_data: string[];
  not_done: string[];
  stopped?: KeyError["kind"];
  limit?: number;
}

/**
 * `checkback watch` (S3a, §8-3-6): pick public locked packages → POST /subscriptions one by one
 * with ecosystem + name only (no version, no path). Default selection: vulnerable direct
 * dependencies, then other direct ones, up to 10. Stops at the plan limit.
 */
export async function watchCommand(io: TtyIO, o: CommandOptions): Promise<number> {
  if (!io.interactive) return refuse(io, o.lang);
  const q = asker(io);
  try {
    return await watch(io, o, q.ask);
  } finally {
    q.close();
  }
}

async function watch(io: TtyIO, o: CommandOptions, ask: (q: string) => Promise<string>): Promise<number> {
  const ctx = await keyContext(io, o);
  if (!ctx) return 1;
  const ko = o.lang === "ko";
  const inv = await readInventory(o.cwd);
  const direct = new Set(inv.lockfiles.flatMap((l) => l.packages.filter((p) => p.direct).map((p) => `${p.ecosystem}:${p.name}`)));
  const locks = new Set(inv.lockfiles.map((l) => l.path));
  const vulnerable = new Set(
    ((await readLastScan(o.cwd, ctx.appDir))?.findings ?? []).filter((f) => f.rule_id === "vulnerable-deps" && f.package).map((f) => `${f.ecosystem}:${f.package}`),
  );
  const seen = new Set<string>();
  const cands = lookupScope(inv)
    .targets.filter((t) => t.version !== null && t.sources.some((s) => locks.has(s)))
    .map((t) => ({ eco: t.ecosystem, name: t.name, key: `${t.ecosystem}:${t.name}` }))
    .filter((c) => !seen.has(c.key) && seen.add(c.key))
    .map((c) => ({ ...c, direct: direct.has(c.key), vuln: vulnerable.has(c.key) }))
    .sort((a, b) => Number(b.direct) - Number(a.direct) || Number(b.vuln) - Number(a.vuln) || (a.key < b.key ? -1 : 1));
  if (cands.length === 0) {
    io.output.write(ko ? "감시할 공개 패키지가 없습니다(lock 파일 필요).\n" : "No public locked packages to watch (a lock file is needed).\n");
    return 1;
  }
  const defaults = cands.slice(0, WATCH_DEFAULT).filter((c) => c.direct).length;
  io.output.write(
    `${cands
      .map((c, i) => `${String(i + 1).padStart(3)}) ${i < defaults ? "[*]" : "[ ]"} ${c.eco} ${c.name}${c.direct ? (ko ? " · 직접" : " · direct") : ""}${c.vuln ? (ko ? " · 취약" : " · vulnerable") : ""}`)
      .join("\n")}\n`,
  );
  io.output.write(
    ko
      ? `보내는 것: 생태계·패키지 이름(버전·경로 없음). 서버 계정에 구독으로 남고 웹(${web(o.lang, "/settings/notifications")})에서 지웁니다.\n`
      : `Sent: ecosystem and package name only (no version, no path). They stay as subscriptions on your account; remove them on the web (${web(o.lang, "/settings/notifications")}).\n`,
  );
  const answer = await ask(ko ? `감시할 번호(예: 1,3,5-7 · Enter=[*] ${defaults}개 · q=취소): ` : `Numbers to watch (e.g. 1,3,5-7 · Enter=[*] ${defaults} · q=cancel): `);
  if (/^q/i.test(answer)) return 1;
  const picked = (answer ? parseSelection(answer, cands.length) : cands.slice(0, defaults).map((_, i) => i)).slice(0, WATCH_MAX).map((i) => cands[i]!);
  if (picked.length === 0) return 1;

  const http = defaultHttp(o.fetch);
  const budget = new ViBudget(ctx.appDir, { keyMode: true });
  const res: WatchResult = { created: [], already: [], no_data: [], not_done: [] };
  for (let i = 0; i < picked.length; i++) {
    const c = picked[i]!;
    let r = await createSubscription(http, budget, ctx.key, c.eco, c.name);
    if (!r.ok && r.error.kind === "rate_limited") {
      await http.sleep(Math.min(r.error.retryAfterMs, 60_000) + 100); // budget is blocked for exactly Retry-After
      r = await createSubscription(http, budget, ctx.key, c.eco, c.name);
    }
    if (r.ok) res.created.push(c.key);
    else if (r.error.kind === "conflict") res.already.push(c.key);
    else if (r.error.kind === "not_found") res.no_data.push(c.key);
    else {
      res.stopped = r.error.kind;
      if (r.error.kind === "subscription_limit") res.limit = r.error.limit;
      res.not_done.push(...picked.slice(i).map((x) => x.key));
      break;
    }
  }
  const file = join(ctx.appDir, "watch", `${projectKey(await realpath(resolve(o.cwd)))}.json`);
  const prev = await readJson<{ names?: string[] }>(file, {});
  await writeJson(file, { names: [...new Set([...(prev.names ?? []), ...res.created, ...res.already])].sort() });
  io.output.write(
    ko
      ? `새로 감시 ${res.created.length} · 이미 감시 중 ${res.already.length} · 데이터 없음 ${res.no_data.length} · 못 함 ${res.not_done.length}\n`
      : `Now watching ${res.created.length} · already ${res.already.length} · no data ${res.no_data.length} · not done ${res.not_done.length}\n`,
  );
  if (res.stopped === "subscription_limit") {
    io.output.write(ko ? `구독 상한(${res.limit}개)에 닿았습니다. 웹에서 구독을 정리하세요: ${web(o.lang, "/settings/notifications")}\n` : `Subscription limit (${res.limit}) reached. Manage subscriptions on the web: ${web(o.lang, "/settings/notifications")}\n`);
  } else if (res.stopped) {
    io.output.write(ko ? `중단: ${res.stopped}\n` : `Stopped: ${res.stopped}\n`);
  }
  return res.stopped && res.stopped !== "subscription_limit" ? 1 : 0;
}

/**
 * `checkback track`: register vulnerable CVEs from the latest scan in the VulnIntel remediation
 * tracker. One list call per 100 CVEs to see what is already registered; never overwrites.
 */
export async function trackCommand(io: TtyIO, o: CommandOptions): Promise<number> {
  if (!io.interactive) return refuse(io, o.lang);
  const q = asker(io);
  try {
    return await track(io, o, q.ask);
  } finally {
    q.close();
  }
}

async function track(io: TtyIO, o: CommandOptions, ask: (q: string) => Promise<string>): Promise<number> {
  const ctx = await keyContext(io, o);
  if (!ctx) return 1;
  const ko = o.lang === "ko";
  const rows = ((await readLastScan(o.cwd, ctx.appDir))?.findings ?? [])
    .filter((f) => f.rule_id === "vulnerable-deps" && f.package && f.version)
    .flatMap((f) => (f.vuln_ids ?? []).filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v)).map((cve) => ({ cve, pkg: f.package!, version: f.version! })));
  const unique = [...new Map(rows.map((r) => [r.cve, r])).values()];
  if (unique.length === 0) {
    io.output.write(ko ? "등록할 CVE가 없습니다(GHSA 전용 항목은 `checkback watch`로 패키지를 감시하세요).\n" : "No CVEs to register (for GHSA-only items, watch the package with `checkback watch`).\n");
    return 1;
  }
  const http = defaultHttp(o.fetch);
  const budget = new ViBudget(ctx.appDir, { keyMode: true });
  const registered = new Set<string>();
  for (let i = 0; i < unique.length; i += 100) {
    const r = await listRemediations(http, budget, ctx.key, unique.slice(i, i + 100).map((u) => u.cve));
    if (!r.ok) {
      io.output.write(ko ? `조치 대장을 읽지 못했습니다: ${r.error.kind}\n` : `Could not read the remediation tracker: ${r.error.kind}\n`);
      return 1;
    }
    const data = (r.value as { data?: unknown }).data;
    for (const it of Array.isArray(data) ? data : []) if (typeof it?.cve_id === "string") registered.add(it.cve_id.toUpperCase());
  }
  io.output.write(`${unique.map((u, i) => `${String(i + 1).padStart(3)}) ${u.cve} · ${u.pkg}@${u.version}${registered.has(u.cve) ? (ko ? " · 등록됨" : " · registered") : ""}`).join("\n")}\n`);
  const answer = await ask(ko ? "등록할 번호(예: 1,3 · all · q=취소): " : "Numbers to register (e.g. 1,3 · all · q=cancel): ");
  if (!answer || /^q/i.test(answer)) return 1;
  const picked = (/^all$/i.test(answer) ? unique.map((_, i) => i) : parseSelection(answer, unique.length)).map((i) => unique[i]!).filter((u) => !registered.has(u.cve));
  let ok = 0;
  for (const u of picked) {
    const r = await putRemediation(http, budget, ctx.key, u.cve, u.pkg, u.version);
    if (r.ok) ok++;
    else {
      io.output.write(ko ? `중단: ${u.cve} — ${r.error.kind}\n` : `Stopped: ${u.cve} — ${r.error.kind}\n`);
      break;
    }
  }
  io.output.write(ko ? `조치 대장 등록 ${ok}건 · ${web(o.lang, "/settings/remediations")}\n` : `Registered ${ok} · ${web(o.lang, "/settings/remediations")}\n`);
  return 0;
}

/** `checkback ignore` / `checkback ignore --remove`: the local ignore list (§5), person only. */
export async function ignoreCommand(io: TtyIO, o: CommandOptions & { remove?: boolean }): Promise<number> {
  if (!io.interactive) return refuse(io, o.lang);
  const q = asker(io);
  try {
    return await ignore(io, o, q.ask);
  } finally {
    q.close();
  }
}

async function ignore(io: TtyIO, o: CommandOptions & { remove?: boolean }, ask: (q: string) => Promise<string>): Promise<number> {
  const ko = o.lang === "ko";
  const appDir = o.appDir ?? defaultAppDir();
  if (o.remove) {
    const list = await listIgnores(o.cwd, appDir);
    if (!list.length) {
      io.output.write(ko ? "무시 목록이 비어 있습니다.\n" : "The ignore list is empty.\n");
      return 1;
    }
    io.output.write(`${list.map((e, i) => `${String(i + 1).padStart(3)}) ${e.id} · ${e.reason} · ${e.at}`).join("\n")}\n`);
    const picked = parseSelection(await ask(ko ? "해제할 번호: " : "Numbers to un-ignore: "), list.length);
    for (const i of picked) await removeIgnore(o.cwd, list[i]!.id, appDir);
    io.output.write(ko ? `${picked.length}개 해제\n` : `Removed ${picked.length}\n`);
    return picked.length ? 0 : 1;
  }
  const findings = (await readLastScan(o.cwd, appDir))?.findings ?? [];
  if (!findings.length) {
    io.output.write(ko ? "먼저 검사하세요(무시할 항목 없음).\n" : "Run a scan first (nothing to ignore).\n");
    return 1;
  }
  io.output.write(`${findings.map((f, i) => `${String(i + 1).padStart(3)}) ${f.severity}/${f.confidence} · ${f.title} · ${f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "-"}`).join("\n")}\n`);
  const picked = parseSelection(await ask(ko ? "무시할 번호: " : "Numbers to ignore: "), findings.length);
  if (!picked.length) return 1;
  const reason = await ask(ko ? "사유(필수): " : "Reason (required): ");
  if (!reason) return 1;
  for (const i of picked) await addIgnore(o.cwd, findings[i]!.id, reason, appDir);
  io.output.write(ko ? `${picked.length}개 무시\n` : `Ignored ${picked.length}\n`);
  return 0;
}
