// Person-only actions (spec: watch, remediation tracking and ignore are never MCP tools). Until the
// GUI (stage 7) exists they are interactive terminal commands; non-interactive runs are refused
// exactly like `consent`.

import { createInterface } from "node:readline/promises";
import { styleText } from "node:util";
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
import { KIND_TEXT } from "./builtins/text.js";
import { CONSENT_HOWTO, DISCLAIMER, KEY_NOTICE, viNotice } from "./notice.js";
import { readLastScan } from "./recheck.js";
import type { Finding, Lang, LocalizedText, ScanResult, Severity, Template } from "./types.js";

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

export interface WatchCandidate {
  eco: "npm" | "PyPI";
  name: string;
  key: string;
  direct: boolean;
  vuln: boolean;
}

/** S3a list: public locked packages, direct first, vulnerable first; `defaults` = how many are pre-selected. */
export async function watchCandidates(cwd: string, appDir: string): Promise<{ cands: WatchCandidate[]; defaults: number }> {
  const inv = await readInventory(cwd);
  const direct = new Set(inv.lockfiles.flatMap((l) => l.packages.filter((p) => p.direct).map((p) => `${p.ecosystem}:${p.name}`)));
  const locks = new Set(inv.lockfiles.map((l) => l.path));
  const vulnerable = new Set(
    ((await readLastScan(cwd, appDir))?.findings ?? []).filter((f) => f.rule_id === "vulnerable-deps" && f.package).map((f) => `${f.ecosystem}:${f.package}`),
  );
  const seen = new Set<string>();
  const cands = lookupScope(inv)
    .targets.filter((t) => t.version !== null && t.sources.some((s) => locks.has(s)))
    .map((t) => ({ eco: t.ecosystem, name: t.name, key: `${t.ecosystem}:${t.name}` }))
    .filter((c) => !seen.has(c.key) && seen.add(c.key))
    .map((c) => ({ ...c, direct: direct.has(c.key), vuln: vulnerable.has(c.key) }))
    .sort((a, b) => Number(b.direct) - Number(a.direct) || Number(b.vuln) - Number(a.vuln) || (a.key < b.key ? -1 : 1));
  return { cands, defaults: cands.slice(0, WATCH_DEFAULT).filter((c) => c.direct).length };
}

async function watch(io: TtyIO, o: CommandOptions, ask: (q: string) => Promise<string>): Promise<number> {
  const ctx = await keyContext(io, o);
  if (!ctx) return 1;
  const ko = o.lang === "ko";
  const { cands, defaults } = await watchCandidates(o.cwd, ctx.appDir);
  if (cands.length === 0) {
    io.output.write(ko ? "감시할 공개 패키지가 없습니다(lock 파일 필요).\n" : "No public locked packages to watch (a lock file is needed).\n");
    return 1;
  }
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
  const res = await subscribePackages(o.cwd, ctx.appDir, ctx.key, picked, o.fetch);
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

/** POST /subscriptions one by one (§8-3-6): ecosystem + name only, at most 50. Stops at the plan limit. */
export async function subscribePackages(cwd: string, appDir: string, key: string, picked: WatchCandidate[], fetch?: Fetch): Promise<WatchResult> {
  const http = defaultHttp(fetch);
  const budget = new ViBudget(appDir, { keyMode: true });
  const res: WatchResult = { created: [], already: [], no_data: [], not_done: [] };
  const list = picked.slice(0, WATCH_MAX);
  for (let i = 0; i < list.length; i++) {
    const c = list[i]!;
    let r = await createSubscription(http, budget, key, c.eco, c.name);
    if (!r.ok && r.error.kind === "rate_limited") {
      await http.sleep(Math.min(r.error.retryAfterMs, 60_000) + 100); // budget is blocked for exactly Retry-After
      r = await createSubscription(http, budget, key, c.eco, c.name);
    }
    if (r.ok) res.created.push(c.key);
    else if (r.error.kind === "conflict") res.already.push(c.key);
    else if (r.error.kind === "not_found") res.no_data.push(c.key);
    else {
      res.stopped = r.error.kind;
      if (r.error.kind === "subscription_limit") res.limit = r.error.limit;
      res.not_done.push(...list.slice(i).map((x) => x.key));
      break;
    }
  }
  const file = join(appDir, "watch", `${projectKey(await realpath(resolve(cwd)))}.json`);
  const prev = await readJson<{ names?: string[] }>(file, {});
  await writeJson(file, { names: [...new Set([...(prev.names ?? []), ...res.created, ...res.already])].sort() });
  return res;
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
  const unique = await trackRows(o.cwd, ctx.appDir);
  if (unique.length === 0) {
    io.output.write(ko ? "등록할 CVE가 없습니다(GHSA 전용 항목은 `checkback watch`로 패키지를 감시하세요).\n" : "No CVEs to register (for GHSA-only items, watch the package with `checkback watch`).\n");
    return 1;
  }
  const reg = await registeredCves(ctx.appDir, ctx.key, unique.map((u) => u.cve), o.fetch);
  if (!reg.ok) {
    io.output.write(ko ? `조치 대장을 읽지 못했습니다: ${reg.kind}\n` : `Could not read the remediation tracker: ${reg.kind}\n`);
    return 1;
  }
  const registered = reg.set;
  io.output.write(`${unique.map((u, i) => `${String(i + 1).padStart(3)}) ${u.cve} · ${u.pkg}@${u.version}${registered.has(u.cve) ? (ko ? " · 등록됨" : " · registered") : ""}`).join("\n")}\n`);
  const answer = await ask(ko ? "등록할 번호(예: 1,3 · all · q=취소): " : "Numbers to register (e.g. 1,3 · all · q=cancel): ");
  if (!answer || /^q/i.test(answer)) return 1;
  const picked = (/^all$/i.test(answer) ? unique.map((_, i) => i) : parseSelection(answer, unique.length)).map((i) => unique[i]!).filter((u) => !registered.has(u.cve));
  const r = await registerCves(ctx.appDir, ctx.key, picked, o.fetch);
  if (r.error) io.output.write(ko ? `중단: ${r.error.cve} — ${r.error.kind}\n` : `Stopped: ${r.error.cve} — ${r.error.kind}\n`);
  io.output.write(ko ? `조치 대장 등록 ${r.ok}건 · ${web(o.lang, "/settings/remediations")}\n` : `Registered ${r.ok} · ${web(o.lang, "/settings/remediations")}\n`);
  return 0;
}

export interface TrackRow {
  cve: string;
  pkg: string;
  version: string;
}

/** CVE rows (GHSA-only items excluded) from the latest scan's vulnerable dependencies, one per CVE. */
export async function trackRows(cwd: string, appDir: string): Promise<TrackRow[]> {
  const rows = ((await readLastScan(cwd, appDir))?.findings ?? [])
    .filter((f) => f.rule_id === "vulnerable-deps" && f.package && f.version)
    .flatMap((f) => (f.vuln_ids ?? []).filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v)).map((cve) => ({ cve, pkg: f.package!, version: f.version! })));
  return [...new Map(rows.map((r) => [r.cve, r])).values()];
}

/** CVEs already in the remediation tracker: one list call per 100 (§8-3-4). */
export async function registeredCves(
  appDir: string, key: string, cves: string[], fetch?: Fetch,
): Promise<{ ok: true; set: Set<string> } | { ok: false; kind: KeyError["kind"] }> {
  const http = defaultHttp(fetch);
  const budget = new ViBudget(appDir, { keyMode: true });
  const set = new Set<string>();
  for (let i = 0; i < cves.length; i += 100) {
    const r = await listRemediations(http, budget, key, cves.slice(i, i + 100));
    if (!r.ok) return { ok: false, kind: r.error.kind };
    const data = (r.value as { data?: unknown }).data;
    for (const it of Array.isArray(data) ? data : []) if (typeof it?.cve_id === "string") set.add(it.cve_id.toUpperCase());
  }
  return { ok: true, set };
}

/** Register rows (callers drop already-registered ones — never overwrite); stops at the first error. */
export async function registerCves(appDir: string, key: string, rows: TrackRow[], fetch?: Fetch): Promise<{ ok: number; error?: { cve: string; kind: KeyError["kind"] } }> {
  const http = defaultHttp(fetch);
  const budget = new ViBudget(appDir, { keyMode: true });
  let ok = 0;
  for (const u of rows) {
    const r = await putRemediation(http, budget, key, u.cve, u.pkg, u.version);
    if (!r.ok) return { ok, error: { cve: u.cve, kind: r.error.kind } };
    ok++;
  }
  return { ok };
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

// ---------- command line: options, help, scan report, CI gate

interface OptSpec {
  flag: string;
  arg?: string;
  values?: readonly string[];
  desc: string;
}
interface CmdSpec {
  name: string;
  desc: string;
  opts: OptSpec[];
}

export const FAIL_ON = ["critical", "high", "medium", "low"] as const;
export type FailOn = (typeof FAIL_ON)[number];

/** Every command and option the CLI accepts; drives parsing, help and suggestions. */
export const COMMANDS: CmdSpec[] = [
  { name: "gui", desc: "Open the local results page in your browser (default)", opts: [{ flag: "--no-open", desc: "Print the URL instead of opening the browser" }] },
  {
    name: "scan",
    desc: "Scan the current folder and print what to fix",
    opts: [
      { flag: "--lang", arg: "en|ko", values: ["en", "ko"], desc: "Language of the result" },
      { flag: "--template", arg: "<file>", desc: "Use a template YAML file instead of the default" },
      { flag: "--json", desc: "Print JSON (default when stdout is not a terminal)" },
      { flag: "--text", desc: "Print the readable report (default in a terminal)" },
      { flag: "--fail-on", arg: "<severity>", values: FAIL_ON, desc: "Exit 1 if a thing to fix at this severity or above exists" },
    ],
  },
  {
    name: "sbom",
    desc: "Print a CycloneDX JSON SBOM of locked dependencies",
    opts: [
      { flag: "--upload-preview", desc: "Print the form a VulnIntel key would send (private packages removed); nothing is uploaded" },
      { flag: "--upload", desc: "Deprecated alias of --upload-preview" },
    ],
  },
  { name: "mcp", desc: "Run the MCP server over stdio (Claude Code and other AI tools)", opts: [] },
  { name: "consent", desc: "Agree to external lookups (interactive)", opts: [] },
  { name: "ignore", desc: "Ignore findings from the last scan, with a reason (interactive)", opts: [{ flag: "--remove", desc: "Un-ignore instead" }] },
  { name: "watch", desc: "Watch locked packages for new vulnerabilities (VulnIntel key, interactive)", opts: [] },
  { name: "track", desc: "Add CVEs from the last scan to your VulnIntel remediation tracker (key, interactive)", opts: [] },
];

export const USAGE_LINE = "usage: checkback [command] [options]";

export function usage(version: string): string {
  const col = (a: string, b: string, c: string): string => `  ${a.padEnd(9)}${b.padEnd(24)}${c}`;
  return [
    `checkback ${version} - local security check for apps built with AI coding tools`,
    "",
    USAGE_LINE,
    "",
    "Commands:",
    ...COMMANDS.map((c) => `  ${c.name.padEnd(9)}${c.desc}`),
    "",
    "Options:",
    col("all", "-h, --help", "Show this help"),
    col("", "-v, --version", "Print the version"),
    ...COMMANDS.flatMap((c) => c.opts.map((o, i) => col(i ? "" : c.name, `${o.flag}${o.arg ? ` ${o.arg}` : ""}`, o.desc))),
    "",
    "  --fail-on takes critical, high, medium or low (low = any severity). Only confirmed findings count.",
    "",
    "Examples:",
    "  npx checkback                        open the results page",
    "  npx checkback scan                   scan in the terminal",
    "  npx checkback scan --fail-on high    fail CI on critical or high findings",
    "",
    "Exit codes: 0 ok, 1 --fail-on threshold reached or the command failed, 2 usage error",
    "Docs: https://github.com/vulnintel/checkback#readme",
    "",
  ].join("\n");
}

function distance(a: string, b: string): number {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prev = cur;
  }
  return prev[b.length]!;
}

/** Closest candidate within 2 edits (an unambiguous-looking prefix also counts), or undefined. */
export function closest(word: string, candidates: string[]): string | undefined {
  const best = candidates
    .map((c) => ({ c, d: word.length > 1 && c.startsWith(word) ? 0.5 : distance(word, c) }))
    .sort((x, y) => x.d - y.d)[0];
  return best && best.d <= 2 ? best.c : undefined;
}

export type CliArgs =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "error"; message: string }
  | { kind: "run"; cmd: string; opts: Record<string, string | true> };

export function parseCli(argv: string[]): CliArgs {
  if (argv[0] === "help" || argv.some((a) => a === "-h" || a === "--help")) return { kind: "help" };
  if (argv.some((a) => a === "-v" || a === "--version")) return { kind: "version" };
  const implicit = argv[0] === undefined || argv[0].startsWith("-"); // `checkback --no-open` = gui
  const cmd = implicit ? "gui" : argv[0]!;
  const args = implicit ? argv : argv.slice(1);
  const hint = (s: string | undefined): string => (s ? ` Did you mean "${s}"?` : "");
  const spec = COMMANDS.find((c) => c.name === cmd);
  if (!spec) return { kind: "error", message: `unknown command "${cmd}".${hint(closest(cmd, [...COMMANDS.map((c) => c.name), "help"]))}` };
  const opts: Record<string, string | true> = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const name = eq > 0 ? a.slice(0, eq) : a;
    const o = spec.opts.find((x) => x.flag === name);
    if (!o) {
      return name.startsWith("-")
        ? { kind: "error", message: `unknown option "${name}" for "${cmd}".${hint(closest(name, spec.opts.map((x) => x.flag)))}` }
        : { kind: "error", message: `unexpected argument "${name}" for "${cmd}".` };
    }
    if (!o.arg) {
      if (eq > 0) return { kind: "error", message: `${name} does not take a value.` };
      opts[name] = true;
      continue;
    }
    const v = eq > 0 ? a.slice(eq + 1) : args[++i];
    if (!v || v.startsWith("-")) return { kind: "error", message: `${name} needs a value: ${o.arg}.` };
    if (o.values && !o.values.includes(v)) return { kind: "error", message: `${name} must be one of ${o.values.join(", ")} (got "${v}").` };
    opts[name] = v;
  }
  return { kind: "run", cmd, opts };
}

const SEV_RANK: Record<FailOn, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/** CI gate: confirmed findings ("things to fix", as in the GUI) at `threshold` or above. */
export function failOnCount(findings: Pick<Finding, "severity" | "confidence">[], threshold: FailOn): number {
  return findings.filter((f) => f.confidence === "confirmed" && SEV_RANK[f.severity] >= SEV_RANK[threshold]).length;
}

type Style = Parameters<typeof styleText>[0];
const SEV_STYLE: Record<Severity, Style> = { critical: ["bold", "red"], high: ["bold", "yellow"], medium: ["bold", "cyan"] };
const SEV_NAME: Record<Lang, Record<Severity, string>> = {
  en: { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM" },
  ko: { critical: "긴급", high: "높음", medium: "보통" },
};

/** One-line description of a finding: the first sentence of the rule text or builtin judgment text. */
function describe(f: Finding, tpl: Template, lang: Lang): string {
  const rule = tpl.rules.find((r) => r.id === f.rule_id);
  const pick = (t?: LocalizedText): string | undefined => t?.[lang] ?? t?.en ?? t?.ko;
  const text = pick(rule && "description" in rule ? rule.description : undefined) ?? pick(KIND_TEXT[`${f.rule_id}/${f.kind}`]?.description) ?? "";
  return (text.split(/(?<=[.!?])\s+/)[0] ?? "").replace(/\{[a-z_]+\}/g, "…");
}

/**
 * Readable scan report for a terminal. Prints titles, locations and rule descriptions only —
 * never secret values or masked values (same exposure as the JSON output).
 */
export function formatScan(r: ScanResult, tpl: Template, lang: Lang, color: boolean): string {
  const ko = lang === "ko";
  const paint = (style: Style, s: string): string => (color ? styleText(style, s, { validateStream: false }) : s); // caller decided TTY/NO_COLOR
  const names = SEV_NAME[lang];
  const cells = (s: string): number => s.length * (ko ? 2 : 1); // Hangul labels are double width
  const width = Math.max(...Object.values(names).map(cells));
  const pad = " ".repeat(width + 4);
  const fix = r.findings.filter((f) => f.confidence === "confirmed");
  const review = r.findings.filter((f) => f.confidence === "review");
  const info = r.findings.length - fix.length - review.length;
  const item = (f: Finding): string[] => {
    const where = f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "";
    const desc = describe(f, tpl, lang);
    return [
      `  ${paint(SEV_STYLE[f.severity], names[f.severity])}${" ".repeat(width - cells(names[f.severity]))}  ${paint("bold", f.title)}`,
      ...(where ? [pad + paint("dim", where)] : []),
      ...(desc ? [pad + desc] : []),
    ];
  };
  const sevLine = (["critical", "high", "medium"] as const).map((s) => `${names[s]} ${fix.filter((f) => f.severity === s).length}`).join(" · ");
  const out = [
    `${paint("bold", ko ? `고칠 일 ${fix.length}개` : `${fix.length} ${fix.length === 1 ? "thing" : "things"} to fix`)}   ${sevLine}`,
    paint("dim", ko ? `확인 필요 ${review.length}개 · 참고 ${info}개 · 검사한 파일 ${r.stats.files}개` : `${review.length} to review · ${info} for information · ${r.stats.files} files checked`),
    "",
  ];
  if (fix.length) out.push(paint("bold", ko ? "고칠 일" : "To fix"), ...fix.flatMap(item), "");
  if (review.length) out.push(paint("bold", ko ? "확인 필요" : "To review"), ...review.flatMap(item), "");
  if (!fix.length && !review.length) {
    const empty = r.stats.files === 0 ? (ko ? "검사할 파일이 없습니다. 프로젝트 폴더에서 실행하세요." : "No files to check. Run it from your project folder.") : ko ? "이 도구의 규칙에 걸린 항목이 없습니다." : "Nothing matched this tool's rules.";
    out.push(empty, "");
  }
  const vi = viNotice(r.vulnintel, lang);
  out.push(
    paint("bold", ko ? "다음 할 일" : "Next"),
    ko ? "  npx checkback         화면에서 고칠 항목을 고르고 AI에 붙여 넣을 수정 지시문을 복사하세요" : "  npx checkback         open the results page, pick findings and copy fix prompts for your AI",
    ko ? "  npx checkback scan    AI가 고친 뒤 다시 검사해 남은 것을 확인하세요" : "  npx checkback scan    scan again after the fix to see what is left",
    ...(r.checked.some((c) => c.reason === "no_consent") ? [paint("dim", `  ${CONSENT_HOWTO[lang]}`)] : []),
    ...(vi ? [paint("dim", `  ${vi}`)] : []),
    paint("dim", `  ${DISCLAIMER[lang].split("\n")[0]}`),
    "",
  );
  return out.join("\n");
}
