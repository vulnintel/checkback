import { createHmac, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { apiKeyOf, defaultAppDir, hasConsent, installKey, readConfig, writeJson, type LocalConfig } from "./appdata.js";
import { firebaseRules, supabaseRls, type BF, type BuiltinCtx } from "./builtins/backend.js";
import { depsBuiltins, type NetCtx } from "./builtins/deps.js";
import type { ViScanStatus } from "./builtins/vi-scan.js";
import { jsImports, pyImports } from "./builtins/imports.js";
import { BUILTIN_NAMES, KIND_TEXT } from "./builtins/text.js";
import { lookupScope, readInventory, type Inventory } from "./deps/inventory.js";
import { ViBudget } from "./net/budget.js";
import { Cache, defaultHttp, VERSION, type Fetch } from "./net/http.js";
import { configValue, parseConfig, parseDotenv } from "./config-file.js";
import {
  collectFiles, decode, isEnvFile, MAX_FILE_BYTES, isExampleOrDoc, isSkippedPath, isTestPath, lineAt, lineTextAt, readText, type FileEntry,
} from "./files.js";
import { gitInfo, globToPathspecs, type GitInfo } from "./git.js";
import { matchAny, matchGlob } from "./glob.js";
import { listIgnores } from "./ignores.js";
import { compareWith, lastScanFile, lockStates, readLastScan, readSnapshot, storedFinding, type StoredScan } from "./recheck.js";
import { envHasOnlyPublicValues, hiddenSourcemapConfig, LATE_RULES, REFINERS } from "./refine.js";
import { RegexRunner, RULE_TOTAL_LIMIT_MS, type RawMatch } from "./regex-runner.js";
import { allowlisted, decodeJwtPayload, fingerprint, isPlaceholder, mask } from "./secrets.js";
import type {
  BuiltinRule, CheckedRule, Confidence, ConfigRule, FileRule, Finding, Lang, NoteCode, PatternRule, Rule, ScanResult, ScanStats, Severity, Template,
} from "./types.js";

export const ENGINE_VERSION = VERSION;

export interface ScanOptions {
  /** Language of finding titles. Default "en". */
  lang?: Lang;
  /** `<appdata>/checkback` override (tests). */
  appDir?: string;
  /** Apply the local ignore list. Default true. */
  ignores?: boolean;
  /** Injected fetch (tests/mocks). External calls still need consent and enabled lookups. */
  fetch?: Fetch;
  /** Injected clock (ms). */
  now?: () => number;
  /** Compare with the fix-request snapshot / previous scan and store this scan (§7-8). Default true. */
  recheck?: boolean;
  /**
   * Wall-clock budget for the whole scan, counted from its start (MCP: 20 s). External lookups
   * still running or not started by then are left pending and continue from cache on the next
   * scan. Default: DEFAULT_SCAN_DEADLINE_MS (CLI/GUI).
   */
  deadlineMs?: number;
  /** Key mode: ask VulnIntel again even if this exact SBOM already has a result ([다시 조회]). */
  refreshVulnIntel?: boolean;
  /** GUI progress (S2): called as each phase starts; `files` is known from "rules" on. */
  onPhase?: (phase: ScanPhase, files: number) => void;
  /** GUI [중지]: checked between phases; an aborted scan rejects and stores nothing. */
  signal?: AbortSignal;
}

export type ScanPhase = "files" | "rules" | "deps" | "external" | "finish";

/** CLI/GUI scan budget (B6: a cold first scan took up to 5 min, mostly paced VulnIntel lookups). */
export const DEFAULT_SCAN_DEADLINE_MS = 90_000;
/** External lookups get at least this much (capped by the budget) even after slow local stages, so repeated scans progress. */
const MIN_LOOKUP_MS = 5_000;

const CONF_RANK: Record<Confidence, number> = { confirmed: 0, review: 1, info: 2 };
const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2 };
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0); // locale-independent
const lower = (a: Confidence, b: Confidence): Confidence => (CONF_RANK[a] >= CONF_RANK[b] ? a : b);

/** Secret rules get placeholder/allowlist/local-only handling and a `secret_kind`. */
export const isSecretRule = (r: PatternRule): boolean => r.build_output || r.id.startsWith("secret-");

const applies = (r: { files: string[]; exclude: string[]; build_output?: boolean }, f: FileEntry): boolean =>
  (!f.build || r.build_output === true) && matchAny(r.files, f.rel) && !matchAny(r.exclude, f.rel);

const literalPath = (glob: string | undefined): string | null => (glob && !/[*?[{]/.test(glob) ? glob : null);

/**
 * Stage-1 scan of `cwd` (fixed target, spec §3) with `template`. Network only for the builtin
 * dependency checks, only after first-run consent, only to the §3-1 services.
 */
export async function scan(cwd: string, template: Template, opts: ScanOptions = {}): Promise<ScanResult> {
  const started = Date.now();
  const root = await realpath(resolve(cwd));
  const appDir = opts.appDir ?? defaultAppDir();
  const cfg = await readConfig(appDir);
  const step = (p: ScanPhase, n = 0): void => {
    opts.signal?.throwIfAborted();
    opts.onPhase?.(p, n);
  };
  step("files");
  const files = await collectFiles(root);
  step("rules", files.length);
  const run = new Run(root, files, await gitInfo(root), opts.lang ?? cfg.lang ?? "en", await installKey(appDir));

  const active: Rule[] = [];
  const builtins: BuiltinRule[] = [];
  for (const r of template.rules) {
    if (r.type === "ai_check") continue; // natural-language checks for the user's AI only
    if (!r.enabled) run.checked.set(r.id, { rule_id: r.id, ran: false, reason: "disabled" });
    else if (r.type === "builtin") {
      run.checked.set(r.id, { rule_id: r.id, ran: true });
      builtins.push(r);
    } else if (r.type === "file" && r.git === "tracked" && !run.git.isRepo) run.checked.set(r.id, { rule_id: r.id, ran: false, reason: "not_git_repo" });
    else {
      run.checked.set(r.id, { rule_id: r.id, ran: true });
      if (!r.when || files.some((f) => !f.build && matchGlob(r.when!, f.rel))) active.push(r);
    }
  }
  await run.textRules(
    active.filter((r): r is PatternRule => r.type === "pattern"),
    active.filter((r): r is ConfigRule => r.type === "config"),
  );
  for (const r of active) if (r.type === "file") await run.fileRule(r);
  const now = (opts.now ?? Date.now)();
  step("deps", files.length);
  const inv = await readInventory(root, files);
  const budget = opts.deadlineMs ?? DEFAULT_SCAN_DEADLINE_MS;
  const deadline = Math.max(started + budget, Date.now() + Math.min(budget, MIN_LOOKUP_MS));
  step("external", files.length);
  await run.builtins(builtins, { cfg, appDir, fetch: opts.fetch, now, inv, deadline, refresh: !!opts.refreshVulnIntel });

  step("finish", files.length);
  let findings = run.finish();
  const ignored = new Set(opts.ignores === false ? [] : (await listIgnores(root, appDir)).map((e) => e.id));
  const before = findings.length;
  findings = findings.filter((f) => !ignored.has(f.id));
  run.stats.ignored = before - findings.length;
  const checked = template.rules.flatMap((r) => run.checked.get(r.id) ?? []);
  const result: ScanResult = {
    engine_version: ENGINE_VERSION,
    template_id: template.id,
    scan_at: new Date(now).toISOString(),
    findings,
    checked,
    stats: run.stats,
    ...(run.vulnintel && { vulnintel: run.vulnintel }),
  };
  if (opts.recheck === false) return result;

  const locks = await lockStates(inv, files);
  const snap = await readSnapshot(root, appDir);
  const base = snap ?? (await readLastScan(root, appDir));
  if (base) {
    const r = compareWith(base, snap ? "fix_request" : "previous", findings, checked, locks, ignored);
    result.findings = r.findings.sort(byPriority);
    result.compare = r.compare;
  }
  const stored: StoredScan = {
    scan_id: randomUUID(),
    scan_at: result.scan_at,
    template_id: template.id,
    engine_version: ENGINE_VERSION,
    findings: findings.map(storedFinding),
    checked,
    locks,
  };
  await writeJson(await lastScanFile(appDir, root), stored);
  return result;
}

/** Fix items first: confidence, severity, then KEV → VPI → EPSS → CVSS (§7-3), then location. */
export function byPriority(a: Finding, b: Finding): number {
  return (
    CONF_RANK[a.confidence] - CONF_RANK[b.confidence] ||
    SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
    Number(b.kev ?? false) - Number(a.kev ?? false) ||
    (b.vpi_level ?? 0) - (a.vpi_level ?? 0) ||
    (b.epss ?? 0) - (a.epss ?? 0) ||
    (b.cvss ?? 0) - (a.cvss ?? 0) ||
    cmp(a.location?.file ?? "", b.location?.file ?? "") ||
    (a.location?.line ?? 0) - (b.location?.line ?? 0) ||
    cmp(a.rule_id, b.rule_id) ||
    cmp(a.id, b.id)
  );
}

interface AddArgs {
  ruleId: string;
  title: string;
  file: string | null;
  line: number | null;
  valueHash: string;
  severity: Severity;
  confidence: Confidence;
  notes: NoteCode[];
  masked?: string;
  secret?: boolean;
  build?: boolean;
  kind?: string;
  extra?: Partial<Finding>;
}

class Run {
  readonly checked = new Map<string, CheckedRule>();
  readonly stats: ScanStats = {
    files: 0,
    skipped: { too_large: 0, binary: 0, utf16: 0, long_line: 0, unreadable: 0, parse_error: 0 },
    allowed_public_keys: 0,
    ignored: 0,
    timed_out: [],
  };
  private readonly findings = new Map<string, Finding>();
  private readonly buildIds = new Set<string>();
  private readonly envStates = new Map<string, Promise<"unknown" | "local-only" | "normal">>();

  constructor(
    readonly root: string,
    readonly files: FileEntry[],
    readonly git: GitInfo,
    readonly lang: Lang,
    private readonly key: Buffer,
  ) {
    this.stats.files = files.length;
  }

  /** Keyed value hash (per-install HMAC-SHA256): stable for recheck pairing, not brute-forceable offline. */
  hv(value: string | Uint8Array): string {
    return createHmac("sha256", this.key).update(value).digest("hex");
  }

  private title(name: { ko?: string; en?: string } | undefined, fallback: string): string {
    return name?.[this.lang] ?? name?.en ?? name?.ko ?? fallback;
  }

  async textRules(patterns: PatternRule[], configs: ConfigRule[]): Promise<void> {
    // Config `review` regexes run in the worker too (spec slots after the pattern rules).
    const runner = new RegexRunner([
      ...patterns.map((r) => ({ match: r.match, review: r.review, allow: r.allow })),
      ...configs.map((r) => ({ match: r.review, review: [], allow: [] })),
    ]);
    const spent = new Map<number, number>();
    const over = new Set<number>();
    const partial = new Set<number>();
    const requireSeen = new Map<number, string>();
    const requireHit = new Set<number>();
    // Value rules first so the late rules can skip lines they already decided (§6-4).
    const late = (k: number): number => Number(LATE_RULES.has(patterns[k]!.id));
    try {
      for (const f of this.files) {
        const pIdx = patterns.flatMap((r, k) => (!over.has(k) && applies(r, f) ? [k] : [])).sort((a, b) => late(a) - late(b));
        const cIdx = configs.flatMap((r, k) => (applies(r, f) ? [k] : []));
        if (pIdx.length === 0 && cIdx.length === 0) continue;
        const t = await readText(f.abs);
        if ("skip" in t) {
          this.stats.skipped[t.skip]++;
          continue;
        }
        if (pIdx.length) {
          const res = await runner.run(t.text, pIdx);
          for (const [k, ms] of res.ms) {
            const total = (spent.get(k) ?? 0) + ms;
            spent.set(k, total);
            if (total > RULE_TOTAL_LIMIT_MS) over.add(k);
          }
          for (const k of res.timedOut) {
            partial.add(k);
            this.stats.timed_out.push({ rule_id: patterns[k]!.id, file: f.rel });
          }
          const occupied = new Set<number>();
          for (const k of pIdx) {
            const rule = patterns[k]!;
            const found = res.matches.get(k);
            if (!found) continue;
            if (rule.mode === "require") {
              if (!requireSeen.has(k)) requireSeen.set(k, f.rel);
              if (found.length) requireHit.add(k);
              continue;
            }
            for (const m of found) await this.patternMatch(rule, f, t.text, m, occupied);
          }
        }
        for (const k of cIdx) await this.configMatch(configs[k]!, f, t.text, runner, patterns.length + k);
      }
    } finally {
      runner.close();
    }
    // A .gitignore above CWD (monorepo subfolder) can cover the .env files: ask git.
    const envFiles = this.files.filter((f) => !f.build && isEnvFile(f.rel)).map((f) => f.rel);
    const envIgnored =
      patterns.some((r) => r.id === "gitignore-env-missing") &&
      envFiles.length > 0 &&
      (await this.git.ignored(envFiles)).size === envFiles.length;
    patterns.forEach((rule, k) => {
      if (over.has(k) || partial.has(k)) {
        this.checked.set(rule.id, { rule_id: rule.id, ran: true, reason: over.has(k) ? "timeout" : "timeout_partial" });
      }
      // A required pattern missing everywhere is the finding — unless a timeout makes that unknowable.
      if (rule.mode === "require" && !requireHit.has(k) && !over.has(k) && !partial.has(k)) {
        if (rule.id === "gitignore-env-missing" && envIgnored) return;
        this.add({
          ruleId: rule.id, title: this.title(rule.name, rule.id), file: requireSeen.get(k) ?? literalPath(rule.files[0]), line: null, valueHash: this.hv(""),
          severity: rule.severity, confidence: "confirmed", notes: [],
        });
      }
    });
  }

  private async patternMatch(rule: PatternRule, f: FileEntry, text: string, m: RawMatch, occupied: Set<number>): Promise<void> {
    const secret = isSecretRule(rule);
    const isLate = LATE_RULES.has(rule.id);
    const line = lineAt(text, m.index);
    if (isLate && occupied.has(line)) return;
    // Settings mentioned in comments are not in effect; secrets in comments still leak.
    if (!secret && /^\s*(#|\/\/|\/\*|\*|<!--|;|!)/.test(lineTextAt(text, m.index))) return;
    let value = m.value;
    let severity = rule.severity;
    let confidence: Confidence = m.review ? "review" : "confirmed";
    const notes: NoteCode[] = [];
    if (secret && !isLate) {
      if (isPlaceholder(value)) return;
      const verdict = allowlisted(value, text.slice(Math.max(0, m.index - 600), m.index + value.length + 600));
      if (verdict === "public") {
        this.stats.allowed_public_keys++;
        occupied.add(line);
        return;
      }
      if (verdict === "legacy_anon") {
        confidence = "info";
        notes.push("legacy_anon_key");
      } else if (rule.jwt_claims) {
        const claims = decodeJwtPayload(value);
        if (claims && !Object.entries(rule.jwt_claims).every(([k, v]) => claims[k] === v)) return;
      }
    }
    const refine = REFINERS[rule.id];
    if (refine) {
      const r = refine({ file: f, text, value, index: m.index, lineText: lineTextAt(text, m.index), severity, confidence, files: this.files });
      if (!r) return;
      severity = r.severity;
      confidence = lower(confidence, r.confidence);
      notes.push(...(r.notes ?? []));
      value = r.value ?? value;
    }
    confidence = await this.adjustByPath(f.rel, confidence, secret ? (isLate ? "late" : "value") : "other", notes);
    if (secret && !isLate) occupied.add(line);
    this.add({
      ruleId: rule.id, title: this.title(rule.name, rule.id), file: f.rel, line, valueHash: this.hv(value), severity, confidence, notes, masked: mask(value), secret, build: f.build,
    });
  }

  private async configMatch(rule: ConfigRule, f: FileEntry, text: string, runner: RegexRunner, slot: number): Promise<void> {
    let data: unknown;
    try {
      data = parseConfig(rule.format, text);
    } catch {
      this.stats.skipped.parse_error++;
      return;
    }
    const v = configValue(rule.format, data, rule.key);
    if (v === undefined || v === null || typeof v === "object") return;
    const sv = String(v);
    let confidence: Confidence = "confirmed";
    if (sv !== String(rule.equals)) {
      if (rule.review.length === 0 || !(await runner.run(sv, [slot])).matches.get(slot)?.length) return;
      confidence = "review";
    }
    const last = rule.key.split(".").pop()!;
    const idx = text.split("\n").findIndex((l) => l.includes(rule.format === "dotenv" || rule.format === "properties" ? rule.key : last));
    const notes: NoteCode[] = [];
    confidence = await this.adjustByPath(f.rel, confidence, "other", notes);
    const value = `${rule.key}=${sv}`;
    this.add({
      ruleId: rule.id, title: this.title(rule.name, rule.id), file: f.rel, line: idx >= 0 ? idx + 1 : null, valueHash: this.hv(value), severity: rule.severity, confidence, notes, masked: mask(value),
    });
  }

  async fileRule(rule: FileRule): Promise<void> {
    const inScope = (rel: string): boolean => matchAny(rule.files, rel) && !matchAny(rule.exclude, rel);
    const onDisk = new Set(this.files.filter((f) => inScope(f.rel)).map((f) => f.rel));
    let paths = [...onDisk];
    if (rule.git === "tracked") {
      paths = paths.filter((p) => this.git.tracked.has(p));
      if (rule.content_check) {
        // §6-5 env-committed: tracked now, or present anywhere in history (all refs).
        const hist = await this.git.historyPaths(rule.files.flatMap(globToPathspecs));
        for (const p of [...hist].sort()) if (inScope(p) && !isSkippedPath(p) && !paths.includes(p)) paths.push(p);
      }
    }
    if (rule.expect === "present") {
      if (paths.length === 0) {
        this.add({
          ruleId: rule.id, title: this.title(rule.name, rule.id), file: literalPath(rule.files[0]), line: null, valueHash: this.hv(""), severity: rule.severity, confidence: "confirmed", notes: [],
        });
      }
      return;
    }
    let hidden: boolean | undefined;
    for (const p of paths) {
      const notes: NoteCode[] = [];
      let confidence: Confidence = "confirmed";
      let valueHash: string;
      let content: Buffer | null = null;
      if (rule.content_check) {
        // History judgment: the same path stays in history whatever the working tree holds now.
        valueHash = this.hv(`path:${p}`);
        content = onDisk.has(p) ? await readTextBuffer(join(this.root, p)) : await this.git.lastHistoryContent(p);
      } else if (onDisk.has(p)) {
        valueHash = await this.hashFile(join(this.root, p));
      } else {
        content = await this.git.lastHistoryContent(p);
        valueHash = this.hv(content ?? "");
      }
      if (rule.git === "tracked" && !this.git.tracked.has(p)) notes.push("history_only");
      if (rule.content_check && content) {
        const t = decode(content);
        if ("text" in t && envHasOnlyPublicValues(parseDotenv(t.text))) {
          confidence = "info";
          notes.push("public_values_only");
        }
      }
      if (rule.id === "sourcemap-in-build") {
        hidden ??= await this.anyHiddenSourcemapConfig();
        const nextDir = /^(.*\/)?\.next\/static\//.exec(p);
        if (hidden) {
          confidence = "info";
          notes.push("hidden_sourcemap");
        } else if (nextDir && this.files.some((f) => f.rel.startsWith(`${nextDir[0]}development/`))) {
          confidence = "info";
          notes.push("dev_build");
        }
      }
      if (isTestPath(p) && CONF_RANK[confidence] < CONF_RANK.review) {
        confidence = "review";
        notes.push("test_path");
      }
      this.add({ ruleId: rule.id, title: this.title(rule.name, rule.id), file: p, line: null, valueHash, severity: rule.severity, confidence, notes });
    }
  }

  private async anyHiddenSourcemapConfig(): Promise<boolean> {
    for (const f of this.files) {
      if (f.build || !/(^|\/)(vite|webpack|next)\.config\.[cm]?[jt]s$/.test(f.rel)) continue;
      const t = await readText(f.abs);
      if ("text" in t && hiddenSourcemapConfig(f.rel, t.text)) return true;
    }
    return false;
  }

  /** §5 path classes: local-only .env* → info, example/doc → info, test paths → review. Only ever lowers. */
  private async adjustByPath(rel: string, conf: Confidence, kind: "value" | "late" | "other", notes: NoteCode[]): Promise<Confidence> {
    const to = (target: Confidence, note: NoteCode | null): void => {
      if (CONF_RANK[target] > CONF_RANK[conf]) {
        conf = target;
        if (note) notes.push(note);
      }
    };
    if (kind === "value" && isEnvFile(rel)) {
      const st = await this.envState(rel);
      if (st === "local-only") to("info", "local_only_env");
      else if (st === "unknown") to("review", null); // not a git repo: tracking unknown
    }
    if (kind !== "late" && isExampleOrDoc(rel)) to("info", "example_or_doc");
    if (isTestPath(rel)) to("review", "test_path");
    return conf;
  }

  /** H5: a .env* that is gitignored, untracked and never in history is a local-only file. */
  private envState(rel: string): Promise<"unknown" | "local-only" | "normal"> {
    let p = this.envStates.get(rel);
    if (!p) {
      p = (async () => {
        if (!this.git.isRepo) return "unknown";
        if (this.git.tracked.has(rel)) return "normal";
        if ((await this.git.historyPaths([":(glob)**/.env*"])).has(rel)) return "normal";
        return (await this.git.ignored([rel])).has(rel) ? "local-only" : "normal";
      })();
      this.envStates.set(rel, p);
    }
    return p;
  }

  add(a: AddArgs): void {
    const id = fingerprint(a.ruleId, a.file ?? "", a.valueHash);
    const prev = this.findings.get(id);
    if (prev && (prev.location?.line ?? 0) <= (a.line ?? 0)) return; // keep the first occurrence
    this.findings.set(id, {
      id,
      rule_id: a.ruleId,
      severity: a.severity,
      confidence: a.confidence,
      title: a.title,
      location: a.file === null ? null : { file: a.file, line: a.line },
      ...(a.masked !== undefined && { masked_match: a.masked }),
      ...(a.secret && { secret_kind: a.ruleId }),
      value_hash: a.valueHash,
      source: "local",
      ...(a.notes.length && { notes: [...new Set(a.notes)] }),
      ...(a.kind && { kind: a.kind }),
      ...a.extra,
    });
    if (a.build) this.buildIds.add(id);
    else this.buildIds.delete(id);
  }

  hashFile(abs: string): Promise<string> {
    return new Promise((res) => {
      const h = createHmac("sha256", this.key);
      createReadStream(abs)
        .on("data", (c) => h.update(c))
        .on("end", () => res(h.digest("hex")))
        .on("error", () => res(this.hv("")));
    });
  }

  /** Stage-4 builtins (§7-1~7-3). External lookups only after consent (§3-1). */
  vulnintel: ViScanStatus | undefined;

  async builtins(
    rules: BuiltinRule[],
    o: { cfg: LocalConfig; appDir: string; fetch?: Fetch; now: number; inv: Inventory; deadline: number; refresh: boolean },
  ): Promise<void> {
    if (rules.length === 0) return;
    const on = (id: string): BuiltinRule | undefined => rules.find((r) => r.id === id);
    const texts = new Map<string, Promise<string | null>>();
    const byRel = new Map(this.files.map((f) => [f.rel, f]));
    const text = (rel: string): Promise<string | null> => {
      let t = texts.get(rel);
      if (!t) {
        const f = byRel.get(rel);
        t = f ? readText(f.abs).then((r) => ("text" in r ? r.text : null)) : Promise.resolve(null);
        texts.set(rel, t);
      }
      return t;
    };
    const inv = o.inv;
    const ctx: BuiltinCtx = {
      files: this.files,
      text,
      findings: [...this.findings.values()],
      now: o.now,
      npmDeps: new Set(inv.manifests.flatMap((m) => (m.ecosystem === "npm" ? m.deps.map((d) => d.name) : []))),
    };
    const out: BF[] = [];
    if (on("supabase-rls")) out.push(...(await supabaseRls(ctx)));
    if (on("firebase-rules")) out.push(...(await firebaseRules(ctx)));
    const vuln = on("vulnerable-deps");
    const hall = on("hallucinated-package");
    if (vuln || hall) {
      const priv = inv.privateConfig;
      const workspace = new Set(inv.manifests.flatMap((m) => (m.name ? [m.name] : [])));
      // Import names go through the same private-registry exclusions as manifest names (§7-2).
      const imports = hall
        ? [...(await jsImports(this.files, text, workspace)), ...(await pyImports(this.files, text))].filter(
            (i) => !priv.allPrivate.includes(i.ecosystem) && !(i.name.startsWith("@") && priv.npmScopes.includes(i.name.split("/")[0]!.toLowerCase())),
          )
        : [];
      const ext = o.cfg.external ?? {};
      let net: NetCtx | null = null;
      if (hasConsent(o.cfg)) {
        net = {
          http: defaultHttp(o.fetch),
          budget: new ViBudget(o.appDir, { keyMode: !!apiKeyOf(o.cfg) }),
          lang: this.lang,
          osv: ext.osv !== false,
          registry: ext.registry !== false,
          vulnintel: ext.vulnintel !== false,
          caches: {
            registry: await Cache.open(o.appDir, "registry"),
            osv: await Cache.open(o.appDir, "osv"),
            vi: await Cache.open(o.appDir, "vulnintel"),
            viScan: await Cache.open(o.appDir, "vulnintel-scan"),
          },
          deadline: o.deadline,
          ...(apiKeyOf(o.cfg) && { key: apiKeyOf(o.cfg) }),
          refreshVulnIntel: o.refresh,
        };
      }
      const r = await depsBuiltins(ctx, {
        inv,
        scope: lookupScope(inv),
        imports,
        text,
        vuln: !!vuln,
        hall: !!hall,
        params: (hall?.params ?? {}) as { allow?: string[]; min_weekly_downloads?: number },
        net,
        now: o.now,
      });
      out.push(...r.findings);
      if (vuln && r.vuln) this.checked.set(vuln.id, { rule_id: vuln.id, ran: false, reason: r.vuln });
      if (hall && r.hall) this.checked.set(hall.id, { rule_id: hall.id, ran: false, reason: r.hall });
      this.vulnintel = r.vulnintel;
      if (net) {
        await net.caches.registry.save(86_400_000, o.now);
        await net.caches.osv.save(7 * 86_400_000, o.now);
        await net.caches.vi.save(86_400_000, o.now);
        await net.caches.viScan.save(Number.MAX_SAFE_INTEGER, o.now);
      }
    }
    for (const b of out) {
      const t = KIND_TEXT[`${b.rule}/${b.kind}`];
      this.add({
        ruleId: b.rule,
        title: this.title(t?.title ?? BUILTIN_NAMES[b.rule], b.rule),
        file: b.file,
        line: b.line,
        valueHash: this.hv(b.value),
        severity: on(b.rule)?.severity ?? b.severity,
        confidence: b.confidence,
        notes: b.notes ?? [],
        kind: b.kind,
        ...(b.extra && { extra: b.extra }),
      });
    }
  }

  finish(): Finding[] {
    // §5: a secret in source and in the browser build is one source finding + "also in build output".
    const source = new Map<string, Finding>();
    for (const f of this.findings.values()) if (!this.buildIds.has(f.id)) source.set(`${f.rule_id}\0${f.value_hash}`, f);
    for (const id of this.buildIds) {
      const b = this.findings.get(id)!;
      const s = source.get(`${b.rule_id}\0${b.value_hash}`);
      if (s && s.secret_kind) {
        this.findings.delete(id);
        s.notes = [...new Set([...(s.notes ?? []), "in_build_output" as const])];
      }
    }
    return [...this.findings.values()].sort(byPriority);
  }
}

async function readTextBuffer(abs: string): Promise<Buffer | null> {
  try {
    return (await stat(abs)).size > MAX_FILE_BYTES ? null : await readFile(abs);
  } catch {
    return null;
  }
}
