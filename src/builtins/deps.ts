// builtin vulnerable-deps (§7-3) and hallucinated-package (§7-2). Network goes only to the
// services in the §3-1 table, only after consent, and only with names in the §7-2 lookup scope.

import { readFileSync } from "node:fs";
import type { Inventory, LookupScope } from "../deps/inventory.js";
import { normalizePyName } from "../deps/locks.js";
import type { ViBudget } from "../net/budget.js";
import { mapLimit, type Cache, type Http } from "../net/http.js";
import { osvQueryBatch, osvVuln, type OsvVuln } from "../net/osv.js";
import { npmAbbrev, npmCreated, npmWeeklyDownloads, pypiExists, releasedAt, type Exists } from "../net/registry.js";
import { publicLookup } from "../net/vulnintel.js";
import { viScan, type ViPackage, type ViScanStatus } from "./vi-scan.js";
import type { CheckedRule, Finding, Lang, NoteCode, Severity } from "../types.js";
import { cmpVersion, cvss3Score, major } from "../versions.js";
import type { BF, BuiltinCtx } from "./backend.js";
import type { ImportRef } from "./imports.js";

const DAY = 86_400_000;
const PUBLIC_LOOKUP_CAP = 200;
const VI_BURST = 15;
const VI_INTERVAL_MS = 1200;
/** B1: rounds of "ask OSV about the candidate fixed versions" (a dirty candidate can reveal newer fixes). */
const FIX_ROUNDS = 4;
/** Above this, timers overflow; requestJson's own 30 s timeout bounds such waits anyway. */
const MAX_TIMER_MS = 2 ** 31 - 1;

export interface NetCtx {
  http: Http;
  budget: ViBudget;
  lang: Lang;
  osv: boolean;
  registry: boolean;
  vulnintel: boolean;
  caches: { registry: Cache; osv: Cache; vi: Cache; viScan: Cache };
  /** Real-clock deadline (ms since epoch). Work not started by then is left for the next scan. */
  deadline: number;
  /** VulnIntel key (key mode: upload instead of OSV vulnerability details, §7-3). */
  key?: string;
  refreshVulnIntel?: boolean;
}

const late = (net: NetCtx): boolean => Date.now() >= net.deadline;

/** Requests and waits still running at the deadline end there too (B15: in-flight calls overran the MCP budget). */
function untilDeadline(h: Http, deadline: number): Http {
  return {
    ...h,
    fetch: (url, init) => {
      const left = Math.max(0, deadline - Date.now());
      if (left >= MAX_TIMER_MS) return h.fetch(url, init);
      const stop = AbortSignal.timeout(left);
      return h.fetch(url, { ...init, signal: init?.signal ? AbortSignal.any([init.signal, stop]) : stop });
    },
    sleep: (ms) => h.sleep(Math.max(0, Math.min(ms, deadline - Date.now()))),
  };
}

export interface DepsInput {
  inv: Inventory;
  scope: LookupScope;
  imports: ImportRef[];
  /** Read a manifest text (to find the line of a name). */
  text(rel: string): Promise<string | null>;
  vuln: boolean;
  hall: boolean;
  params: { allow?: string[]; min_weekly_downloads?: number };
  /** null = no consent yet: local judgments only. */
  net: NetCtx | null;
  now: number;
}

type Reason = CheckedRule["reason"] | undefined;
export interface DepsOut {
  findings: BF[];
  vuln: Reason;
  hall: Reason;
  vulnintel?: ViScanStatus;
}

let popular: { set: Set<string>; byLen: Map<number, string[]> } | undefined;
function popularNames(): { set: Set<string>; byLen: Map<number, string[]> } {
  if (!popular) {
    const names = (JSON.parse(readFileSync(new URL("../../data/npm-high-impact.json", import.meta.url), "utf8")) as { names: string[] }).names;
    const byLen = new Map<number, string[]>();
    for (const n of names) byLen.set(n.length, [...(byLen.get(n.length) ?? []), n]);
    popular = { set: new Set(names), byLen };
  }
  return popular;
}

/** Levenshtein distance capped at 3 (band 2). */
export function lev2(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j]! + 1, cur[j - 1]! + 1, prev[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]!);
    }
    if (best > 2) return 3;
    prev = cur;
  }
  return Math.min(prev[b.length]!, 3);
}

function nearPopular(name: string): string | null {
  const p = popularNames();
  if (p.set.has(name) || name.length < 4) return null;
  for (let L = name.length - 2; L <= name.length + 2; L++) for (const n of p.byLen.get(L) ?? []) if (lev2(name, n) <= 2) return n;
  return null;
}

async function lineOfName(text: (rel: string) => Promise<string | null>, file: string, name: string): Promise<number | null> {
  const t = await text(file);
  if (!t) return null;
  const i = t.search(new RegExp(`(^|["'\\s\\[])${name.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")}(["'\\s=<>~!;\\[]|$)`, "im"));
  return i < 0 ? null : t.slice(0, i + 1).split("\n").length;
}

export async function depsBuiltins(ctx: BuiltinCtx, d: DepsInput): Promise<DepsOut> {
  const out: BF[] = [];
  let vuln: Reason;
  let hall: Reason;
  const { inv, scope } = d;
  const net: NetCtx | null = d.net && { ...d.net, http: untilDeadline(d.net.http, d.net.deadline) };

  // ---- local: version unknown / unreadable or unsupported lock (§7-3)
  if (d.vuln) {
    // Any lock of the manifest's ecosystem in its folder or above covers it: parsed ones are checked,
    // broken / not-yet-supported ones get their own item below — never "no lock file" (B3, B8).
    const locks = inv.lockfiles.filter((l) => l.kind !== "requirements");
    const lockDirs = new Set([...locks.map((l) => `${lockEco(l.kind)}\0${dirOf(l.path)}`), ...inv.unsupported.map((u) => `${unsupportedEco(u.kind)}\0${dirOf(u.path)}`)]);
    const reqDirs = new Set(inv.lockfiles.filter((l) => l.kind === "requirements").map((l) => dirOf(l.path)));
    // Next to a parsed lock of its ecosystem (1c E4: bun.lock + package-lock.json) the unsupported one is only a note.
    const parsed = new Set(locks.filter((l) => l.status === "ok").map((l) => `${lockEco(l.kind)}\0${dirOf(l.path)}`));
    for (const u of inv.unsupported) {
      const eco = unsupportedEco(u.kind);
      const beside = parsed.has(`${eco}\0${dirOf(u.path)}`) || (eco === "PyPI" && reqDirs.has(dirOf(u.path)));
      out.push({ rule: "vulnerable-deps", kind: "unsupported_lock", severity: "medium", confidence: beside ? "info" : "review", file: u.path, line: null, value: `unsupported:${u.kind}` });
    }
    for (const l of inv.lockfiles) {
      if (l.status === "ok") continue;
      out.push({ rule: "vulnerable-deps", kind: l.status === "regenerate" ? "lock_regenerate" : "lock_unreadable", severity: "medium", confidence: "review", file: l.path, line: null, value: `${l.status}:${l.path}:${l.detail ?? ""}` });
    }
    for (const m of inv.manifests) {
      if (m.deps.length === 0) continue;
      const dir = dirOf(m.path);
      const covered = ancestors(dir).some((a) => lockDirs.has(`${m.ecosystem}\0${a}`)) || (m.ecosystem === "PyPI" && reqDirs.has(dir));
      if (!covered) out.push({ rule: "vulnerable-deps", kind: "version_unknown", severity: "medium", confidence: "review", file: m.path, line: null, value: `unlocked:${m.path}` });
    }
    // An unpinned requirements name that a parsed uv.lock in the same folder or above pins is covered by that lock.
    const uvPinned = new Map<string, Set<string>>();
    for (const l of locks) if (l.kind === "uv" && l.status === "ok") uvPinned.set(dirOf(l.path), new Set(l.packages.filter((p) => p.version !== null).map((p) => p.name)));
    for (const l of inv.lockfiles) {
      if (l.kind === "requirements" && l.packages.some((p) => p.version === null && !ancestors(dirOf(l.path)).some((a) => uvPinned.get(a)?.has(p.name)))) {
        out.push({ rule: "vulnerable-deps", kind: "version_unpinned", severity: "medium", confidence: "review", file: l.path, line: null, value: `unpinned:${l.path}` });
      }
    }
  }

  const allow = new Set(d.params.allow ?? []);
  const targets = scope.targets.filter((t) => !allow.has(t.name));
  const versioned = targets.filter((t) => t.version !== null);

  let enriching: Promise<void> = Promise.resolve();
  let vulnPkgs: VulnPkg[] = [];

  // ---- key mode: VulnIntel scan job for vulnerabilities (OSV still runs for MAL-)
  let viPackages: ViPackage[] | null = null;
  let viStatus: ViScanStatus | undefined;
  if (d.vuln && net?.key) {
    const r = await viScan(inv, {
      http: net.http, budget: net.budget, key: net.key, lang: net.lang, cache: net.caches.viScan, now: d.now, deadline: net.deadline,
      ...(net.refreshVulnIntel && { refresh: true }),
    });
    viPackages = r.packages;
    viStatus = r.status;
  }

  // ---- OSV (vulnerabilities + MAL-)
  const vulnsByTarget = new Map<number, { id: string; modified: string }[]>();
  if (!net) {
    vuln = d.vuln ? "no_consent" : undefined;
  } else if (!net.osv) {
    vuln = d.vuln ? "external_disabled" : undefined;
  } else if (versioned.length && late(net)) {
    vuln = "timeout_partial";
  } else if (versioned.length) {
    const r = await osvQueryBatch(net.http, versioned.map((t) => ({ ecosystem: t.ecosystem, name: t.name, version: t.version! })));
    if (r.offline || r.results.some((x) => x === null)) vuln = late(net) ? "timeout_partial" : "offline";
    r.results.forEach((ids, i) => ids && ids.length && vulnsByTarget.set(i, ids));
  }

  // MAL- → malicious, never fetch details for these (§8-1).
  if (d.hall) {
    for (const [i, ids] of vulnsByTarget) {
      const mal = ids.filter((v) => v.id.startsWith("MAL-")).map((v) => v.id);
      if (!mal.length) continue;
      const t = versioned[i]!;
      out.push({
        rule: "hallucinated-package", kind: "malicious", severity: "critical", confidence: "confirmed", file: t.sources[0]!, line: null,
        value: `${t.ecosystem}:${t.name}@${t.version}:mal`, extra: { ...pkgFields(t), vuln_ids: mal.sort(), source: "osv" },
      });
    }
  }

  if (viPackages) {
    // VulnIntel answered: its result replaces OSV details for vulnerabilities.
    if (vuln === "offline" || vuln === "external_disabled") vuln = undefined;
    const byKey = new Map(versioned.map((t) => [pkgKey(t.ecosystem, t.name) + "@" + t.version, t]));
    const pkgs: VulnPkg[] = [];
    for (const p of viPackages) {
      const t = byKey.get(pkgKey(p.ecosystem.toLowerCase() === "pypi" ? "PyPI" : p.ecosystem, p.name) + "@" + p.version);
      const vulns = p.vulns.filter((v) => !v.id.startsWith("MAL-"));
      if (!t || !vulns.length) continue;
      pkgs.push({
        t,
        ids: vulns.map((v) => ({ id: v.id, modified: "" })),
        unknownOnly: vulns.every((v) => v.unknown),
        vulns: vulns.map((v) => ({
          id: v.id,
          modified: "",
          aliases: v.aliases,
          kev: v.kev,
          ...(v.severity && { osvSeverity: v.severity }),
          ...(v.cvss !== undefined && { cvss: v.cvss }),
          fixed: { [pkgKey(t.ecosystem, t.name)]: v.fixed },
          ...(v.vpi !== undefined && { vi: { kev: v.kev, vpi: v.vpi, epss: v.epss ?? null, cvss: v.cvss ?? null } }),
        })),
        fromVulnIntel: true,
      });
    }
    if (net) enriching = Promise.all([enrich(pkgs, net, d.now), verifyFixes(pkgs, net, d.now)]).then(() => undefined);
    vulnPkgs = pkgs;
  } else if (d.vuln && net && vulnsByTarget.size) {
    const pkgs: VulnPkg[] = [];
    for (const [i, ids] of vulnsByTarget) {
      const real = ids.filter((v) => !v.id.startsWith("MAL-"));
      if (real.length) pkgs.push({ t: versioned[i]!, ids: real, vulns: [] });
    }
    const details = await osvDetails(pkgs.flatMap((p) => p.ids), net, d.now);
    for (const p of pkgs) p.vulns = p.ids.map((v) => details.get(v.id)).filter((x): x is Detail => !!x);
    if (pkgs.some((p) => p.vulns.length < p.ids.length) && late(net) && !vuln) vuln = "timeout_partial";

    // Both run while the registry phase below runs (different hosts).
    enriching = Promise.all([enrich(pkgs, net, d.now), verifyFixes(pkgs, net, d.now)]).then(() => undefined);
    vulnPkgs = pkgs;
  }

  // ---- registry existence / heuristics (§7-2, §8-2)
  if (d.hall) {
    if (!net) hall = "no_consent";
    else if (!net.registry) hall = "external_disabled";
    else {
      const importOnly = d.imports.filter((i) => i.lookup && !targets.some((t) => t.ecosystem === i.ecosystem && t.name === i.name));
      const lookups = [
        ...targets.map((t) => ({ eco: t.ecosystem, name: t.name, version: t.version, file: t.sources[0]!, fromLock: t.version !== null && !isManifest(t.sources[0]!), line: null as number | null, dev: t.dev })),
        ...importOnly.filter((i) => !allow.has(i.name)).map((i) => ({ eco: i.ecosystem, name: i.name, version: null, file: i.file, fromLock: false, line: i.line as number | null, dev: false })),
      ];
      const byName = new Map<string, typeof lookups>();
      // Manifest and import names first (likely hallucinations), lock-only names after.
      for (const l of [...lookups.filter((x) => !x.fromLock), ...lookups.filter((x) => x.fromLock)]) {
        byName.set(`${l.eco}\0${l.name}`, [...(byName.get(`${l.eco}\0${l.name}`) ?? []), l]);
      }
      let offline = false;
      let partial = false;
      const reg = new Map<string, Reg>();
      await mapLimit([...byName.keys()], 4, async (key) => {
        const [eco, name] = key.split("\0") as ["npm" | "PyPI", string];
        const cached = net.caches.registry.get<Reg>(key, DAY, d.now);
        if (cached) return void reg.set(key, cached);
        if (late(net)) {
          partial = true;
          return;
        }
        let r: Reg;
        if (eco === "npm") {
          const a = await npmAbbrev(net.http, name);
          const scripts: Record<string, boolean> = {};
          for (const [v, m] of Object.entries(a.body?.versions ?? {})) if (m?.hasInstallScript) scripts[v] = true;
          r = { s: a.s, latest: a.body?.["dist-tags"]?.latest, scripts };
        } else r = { s: await pypiExists(net.http, name), scripts: {} };
        if ((r.s === "offline" || r.s === "error") && late(net)) {
          partial = true; // cut off by the deadline, not a real failure
          return;
        }
        if (r.s === "offline") offline = true;
        if (r.s === "ok" || r.s === "missing") net.caches.registry.set(key, r, d.now);
        reg.set(key, r);
      });
      if (offline) hall = "offline";
      else if (partial) hall = "timeout_partial";
      const minWeekly = d.params.min_weekly_downloads ?? 1000;
      for (const [key, ls] of byName) {
        const r = reg.get(key);
        if (!r) continue; // not looked up before the deadline
        const l = ls[0]!;
        const fields = { ecosystem: l.eco, package: l.name, ...(l.version && { version: l.version }), source: "registry" as const };
        const line = l.line ?? (isManifest(l.file) ? await lineOfName(d.text, l.file, l.name) : null);
        if (r.s === "missing") {
          const removed = ls.every((x) => x.fromLock);
          out.push({ rule: "hallucinated-package", kind: removed ? "removed" : "not_found", severity: "high", confidence: "review", file: l.file, line, value: `${key}:404`, extra: fields });
          continue;
        }
        if (r.s !== "ok") continue;
        if (l.eco === "npm" && (r.latest === "0.0.1-security" || ls.some((x) => x.version === "0.0.1-security"))) {
          if (out.some((o) => o.kind === "malicious" && o.extra?.package === l.name && o.extra?.ecosystem === l.eco)) continue; // OSV MAL- already reported
          out.push({ rule: "hallucinated-package", kind: "malicious", severity: "critical", confidence: "confirmed", file: l.file, line, value: `${key}:security`, extra: fields });
          continue;
        }
        // Edit-distance heuristic — npm only (PyPI list unlicensed, U13: off).
        if (l.eco === "npm" && !late(net)) {
          const near = nearPopular(l.name);
          if (near) {
            // Same 24-hour cache entry as the existence check (§8-2).
            if (r.created === undefined) {
              r.created = await npmCreated(net.http, l.name);
              net.caches.registry.set(key, r, d.now);
            }
            const created = r.created;
            if (created && d.now - Date.parse(created) <= 30 * DAY) {
              if (r.weekly === undefined) {
                r.weekly = await npmWeeklyDownloads(net.http, l.name);
                net.caches.registry.set(key, r, d.now);
              }
              const weekly = r.weekly;
              if (weekly !== null && weekly < minWeekly) {
                const v = ls.find((x) => x.version)?.version ?? r.latest ?? "";
                const script = r.scripts[v] === true;
                out.push({
                  rule: "hallucinated-package", kind: "suspicious", severity: script ? "high" : "medium", confidence: "review", file: l.file, line,
                  value: `${key}:near:${near}`, extra: fields,
                });
              }
            }
          }
        }
      }
    }
    // Undeclared imports: info, never an "add it" suggestion (§7-2).
    const declared = new Set([...inv.manifests.flatMap((m) => m.deps.map((x) => `${m.ecosystem}\0${m.ecosystem === "PyPI" ? normalizePyName(x.name) : x.name}`)), ...inv.lockfiles.flatMap((l) => l.packages.map((p) => `${p.ecosystem}\0${p.name}`))]);
    for (const i of d.imports) {
      const key = `${i.ecosystem}\0${i.name}`;
      if (declared.has(key) || out.some((o) => o.value === `${key}:404`)) continue;
      out.push({ rule: "hallucinated-package", kind: "undeclared_import", severity: "medium", confidence: "info", file: i.file, line: i.line, value: `${key}:import`, extra: { ecosystem: i.ecosystem, package: i.name } });
    }
  }
  await enriching;
  // No fixed version: when was the installed version released? (compared with the advisories in vulnFinding)
  if (net?.registry) {
    await mapLimit(vulnPkgs.filter((p) => !fixOf(p) && p.vulns.some((v) => v.published)), 4, async (p) => {
      const key = `released:${pkgKey(p.t.ecosystem, p.t.name)}@${p.t.version}`;
      const hit = net.caches.registry.get<string>(key, DAY, d.now);
      if (hit || late(net)) return void (p.released = hit);
      const at = await releasedAt(net.http, p.t.ecosystem, p.t.name, p.t.version!);
      if (at) net.caches.registry.set(key, at, d.now);
      p.released = at ?? undefined;
    });
  }
  for (const p of vulnPkgs) out.push(vulnFinding(p, inv, net?.lang));
  return { findings: out, vuln, hall, ...(viStatus && { vulnintel: viStatus }) };
}

/**
 * Priority enrichment (§8-4/§8-5): whole packages in priority order (most severe first), so each
 * scan finishes packages instead of leaving one ID pending in every package (N4). Capped per scan,
 * paced to one call per VI_INTERVAL_MS (from call start) after a short burst; a full shared bucket
 * waits for a slot. Anything not done by the deadline is "priority pending" and continues from cache.
 */
async function enrich(pkgs: VulnPkg[], net: NetCtx, now: number): Promise<void> {
  if (!net.vulnintel) return;
  const order = [...pkgs].sort((a, b) => sevRank(baseSeverity(a)) - sevRank(baseSeverity(b)) || topCvss(b) - topCvss(a));
  let calls = 0;
  let last = 0;
  let stop = false;
  for (const p of order) {
    for (const v of p.vulns) {
      if (v.vi) continue; // B1 fields already came with the VulnIntel scan result
      const id = v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id;
      // KEV/VPI/EPSS/CVSS do not depend on the language: one entry per ID (switching ko/en must not re-ask).
      const hit = net.caches.vi.get<ViInfo | null>(id, DAY, now);
      if (hit !== undefined) {
        v.vi = hit ?? undefined;
        continue;
      }
      let r: Awaited<ReturnType<typeof publicLookup>> | undefined;
      while (!stop && calls < PUBLIC_LOOKUP_CAP) {
        const wait = calls >= VI_BURST || r ? Math.max(0, last + VI_INTERVAL_MS - Date.now()) : 0;
        if (Date.now() + wait >= net.deadline) break;
        if (wait) await net.http.sleep(wait);
        last = Date.now();
        r = await publicLookup(net.http, net.budget, id, net.lang);
        if (r.ok || r.reason !== "budget") break; // budget: the shared per-minute bucket is full — wait for a slot
      }
      if (!r || (!r.ok && (r.reason === "budget" || late(net)))) {
        p.pending = true; // out of time, calls or (after a 429/offline) allowed calls: the rest waits for the next scan
        stop = true;
        continue;
      }
      calls++;
      if (r.ok) {
        // The description is the only language-dependent field: kept per language, never re-asked for the other one.
        const text = r.value.description?.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\s]+/gu, " ").trim().slice(0, 1000);
        v.vi = { kev: r.value.is_kev, vpi: r.value.vpi_level, epss: r.value.epss, cvss: r.value.cvss, ...(text && { desc: { [net.lang]: text } }) };
        net.caches.vi.set(id, v.vi, now);
      } else if (r.reason === "not_found") net.caches.vi.set(id, null, now);
      else {
        p.failed = true;
        if (r.reason === "rate_limited" || r.reason === "offline") stop = true;
      }
    }
  }
}

/** OSV details by id (7-day cache keyed by `modified`); ids not fetched before the deadline are missing. */
async function osvDetails(ids: { id: string; modified: string }[], net: NetCtx, now: number): Promise<Map<string, Detail | null>> {
  const details = new Map<string, Detail | null>();
  await mapLimit([...new Map(ids.map((v) => [v.id, v])).values()], 8, async (v) => {
    if (late(net)) return; // left for the next scan (cards keep their ids, severity may be unknown)
    const cached = net.caches.osv.get<Detail>(v.id, 7 * DAY, now);
    if (cached?.ranges && cached.published !== undefined && cached.modified === v.modified) return void details.set(v.id, { ...cached }); // copy: priority data must not leak into the 7-day cache
    const raw = await osvVuln(net.http, v.id);
    const det = raw ? { ...toDetail(raw), modified: v.modified || raw.modified || "" } : null;
    if (det) net.caches.osv.set(v.id, { ...det }, now);
    details.set(v.id, det);
  });
  return details;
}

/**
 * B1: the suggested fixed version must itself be free of the package's known vulnerabilities —
 * including ones introduced after the current version, which the current version's vulns do not
 * show. Every candidate that escapes the known ranges is asked to OSV (querybatch, 24 h cache);
 * vulns found on a candidate join the range check and may bring newer candidates, for a few rounds.
 * A pick that was not asked by then (offline, deadline, round cap) shows as "fix_unverified".
 */
async function verifyFixes(pkgs: VulnPkg[], net: NetCtx, now: number): Promise<void> {
  for (const p of pkgs) {
    p.asked = new Map();
    p.other = [];
  }
  type Ask = { p: VulnPkg; c: string; ids?: { id: string; modified: string }[] | undefined };
  const cacheKey = (a: Ask): string => `fix:${pkgKey(a.p.t.ecosystem, a.p.t.name)}@${a.c}`;
  for (let round = 0; round < FIX_ROUNDS && net.osv && !late(net); round++) {
    const ask: Ask[] = pkgs.flatMap((p) => fixCandidates(p).filter((c) => !p.asked!.has(c)).map((c) => ({ p, c })));
    if (!ask.length) return;
    for (const a of ask) a.ids = net.caches.osv.get(cacheKey(a), DAY, now);
    const need = ask.filter((a) => !a.ids);
    let failed = false;
    if (need.length) {
      const r = await osvQueryBatch(net.http, need.map((a) => ({ ecosystem: a.p.t.ecosystem, name: a.p.t.name, version: a.c })));
      r.results.forEach((ids, i) => {
        if (!ids) return void (failed = true);
        need[i]!.ids = ids;
        net.caches.osv.set(cacheKey(need[i]!), ids, now);
      });
    }
    // MAL- on a candidate makes it dirty; its details are never fetched (§8-1).
    const fresh = ask.flatMap((a) => (a.ids ?? []).filter((v) => !v.id.startsWith("MAL-") && !knownIds(a.p).has(v.id)));
    const details = await osvDetails(fresh, net, now);
    for (const a of ask) {
      if (!a.ids) continue;
      a.p.asked!.set(a.c, a.ids.length === 0);
      for (const v of a.ids) {
        const det = details.get(v.id);
        if (det && !knownIds(a.p).has(v.id)) a.p.other!.push(det);
      }
    }
    if (failed) return;
  }
}

/** B1: candidates OSV reported vulnerable are out; a pick OSV was not asked about is marked fix_unverified. */
const fixOf = (p: VulnPkg): string | undefined => pickFix(fixCandidates(p).filter((c) => p.asked?.get(c) !== false), p.t.version!);
const knownIds = (p: VulnPkg): Set<string> => new Set([...p.vulns, ...(p.other ?? [])].map((v) => v.id));
const fixCandidates = (p: VulnPkg): string[] => safeFixes([...p.vulns, ...(p.other ?? [])], pkgKey(p.t.ecosystem, p.t.name), p.t.version!);
const lockEco = (kind: string): "npm" | "PyPI" => (kind === "uv" ? "PyPI" : "npm");
const unsupportedEco = (kind: string): "npm" | "PyPI" => (/^(poetry|pipenv)$/.test(kind) ? "PyPI" : "npm");

interface Reg {
  s: Exists;
  latest?: string;
  scripts: Record<string, boolean>;
  created?: string | null;
  weekly?: number | null;
}

interface ViInfo {
  kev: boolean;
  vpi: number | null;
  epss: number | null;
  cvss: number | null;
  /** Public lookup description by language (B2). */
  desc?: Partial<Record<Lang, string>>;
}

interface Detail {
  id: string;
  modified: string;
  /** OSV `published` ("" when the record has none); absent on VulnIntel results. */
  published?: string;
  aliases: string[];
  osvSeverity?: string;
  cvss?: number;
  /** "eco:name" → fixed versions */
  fixed: Record<string, string[]>;
  /** "eco:name" → affected ranges (OSV details only; VulnIntel results carry fixed versions only). */
  ranges?: Record<string, AffectedRange[]>;
  vi?: ViInfo;
  /** KEV flag from a VulnIntel scan result. */
  kev?: boolean;
}

/** One OSV ECOSYSTEM/SEMVER interval: [introduced, fixed) or [introduced, last_affected]; open when neither. */
interface AffectedRange {
  introduced: string;
  fixed?: string;
  last_affected?: string;
}

interface VulnPkg {
  t: LookupScope["targets"][number];
  ids: { id: string; modified: string }[];
  vulns: Detail[];
  pending?: boolean;
  failed?: boolean;
  /** VulnIntel reported only unknown_vulnerabilities (version could not be judged) → review. */
  unknownOnly?: boolean;
  fromVulnIntel?: boolean;
  /** B1: vulns found on candidate fixed versions (not on the current one) — only for choosing the fix. */
  other?: Detail[];
  /** B1: candidate fixed version → OSV says it has no known vulnerability (true) / has some (false). */
  asked?: Map<string, boolean>;
  /** Registry release time of the installed version (looked up only when there is no fixed version). */
  released?: string;
}

const pkgKey = (eco: string, name: string): string => `${eco}:${eco === "PyPI" ? normalizePyName(name) : name}`;

function toDetail(v: OsvVuln): Detail {
  const fixed: Record<string, string[]> = {};
  const ranges: Record<string, AffectedRange[]> = {};
  for (const a of v.affected ?? []) {
    if (!a.package?.name || !a.package.ecosystem) continue;
    const k = pkgKey(a.package.ecosystem, a.package.name);
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue; // commit hashes, not versions
      let from: string | undefined;
      for (const e of r.events ?? []) {
        if (e.introduced !== undefined) from = e.introduced;
        if (e.fixed) (fixed[k] ??= []).push(e.fixed);
        if (from === undefined || !(e.fixed || e.last_affected)) continue;
        (ranges[k] ??= []).push({ introduced: from, ...(e.fixed ? { fixed: e.fixed } : { last_affected: e.last_affected! }) });
        from = undefined;
      }
      if (from !== undefined) (ranges[k] ??= []).push({ introduced: from });
    }
  }
  const scores = (v.severity ?? []).map((s) => (/^CVSS:3/.test(s.score) ? cvss3Score(s.score) : null)).filter((x): x is number => x !== null);
  const osvSeverity = v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  return {
    id: v.id,
    modified: v.modified ?? "",
    published: v.published ?? "",
    aliases: v.aliases ?? [],
    ...(osvSeverity && { osvSeverity: osvSeverity.toUpperCase() }),
    ...(scores.length && { cvss: Math.max(...scores) }),
    fixed,
    ranges,
  };
}

const SEV: Severity[] = ["critical", "high", "medium"];
const sevRank = (s: Severity): number => SEV.indexOf(s);

/**
 * Severity: KEV → critical, else the advisory's OSV severity or CVSS. VPI (and the public lookup's
 * CVSS) only badge and sort: a lookup that did not finish in time must not change the severity scale
 * between scans (VPI 2 once read "high" from OSV, then "medium" from VPI on the next scan).
 */
function vulnSeverity(v: Detail): { sev: Severity; known: boolean } {
  if (v.vi?.kev || v.kev) return { sev: "critical", known: true };
  const cv = v.cvss;
  if (v.osvSeverity === "CRITICAL" || (cv ?? 0) >= 9) return { sev: "critical", known: true };
  if (v.osvSeverity === "HIGH" || (cv ?? 0) >= 7) return { sev: "high", known: true };
  return { sev: "medium", known: !!v.osvSeverity || cv !== undefined };
}

/** Severity from OSV data only (§7-3 "no vpi_level" branch): deterministic before enrichment. */
const baseSeverity = (p: VulnPkg): Severity => p.vulns.map((v) => vulnSeverity({ ...v, vi: undefined, kev: undefined }).sev).sort((a, b) => sevRank(a) - sevRank(b))[0] ?? "medium";
const topCvss = (p: VulnPkg): number => Math.max(0, ...p.vulns.map((v) => v.cvss ?? 0));

/**
 * B3: one id per vulnerability. OSV lists one vulnerability as several records (GHSA, PYSEC, …) that
 * alias each other and a CVE: ids joined through aliases are one vulnerability, shown by its CVE (all of
 * them, so the CVE list `track` reads stays the same), else its GHSA, else its first id.
 */
export function foldIds(ids: string[], vulns: Pick<Detail, "id" | "aliases">[]): string[] {
  const up = new Map<string, string>();
  const root = (x: string): string => {
    while (up.has(x)) x = up.get(x)!;
    return x;
  };
  const join = (a: string, b: string): void => {
    const [ra, rb] = [root(a), root(b)];
    if (ra !== rb) up.set(ra, rb);
  };
  for (const v of vulns) for (const a of v.aliases) join(v.id, a);
  const groups = new Map<string, string[]>();
  for (const x of new Set([...ids, ...vulns.flatMap((v) => [v.id, ...v.aliases])])) groups.set(root(x), [...(groups.get(root(x)) ?? []), x]);
  const keep = new Set(ids.map(root));
  return [...groups].flatMap(([r, m]) => {
    if (!keep.has(r)) return [];
    const s = m.sort();
    const cves = s.filter((x) => x.startsWith("CVE-"));
    return cves.length ? cves : [s.find((x) => x.startsWith("GHSA-")) ?? s[0]!];
  }).sort();
}

/** Most severe first: §7-3 severity, then VPI, then CVSS. */
const bySeverity = (a: Detail, b: Detail): number =>
  sevRank(vulnSeverity(a).sev) - sevRank(vulnSeverity(b).sev) || (b.vi?.vpi ?? 0) - (a.vi?.vpi ?? 0) || (b.cvss ?? b.vi?.cvss ?? 0) - (a.cvss ?? a.vi?.cvss ?? 0);

function vulnFinding(p: VulnPkg, inv: Inventory, lang?: Lang): BF {
  const { t } = p;
  const notes: NoteCode[] = [];
  // N4: VPI/EPSS badges show once every ID of the package has its priority; the severity never waits for them.
  const done = !p.pending && !p.failed;
  const kev = p.vulns.some((v) => v.vi?.kev || v.kev);
  const sevs = p.vulns.map(vulnSeverity);
  const severity = sevs.map((s) => s.sev).sort((a, b) => sevRank(a) - sevRank(b))[0] ?? "medium";
  if (!sevs.length || sevs.every((s) => !s.known)) notes.push("severity_unknown");
  if (t.dev) notes.push("dev_dependency");
  if (p.pending) notes.push("priority_pending");
  if (p.failed) notes.push("priority_failed");
  const fix = fixOf(p);
  if (fix && major(fix) !== major(t.version!)) notes.push("major_upgrade");
  if (fix && p.asked?.get(fix) !== true) notes.push("fix_unverified");
  // No fix, and the installed version came out after every advisory was published: an open-ended range
  // (one bad release, `introduced` with no end) may not cover it — a person checks (PYSEC-2022-252).
  const afterAdvisory =
    !fix && !!p.released && p.vulns.length === p.ids.length && p.vulns.every((v) => !!v.published && Date.parse(v.published) < Date.parse(p.released!));
  if (afterAdvisory) notes.push("released_after_advisory");
  const ids = foldIds(p.ids.map((v) => v.id), p.vulns);
  // B2: the most severe vulnerability that has a VulnIntel description in the scan's language.
  const described = lang ? p.vulns.filter((v) => v.vi?.desc?.[lang]).sort(bySeverity)[0] : undefined;
  const max = (xs: (number | null | undefined)[]): number | undefined => {
    const n = xs.filter((x): x is number => typeof x === "number");
    return n.length ? Math.max(...n) : undefined;
  };
  const vpi = done ? max(p.vulns.map((v) => v.vi?.vpi)) : undefined;
  const epss = done ? max(p.vulns.map((v) => v.vi?.epss)) : undefined;
  const cvss = max(p.vulns.map((v) => v.cvss ?? (done ? v.vi?.cvss : undefined)));
  const dependency = dependencyOf(inv, t);
  return {
    rule: "vulnerable-deps",
    kind: fix ? "vulnerable" : "vulnerable_no_fix",
    severity,
    confidence: p.unknownOnly || afterAdvisory ? "review" : "confirmed",
    file: t.sources[0]!,
    line: null,
    value: `${t.ecosystem}:${t.name}@${t.version}`,
    notes,
    extra: {
      ...pkgFields(t),
      ...(fix && { fixed_version: fix }),
      vuln_ids: ids,
      kev,
      ...(vpi !== undefined && { vpi_level: vpi }),
      ...(epss !== undefined && { epss }),
      ...(cvss !== undefined && { cvss }),
      source: p.fromVulnIntel || p.vulns.some((v) => v.vi) ? "vulnintel" : "osv",
      ...(t.sources.length > 1 && { related: t.sources }),
      ...(dependency && { dependency }),
      ...(described && { vuln_description: { id: described.aliases.find((a) => a.startsWith("CVE-")) ?? described.id, text: described.vi!.desc![lang!]! } }),
    },
  };
}

/**
 * §6-3 fix command input: how the package reaches the project according to its lock (not for
 * requirements files) — direct (with the declaring manifest at or below the lock's folder and its
 * section) or through another package — and whether the lock holds another major line of it.
 */
function dependencyOf(inv: Inventory, t: LookupScope["targets"][number]): Finding["dependency"] | undefined {
  const lock = inv.lockfiles.find((l) => l.path === t.sources[0] && l.kind !== "requirements" && l.status === "ok");
  if (!lock || t.version === null) return undefined;
  const same = lock.packages.filter((p) => p.name === t.name && p.version !== null);
  const other_majors = same.some((p) => major(p.version!) !== major(t.version!));
  const eco = lockEco(lock.kind);
  const dir = dirOf(lock.path);
  const direct = !!same.find((p) => p.version === t.version)?.direct;
  // The lock's own folder first, then workspace members below it; no declaring manifest found → no command named.
  const decl = direct
    ? inv.manifests
        .filter((m) => m.ecosystem === eco && (dir === "" || m.path.startsWith(`${dir}/`)))
        .sort((a, b) => a.path.split("/").length - b.path.split("/").length)
        .flatMap((m) => m.deps.filter((d) => (eco === "PyPI" ? normalizePyName(d.name) : d.name) === t.name).map((d) => ({ manifest: m.path, section: d.section })))[0]
    : undefined;
  return { direct, ...decl, ...(other_majors && { other_majors }) };
}

/**
 * §7-3 fixed version: the smallest fixed version above `cur` that none of the package's known vulns
 * still affects, same major preferred. A per-vuln fix can sit inside another vuln's later range
 * (1c E2: 0.3.34 → 1.2.22 still hit by [1.0.0, 1.3.3)), so every candidate is checked against all
 * ranges. No such version → undefined ("no fixed version"). Vulns without range data (VulnIntel
 * results) fall back to "at least that vuln's own smallest fix".
 */
export function safeFix(vulns: Pick<Detail, "fixed" | "ranges">[], key: string, cur: string): string | undefined {
  return pickFix(safeFixes(vulns, key, cur), cur);
}

/** Same major first, else the smallest (= the next major's minimum). */
const pickFix = (xs: string[], cur: string): string | undefined => xs.find((f) => major(f) === major(cur)) ?? xs[0];

/** Every fixed version above `cur` that escapes all known ranges, ascending (safeFix candidates). */
function safeFixes(vulns: Pick<Detail, "fixed" | "ranges">[], key: string, cur: string): string[] {
  const above = (v: Pick<Detail, "fixed">): string[] => (v.fixed[key] ?? []).filter((f) => cmpVersion(f, cur) > 0).sort(cmpVersion);
  const pick = (xs: string[]): string | undefined => pickFix(xs, cur);
  const hits = (v: Pick<Detail, "fixed" | "ranges">, c: string): boolean => {
    const r = v.ranges?.[key];
    if (!r) {
      const own = pick(above(v));
      return !!own && cmpVersion(c, own) < 0;
    }
    return r.some((x) => cmpVersion(c, x.introduced) >= 0 && (x.fixed ? cmpVersion(c, x.fixed) < 0 : x.last_affected ? cmpVersion(c, x.last_affected) <= 0 : true));
  };
  const cands = [...new Set(vulns.flatMap(above))].sort(cmpVersion);
  return cands.filter((c) => !vulns.some((v) => hits(v, c)));
}

const pkgFields = (t:LookupScope["targets"][number]): { ecosystem: "npm" | "PyPI"; package: string; version: string | null; lockfile: string } => ({
  ecosystem: t.ecosystem,
  package: t.name,
  version: t.version,
  lockfile: t.sources[0]!,
});

const dirOf = (p: string): string => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
const ancestors = (dir: string): string[] => {
  const out = [dir];
  while (dir) {
    dir = dirOf(dir);
    out.push(dir);
  }
  return out;
};
const isManifest = (p: string): boolean => /(^|\/)(package\.json|pyproject\.toml|Pipfile|requirements[^/]*\.txt)$/.test(p);
