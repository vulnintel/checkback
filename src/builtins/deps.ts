// builtin vulnerable-deps (§7-3) and hallucinated-package (§7-2). Network goes only to the
// services in the §3-1 table, only after consent, and only with names in the §7-2 lookup scope.

import { readFileSync } from "node:fs";
import type { Inventory, LookupScope } from "../deps/inventory.js";
import { normalizePyName } from "../deps/locks.js";
import type { ViBudget } from "../net/budget.js";
import { mapLimit, type Cache, type Http } from "../net/http.js";
import { osvQueryBatch, osvVuln, type OsvVuln } from "../net/osv.js";
import { npmAbbrev, npmCreated, npmWeeklyDownloads, pypiExists, type Exists } from "../net/registry.js";
import { publicLookup } from "../net/vulnintel.js";
import type { CheckedRule, Lang, NoteCode, Severity } from "../types.js";
import { cmpVersion, cvss3Score, major } from "../versions.js";
import type { BF, BuiltinCtx } from "./backend.js";
import type { ImportRef } from "./imports.js";

const DAY = 86_400_000;
const PUBLIC_LOOKUP_CAP = 200;
const VI_BURST = 15;
const VI_INTERVAL_MS = 1200;

export interface NetCtx {
  http: Http;
  budget: ViBudget;
  lang: Lang;
  osv: boolean;
  registry: boolean;
  vulnintel: boolean;
  caches: { registry: Cache; osv: Cache; vi: Cache };
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
  const { inv, scope, net } = d;

  // ---- local: version unknown / unsupported lock (§7-3)
  if (d.vuln) {
    const lockDirs = new Set([...inv.lockfiles.filter((l) => l.kind !== "requirements").map((l) => l.path), ...inv.unsupported.map((u) => u.path)].map(dirOf));
    const unsupportedDirs = new Set(inv.unsupported.map((u) => dirOf(u.path)));
    for (const u of inv.unsupported) out.push({ rule: "vulnerable-deps", kind: "unsupported_lock", severity: "medium", confidence: "info", file: u.path, line: null, value: `unsupported:${u.kind}` });
    for (const m of inv.manifests) {
      if (m.deps.length === 0) continue;
      const dir = dirOf(m.path);
      const covered = ancestors(dir).some((a) => lockDirs.has(a) && !unsupportedDirs.has(a)) ||
        (m.ecosystem === "PyPI" && inv.lockfiles.some((l) => l.kind === "requirements" && dirOf(l.path) === dir));
      if (!covered) out.push({ rule: "vulnerable-deps", kind: "version_unknown", severity: "medium", confidence: "review", file: m.path, line: null, value: `unlocked:${m.path}` });
    }
    for (const l of inv.lockfiles) {
      if (l.kind === "requirements" && l.packages.some((p) => p.version === null)) {
        out.push({ rule: "vulnerable-deps", kind: "version_unknown", severity: "medium", confidence: "review", file: l.path, line: null, value: `unpinned:${l.path}` });
      }
    }
  }

  const allow = new Set(d.params.allow ?? []);
  const targets = scope.targets.filter((t) => !allow.has(t.name));
  const versioned = targets.filter((t) => t.version !== null);

  // ---- OSV (vulnerabilities + MAL-)
  const vulnsByTarget = new Map<number, { id: string; modified: string }[]>();
  if (!net) {
    vuln = d.vuln ? "no_consent" : undefined;
  } else if (!net.osv) {
    vuln = d.vuln ? "external_disabled" : undefined;
  } else if (versioned.length) {
    const r = await osvQueryBatch(net.http, versioned.map((t) => ({ ecosystem: t.ecosystem, name: t.name, version: t.version! })));
    if (r.offline || r.results.some((x) => x === null)) vuln = "offline";
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

  if (d.vuln && net && vulnsByTarget.size) {
    const pkgs: VulnPkg[] = [];
    for (const [i, ids] of vulnsByTarget) {
      const real = ids.filter((v) => !v.id.startsWith("MAL-"));
      if (real.length) pkgs.push({ t: versioned[i]!, ids: real, vulns: [] });
    }
    const all = pkgs.flatMap((p) => p.ids);
    const details = new Map<string, Detail | null>();
    await mapLimit([...new Map(all.map((v) => [v.id, v])).values()], 8, async (v) => {
      const key = v.id;
      const cached = net.caches.osv.get<Detail>(key, 7 * DAY, d.now);
      if (cached && cached.modified === v.modified) return void details.set(key, cached);
      const raw = await osvVuln(net.http, v.id);
      const det = raw ? toDetail(raw) : null;
      if (det) net.caches.osv.set(key, det, d.now);
      details.set(key, det);
    });
    for (const p of pkgs) p.vulns = p.ids.map((v) => details.get(v.id)).filter((x): x is Detail => !!x);

    // Priority enrichment (§8-4/§8-5): most severe IDs first across all packages, capped per
    // scan, paced to ~50/min after a short burst (the server's per-IP limit allows a burst of 20).
    if (net.vulnintel) {
      const queue = pkgs
        .flatMap((p) => p.vulns.map((v) => ({ p, v, s: vulnSeverity({ ...v, vi: undefined }) })))
        .sort((a, b) => sevRank(a.s.sev) - sevRank(b.s.sev) || (b.v.cvss ?? 0) - (a.v.cvss ?? 0));
      let calls = 0;
      let stop = false;
      for (const { p, v } of queue) {
        const id = v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id;
        const key = `${id}:${net.lang}`;
        const hit = net.caches.vi.get<ViInfo | null>(key, DAY, d.now);
        if (hit !== undefined) {
          v.vi = hit ?? undefined;
          continue;
        }
        if (stop || calls >= PUBLIC_LOOKUP_CAP) {
          p.pending = true;
          continue;
        }
        if (calls >= VI_BURST) await net.http.sleep(VI_INTERVAL_MS);
        calls++;
        const r = await publicLookup(net.http, net.budget, id, net.lang);
        if (r.ok) {
          v.vi = { kev: r.value.is_kev, vpi: r.value.vpi_level, epss: r.value.epss, cvss: r.value.cvss };
          net.caches.vi.set(key, v.vi, d.now);
        } else if (r.reason === "not_found") net.caches.vi.set(key, null, d.now);
        else if (r.reason === "budget") p.pending = true;
        else {
          p.failed = true;
          if (r.reason === "rate_limited" || r.reason === "offline") stop = true;
        }
      }
    }
    for (const p of pkgs) out.push(vulnFinding(p));
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
      for (const l of lookups) byName.set(`${l.eco}\0${l.name}`, [...(byName.get(`${l.eco}\0${l.name}`) ?? []), l]);
      let offline = false;
      const reg = new Map<string, Reg>();
      await mapLimit([...byName.keys()], 4, async (key) => {
        const [eco, name] = key.split("\0") as ["npm" | "PyPI", string];
        const cached = net.caches.registry.get<Reg>(key, DAY, d.now);
        if (cached) return void reg.set(key, cached);
        let r: Reg;
        if (eco === "npm") {
          const a = await npmAbbrev(net.http, name);
          const scripts: Record<string, boolean> = {};
          for (const [v, m] of Object.entries(a.body?.versions ?? {})) if (m?.hasInstallScript) scripts[v] = true;
          r = { s: a.s, latest: a.body?.["dist-tags"]?.latest, scripts };
        } else r = { s: await pypiExists(net.http, name), scripts: {} };
        if (r.s === "offline") offline = true;
        if (r.s === "ok" || r.s === "missing") net.caches.registry.set(key, r, d.now);
        reg.set(key, r);
      });
      if (offline) hall = "offline";
      const minWeekly = d.params.min_weekly_downloads ?? 1000;
      for (const [key, ls] of byName) {
        const r = reg.get(key)!;
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
        if (l.eco === "npm") {
          const near = nearPopular(l.name);
          if (near) {
            const created = await npmCreated(net.http, l.name);
            if (created && d.now - Date.parse(created) <= 30 * DAY) {
              const weekly = await npmWeeklyDownloads(net.http, l.name);
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
  return { findings: out, vuln, hall };
}

interface Reg {
  s: Exists;
  latest?: string;
  scripts: Record<string, boolean>;
}

interface ViInfo {
  kev: boolean;
  vpi: number | null;
  epss: number | null;
  cvss: number | null;
}

interface Detail {
  id: string;
  modified: string;
  aliases: string[];
  osvSeverity?: string;
  cvss?: number;
  /** "eco:name" → fixed versions */
  fixed: Record<string, string[]>;
  vi?: ViInfo;
}

interface VulnPkg {
  t: LookupScope["targets"][number];
  ids: { id: string; modified: string }[];
  vulns: Detail[];
  pending?: boolean;
  failed?: boolean;
}

const pkgKey = (eco: string, name: string): string => `${eco}:${eco === "PyPI" ? normalizePyName(name) : name}`;

function toDetail(v: OsvVuln): Detail {
  const fixed: Record<string, string[]> = {};
  for (const a of v.affected ?? []) {
    if (!a.package?.name || !a.package.ecosystem) continue;
    const k = pkgKey(a.package.ecosystem, a.package.name);
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) (fixed[k] ??= []).push(e.fixed);
  }
  const scores = (v.severity ?? []).map((s) => (/^CVSS:3/.test(s.score) ? cvss3Score(s.score) : null)).filter((x): x is number => x !== null);
  const osvSeverity = v.database_specific?.severity ?? v.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  return {
    id: v.id,
    modified: v.modified ?? "",
    aliases: v.aliases ?? [],
    ...(osvSeverity && { osvSeverity: osvSeverity.toUpperCase() }),
    ...(scores.length && { cvss: Math.max(...scores) }),
    fixed,
  };
}

const SEV: Severity[] = ["critical", "high", "medium"];
const sevRank = (s: Severity): number => SEV.indexOf(s);

/** §7-3 severity mapping: KEV → critical, VPI 5–6 critical / 4 high / 1–3 medium, else OSV severity or CVSS. */
function vulnSeverity(v: Detail): { sev: Severity; known: boolean } {
  if (v.vi?.kev) return { sev: "critical", known: true };
  if (v.vi?.vpi) return { sev: v.vi.vpi >= 5 ? "critical" : v.vi.vpi === 4 ? "high" : "medium", known: true };
  const cv = v.cvss ?? v.vi?.cvss ?? undefined;
  if (v.osvSeverity === "CRITICAL" || (cv ?? 0) >= 9) return { sev: "critical", known: true };
  if (v.osvSeverity === "HIGH" || (cv ?? 0) >= 7) return { sev: "high", known: true };
  return { sev: "medium", known: !!v.osvSeverity || cv !== undefined };
}

function vulnFinding(p: VulnPkg): BF {
  const { t } = p;
  const notes: NoteCode[] = [];
  const sevs = p.vulns.map(vulnSeverity);
  const severity = sevs.map((s) => s.sev).sort((a, b) => sevRank(a) - sevRank(b))[0] ?? "medium";
  if (!sevs.length || sevs.every((s) => !s.known)) notes.push("severity_unknown");
  if (t.dev) notes.push("dev_dependency");
  if (p.pending) notes.push("priority_pending");
  if (p.failed) notes.push("priority_failed");
  // Smallest fix above the current version per vuln, same major preferred; the package needs the largest of those.
  let fix: string | undefined;
  for (const v of p.vulns) {
    const cands = (v.fixed[pkgKey(t.ecosystem, t.name)] ?? []).filter((f) => cmpVersion(f, t.version!) > 0).sort(cmpVersion);
    const pick = cands.find((f) => major(f) === major(t.version!)) ?? cands[0];
    if (pick && (!fix || cmpVersion(pick, fix) > 0)) fix = pick;
  }
  if (fix && major(fix) !== major(t.version!)) notes.push("major_upgrade");
  const ids = [...new Set(p.ids.map((v) => v.id).concat(p.vulns.flatMap((v) => v.aliases.filter((a) => a.startsWith("CVE-")))))].sort();
  const max = (xs: (number | null | undefined)[]): number | undefined => {
    const n = xs.filter((x): x is number => typeof x === "number");
    return n.length ? Math.max(...n) : undefined;
  };
  const vpi = max(p.vulns.map((v) => v.vi?.vpi));
  const epss = max(p.vulns.map((v) => v.vi?.epss));
  const cvss = max(p.vulns.map((v) => v.cvss ?? v.vi?.cvss));
  return {
    rule: "vulnerable-deps",
    kind: fix ? "vulnerable" : "vulnerable_no_fix",
    severity,
    confidence: "confirmed",
    file: t.sources[0]!,
    line: null,
    value: `${t.ecosystem}:${t.name}@${t.version}`,
    notes,
    extra: {
      ...pkgFields(t),
      ...(fix && { fixed_version: fix }),
      vuln_ids: ids,
      kev: p.vulns.some((v) => v.vi?.kev),
      ...(vpi !== undefined && { vpi_level: vpi }),
      ...(epss !== undefined && { epss }),
      ...(cvss !== undefined && { cvss }),
      source: p.vulns.some((v) => v.vi) ? "vulnintel" : "osv",
      ...(t.sources.length > 1 && { related: t.sources }),
    },
  };
}

const pkgFields = (t: LookupScope["targets"][number]): { ecosystem: "npm" | "PyPI"; package: string; version: string | null; lockfile: string } => ({
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
