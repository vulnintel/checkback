// Stage 4 recheck (§7-8): compare a scan with the fix-request snapshot (or the previous scan).
// Stored files hold fingerprints, keyed value hashes, rule ids, confidences and locations only —
// never values or masked values (§10-3).

import { createHash } from "node:crypto";
import { realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { defaultAppDir, projectKey, readJson, writeJson } from "./appdata.js";
import type { Inventory } from "./deps/inventory.js";
import { readText, type FileEntry } from "./files.js";
import type { CheckedRule, Confidence, Finding, RecheckStatus } from "./types.js";
import { satisfies } from "./versions.js";

export type StoredFinding = Omit<Finding, "masked_match" | "recheck" | "recheck_note" | "carried" | "previous_version">;

export interface LockState {
  path: string;
  lockHash: string;
  manifestHash: string | null;
  manifestDeps: Record<string, string> | null;
  root: { deps: Record<string, string>; versions: Record<string, string> } | null;
  entries: Record<string, { version: string; integrity?: string; resolved?: string }[]>;
}

export interface StoredScan {
  /** Random id per scan: "was there a scan since the snapshot?" (§7-8 M5). */
  scan_id: string;
  scan_at: string;
  template_id: string;
  engine_version: string;
  findings: StoredFinding[];
  checked: CheckedRule[];
  locks: LockState[];
}

export interface Snapshot extends StoredScan {
  created_at: string;
  /** Finding ids the user asked the AI to fix. */
  requested: string[];
}

export interface Compare {
  baseline: "fix_request" | "previous";
  baseline_at: string;
  counts: Record<RecheckStatus, number>;
  /** Baseline items that are gone. Secret items ask the user to confirm revocation (§7-8). */
  resolved: { id: string; rule_id: string; title: string; location: Finding["location"]; confirm_revocation?: true }[];
  requested?: string[];
}

const DEP_RULES = new Set(["vulnerable-deps", "hallucinated-package"]);
const CONF_RANK: Record<Confidence, number> = { confirmed: 0, review: 1, info: 2 };
const sha = (s: string): string => createHash("sha256").update(s).digest("hex");
/** Secret items pair by value hash wherever it shows up; key files by content hash (AC67 h). */
const secretish = (f: StoredFinding): boolean => !!f.secret_kind || f.rule_id === "key-file-committed";

const file = async (appDir: string, cwd: string, dir: string): Promise<string> =>
  join(appDir, dir, `${projectKey(await realpath(resolve(cwd)))}.json`);

export const lastScanFile = (appDir: string, cwd: string): Promise<string> => file(appDir, cwd, "last-scan");
export const snapshotFile = (appDir: string, cwd: string): Promise<string> => file(appDir, cwd, "fix-baseline");

export function storedFinding(f: Finding): StoredFinding {
  const { masked_match: _m, recheck: _r, recheck_note: _n, carried: _c, previous_version: _p, ...rest } = f;
  return rest;
}

export async function readLastScan(cwd: string, appDir = defaultAppDir()): Promise<StoredScan | null> {
  return readJson<StoredScan | null>(await lastScanFile(appDir, cwd), null);
}

export async function readSnapshot(cwd: string, appDir = defaultAppDir()): Promise<Snapshot | null> {
  return readJson<Snapshot | null>(await snapshotFile(appDir, cwd), null);
}

/** S6 "clear recheck baseline". */
export async function clearSnapshot(cwd: string, appDir = defaultAppDir()): Promise<void> {
  const { rm } = await import("node:fs/promises");
  await rm(await snapshotFile(appDir, cwd), { force: true });
}

/**
 * Record a fix request (GUI copy / MCP fix_prompts). No scan since the snapshot → add ids to it;
 * otherwise start a new snapshot from the latest scan (§7-8 M5).
 */
export async function recordFixRequest(cwd: string, ids: string[], appDir = defaultAppDir(), now = Date.now()): Promise<Snapshot> {
  const last = await readLastScan(cwd, appDir);
  if (!last) throw new Error("no scan to base the fix request on — run scan first");
  const known = new Set(last.findings.map((f) => f.id));
  const unknown = ids.filter((i) => !known.has(i));
  if (unknown.length) throw new Error(`unknown finding id: ${unknown.join(", ")}`);
  const prev = await readSnapshot(cwd, appDir);
  const snap: Snapshot =
    prev && prev.scan_id === last.scan_id
      ? { ...prev, requested: [...new Set([...prev.requested, ...ids])] }
      : { ...last, created_at: new Date(now).toISOString(), requested: [...new Set(ids)] };
  await writeJson(await snapshotFile(appDir, cwd), snap);
  return snap;
}

/** Lock consistency inputs for npm/pnpm locks (requirements have no separate lock). */
export async function lockStates(inv: Inventory, files: FileEntry[]): Promise<LockState[]> {
  const byRel = new Map(files.map((f) => [f.rel, f]));
  const txt = async (rel: string): Promise<string | null> => {
    const f = byRel.get(rel);
    const t = f ? await readText(f.abs) : null;
    return t && "text" in t ? t.text : null;
  };
  const out: LockState[] = [];
  for (const l of inv.lockfiles) {
    if (l.kind === "requirements" || l.status !== "ok") continue;
    const dir = l.path.includes("/") ? l.path.slice(0, l.path.lastIndexOf("/") + 1) : "";
    const lock = await txt(l.path);
    const man = await txt(`${dir}package.json`);
    let manifestDeps: Record<string, string> | null = null;
    try {
      const m = man ? (JSON.parse(man) as Record<string, Record<string, string> | undefined>) : null;
      if (m) manifestDeps = { ...m.dependencies, ...m.devDependencies, ...m.optionalDependencies };
    } catch {
      manifestDeps = null;
    }
    const entries: LockState["entries"] = {};
    for (const p of l.packages) {
      if (p.version === null) continue;
      (entries[p.name] ??= []).push({ version: p.version, ...(p.integrity && { integrity: p.integrity }), ...(p.resolved && { resolved: p.resolved }) });
    }
    out.push({ path: l.path, lockHash: sha(lock ?? ""), manifestHash: man === null ? null : sha(man), manifestDeps, root: l.root ?? null, entries });
  }
  return out;
}

/**
 * §7-8 H1: a lock changed after the baseline looks hand-edited when
 * (1) manifest direct names ≠ lock root names, (2) a root version breaks the manifest range or the
 * recorded spec differs, (3) same version with a different integrity, (4) a changed version keeps
 * the old integrity / has none, or the resolved URL names another version. Local checks only.
 * With `pkg`, only that package is judged (1c E1: a manifest-only bump of one package must not
 * flag every other dependency item of the same lock).
 */
export function lockLooksHandEdited(base: LockState | undefined, cur: LockState | undefined, pkg?: string): boolean {
  if (!cur) return false;
  if (base && base.lockHash === cur.lockHash && base.manifestHash === cur.manifestHash) return false;
  const only = (n: string): boolean => pkg === undefined || n === pkg;
  if (cur.root && cur.manifestDeps) {
    if (pkg === undefined) {
      const m = Object.keys(cur.manifestDeps).sort().join("\0");
      const l = Object.keys(cur.root.deps).sort().join("\0");
      if (m !== l) return true;
    } else if (Object.hasOwn(cur.manifestDeps, pkg) !== Object.hasOwn(cur.root.deps, pkg)) return true;
    for (const [n, spec] of Object.entries(cur.manifestDeps)) {
      if (!only(n)) continue;
      if (cur.root.deps[n] !== spec) return true;
      const v = cur.root.versions[n];
      if (v && /^\d/.test(v) && !satisfies(v, spec)) return true;
    }
  }
  for (const [name, list] of Object.entries(cur.entries)) {
    if (!only(name)) continue;
    for (const e of list) {
      const urlVer = e.resolved ? /\/-\/(?:[^/]+?)-(\d[^/]*?)\.tgz(?:[?#].*)?$/.exec(e.resolved)?.[1] : undefined;
      if (urlVer && urlVer !== e.version) return true;
      const prev = base?.entries[name] ?? [];
      if (!prev.length) continue;
      const same = prev.find((p) => p.version === e.version);
      if (same) {
        if (same.integrity && e.integrity && same.integrity !== e.integrity) return true;
      } else if (!e.integrity || prev.some((p) => p.integrity === e.integrity)) return true;
    }
  }
  return false;
}

/** Apply recheck statuses to `findings` (mutated copies returned) and build the compare summary. */
export function compareWith(
  base: StoredScan,
  kind: "fix_request" | "previous",
  findings: Finding[],
  checked: CheckedRule[],
  locks: LockState[],
  ignored: Set<string>,
): { findings: Finding[]; compare: Compare } {
  const baseFindings = base.findings.filter((f) => !ignored.has(f.id));
  const baseIds = new Set(baseFindings.map((f) => f.id));
  const cur = findings.map((f) => ({ ...f }));
  const byId = new Map(cur.map((f) => [f.id, f]));
  const used = new Set<string>();
  const counts = { resolved: 0, remaining: 0, new: 0, same_key: 0, moved: 0, downgraded: 0, lock_mismatch: 0, not_checked: 0 } as Record<RecheckStatus, number>;
  const resolved: Compare["resolved"] = [];
  const carried: Finding[] = [];
  const ranFully = (ruleId: string): boolean => {
    const c = checked.find((x) => x.rule_id === ruleId);
    return !!c && c.ran && !c.reason;
  };
  const mark = (f: Finding, s: RecheckStatus, note?: string): void => {
    f.recheck = s;
    if (note) f.recheck_note = note;
    used.add(f.id);
    counts[s]++;
  };
  const carry = (b: StoredFinding, s: RecheckStatus, note: string): void => {
    carried.push({ ...b, recheck: s, recheck_note: note, carried: true });
    counts[s]++;
  };
  const baseLock = new Map(base.locks.map((l) => [l.path, l]));
  const curLock = new Map(locks.map((l) => [l.path, l]));
  const handEdited = (f: StoredFinding): boolean => {
    const p = f.lockfile ?? f.location?.file ?? "";
    return DEP_RULES.has(f.rule_id) && !!f.package && lockLooksHandEdited(baseLock.get(p), curLock.get(p), f.package);
  };
  // A value set by a variable/env (env_driven) cannot be judged fixed statically (1c E3).
  const unverifiable = (f: Finding): string | undefined => (f.notes?.includes("env_driven") ? "static_unverifiable" : undefined);
  // Q4: a dependency item still there while its manifest changed and its lock did not → "reinstall" note.
  const lockNotRegenerated = (f: Finding): string | undefined => {
    if (!DEP_RULES.has(f.rule_id)) return undefined;
    const p = f.lockfile ?? f.location?.file ?? "";
    const [bl, cl] = [baseLock.get(p), curLock.get(p)];
    return bl && cl && bl.lockHash === cl.lockHash && bl.manifestHash !== cl.manifestHash ? "lock_not_regenerated" : undefined;
  };
  // Q3: a new vulnerable item of the same ecosystem + package at another version, same lock preferred.
  const bumpedTo = (b: StoredFinding): Finding | undefined => {
    if (b.rule_id !== "vulnerable-deps" || !b.package || !b.version) return undefined;
    const pool = cur.filter(
      (f) => f.rule_id === b.rule_id && f.ecosystem === b.ecosystem && f.package === b.package && !!f.version && f.version !== b.version && !used.has(f.id) && !baseIds.has(f.id),
    );
    return pool.find((f) => f.lockfile === b.lockfile) ?? pool[0];
  };

  for (const b of baseFindings) {
    const same = byId.get(b.id);
    if (same) {
      // §7-8 "check (lock)" applies only to dependency items that disappeared; same fingerprint = "remaining".
      mark(same, "remaining", unverifiable(same) ?? lockNotRegenerated(same));
      continue;
    }
    if (!ranFully(b.rule_id)) {
      carry(b, "not_checked", "rule_not_checked");
      continue;
    }
    const fresh = (f: Finding): boolean => !used.has(f.id) && !baseIds.has(f.id) && f.value_hash === b.value_hash;
    if (secretish(b)) {
      const c = cur.find((f) => fresh(f) && (f.secret_kind || f.rule_id === "key-file-committed"));
      if (c) {
        mark(c, "same_key", "same_key_remains");
        c.severity = b.severity;
        c.confidence = b.confidence; // stays a fix item even in a local-only/test/example location
        continue;
      }
    } else {
      const c = cur.find((f) => fresh(f) && f.rule_id === b.rule_id);
      if (c) {
        if (CONF_RANK[c.confidence] > CONF_RANK[b.confidence]) {
          mark(c, "downgraded", "moved_to_lower_confidence");
          c.confidence = b.confidence;
        } else mark(c, "moved", "moved_elsewhere");
        continue;
      }
    }
    if (handEdited(b)) {
      carry(b, "lock_mismatch", "lock_hand_edited");
      continue;
    }
    const bumped = bumpedTo(b);
    if (bumped) {
      bumped.previous_version = b.version!;
      mark(bumped, "remaining", "version_bumped_still_vulnerable");
      continue;
    }
    counts.resolved++;
    resolved.push({ id: b.id, rule_id: b.rule_id, title: b.title, location: b.location, ...(secretish(b) && { confirm_revocation: true as const }) });
  }
  for (const f of cur) {
    if (used.has(f.id) || baseIds.has(f.id)) continue;
    mark(f, "new", unverifiable(f));
  }
  return {
    findings: [...cur, ...carried],
    compare: {
      baseline: kind,
      baseline_at: kind === "fix_request" ? (base as Snapshot).created_at : base.scan_at,
      counts,
      resolved,
      ...(kind === "fix_request" && { requested: (base as Snapshot).requested }),
    },
  };
}
