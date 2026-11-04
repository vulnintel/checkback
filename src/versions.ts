// Version helpers for npm (semver) and PyPI (PEP 440, approximate) plus a CVSS v3 base-score
// calculator. shortcut: PEP 440 epochs/local versions and exotic semver ranges are compared
// approximately; upgrade to a full PEP 440 / node-semver port if cards show wrong fixed versions.

type Parsed = { nums: number[]; rest: string };

function parse(v: string): Parsed {
  const m = /^v?(\d+(?:\.\d+)*)(.*)$/.exec(v.trim());
  if (!m) return { nums: [], rest: v };
  return { nums: m[1]!.split(".").map(Number), rest: m[2]!.replace(/^[.-]/, "") };
}

/** Pre-release tags sort before the release; post/build tags after it. */
function restRank(rest: string): number {
  if (rest === "" || rest.startsWith("+")) return 0;
  return /^(post|rev|r\d)/i.test(rest) ? 1 : -1;
}

export function cmpVersion(a: string, b: string): number {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const d = (pa.nums[i] ?? 0) - (pb.nums[i] ?? 0);
    if (d) return Math.sign(d);
  }
  const ra = restRank(pa.rest);
  const rb = restRank(pb.rest);
  if (ra !== rb) return Math.sign(ra - rb);
  // Compare tags token by token, numbers numerically.
  const ta = pa.rest.split(/[.\-+]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/);
  const tb = pb.rest.split(/[.\-+]|(?<=\d)(?=\D)|(?<=\D)(?=\d)/);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i] ?? "";
    const y = tb[i] ?? "";
    if (x === y) continue;
    if (/^\d+$/.test(x) && /^\d+$/.test(y)) return Math.sign(Number(x) - Number(y));
    return x < y ? -1 : 1;
  }
  return 0;
}

export const major = (v: string): number => parse(v).nums[0] ?? 0;

/**
 * npm range check for the lock-consistency test (§7-8 H1 rule 2). Supports `^ ~ >= > <= < =`,
 * x-ranges, `*`, hyphen ranges and `||`. Unknown syntax (tags, URLs) → true (cannot judge).
 */
export function satisfies(version: string, range: string): boolean {
  const r = range.trim();
  if (r === "" || r === "*" || r === "latest" || /^[a-z]+:/i.test(r) || /^[\w-]+\/[\w.-]+/.test(r)) return true;
  return r.split("||").some((part) => {
    const p = part.trim();
    const hy = /^(\S+)\s+-\s+(\S+)$/.exec(p);
    if (hy) return cmpVersion(version, fill(hy[1]!, 0)) >= 0 && cmpVersion(version, fill(hy[2]!, 0)) <= 0;
    return p.split(/\s+/).filter(Boolean).every((c) => comparator(version, c));
  });
}

function fill(v: string, n: number): string {
  const parts = v.replace(/^v/, "").split(".").filter((x) => x !== "x" && x !== "X" && x !== "*");
  while (parts.length < 3) parts.push(String(n));
  return parts.join(".");
}

function comparator(v: string, c: string): boolean {
  const m = /^(\^|~|>=|<=|>|<|=)?\s*v?([\dxX*][\w.*+-]*)$/.exec(c);
  if (!m) return true;
  const [, op = "", raw] = m;
  const segs = raw!.split(/[.+-]/).slice(0, 3);
  const wild = segs.findIndex((s) => /^[xX*]$/.test(s));
  const given = wild < 0 ? Math.min(segs.length, 3) : wild;
  const base = fill(raw!, 0);
  const [M = 0, mi = 0, pa = 0] = base.split(".").map(Number);
  const ge = (x: string): boolean => cmpVersion(v, x) >= 0;
  const lt = (x: string): boolean => cmpVersion(v, x) < 0;
  switch (op) {
    case ">=":
      return ge(base);
    case ">":
      return cmpVersion(v, base) > 0;
    case "<=":
      return cmpVersion(v, base) <= 0;
    case "<":
      return lt(base);
    case "~":
      return ge(base) && lt(given >= 2 ? `${M}.${mi + 1}.0` : `${M + 1}.0.0`);
    case "^":
      return ge(base) && lt(M > 0 || given < 2 ? `${M + 1}.0.0` : mi > 0 || given < 3 ? `0.${mi + 1}.0` : `0.0.${pa + 1}`);
    default:
      if (given < 3) return ge(base) && lt(given === 0 ? "999999.0.0" : given === 1 ? `${M + 1}.0.0` : `${M}.${mi + 1}.0`);
      return cmpVersion(v, raw!) === 0;
  }
}

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

/** CVSS v3.x base score from a vector string; null for other versions or malformed vectors. */
export function cvss3Score(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m: Record<string, string> = {};
  for (const kv of vector.split("/").slice(1)) {
    const [k, v] = kv.split(":");
    if (k && v) m[k] = v;
  }
  const av = W.AV[m.AV as keyof typeof W.AV];
  const ac = W.AC[m.AC as keyof typeof W.AC];
  const ui = W.UI[m.UI as keyof typeof W.UI];
  const [c, i, a] = [m.C, m.I, m.A].map((x) => W.CIA[x as keyof typeof W.CIA]);
  const changed = m.S === "C";
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR as "N" | "L" | "H"];
  if ([av, ac, ui, c, i, a, pr].some((x) => x === undefined) || (m.S !== "U" && m.S !== "C")) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * av! * ac! * pr! * ui!;
  const roundUp = (x: number): number => {
    const n = Math.round(x * 100000);
    return n % 10000 === 0 ? n / 100000 : (Math.floor(n / 10000) + 1) / 10;
  };
  return roundUp(Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10));
}
