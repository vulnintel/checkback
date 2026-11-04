import { parseAllDocuments } from "yaml";

export type Ecosystem = "npm" | "PyPI";

export interface Package {
  ecosystem: Ecosystem;
  name: string;
  /** Exact resolved version; null when the source does not pin one (requirements without `==`). */
  version: string | null;
  dev: boolean;
  /** Declared directly by a manifest (vs. transitive). */
  direct: boolean;
  /**
   * registry = public registry; private = resolved from another registry / tarball URL;
   * local = workspace, file:, link:, git — never sent anywhere (§7-2 rule 5).
   */
  origin: "registry" | "private" | "local";
  integrity?: string;
  resolved?: string;
  license?: string;
}

export interface LockParse {
  status: "ok" | "regenerate" | "error";
  /** For regenerate/error: short reason (no file content). */
  detail?: string;
  packages: Package[];
  /** requirements: index URLs found (`-i`, `--index-url`, `--extra-index-url`). */
  indexUrls?: string[];
  /** requirements: `-r` files that were followed (CWD-relative). */
  includes?: string[];
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

const PUBLIC_NPM = /^https?:\/\/registry\.(npmjs\.org|yarnpkg\.com)\//;

function npmOrigin(version: string, resolved: string | undefined): Package["origin"] {
  if (/^(file|link|workspace|git|git\+[a-z]+|github|portal):/.test(version) || version.includes("/")) return "local";
  if (!resolved) return "registry";
  if (PUBLIC_NPM.test(resolved)) return "registry";
  return /^https?:\/\//.test(resolved) && !/^git/.test(resolved) ? "private" : "local";
}

const depNames = (o: unknown): string[] =>
  isObj(o) ? ["dependencies", "devDependencies", "optionalDependencies"].flatMap((k) => (isObj(o[k]) ? Object.keys(o[k] as Obj) : [])) : [];

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1–3. */
export function parseNpmLock(text: string, manifest?: unknown): LockParse {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { status: "error", detail: "invalid JSON", packages: [] };
  }
  if (!isObj(data)) return { status: "error", detail: "invalid lockfile", packages: [] };
  const out = new Map<string, Package>();
  const put = (p: Package): void => {
    const key = `${p.name}@${p.version}`;
    const prev = out.get(key);
    if (!prev) out.set(key, p);
    else {
      prev.dev &&= p.dev; // prod anywhere wins
      prev.direct ||= p.direct;
    }
  };
  if (isObj(data.packages)) {
    // v2/v3: keys are install paths. Non-node_modules keys are the root ("") and workspace folders.
    const entries = Object.entries(data.packages);
    const declared = new Set(entries.filter(([k]) => !k.includes("node_modules/")).flatMap(([, e]) => depNames(e)));
    for (const [k, e] of entries) {
      const at = k.lastIndexOf("node_modules/");
      if (at < 0 || !isObj(e)) continue;
      const name = typeof e.name === "string" ? e.name : k.slice(at + "node_modules/".length);
      const version = typeof e.version === "string" ? e.version : typeof e.resolved === "string" ? e.resolved : "";
      const resolved = typeof e.resolved === "string" ? e.resolved : undefined;
      put({
        ecosystem: "npm",
        name,
        version: version || null,
        dev: e.dev === true,
        direct: declared.has(name) && !k.slice(0, at).includes("node_modules/"),
        origin: e.link === true ? "local" : npmOrigin(version, resolved),
        ...(typeof e.integrity === "string" && { integrity: e.integrity }),
        ...(resolved && { resolved }),
        ...(typeof e.license === "string" && { license: e.license }),
      });
    }
  } else if (isObj(data.dependencies)) {
    // v1: nested tree.
    const declared = new Set(depNames(manifest));
    const walk = (deps: Obj, depth: number): void => {
      for (const [name, e] of Object.entries(deps)) {
        if (!isObj(e)) continue;
        const version = typeof e.version === "string" ? e.version : "";
        const resolved = typeof e.resolved === "string" ? e.resolved : undefined;
        put({
          ecosystem: "npm",
          name,
          version: version || null,
          dev: e.dev === true,
          direct: depth === 0 && (declared.size === 0 || declared.has(name)),
          origin: npmOrigin(version, resolved),
          ...(typeof e.integrity === "string" && { integrity: e.integrity }),
          ...(resolved && { resolved }),
        });
        if (isObj(e.dependencies)) walk(e.dependencies, depth + 1);
      }
    };
    walk(data.dependencies, 0);
  }
  return { status: "ok", packages: [...out.values()] };
}

const SUPPORTED_PNPM = new Set(["6.0", "6.1", "9.0"]);

/** pnpm-lock.yaml: lockfileVersion 6.0 / 6.1 / 9.0, including pnpm 11 multi-document files. */
export function parsePnpmLock(text: string): LockParse {
  const docs = parseAllDocuments(text, { schema: "core", merge: false });
  const objs: Obj[] = [];
  for (const d of Array.isArray(docs) ? docs : [docs]) {
    if (d.errors.length) return { status: "error", detail: "invalid YAML", packages: [] };
    const o: unknown = d.toJS({ maxAliasCount: 50 });
    if (isObj(o) && o.lockfileVersion !== undefined) objs.push(o);
  }
  if (objs.length === 0) return { status: "error", detail: "no lockfileVersion", packages: [] };
  const out = new Map<string, Package>();
  for (const o of objs) {
    const v = String(o.lockfileVersion);
    if (/^[1-5](\.|$)/.test(v)) return { status: "regenerate", detail: `lockfileVersion ${v} — regenerate with pnpm 8 or later`, packages: [] };
    if (!SUPPORTED_PNPM.has(v)) return { status: "error", detail: `unsupported lockfileVersion ${v}`, packages: [] };
    const importers: Obj[] = isObj(o.importers) ? Object.values(o.importers).filter(isObj) : [o];
    const direct = new Set<string>();
    const prodRoots: string[] = [];
    for (const imp of importers) {
      for (const sect of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const deps = imp[sect];
        if (!isObj(deps)) continue;
        for (const [name, d] of Object.entries(deps)) {
          const ver = isObj(d) ? String(d.version ?? "") : String(d ?? "");
          const ref = snapshotKey(name, ver);
          direct.add(stripPeers(ref));
          if (sect !== "devDependencies") prodRoots.push(ref);
        }
      }
    }
    const prod = v === "9.0" ? reachable(prodRoots, isObj(o.snapshots) ? o.snapshots : {}) : null;
    for (const [rawKey, e] of Object.entries(isObj(o.packages) ? o.packages : {})) {
      if (!isObj(e)) continue;
      const key = stripPeers(rawKey.replace(/^\//, ""));
      const at = key.lastIndexOf("@");
      if (at <= 0) continue;
      const name = typeof e.name === "string" ? e.name : key.slice(0, at);
      const version = typeof e.version === "string" ? e.version : key.slice(at + 1);
      const res = isObj(e.resolution) ? e.resolution : {};
      const origin: Package["origin"] =
        res.type === "git" || res.type === "directory" || "directory" in res || "repo" in res || /[:/]/.test(version)
          ? "local"
          : typeof res.tarball === "string"
            ? "private" // §7-5: resolution.tarball is treated as non-public
            : "registry";
      const p: Package = {
        ecosystem: "npm",
        name,
        version,
        dev: prod ? !prod.has(key) : e.dev === true,
        direct: direct.has(key),
        origin,
        ...(typeof res.integrity === "string" && { integrity: res.integrity }),
        ...(typeof res.tarball === "string" && { resolved: res.tarball }),
      };
      const k = `${name}@${version}`;
      if (!out.has(k)) out.set(k, p);
    }
  }
  return { status: "ok", packages: [...out.values()] };
}

const stripPeers = (k: string): string => {
  const i = k.indexOf("(");
  return i < 0 ? k : k.slice(0, i);
};

/** Importer/snapshot dependency value → snapshot key. Aliases (`npm:` deps) are stored as `real@ver`. */
function snapshotKey(name: string, rawVer: string): string {
  const ver = rawVer.replace(/^\//, "");
  return /^[\d]|^(link|file|workspace):/.test(ver) ? `${name}@${ver}` : ver.includes("@") ? ver : `${name}@${ver}`;
}

function reachable(roots: string[], snapshots: Obj): Set<string> {
  const seen = new Set<string>();
  const stack = [...roots];
  while (stack.length) {
    const k = stack.pop()!;
    if (seen.has(k)) continue;
    seen.add(k);
    const s = snapshots[k];
    if (!isObj(s)) continue;
    for (const sect of ["dependencies", "optionalDependencies"]) {
      if (isObj(s[sect])) for (const [n, v] of Object.entries(s[sect] as Obj)) stack.push(snapshotKey(n, String(v)));
    }
  }
  return new Set([...seen].map(stripPeers));
}

/** PEP 503 name normalization (OSV/PyPI canonical form). */
export const normalizePyName = (n: string): string => n.toLowerCase().replace(/[-_.]+/g, "-");

/**
 * requirements*.txt: `==` pins only give a version; `-r` is followed via `readInclude` (which must
 * refuse paths outside CWD); hashes, markers and constraints files are ignored.
 */
export function parseRequirements(
  text: string,
  rel: string,
  readInclude: (rel: string) => string | null,
  seen: Set<string> = new Set([rel]),
): LockParse {
  const packages: Package[] = [];
  const indexUrls: string[] = [];
  const includes: string[] = [];
  const dir = rel.includes("/") ? rel.slice(0, rel.lastIndexOf("/") + 1) : "";
  for (let line of text.replace(/\\\r?\n/g, " ").split(/\r?\n/)) {
    line = line.replace(/(^|\s)#.*$/, "").trim();
    if (!line) continue;
    const opt = /^(-r|--requirement|-i|--index-url|--extra-index-url)(?:\s+|=)(\S+)/.exec(line);
    if (opt) {
      if (opt[1] === "-r" || opt[1] === "--requirement") {
        const target = joinRel(dir, opt[2]!);
        if (target && !seen.has(target)) {
          seen.add(target);
          const inc = readInclude(target);
          if (inc !== null) {
            const sub = parseRequirements(inc, target, readInclude, seen);
            packages.push(...sub.packages);
            indexUrls.push(...(sub.indexUrls ?? []));
            includes.push(target, ...(sub.includes ?? []));
          }
        }
      } else indexUrls.push(opt[2]!);
      continue;
    }
    if (line.startsWith("-") || /^(\.|\/|[a-z+]+:\/\/)/i.test(line)) continue; // other options, paths, URLs
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(line);
    if (!m) continue;
    const spec = m[3]!.split(";")[0]!.replace(/--hash=\S+/g, "").trim();
    if (spec.startsWith("@")) continue; // `name @ url` direct reference
    const pin = /^===?\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)$/.exec(spec);
    packages.push({ ecosystem: "PyPI", name: normalizePyName(m[1]!), version: pin ? pin[1]! : null, dev: false, direct: true, origin: "registry" });
  }
  return { status: "ok", packages, indexUrls, includes };
}

/** Join a relative include path; null if it escapes CWD or is absolute. */
export function joinRel(dir: string, p: string): string | null {
  if (/^([A-Za-z]:|[/\\~])/.test(p)) return null;
  const out: string[] = [];
  for (const seg of `${dir}${p}`.replace(/\\/g, "/").split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (!out.pop()) return null;
    } else out.push(seg);
  }
  return out.join("/") || null;
}
