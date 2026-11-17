import { parse as parseToml } from "smol-toml";
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
  /** npm v2/v3 / pnpm / uv: what the lock records for the root manifest (§7-8 lock consistency). */
  root?: { deps: Record<string, string>; versions: Record<string, string> };
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

const depSpecs = (o: unknown): Record<string, string> =>
  isObj(o)
    ? Object.fromEntries(["dependencies", "devDependencies", "optionalDependencies"].flatMap((k) => (isObj(o[k]) ? Object.entries(o[k] as Obj).map(([n, v]) => [n, String(v)]) : [])))
    : {};

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
  let root: LockParse["root"];
  if (isObj(data.packages)) {
    // v2/v3: keys are install paths. Non-node_modules keys are the root ("") and workspace folders.
    const entries = Object.entries(data.packages);
    const pk = data.packages;
    const deps = depSpecs(pk[""]);
    root = {
      deps,
      versions: Object.fromEntries(
        Object.keys(deps).flatMap((n) => {
          const e = pk[`node_modules/${n}`];
          return isObj(e) && typeof e.version === "string" ? [[n, e.version]] : [];
        }),
      ),
    };
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
  return { status: "ok", packages: [...out.values()], ...(root && { root }) };
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
  let root: LockParse["root"];
  for (const o of objs) {
    const v = String(o.lockfileVersion);
    if (/^[1-5](\.|$)/.test(v)) return { status: "regenerate", detail: `lockfileVersion ${v} — regenerate with pnpm 8 or later`, packages: [] };
    if (!SUPPORTED_PNPM.has(v)) return { status: "error", detail: `unsupported lockfileVersion ${v}`, packages: [] };
    const importers: Obj[] = isObj(o.importers) ? Object.values(o.importers).filter(isObj) : [o];
    const rootImp = isObj(o.importers) ? o.importers["."] : o;
    if (isObj(rootImp) && ["dependencies", "devDependencies", "optionalDependencies"].some((k) => isObj(rootImp[k]))) {
      root = { deps: {}, versions: {} };
      for (const sect of ["dependencies", "devDependencies", "optionalDependencies"]) {
        if (!isObj(rootImp[sect])) continue;
        for (const [n, d] of Object.entries(rootImp[sect] as Obj)) {
          if (!isObj(d)) continue;
          root.deps[n] = String(d.specifier ?? "");
          root.versions[n] = stripPeers(String(d.version ?? ""));
        }
      }
    }
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
  return { status: "ok", packages: [...out.values()], ...(root && { root }) };
}

const JSON_STR = String.raw`"(?:[^"\\]|\\.)*"`;
const JSONC_COMMENT = new RegExp(`${JSON_STR}|//[^\\n]*|/\\*[\\s\\S]*?\\*/`, "g");
const JSONC_TRAILING_COMMA = new RegExp(`${JSON_STR}|,(?=\\s*[}\\]])`, "g");
/** JSON with comments and trailing commas (bun.lock); strings are kept as they are. */
const parseJsonc = (t: string): unknown => {
  const keep = (m: string): string => (m[0] === '"' ? m : "");
  return JSON.parse(t.replace(JSONC_COMMENT, keep).replace(JSONC_TRAILING_COMMA, keep));
};

const BUN_DEP_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"];

/** `"@scope/a/b"` → `["@scope/a", "b"]`: a bun.lock package key is the install path as package names. */
function bunKeyNames(key: string): string[] {
  const s = key.split("/");
  const out: string[] = [];
  for (let i = 0; i < s.length; i++) out.push(s[i]!.startsWith("@") && i + 1 < s.length ? `${s[i]}/${s[++i]}` : s[i]!);
  return out;
}

/**
 * bun.lock (Bun 1.1+ text lockfile, lockfileVersion 0 / 1). `packages` keys are install paths
 * (`parent/child` for a nested copy); a value is `[ident, ...]` with `ident = name@resolution`: npm
 * entries are `[ident, registry tarball or "", info, integrity]`, git `[ident, info, tag, integrity]`,
 * file / link / tarball `[ident, info]`, workspace `[ident]`. A dependency resolves from its parent's
 * path upward, like node_modules. Roots = every workspace (`""` is the root package.json): their
 * dependencies are direct; packages reachable only through devDependencies are dev.
 */
export function parseBunLock(text: string): LockParse {
  let d: unknown;
  try {
    d = parseJsonc(text);
  } catch {
    return { status: "error", detail: "invalid JSON", packages: [] };
  }
  if (!isObj(d) || !isObj(d.packages)) return { status: "error", detail: "invalid lockfile", packages: [] };
  if (d.lockfileVersion !== 0 && d.lockfileVersion !== 1) return { status: "error", detail: `unsupported lockfileVersion ${String(d.lockfileVersion)}`, packages: [] };
  const pk = d.packages;
  const workspaces = isObj(d.workspaces) ? Object.entries(d.workspaces).filter((e): e is [string, Obj] => isObj(e[1])) : [];
  const info = (key: string): Obj => {
    const e = pk[key];
    return (Array.isArray(e) ? (e.find(isObj) as Obj | undefined) : undefined) ?? {};
  };
  const resolve = (from: string[], name: string): string | undefined => {
    for (let i = from.length; i >= 0; i--) {
      const k = [...from.slice(0, i), name].join("/");
      if (Array.isArray(pk[k])) return k;
    }
    return undefined;
  };
  const names = (o: Obj, sections: string[]): string[] => sections.flatMap((s) => (isObj(o[s]) ? Object.keys(o[s] as Obj) : []));
  const identOf = (key: string): { name: string; version: string } | null => {
    const e = pk[key];
    const ident = Array.isArray(e) && typeof e[0] === "string" ? e[0] : "";
    const at = ident.indexOf("@", 1);
    return at > 0 ? { name: ident.slice(0, at), version: ident.slice(at + 1) } : null;
  };

  const direct = new Set<string>();
  const prodRoots: string[] = [];
  for (const [path, ws] of workspaces) {
    // Packages nested under a workspace member are keyed by its package name (`@app/ui/lodash`).
    const from = path === "" || typeof ws.name !== "string" ? [] : [ws.name];
    for (const sect of BUN_DEP_SECTIONS) {
      for (const n of names(ws, [sect])) {
        const k = resolve(from, n);
        if (!k) continue;
        direct.add(k);
        if (sect !== "devDependencies") prodRoots.push(k);
      }
    }
    // Bun installs peers: prod, but not declared dependencies.
    for (const n of names(ws, ["peerDependencies"])) {
      const k = resolve(from, n);
      if (k) prodRoots.push(k);
    }
  }
  const prod = new Set<string>();
  const stack = [...prodRoots];
  while (stack.length) {
    const k = stack.pop()!;
    if (prod.has(k)) continue;
    prod.add(k);
    const from = bunKeyNames(k);
    for (const n of names(info(k), ["dependencies", "optionalDependencies", "peerDependencies"])) {
      const c = resolve(from, n);
      if (c) stack.push(c);
    }
  }

  const out = new Map<string, Package>();
  for (const [key, e] of Object.entries(pk)) {
    const id = identOf(key);
    if (!id || !Array.isArray(e)) continue;
    const resolved = typeof e[1] === "string" && e[1] ? e[1] : undefined;
    const integrity = e.find((x): x is string => typeof x === "string" && /^sha\d+-/.test(x));
    const p: Package = {
      ecosystem: "npm",
      name: id.name,
      version: id.version || null,
      dev: !prod.has(key),
      direct: direct.has(key),
      origin: npmOrigin(id.version, resolved),
      ...(integrity && { integrity }),
      ...(resolved && { resolved }),
    };
    const prev = out.get(`${id.name}@${id.version}`);
    if (!prev) out.set(`${id.name}@${id.version}`, p);
    else {
      prev.dev &&= p.dev; // prod anywhere wins
      prev.direct ||= p.direct;
    }
  }

  // §7-8: what the lock recorded for the root package.json.
  const top = workspaces.find(([path]) => path === "")?.[1];
  let root: LockParse["root"];
  if (top) {
    root = { deps: {}, versions: {} };
    for (const sect of BUN_DEP_SECTIONS) {
      if (!isObj(top[sect])) continue;
      for (const [n, spec] of Object.entries(top[sect] as Obj)) {
        root.deps[n] = String(spec);
        const k = resolve([], n);
        const v = k ? identOf(k)?.version : undefined;
        if (v) root.versions[n] = v;
      }
    }
  }
  return { status: "ok", packages: [...out.values()], ...(root && { root }) };
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

export const PYPI_HOST = /^https?:\/\/(?:[^/@]*@)?(?:pypi\.org|pypi\.python\.org|files\.pythonhosted\.org)(?:[:/]|$)/i;

/**
 * Python declarations (name + PEP 508 spec, or "local:" for path/git/url/workspace) → name → one
 * comparable range in the npm-style syntax `satisfies` reads: markers dropped, whitespace removed,
 * `==` → `=`, comma clauses sorted and space-joined, several declarations of a name joined with `||`.
 * Both sides of the uv lock-consistency check (pyproject and uv.lock metadata) go through this.
 */
export function pySpecMap(deps: { name: string; spec: string }[]): Record<string, string> {
  const by = new Map<string, Set<string>>();
  for (const d of deps) {
    const raw = d.spec.trim();
    const spec = /^(local:|@)/.test(raw)
      ? "local:"
      : raw.split(";")[0]!.replace(/\s+/g, "").split(",").filter(Boolean).map((c) => c.replace(/^===?/, "=")).sort().join(" ");
    const n = normalizePyName(d.name);
    by.set(n, (by.get(n) ?? new Set()).add(spec));
  }
  return Object.fromEntries([...by].map(([n, s]) => [n, [...s].sort().join(" || ")]));
}

const UV_LOCAL_KEYS = ["git", "url", "path", "directory", "editable", "virtual", "workspace"];

/**
 * uv.lock (lock `version = 1`, any revision). Only packages whose source is a registry are versions
 * from an index (PyPI → registry, any other index → private); editable / virtual / path / directory /
 * git / url sources are same-repo or direct sources (local, never looked up). A name may appear at
 * several versions (resolution forks). Roots = editable / virtual packages (the project and its
 * workspace members): their dependencies are direct; packages reachable only through dev groups are dev.
 */
export function parseUvLock(text: string): LockParse {
  let d: Obj;
  try {
    d = parseToml(text) as Obj;
  } catch {
    return { status: "error", detail: "invalid TOML", packages: [] };
  }
  if (d.version !== 1) return { status: "error", detail: d.version === undefined ? "no lock version" : `unsupported lock version ${String(d.version)}`, packages: [] };
  const pkgs = (Array.isArray(d.package) ? d.package : []).filter(isObj).filter((p) => typeof p.name === "string");
  const src = (p: Obj): Obj => (isObj(p.source) ? p.source : {});
  const isRoot = (p: Obj): boolean => "editable" in src(p) || "virtual" in src(p);
  const refs = (o: unknown): Obj[] => (Array.isArray(o) ? o.filter(isObj) : isObj(o) ? Object.values(o).flatMap(refs) : []);
  const byName = new Map<string, Obj[]>();
  for (const p of pkgs) byName.set(normalizePyName(p.name as string), [...(byName.get(normalizePyName(p.name as string)) ?? []), p]);
  // A dependency names a version only when its name is locked at several.
  const resolve = (r: Obj): Obj[] => (byName.get(normalizePyName(String(r.name))) ?? []).filter((p) => typeof r.version !== "string" || p.version === r.version);

  const roots = pkgs.filter(isRoot);
  const direct = new Set(roots.flatMap((p) => [p.dependencies, p["optional-dependencies"], p["dev-dependencies"]].flatMap(refs)).map((r) => normalizePyName(String(r.name))));
  const prod = new Set<Obj>();
  const stack = [...roots];
  while (stack.length) {
    const p = stack.pop()!;
    if (prod.has(p)) continue;
    prod.add(p);
    // shortcut: every optional-dependencies (extra) of a reached package counts as prod; split by requested extras if dev flags look wrong.
    for (const r of [p.dependencies, p["optional-dependencies"]].flatMap(refs)) stack.push(...resolve(r));
  }

  const packages: Package[] = pkgs.map((p) => {
    const s = src(p);
    const hash = isObj(p.sdist) && typeof p.sdist.hash === "string" ? p.sdist.hash : refs(p.wheels).find((w) => typeof w.hash === "string")?.hash;
    return {
      ecosystem: "PyPI",
      name: normalizePyName(p.name as string),
      version: typeof p.version === "string" ? p.version : null,
      dev: !prod.has(p),
      direct: direct.has(normalizePyName(p.name as string)),
      origin: typeof s.registry === "string" ? (PYPI_HOST.test(s.registry) ? "registry" : "private") : "local",
      ...(typeof hash === "string" && { integrity: hash }),
    };
  });

  // §7-8: what the lock recorded from the root pyproject (requires-dist + dependency groups).
  const top = pkgs.find((p) => src(p).editable === "." || src(p).virtual === ".");
  let root: LockParse["root"];
  if (top && isObj(top.metadata)) {
    const reqs = [top.metadata["requires-dist"], top.metadata["requires-dev"]].flatMap(refs);
    const deps = pySpecMap(reqs.map((r) => ({ name: String(r.name), spec: UV_LOCAL_KEYS.some((k) => k in r) ? "local:" : typeof r.specifier === "string" ? r.specifier : "" })));
    const versions: Record<string, string> = {};
    for (const n of Object.keys(deps)) {
      const vs = (byName.get(n) ?? []).map((p) => p.version).filter((v): v is string => typeof v === "string");
      if (vs.length === 1) versions[n] = vs[0]!; // forked versions: no single version to check
    }
    root = { deps, versions };
  }
  return { status: "ok", packages, ...(root && { root }) };
}

/**
 * requirements*.txt: `==` pins only give a version; `-r` (*.txt / *.in only) is followed via `readInclude`
 * (which must refuse paths outside CWD); hashes, markers and constraints files (`-c`) are ignored.
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
        // Only requirement-like files: `-r .env` must not turn secret lines into names sent to PyPI.
        if (target && /\.(txt|in)$/i.test(target) && !seen.has(target)) {
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
    if (line.startsWith("-") || /^(\.|\/|[a-z][a-z0-9+.-]*:)/i.test(line)) continue; // other options (-e ./pkg), paths, URLs, file:../pkg
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
