import { readFileSync, statSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import { collectFiles, decode, MAX_FILE_BYTES, readText, type FileEntry } from "../files.js";
import { normalizePyName, parseNpmLock, parsePnpmLock, parseRequirements, parseUvLock, PYPI_HOST, type Ecosystem, type Package } from "./locks.js";

export interface Lockfile {
  /** CWD-relative path. */
  path: string;
  kind: "npm" | "pnpm" | "uv" | "requirements";
  status: "ok" | "regenerate" | "error";
  detail?: string;
  packages: Package[];
  /** What the lock records for its root manifest (npm v2/v3, pnpm, uv). */
  root?: { deps: Record<string, string>; versions: Record<string, string> };
}

export interface ManifestDep {
  name: string;
  /** Declared spec; local/workspace/git specs are kept so callers can see why a name is excluded. */
  spec: string;
  dev: boolean;
}

export interface Manifest {
  path: string;
  ecosystem: Ecosystem;
  /** package.json `name` / pyproject project name, PEP 503-normalized (same-repo workspace names are never looked up). */
  name?: string;
  deps: ManifestDep[];
}

export interface PrivateConfig {
  /** npm scopes routed to a non-public registry (`@acme`). */
  npmScopes: string[];
  /** The ecosystem's default registry/index is not public → whole ecosystem excluded (§7-2 rule 4). */
  allPrivate: Ecosystem[];
  /** CWD-relative files that set the above, or user-level sources (`~/.npmrc`, `env:PIP_INDEX_URL`). */
  files: string[];
}

export interface Inventory {
  lockfiles: Lockfile[];
  /** Lockfiles we recognize but do not parse yet (patch release): yarn, bun, poetry, Pipfile.lock. */
  unsupported: { path: string; kind: string }[];
  manifests: Manifest[];
  privateConfig: PrivateConfig;
}

const UNSUPPORTED = new Map([
  ["yarn.lock", "yarn"], ["bun.lock", "bun"], ["bun.lockb", "bun-binary"], ["poetry.lock", "poetry"], ["Pipfile.lock", "pipenv"],
]);
const NPM_HOST = /^https?:\/\/registry\.(?:npmjs\.org|yarnpkg\.com)\/?$/i;
const LOCAL_SPEC = /^(workspace|file|link|portal|git|git\+[a-z]+|github|gitlab|bitbucket|https?):|^[./~]|^[\w-]+\/[\w.-]+(#.*)?$/;

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const base = (rel: string): string => rel.slice(rel.lastIndexOf("/") + 1);

/**
 * Read every supported lockfile, manifest and registry config under `cwd`, plus the user-level
 * registry settings in `env` (config files under the home folder, npm/pip env vars). Local only.
 */
export async function readInventory(cwd: string, files?: FileEntry[], env: NodeJS.ProcessEnv = process.env): Promise<Inventory> {
  const root = await realpath(resolve(cwd));
  const all = (files ?? (await collectFiles(root))).filter((f) => !f.build);
  const byRel = new Map(all.map((f) => [f.rel, f]));
  const texts = new Map<string, string | null>();
  const text = async (rel: string): Promise<string | null> => {
    if (!texts.has(rel)) {
      const f = byRel.get(rel); // only collected files: inside CWD, no symlinks
      const t = f ? await readText(f.abs) : null;
      texts.set(rel, t && "text" in t ? t.text : null);
    }
    return texts.get(rel)!;
  };

  const inv: Inventory = { lockfiles: [], unsupported: [], manifests: [], privateConfig: { npmScopes: [], allPrivate: [], files: [] } };
  const priv = inv.privateConfig;
  const markAll = (eco: Ecosystem, rel: string): void => {
    if (!priv.allPrivate.includes(eco)) priv.allPrivate.push(eco);
    if (!priv.files.includes(rel)) priv.files.push(rel);
  };
  const markScope = (scope: string, rel: string): void => {
    if (!priv.npmScopes.includes(scope)) priv.npmScopes.push(scope);
    if (!priv.files.includes(rel)) priv.files.push(rel);
  };

  /** `registry` / `@scope:registry` (npmrc key or npm_config_* env suffix) → private unless the public registry. */
  const npmRegistry = (key: string, url: string, label: string): void => {
    if (NPM_HOST.test(url)) return;
    if (/^registry$/i.test(key)) markAll("npm", label);
    else if (/^@[a-z0-9._-]+:registry$/i.test(key)) markScope(key.slice(0, key.indexOf(":")).toLowerCase(), label);
  };
  const npmrc = (t: string, label: string): void => {
    for (const line of t.split(/\r?\n/)) {
      const m = /^\s*(registry|@[a-z0-9._-]+:registry)\s*=\s*(\S+)/i.exec(line);
      if (m) npmRegistry(m[1]!, m[2]!, label);
    }
  };
  const yarnrc = (t: string, label: string): void => {
    let y: unknown;
    try {
      y = parseYaml(t, { schema: "core", maxAliasCount: 50 });
    } catch {
      return;
    }
    if (!isObj(y)) return;
    if (typeof y.npmRegistryServer === "string" && !NPM_HOST.test(y.npmRegistryServer)) markAll("npm", label);
    if (isObj(y.npmScopes)) {
      for (const [scope, cfg] of Object.entries(y.npmScopes)) {
        if (isObj(cfg) && typeof cfg.npmRegistryServer === "string" && !NPM_HOST.test(cfg.npmRegistryServer)) markScope(`@${scope.replace(/^@/, "").toLowerCase()}`, label);
      }
    }
  };

  // `-r` includes: only collected files (inside CWD, no symlinks), read synchronously.
  const readInclude = (rel: string): string | null => {
    const f = byRel.get(rel);
    try {
      if (!f || statSync(f.abs).size > MAX_FILE_BYTES) return null;
      const t = decode(readFileSync(f.abs));
      return "text" in t ? t.text : null;
    } catch {
      return null;
    }
  };

  // pnpm catalogs (B7): `"x": "catalog:"` takes its spec (possibly an `npm:` alias) from pnpm-workspace.yaml.
  // shortcut: catalogs of every pnpm-workspace.yaml are merged; split per workspace root if two ever disagree.
  const catalogs = new Map<string, Obj>();
  for (const f of all) {
    if (base(f.rel) !== "pnpm-workspace.yaml") continue;
    let y: unknown;
    try {
      y = parseYaml((await text(f.rel)) ?? "", { schema: "core", maxAliasCount: 50 });
    } catch {
      continue;
    }
    if (!isObj(y)) continue;
    if (isObj(y.catalog)) catalogs.set("default", { ...catalogs.get("default"), ...y.catalog });
    if (isObj(y.catalogs)) for (const [n, c] of Object.entries(y.catalogs)) if (isObj(c)) catalogs.set(n, { ...catalogs.get(n), ...c });
  }
  const catalogSpec = (name: string, spec: string): string => {
    const m = /^catalog:(.*)$/.exec(spec);
    const v = m ? catalogs.get(m[1]!.trim() || "default")?.[name] : undefined;
    return typeof v === "string" ? v : spec;
  };

  for (const f of all) {
    const b = base(f.rel);
    const unsupported = UNSUPPORTED.get(b);
    if (unsupported) {
      inv.unsupported.push({ path: f.rel, kind: unsupported });
      continue;
    }
    if (b === "uv.lock") {
      const t = await text(f.rel);
      // Any non-PyPI index in the lock (even an unreadable one) keeps every PyPI name local (§7-2 rule 4).
      for (const m of t?.matchAll(/registry\s*=\s*"([^"]+)"/g) ?? []) if (!PYPI_HOST.test(m[1]!)) markAll("PyPI", f.rel);
      inv.lockfiles.push({ path: f.rel, kind: "uv", ...(t === null ? { status: "error", detail: "unreadable", packages: [] } : parseUvLock(t)) });
    } else if (b === "package-lock.json" || b === "npm-shrinkwrap.json") {
      const t = await text(f.rel);
      const dir = f.rel.slice(0, f.rel.length - b.length);
      const pj = await text(`${dir}package.json`);
      let manifest: unknown;
      try {
        manifest = pj ? JSON.parse(pj) : undefined;
      } catch {
        manifest = undefined;
      }
      inv.lockfiles.push({ path: f.rel, kind: "npm", ...(t === null ? { status: "error", detail: "unreadable", packages: [] } : parseNpmLock(t, manifest)) });
    } else if (b === "pnpm-lock.yaml") {
      const t = await text(f.rel);
      inv.lockfiles.push({ path: f.rel, kind: "pnpm", ...(t === null ? { status: "error", detail: "unreadable", packages: [] } : parsePnpmLock(t)) });
    } else if (/^requirements[^/]*\.txt$/i.test(b)) {
      const t = await text(f.rel);
      if (t === null) continue;
      const r = parseRequirements(t, f.rel, readInclude);
      for (const url of r.indexUrls ?? []) if (!PYPI_HOST.test(url)) markAll("PyPI", f.rel);
      inv.lockfiles.push({ path: f.rel, kind: "requirements", status: r.status, packages: r.packages });
    } else if (b === "package.json") {
      const t = await text(f.rel);
      try {
        const d: unknown = t ? JSON.parse(t) : null;
        if (!isObj(d)) continue;
        const deps: ManifestDep[] = [];
        for (const [sect, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]] as const) {
          if (isObj(d[sect])) for (const [name, spec] of Object.entries(d[sect])) deps.push({ name, spec: catalogSpec(name, String(spec)), dev });
        }
        inv.manifests.push({ path: f.rel, ecosystem: "npm", ...(typeof d.name === "string" && { name: d.name }), deps });
      } catch {
        // invalid package.json: nothing to list
      }
    } else if (b === "pyproject.toml" || b === "Pipfile") {
      const t = await text(f.rel);
      let d: Obj;
      try {
        d = t ? (parseToml(t) as Obj) : {};
      } catch {
        continue;
      }
      const tool = isObj(d.tool) ? d.tool : {};
      // The project's own name: same-repo packages (uv workspace members, path deps) are never looked up (B7).
      const own = isObj(d.project) && typeof d.project.name === "string" ? d.project.name : isObj(tool.poetry) && typeof tool.poetry.name === "string" ? tool.poetry.name : undefined;
      inv.manifests.push({ path: f.rel, ecosystem: "PyPI", ...(own && { name: normalizePyName(own) }), deps: pythonDeps(b, d) });
      const sources = [
        ...(Array.isArray(d.source) ? d.source : []), // Pipfile [[source]]
        ...(isObj(tool.poetry) && Array.isArray(tool.poetry.source) ? tool.poetry.source : []),
        ...(isObj(tool.uv) && Array.isArray(tool.uv.index) ? tool.uv.index : []),
      ];
      for (const s of sources) if (isObj(s) && typeof s.url === "string" && !PYPI_HOST.test(s.url)) markAll("PyPI", f.rel);
    } else if (b === ".npmrc") {
      npmrc((await text(f.rel)) ?? "", f.rel);
    } else if (b === ".yarnrc.yml") {
      yarnrc((await text(f.rel)) ?? "", f.rel);
    }
  }
  await userRegistryConfig(env, {
    npmrc,
    yarnrc,
    npmRegistry,
    pip: (urls, label) => {
      for (const u of urls) if (!PYPI_HOST.test(u)) markAll("PyPI", label);
    },
  });
  priv.npmScopes.sort();
  priv.files.sort();
  return inv;
}

interface UserConfigSinks {
  npmrc(text: string, label: string): void;
  yarnrc(text: string, label: string): void;
  npmRegistry(key: string, url: string, label: string): void;
  pip(urls: string[], label: string): void;
}

/** `index-url` / `extra-index-url` values (incl. indented continuation lines) from a pip.conf / pip.ini. */
export function pipConfigUrls(t: string): string[] {
  const out: string[] = [];
  let on = false;
  for (const line of t.split(/\r?\n/)) {
    const m = /^([\w-]+)\s*[=:]\s*(.*)$/.exec(line);
    if (m) {
      on = /^(extra[-_])?index[-_]url$/i.test(m[1]!);
      if (on) out.push(...m[2]!.split(/\s+/).filter(Boolean));
    } else if (on && /^\s+\S/.test(line)) out.push(...line.trim().split(/\s+/));
    else on = false;
  }
  return out;
}

/**
 * §7-2 rules applied to registry settings outside the repo: a private registry set only in ~/.npmrc,
 * pip.conf or the environment must keep private names from going out too. Read only — values (URLs,
 * tokens) are never kept; labels name the source, with the home folder shown as `~`.
 */
async function userRegistryConfig(env: NodeJS.ProcessEnv, sink: UserConfigSinks): Promise<void> {
  const home = (process.platform === "win32" ? env.USERPROFILE || env.HOME : env.HOME) || homedir();
  const label = (p: string): string => (p.startsWith(home) ? `~${p.slice(home.length).replace(/\\/g, "/")}` : p);
  const read = async (p: string): Promise<string | null> => {
    const t = await readText(p);
    return "text" in t ? t.text : null;
  };
  const get = (name: string): string | undefined => env[name] || env[name.toLowerCase()] || undefined;
  const xdg = env.XDG_CONFIG_HOME || join(home, ".config");

  // npm, and pnpm (reads the same npmrc plus its own rc): user npmrc, pnpm rc per OS, npm_config_* env (any case).
  const npmrcFiles = [
    get("NPM_CONFIG_USERCONFIG") || join(home, ".npmrc"),
    join(xdg, "pnpm", "rc"),
    join(env.LOCALAPPDATA || join(home, "AppData", "Local"), "pnpm", "config", "rc"),
    join(home, "Library", "Preferences", "pnpm", "rc"),
  ];
  for (const p of new Set(npmrcFiles)) {
    const t = await read(p);
    if (t !== null) sink.npmrc(t, label(p));
  }
  for (const [k, v] of Object.entries(env)) {
    const m = /^npm_config_(.+)$/i.exec(k);
    if (m && v) sink.npmRegistry(m[1]!, v, `env:${k}`);
  }
  // yarn berry: home .yarnrc.yml, YARN_NPM_REGISTRY_SERVER.
  const yarnrc = join(home, ".yarnrc.yml");
  const y = await read(yarnrc);
  if (y !== null) sink.yarnrc(y, label(yarnrc));
  const yr = get("YARN_NPM_REGISTRY_SERVER");
  if (yr) sink.yarnrc(JSON.stringify({ npmRegistryServer: yr }), "env:YARN_NPM_REGISTRY_SERVER");

  // pip: every location pip reads on any OS (missing ones are skipped), PIP_CONFIG_FILE, the venv, env.
  const pipFiles = [
    get("PIP_CONFIG_FILE"),
    join(env.APPDATA || join(home, "AppData", "Roaming"), "pip", "pip.ini"),
    join(home, "pip", "pip.ini"),
    join(env.ProgramData || env.PROGRAMDATA || "C:\\ProgramData", "pip", "pip.ini"),
    join(xdg, "pip", "pip.conf"),
    join(home, ".pip", "pip.conf"),
    join(home, "Library", "Application Support", "pip", "pip.conf"),
    "/etc/pip.conf",
    "/etc/xdg/pip/pip.conf",
    ...(env.VIRTUAL_ENV ? [join(env.VIRTUAL_ENV, "pip.ini"), join(env.VIRTUAL_ENV, "pip.conf")] : []),
  ];
  for (const p of new Set(pipFiles.filter((x): x is string => !!x))) {
    const t = await read(p);
    if (t !== null) sink.pip(pipConfigUrls(t), label(p));
  }
  for (const k of ["PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL"]) {
    const v = get(k);
    if (v) sink.pip(v.split(/\s+/).filter(Boolean), `env:${k}`);
  }
}

function pythonDeps(file: string, d: Obj): ManifestDep[] {
  const out: ManifestDep[] = [];
  const pep508 = (s: unknown, dev: boolean): void => {
    const m = typeof s === "string" ? /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$/.exec(s) : null;
    if (m) out.push({ name: normalizePyName(m[1]!), spec: m[3]!.trim(), dev });
  };
  const table = (t: unknown, dev: boolean): void => {
    if (isObj(t)) {
      for (const [n, v] of Object.entries(t)) {
        if (n.toLowerCase() !== "python") out.push({ name: normalizePyName(n), spec: typeof v === "string" ? v : isObj(v) && (v.path || v.git || v.url) ? "local:" : "", dev });
      }
    }
  };
  if (file === "Pipfile") {
    table(d.packages, false);
    table(d["dev-packages"], true);
    return out;
  }
  const project = isObj(d.project) ? d.project : {};
  for (const s of Array.isArray(project.dependencies) ? project.dependencies : []) pep508(s, false);
  if (isObj(project["optional-dependencies"])) for (const l of Object.values(project["optional-dependencies"])) for (const s of Array.isArray(l) ? l : []) pep508(s, false);
  if (isObj(d["dependency-groups"])) for (const l of Object.values(d["dependency-groups"])) for (const s of Array.isArray(l) ? l : []) pep508(s, true);
  const poetry = isObj(d.tool) && isObj(d.tool.poetry) ? d.tool.poetry : {};
  table(poetry.dependencies, false);
  table(poetry["dev-dependencies"], true);
  // Legacy uv dev list (uv.lock records it as the "dev" group).
  const uvTool = isObj(d.tool) && isObj(d.tool.uv) ? d.tool.uv : {};
  for (const s of Array.isArray(uvTool["dev-dependencies"]) ? uvTool["dev-dependencies"] : []) pep508(s, true);
  if (isObj(poetry.group)) for (const g of Object.values(poetry.group)) if (isObj(g)) table(g.dependencies, true);
  // [tool.uv.sources] workspace / path / git / url entries are not from PyPI (B7).
  const uv = isObj(uvTool.sources) ? uvTool.sources : {};
  const local = new Set(Object.entries(uv).filter(([, v]) => [v].flat().some((s) => isObj(s) && (s.workspace === true || s.path || s.git || s.url))).map(([n]) => normalizePyName(n)));
  for (const x of out) if (local.has(x.name)) x.spec = "local:";
  return out;
}

export interface LookupTarget {
  ecosystem: Ecosystem;
  name: string;
  /** null = from a manifest only (name lookup, no version). */
  version: string | null;
  /** CWD-relative lockfile or manifest paths that contain it. */
  sources: string[];
  dev: boolean;
}

export interface LookupScope {
  /** May be sent to OSV / registries / VulnIntel (§3-1). */
  targets: LookupTarget[];
  excluded: { local: number; workspace: number; private_scope: number; private_registry: number };
  /** Ecosystems excluded entirely by a non-public default registry/index (S4 info). */
  privateEcosystems: Ecosystem[];
}

const npmScope = (name: string): string | null => (name.startsWith("@") ? name.slice(0, name.indexOf("/")).toLowerCase() : null);

/**
 * §7-2 external lookup scope: lock entries + manifest names missing from every lock of that
 * ecosystem; private scopes / registries, local specs and same-repo workspace names excluded.
 * (Import names are added by the builtin in stage 4.)
 */
export function lookupScope(inv: Inventory): LookupScope {
  const priv = inv.privateConfig;
  const workspace = new Set(inv.manifests.flatMap((m) => (m.name ? [`${m.ecosystem}\0${m.name}`] : [])));
  const excluded = { local: 0, workspace: 0, private_scope: 0, private_registry: 0 };
  const reason = (eco: Ecosystem, name: string, origin: Package["origin"]): keyof typeof excluded | null => {
    if (origin === "local") return "local";
    if (workspace.has(`${eco}\0${eco === "PyPI" ? normalizePyName(name) : name}`)) return "workspace";
    if (priv.allPrivate.includes(eco)) return "private_registry";
    const scope = eco === "npm" ? npmScope(name) : null;
    if (scope && priv.npmScopes.includes(scope)) return "private_scope";
    return origin === "private" ? "private_registry" : null;
  };
  const targets = new Map<string, LookupTarget>();
  const add = (eco: Ecosystem, name: string, version: string | null, source: string, dev: boolean): void => {
    const key = `${eco}\0${name}\0${version ?? ""}`;
    const t = targets.get(key);
    if (t) {
      if (!t.sources.includes(source)) t.sources.push(source);
      t.dev &&= dev;
    } else targets.set(key, { ecosystem: eco, name, version, sources: [source], dev });
  };
  const locked = new Set<string>();
  for (const lf of inv.lockfiles) {
    for (const p of lf.packages) {
      locked.add(`${p.ecosystem}\0${p.name}`);
      const r = reason(p.ecosystem, p.name, p.origin);
      if (r) excluded[r]++;
      else add(p.ecosystem, p.name, p.version, lf.path, p.dev);
    }
  }
  for (const m of inv.manifests) {
    for (const d of m.deps) {
      let name = d.name;
      const alias = /^npm:((?:@[^/@]+\/)?[^@]+)/.exec(d.spec);
      if (alias) name = alias[1]!;
      if (locked.has(`${m.ecosystem}\0${name}`)) continue;
      const local = m.ecosystem === "npm" ? !alias && LOCAL_SPEC.test(d.spec) : /^local:|^@/.test(d.spec);
      const r = reason(m.ecosystem, name, local ? "local" : "registry");
      if (r) excluded[r]++;
      else add(m.ecosystem, name, null, m.path, d.dev);
    }
  }
  const sorted = [...targets.values()].sort((a, b) => cmp(a.ecosystem, b.ecosystem) || cmp(a.name, b.name) || cmp(a.version ?? "", b.version ?? ""));
  // A lock file is the primary source; a requirements file (often `uv export` output) comes after it.
  const reqLast = (s: string): number => (/(^|\/)requirements[^/]*\.txt$/i.test(s) ? 1 : 0);
  for (const t of sorted) t.sources.sort((a, b) => reqLast(a) - reqLast(b) || cmp(a, b));
  return { targets: sorted, excluded, privateEcosystems: [...priv.allPrivate].sort() };
}

const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
