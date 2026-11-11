import { readFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { parseUvLock } from "../src/deps/locks.js";
import { collectFiles } from "../src/files.js";
import { buildSbom, loadDefaultTemplate, lookupScope, readInventory, scan, type ScanResult } from "../src/index.js";
import { fixPromptText } from "../src/prompts.js";
import { lockLooksHandEdited, lockStates, recordFixRequest } from "../src/recheck.js";
import { byRule, consentedAppDir, mockNet, project, scanDefault } from "./helpers.js";

// Real uv.lock files written by uv 0.11 (`uv lock`): a single project with a forked resolution, and a
// workspace with a member, a path dependency and a git dependency.
const fx = (p: string): string => readFileSync(new URL(`./fixtures/locks/${p}`, import.meta.url), "utf8");
const simpleFiles = (): Record<string, string> => ({ "pyproject.toml": fx("uv-simple/pyproject.toml"), "uv.lock": fx("uv-simple/uv.lock") });
const wsFiles = (): Record<string, string> =>
  Object.fromEntries(["pyproject.toml", "uv.lock", "packages/ws-lib/pyproject.toml", "vendor/localpkg/pyproject.toml"].map((p) => [p, fx(`uv-workspace/${p}`)]));

const NOW = Date.UTC(2026, 10, 4);
const JINJA = { id: "GHSA-jj-0001", aliases: ["CVE-2019-10906"], database_specific: { severity: "HIGH" }, affected: [{ package: { ecosystem: "PyPI", name: "jinja2" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.10.1" }] }] }] };
const jinjaNet = (versions = ["2.10"]): ReturnType<typeof mockNet> =>
  mockNet({ osv: Object.fromEntries(versions.map((v) => [`PyPI:jinja2@${v}`, [JINJA.id]])), vulns: { [JINJA.id]: JINJA } });
const pkgs = (r: ReturnType<typeof parseUvLock>): string[] => r.packages.map((p) => `${p.name}@${p.version}:${p.origin}${p.dev ? ":dev" : ""}${p.direct ? ":direct" : ""}`).sort();

describe("uv.lock parser", () => {
  it("real lock: registry packages, forked versions (resolution-markers), dev group, extras, project itself local", () => {
    const r = parseUvLock(fx("uv-simple/uv.lock"));
    expect(r.status).toBe("ok");
    expect(pkgs(r)).toEqual([
      "certifi@2026.10.23:registry",
      "charset-normalizer@3.5.2:registry",
      "click@8.0.0:registry:direct",
      "colorama@0.4.6:registry",
      "idna@3.20:registry",
      "iniconfig@2.0.0:registry:dev:direct",
      "jinja2@2.10:registry:direct",
      "markupsafe@3.0.4:registry",
      "requests@2.32.5:registry:direct",
      "requests@2.34.2:registry:direct",
      "six@1.15.0:registry:direct",
      "six@1.16.0:registry:direct",
      "urllib3@2.6.3:registry",
      "urllib3@2.8.0:registry",
      "uv-app@0.1.0:local",
    ]);
    expect(r.packages.filter((p) => p.origin === "registry").every((p) => p.integrity?.startsWith("sha256:"))).toBe(true);
    // Forked names have no single version to check against the manifest range.
    expect(r.root).toEqual({
      deps: { click: "=8.0.0", iniconfig: "=2.0.0", jinja2: "=2.10", requests: "<3 >=2.20", six: "=1.15.0 || =1.16.0" },
      versions: { click: "8.0.0", iniconfig: "2.0.0", jinja2: "2.10" },
    });
  });

  it("real workspace lock: editable member, virtual root, directory and git sources are local", () => {
    const r = parseUvLock(fx("uv-workspace/uv.lock"));
    expect(pkgs(r)).toEqual([
      "localpkg@0.1.0:local:direct",
      "markupsafe@2.1.5:registry:direct",
      "packaging@24.0:local:direct",
      "six@1.16.0:registry:direct",
      "ws-lib@0.1.0:local:direct",
      "ws-root@0.1.0:local",
    ]);
  });

  it("names are PEP 503-normalized; a non-PyPI index is private; url / path sources are local", () => {
    const r = parseUvLock(`version = 1
revision = 2

[[package]]
name = "Foo_Bar.baz"
version = "1.0"
source = { registry = "https://pypi.acme.dev/simple" }
wheels = [{ url = "https://pypi.acme.dev/f/foo_bar.baz-1.0-py3-none-any.whl", hash = "sha256:aa" }]

[[package]]
name = "wheelpkg"
version = "2.0"
source = { url = "https://example.com/wheelpkg-2.0-py3-none-any.whl" }

[[package]]
name = "pathwhl"
version = "3.0"
source = { path = "dist/pathwhl-3.0-py3-none-any.whl" }
`);
    expect(r.packages.map((p) => [p.name, p.origin, p.integrity])).toEqual([
      ["foo-bar-baz", "private", "sha256:aa"],
      ["wheelpkg", "local", undefined],
      ["pathwhl", "local", undefined],
    ]);
  });

  it("unsupported lock version, missing version and broken TOML are errors (lock could not be read)", () => {
    expect(parseUvLock('version = 2\n[[package]]\nname = "x"\n')).toMatchObject({ status: "error", detail: "unsupported lock version 2", packages: [] });
    expect(parseUvLock('[[package]]\nname = "x"\n')).toMatchObject({ status: "error", detail: "no lock version" });
    expect(parseUvLock("version = 1\n<<<<<<< HEAD\n")).toMatchObject({ status: "error", detail: "invalid TOML" });
  });
});

describe("uv.lock inventory, lookup scope and SBOM", () => {
  it("workspace: members, path and git packages are never looked up (dify-style layout)", async () => {
    const s = lookupScope(await readInventory(project(wsFiles())));
    expect(s.targets.map((t) => `${t.name}@${t.version}`)).toEqual(["markupsafe@2.1.5", "six@1.16.0"]);
    expect(s.targets.every((t) => t.sources[0] === "uv.lock")).toBe(true);
  });

  it("a non-PyPI index in uv.lock keeps all PyPI names local (§7-2 rule 4)", async () => {
    const lock = 'version = 1\n\n[[package]]\nname = "torch"\nversion = "2.4.0"\nsource = { registry = "https://download.pytorch.org/whl/cpu" }\n';
    const s = lookupScope(await readInventory(project({ "uv.lock": lock, "requirements.txt": "requests==2.31.0\n" })));
    expect(s.targets).toEqual([]);
    expect(s.privateEcosystems).toEqual(["PyPI"]);
  });

  it("SBOM lists uv.lock registry packages as pkg:pypi purls (forked versions both), never the project or members", async () => {
    let bom = JSON.parse(buildSbom(await readInventory(project(simpleFiles())))) as { components: { purl: string }[] };
    const purls = bom.components.map((c) => c.purl);
    expect(purls).toContain("pkg:pypi/jinja2@2.10");
    expect(purls).toEqual(expect.arrayContaining(["pkg:pypi/six@1.15.0", "pkg:pypi/six@1.16.0"]));
    expect(purls).toHaveLength(14);
    bom = JSON.parse(buildSbom(await readInventory(project(wsFiles())))) as { components: { purl: string }[] };
    expect(bom.components.map((c) => c.purl)).toEqual(["pkg:pypi/markupsafe@2.1.5", "pkg:pypi/six@1.16.0"]);
  });
});

describe("vulnerable-deps with uv.lock", () => {
  it("finds the vulnerable locked version; only registry names go to OSV; no 'unsupported' or 'version unknown' item", async () => {
    const net = jinjaNet();
    const r = await scanDefault(project({ ...simpleFiles(), "api/pyproject.toml": '[project]\nname = "api"\ndependencies = ["flask"]\n' }), {
      appDir: await consentedAppDir({ vulnintel: false, registry: false }),
      fetch: net.fetch,
      now: () => NOW,
    });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ kind: "vulnerable", package: "jinja2", version: "2.10", fixed_version: "2.10.1", lockfile: "uv.lock", ecosystem: "PyPI" }]);
    const sent = net.calls.filter((c) => c.url.endsWith("/v1/querybatch")).map((c) => c.body ?? "").join("\n");
    expect(sent).toContain('"name":"jinja2"');
    expect(sent).not.toMatch(/uv-app|"name":"api"/);
  });

  it("workspace: zero OSV queries for members, path or git packages", async () => {
    const net = mockNet({});
    await scanDefault(project(wsFiles()), { appDir: await consentedAppDir({ vulnintel: false, registry: false }), fetch: net.fetch, now: () => NOW });
    const names = net.calls.filter((c) => c.url.endsWith("/v1/querybatch")).flatMap((c) => (JSON.parse(c.body!) as { queries: { package: { name: string } }[] }).queries.map((q) => q.package.name));
    expect([...new Set(names)].sort()).toEqual(["markupsafe", "six"]);
  });

  it("uv.lock + requirements.txt in one folder: one item per package@version with uv.lock as its lock; names uv.lock pins are not 'unpinned'", async () => {
    const net = jinjaNet();
    const appDir = await consentedAppDir({ vulnintel: false, registry: false });
    // `uv export`-style pins plus a hand-written unpinned name that uv.lock pins.
    let r = await scanDefault(project({ ...simpleFiles(), "requirements.txt": "jinja2==2.10\nrequests\n" }), { appDir, fetch: net.fetch, now: () => NOW });
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ kind: "vulnerable", package: "jinja2", lockfile: "uv.lock", related: ["uv.lock", "requirements.txt"] }]);
    // A name uv.lock does not pin is still unpinned.
    r = await scanDefault(project({ ...simpleFiles(), "requirements.txt": "jinja2==2.10\nflask\n" }), { appDir, fetch: net.fetch, now: () => NOW });
    expect(byRule(r, "vulnerable-deps").map((f) => f.kind).sort()).toEqual(["version_unpinned", "vulnerable"]);
  });

  it("B3/B8: unsupported uv.lock version → 'lock could not be read', and it still covers the pyproject (no 'no lock file')", async () => {
    const at = (r: ScanResult): (string | undefined)[][] => byRule(r, "vulnerable-deps").map((f) => [f.kind, f.confidence, f.location?.file]);
    const py = '[project]\nname = "app"\ndependencies = ["fastapi"]\n';
    expect(at(await scanDefault(project({ "pyproject.toml": py, "uv.lock": "version = 9\n" })))).toEqual([["lock_unreadable", "review", "uv.lock"]]);
    // A root uv.lock covers member pyprojects, not a package.json.
    const r = await scanDefault(
      project({ "uv.lock": "version = 1\n", "pyproject.toml": py, "server/pyproject.toml": '[project]\nname = "srv"\ndependencies = ["uvicorn"]\n', "web/package.json": JSON.stringify({ name: "w", dependencies: { x: "1" } }) }),
    );
    expect(at(r)).toEqual([["version_unknown", "review", "web/package.json"]]);
  });

  it("fix prompt for a uv.lock item names the uv commands (bump a declared package / upgrade a transitive one), never a new install", async () => {
    const r = await scanDefault(project(simpleFiles()), { appDir: await consentedAppDir({ vulnintel: false, registry: false }), fetch: jinjaNet().fetch, now: () => NOW });
    const tpl = await loadDefaultTemplate();
    const f = byRule(r, "vulnerable-deps")[0]!;
    const ko = fixPromptText([f], tpl, "ko").text;
    expect(ko).toContain('`uv add "jinja2>=2.10.1"`');
    expect(ko).toContain("`uv lock --upgrade-package jinja2`");
    expect(ko).toContain("lock 파일을 손으로 고치지 마세요");
    expect(fixPromptText([f], tpl, "en").text).toContain("pyproject.toml already declares the package");
    // The generic package-manager sentence is replaced, not repeated.
    expect(ko).not.toContain("패키지 매니저 명령으로");
  });
});

describe("recheck lock consistency with uv.lock (§7-8)", () => {
  const lock = (o: { v?: string; hash?: string; spec?: string; extra?: string } = {}): string => `version = 1
revision = 3
requires-python = ">=3.9"

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "jinja2" }]

[package.metadata]
requires-dist = [{ name = "jinja2", specifier = "${o.spec ?? ">=2.10"}" }${o.extra ?? ""}]

[[package]]
name = "jinja2"
version = "${o.v ?? "2.10"}"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/00/jinja2-${o.v ?? "2.10"}.tar.gz", hash = "sha256:${o.hash ?? "a0"}" }
`;
  const py = (spec = ">= 2.10", more = ""): string => `[project]\nname = "app"\nversion = "0.1.0"\ndependencies = ["Jinja2 ${spec}"${more}]\n`;
  const state = async (files: Record<string, string>) => {
    const dir = await realpath(project(files));
    return (await lockStates(await readInventory(dir), await collectFiles(dir)))[0]!;
  };
  const rescan = async (dir: string, appDir: string, fetch: typeof globalThis.fetch): Promise<ScanResult> =>
    scan(dir, await loadDefaultTemplate(), { appDir, fetch, now: () => NOW });
  const baseline = async (dir: string, appDir: string, fetch: typeof globalThis.fetch): Promise<void> => {
    const r = await rescan(dir, appDir, fetch);
    await recordFixRequest(dir, r.findings.filter((f) => f.confidence !== "info").map((f) => f.id), appDir, NOW);
  };

  it("real uv locks agree with their pyproject (markers, extras, groups, workspace sources, spacing)", async () => {
    expect(lockLooksHandEdited(undefined, await state(simpleFiles()))).toBe(false);
    expect(lockLooksHandEdited(undefined, await state(wsFiles()))).toBe(false);
  });

  it("(1) manifest names ≠ lock root; (2) locked version outside the recorded range; (3) same version, new hash; (4) new version, old hash or none", async () => {
    const base = await state({ "pyproject.toml": py(), "uv.lock": lock() });
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(">= 2.10", ', "rich"'), "uv.lock": lock({ hash: "a1" }) }))).toBe(true); // (1)
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(), "uv.lock": lock({ hash: "a1", extra: ', { name = "ghost" }' }) }))).toBe(true); // (1)
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py("<2.10"), "uv.lock": lock({ spec: "<2.10" }) }))).toBe(true); // (2)
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(), "uv.lock": lock({ hash: "b0" }) }))).toBe(true); // (3)
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(), "uv.lock": lock({ v: "2.10.1" }) }))).toBe(true); // (4) old hash
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(), "uv.lock": lock({ v: "2.10.1" }).replace(/^sdist = .*$/m, "") }))).toBe(true); // (4) no hash
    expect(lockLooksHandEdited(base, await state({ "pyproject.toml": py(), "uv.lock": lock({ v: "2.10.1", hash: "c0" }) }))).toBe(false); // real upgrade
  });

  it("hand-bumped uv.lock (hash kept) → 'lock mismatch'; regenerated → resolved", async () => {
    const net = jinjaNet();
    const appDir = await consentedAppDir({ vulnintel: false, registry: false });
    const dir = project({ "pyproject.toml": py(), "uv.lock": lock() });
    await baseline(dir, appDir, net.fetch);
    project({ "uv.lock": lock({ v: "2.10.1" }) }, dir);
    let r = await rescan(dir, appDir, net.fetch);
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ recheck: "lock_mismatch", carried: true, package: "jinja2", version: "2.10" }]);
    project({ "uv.lock": lock({ v: "2.10.1", hash: "c0" }) }, dir);
    r = await rescan(dir, appDir, net.fetch);
    expect(r.compare!.counts).toMatchObject({ resolved: 1, lock_mismatch: 0 });
  });

  it("Q4: pyproject bumped, uv.lock untouched → 'remaining' + lock_not_regenerated; Q3: re-locked at a still-vulnerable version pairs", async () => {
    const net = jinjaNet(["2.10", "2.10.0.post1"]);
    const appDir = await consentedAppDir({ vulnintel: false, registry: false });
    const dir = project({ "pyproject.toml": py(), "uv.lock": lock() });
    await baseline(dir, appDir, net.fetch);
    project({ "pyproject.toml": py(">=2.10.1") }, dir);
    let r = await rescan(dir, appDir, net.fetch);
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ recheck: "remaining", recheck_note: "lock_not_regenerated", package: "jinja2" }]);
    // Whitespace / ordering only: the declaration did not change → no note.
    project({ "pyproject.toml": py(">=2.10 ") }, dir);
    r = await rescan(dir, appDir, net.fetch);
    expect(byRule(r, "vulnerable-deps")[0]!.recheck_note).toBeUndefined();
    // Regenerated at another vulnerable version → one 'remaining' card A → B.
    project({ "pyproject.toml": py(), "uv.lock": lock({ v: "2.10.0.post1", hash: "d0" }) }, dir);
    r = await rescan(dir, appDir, net.fetch);
    expect(byRule(r, "vulnerable-deps")).toMatchObject([{ recheck: "remaining", recheck_note: "version_bumped_still_vulnerable", previous_version: "2.10", version: "2.10.0.post1" }]);
  });
});
