import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { realpath } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { projectKey } from "../src/appdata.js";
import { ignoreCommand } from "../src/commands.js";
import { findingLabel } from "../src/ignores.js";
import { addIgnore, listIgnores, removeIgnore } from "../src/index.js";
import { byRule, K, project, scanDefault, tempDir, tty } from "./helpers.js";

describe("AC45 ignore list (local, outside the project)", () => {
  it("hides an ignored finding across re-runs and line moves; removing it shows it again", async () => {
    const appDir = tempDir();
    const key = K.openai();
    const dir = project({ "src/a.ts": `const k = "${key}";\n` });
    const first = byRule(await scanDefault(dir, { appDir }), "secret-openai");
    expect(first).toHaveLength(1);

    await addIgnore(dir, first[0]!.id, "test key", appDir);
    // Stored under <appdata>/ignores/<project hash>.json — nothing written into the project, no secret in it.
    const files = readdirSync(join(appDir, "ignores"));
    expect(files).toHaveLength(1);
    expect(readFileSync(join(appDir, "ignores", files[0]!), "utf8")).not.toContain(key);
    expect(readdirSync(dir)).toEqual(["src"]);

    let r = await scanDefault(dir, { appDir });
    expect(byRule(r, "secret-openai")).toEqual([]);
    expect(r.stats.ignored).toBe(1);

    project({ "src/a.ts": `// moved\n\n\nconst k = "${key}";\n` }, dir);
    r = await scanDefault(dir, { appDir });
    expect(byRule(r, "secret-openai")).toEqual([]);

    await removeIgnore(dir, first[0]!.id, appDir);
    expect(await listIgnores(dir, appDir)).toEqual([]);
    expect(byRule(await scanDefault(dir, { appDir }), "secret-openai")).toMatchObject([{ id: first[0]!.id, location: { line: 4 } }]);
  });

  it("A5: each entry keeps a label of what was ignored; the CLI list shows it; old entries without one still work", async () => {
    const appDir = tempDir();
    const key = K.openai();
    const dir = project({ "src/a.ts": `const k = "${key}";\n`, "src/b.ts": `const k2 = "${K.openai()}";\n` });
    const [fa, fb] = byRule(await scanDefault(dir, { appDir }), "secret-openai");
    await addIgnore(dir, fa!.id, "test key", appDir);
    expect(await listIgnores(dir, appDir)).toMatchObject([{ id: fa!.id, reason: "test key", label: `${fa!.title} — src/a.ts:1` }]);
    expect(JSON.stringify(await listIgnores(dir, appDir))).not.toContain(key.slice(-6));
    // an entry written before labels existed
    const file = join(appDir, "ignores", `${projectKey(await realpath(dir))}.json`);
    const list = JSON.parse(readFileSync(file, "utf8")) as object[];
    writeFileSync(file, JSON.stringify([...list, { id: fb!.id, reason: "old", at: "2026-01-01T00:00:00.000Z" }]));
    expect(byRule(await scanDefault(dir, { appDir }), "secret-openai")).toEqual([]);
    const t = tty(["2"]);
    expect(await ignoreCommand(t.io, { cwd: dir, appDir, lang: "en", remove: true })).toBe(0);
    expect(t.out()).toContain(`  1) ${fa!.title} — src/a.ts:1 · test key · `);
    expect(t.out()).toContain(`  2) ${fb!.id} · old · `);
    expect((await listIgnores(dir, appDir)).map((e) => e.id)).toEqual([fa!.id]);
  });

  it("A5: label parts — package@version and file:line, missing parts left out", () => {
    expect(findingLabel({ title: "Vulnerable package", package: "lodash", version: "4.17.15", location: { file: "package-lock.json", line: null } })).toBe("Vulnerable package — lodash@4.17.15 · package-lock.json");
    expect(findingLabel({ title: "RLS off", location: { file: "a.sql", line: 3 } })).toBe("RLS off — a.sql:3");
    expect(findingLabel({ title: "No lock", location: null })).toBe("No lock");
  });

  it("fingerprint ignores line numbers but not the file or the value", async () => {
    const a = K.openai();
    const dir = project({ "a.ts": `const k = "${a}";`, "b.ts": `const k = "${a}";` });
    const ids = byRule(await scanDefault(dir), "secret-openai").map((f) => f.id);
    expect(new Set(ids).size).toBe(2);
  });
});
