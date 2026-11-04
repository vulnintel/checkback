import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { addIgnore, listIgnores, removeIgnore } from "../src/index.js";
import { byRule, K, project, scanDefault, tempDir } from "./helpers.js";

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

  it("fingerprint ignores line numbers but not the file or the value", async () => {
    const a = K.openai();
    const dir = project({ "a.ts": `const k = "${a}";`, "b.ts": `const k = "${a}";` });
    const ids = byRule(await scanDefault(dir), "secret-openai").map((f) => f.id);
    expect(new Set(ids).size).toBe(2);
  });
});
