import { describe, expect, it } from "vitest";
import { loadTemplate, scan } from "../src/index.js";
import { findSlowPattern, RegexRunner } from "../src/regex-runner.js";
import { byRule, project, tempDir } from "./helpers.js";

describe("regex runner (§10-2, O4 worker_threads + time limit)", () => {
  it("returns matches with review flags and allow filtering", async () => {
    const r = new RegexRunner([{ match: ["k=\\w+"], review: ["test"], allow: ["ok"] }]);
    try {
      const res = await r.run("k=a\nk=b test\nk=c ok\n", [0]);
      expect(res.matches.get(0)!.map((m) => [m.value, m.review])).toEqual([
        ["k=a", false],
        ["k=b", true],
      ]);
    } finally {
      r.close();
    }
  });

  it("kills a runaway rule and still returns the other rules' results", async () => {
    const r = new RegexRunner([
      { match: ["(x+x+)+y"], review: [], allow: [] },
      { match: ["needle"], review: [], allow: [] },
    ]);
    try {
      const t0 = Date.now();
      const res = await r.run(`${"x".repeat(40)} needle`, [0, 1]);
      expect(res.timedOut).toEqual([0]);
      expect(res.matches.get(1)!.length).toBe(1);
      expect(Date.now() - t0).toBeLessThan(3000);
      // The runner recovers for the next file.
      expect((await r.run("needle", [1])).matches.get(1)!.length).toBe(1);
    } finally {
      r.close();
    }
  });

  it("import check flags catastrophic patterns only", async () => {
    expect(await findSlowPattern(["^(a+)+$", "sk-[A-Za-z0-9]{20,}"])).toBe("^(a+)+$");
    expect(await findSlowPattern(["sk-[A-Za-z0-9]{20,}", "(?<![A-Z])AKIA[A-Z0-9]{16}"])).toBeNull();
  });

  it("AC43: a rule timing out during a scan is skipped, the rest of the results come out", async () => {
    // Passes the import test (no long x runs in the samples) but explodes on this file.
    const tpl = await loadTemplate(`schema: 1
id: t
name: T
rules:
  - id: slow
    type: pattern
    severity: high
    files: ['**/*']
    match: ['(x+x+)+y']
  - id: fast
    type: pattern
    severity: medium
    files: ['**/*']
    match: ['needle']
`);
    const dir = project({ "a.txt": `${"x".repeat(40)}\nneedle\n` });
    const res = await scan(dir, tpl, { appDir: tempDir() });
    expect(byRule(res, "fast")).toHaveLength(1);
    expect(byRule(res, "slow")).toHaveLength(0);
    expect(res.stats.timed_out).toEqual([{ rule_id: "slow", file: "a.txt" }]);
    expect(res.checked.find((c) => c.rule_id === "slow")).toMatchObject({ ran: true, reason: "timeout_partial" });
  });
});
