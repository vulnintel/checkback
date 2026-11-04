import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("..", import.meta.url));
const read = (p: string): string => readFileSync(join(root, p), "utf8");
const files = (dir: string): string[] =>
  readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory() ? files(p) : [relative(join(root, "plugin"), p).split("\\").join("/")];
  });

describe("AC69 plugin package (draft, §7-7-2)", () => {
  it("contains only plugin.json, SKILL.md and .mcp.json — no hooks, bin, agents, commands", () => {
    expect(files(join(root, "plugin")).sort()).toEqual([".claude-plugin/plugin.json", ".mcp.json", "skills/checkback/SKILL.md"]);
  });

  it("names: plugin checkback, marketplace vulnintel; no Claude/Anthropic in product names (AC70)", () => {
    const plugin = JSON.parse(read("plugin/.claude-plugin/plugin.json"));
    const market = JSON.parse(read(".claude-plugin/marketplace.json"));
    expect(plugin.name).toBe("checkback");
    expect(market.name).toBe("vulnintel");
    expect(market.plugins).toEqual([expect.objectContaining({ name: "checkback", source: "./plugin" })]);
    for (const n of [plugin.name, market.name, market.owner.name, ...market.plugins.map((p: { name: string }) => p.name)]) expect(n).not.toMatch(/claude|anthropic/i);
    expect(plugin.description).toMatch(/a plugin for Claude Code$/); // plain description only
  });

  it(".mcp.json pins checkback@x.y.z (same as the plugin version) and carries no key", () => {
    const mcp = read("plugin/.mcp.json");
    const cfg = JSON.parse(mcp).mcpServers.checkback;
    expect(cfg.command).toBe("npx");
    expect(cfg.args).toEqual(["-y", `checkback@${JSON.parse(read("plugin/.claude-plugin/plugin.json")).version}`, "mcp"]);
    expect(cfg.args[1]).toMatch(/^checkback@\d+\.\d+\.\d+$/);
    expect(cfg.env).toBeUndefined();
    expect(mcp).not.toMatch(/VULNINTEL|api[_-]?key|vi_live_/i);
  });

  it("skill: scan → (optional) ai_check_prompt → fix_prompts → approved edits → scan, with the required rules", () => {
    const s = read("plugin/skills/checkback/SKILL.md");
    const fm = /^---\n([\s\S]*?)\n---/.exec(s.replace(/\r\n/g, "\n"))![1]!;
    expect(fm).toMatch(/^name: checkback$/m);
    expect(fm).toMatch(/^description: .+/m);
    expect(fm).not.toMatch(/allowed-tools|disable-model-invocation|permission/);
    const order = ["Call `scan`", "`ai_check_prompt`", "`fix_prompts`", "normal approval", "Call `scan` again"].map((k) => s.indexOf(k));
    expect(order.every((i) => i > 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(s).toMatch(/do not report them as fixed/);
    expect(s).toMatch(/"AI judgment"/);
    expect(s).toMatch(/Do not quote secret values/);
    expect(s).toMatch(/install new packages/);
    expect(s).toMatch(/edit lock files by hand/);
    expect(s).toMatch(/Do not ask the user to widen permissions or switch to an auto-approve mode/);
    expect(s).toMatch(/revoke the key at the provider/);
  });
});
