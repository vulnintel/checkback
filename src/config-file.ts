import { parse as parseToml } from "smol-toml";
import { parse as parseYaml } from "yaml";
import { dotenvValue } from "./refine.js";
import type { ConfigRule } from "./types.js";

/** Flat key → value for dotenv / properties; parsed tree for json / yaml / toml. Throws on syntax errors. */
export function parseConfig(format: ConfigRule["format"], text: string): unknown {
  switch (format) {
    case "json":
      return JSON.parse(text);
    case "yaml":
      return parseYaml(text, { schema: "core", maxAliasCount: 50, merge: false });
    case "toml":
      return parseToml(text);
    case "dotenv":
      return parseDotenv(text);
    case "properties": {
      const out: Record<string, string> = {};
      for (const line of text.split(/\r?\n/)) {
        const m = /^\s*([^#!\s=:][^=:\s]*)\s*[=:]\s*(.*)$/.exec(line);
        if (m) out[m[1]!] = m[2]!.trim();
      }
      return out;
    }
  }
}

export function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/.exec(line);
    if (m) out[m[1]!] = dotenvValue(m[2]!);
  }
  return out;
}

/** dotenv/properties keys are literal (they may contain dots); json/yaml/toml keys are dot paths. */
export function configValue(format: ConfigRule["format"], data: unknown, key: string): unknown {
  if (format === "dotenv" || format === "properties") return (data as Record<string, unknown>)[key];
  let cur = data;
  for (const part of key.split(".")) {
    if (typeof cur !== "object" || cur === null || !Object.prototype.hasOwnProperty.call(cur, part)) return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}
