#!/usr/bin/env node
// Entry points: `checkback mcp` (stdio MCP server), `checkback consent` (TTY only).
// `scan` / `sbom` print JSON for development checks. The GUI arrives in stage 7.
import { readFile } from "node:fs/promises";
import { defaultAppDir, readConfig } from "./appdata.js";
import { consentCommand } from "./consent.js";
import { buildSbom, loadDefaultTemplate, loadTemplate, readInventory, scan } from "./index.js";
import { runStdioServer } from "./mcp.js";
import { osLang } from "./notice.js";

const [cmd, ...args] = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (cmd === "mcp") {
  await runStdioServer({ cwd: process.cwd() });
} else if (cmd === "consent") {
  const appDir = defaultAppDir();
  const lang = (await readConfig(appDir)).lang ?? osLang();
  process.exitCode = await consentCommand(
    { input: process.stdin, output: process.stdout, error: process.stderr, interactive: !!process.stdin.isTTY && !!process.stdout.isTTY },
    appDir,
    lang,
  );
} else if (cmd === "scan") {
  const tplPath = flag("--template");
  const template = tplPath ? await loadTemplate(await readFile(tplPath)) : await loadDefaultTemplate();
  const lang = flag("--lang") === "ko" ? "ko" : flag("--lang") === "en" ? "en" : undefined;
  const r = await scan(process.cwd(), template, { ...(lang && { lang }) });
  // Development output: drop GUI-only masked values from the terminal.
  process.stdout.write(`${JSON.stringify({ ...r, findings: r.findings.map(({ masked_match: _m, ...f }) => f) }, null, 2)}\n`);
} else if (cmd === "sbom") {
  process.stdout.write(`${buildSbom(await readInventory(process.cwd()), { forUpload: args.includes("--upload") })}\n`);
} else {
  process.stderr.write("usage: checkback mcp | checkback consent | checkback scan [--lang ko|en] [--template file.yaml] | checkback sbom [--upload]\n");
  process.exitCode = 2;
}
