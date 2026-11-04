#!/usr/bin/env node
// Entry points: `checkback` / `checkback gui` (local web GUI, opens the browser unless --no-open),
// `checkback mcp` (stdio MCP server), `checkback consent` (TTY only).
// `scan` / `sbom` print JSON for development checks.
import { readFile } from "node:fs/promises";
import { defaultAppDir, readConfig } from "./appdata.js";
import { ignoreCommand, trackCommand, watchCommand } from "./commands.js";
import { consentCommand } from "./consent.js";
import { buildSbom, loadDefaultTemplate, loadTemplate, readInventory, scan } from "./index.js";
import { runStdioServer } from "./mcp.js";
import { osLang } from "./notice.js";

const [cmd, ...args] = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (cmd === undefined || cmd === "gui" || cmd === "--no-open") {
  const { startGui } = await import("./gui/server.js");
  const { openBrowser } = await import("./gui/open.js");
  const lang = (await readConfig(defaultAppDir())).lang ?? osLang();
  const g = await startGui({ cwd: process.cwd(), onIdle: () => process.exit(0) });
  process.stdout.write(
    lang === "ko"
      ? `checkback 화면: ${g.url}
(이 주소는 이번 실행에서만 쓸 수 있습니다. 끝내려면 Ctrl+C)
`
      : `checkback screen: ${g.url}
(This address works for this run only. Press Ctrl+C to stop.)
`,
  );
  if (!process.argv.includes("--no-open")) openBrowser(g.url);
} else if (cmd === "mcp") {
  // Plugin MCP servers start in the plugin folder; Claude Code passes the project root here.
  await runStdioServer({ cwd: process.env.CLAUDE_PROJECT_DIR || process.cwd() });
} else if (cmd === "consent") {
  const appDir = defaultAppDir();
  const lang = (await readConfig(appDir)).lang ?? osLang();
  process.exitCode = await consentCommand(
    { input: process.stdin, output: process.stdout, error: process.stderr, interactive: !!process.stdin.isTTY && !!process.stdout.isTTY },
    appDir,
    lang,
  );
} else if (cmd === "watch" || cmd === "track" || cmd === "ignore") {
  const appDir = defaultAppDir();
  const lang = (await readConfig(appDir)).lang ?? osLang();
  const io = { input: process.stdin, output: process.stdout, error: process.stderr, interactive: !!process.stdin.isTTY && !!process.stdout.isTTY };
  const o = { cwd: process.cwd(), appDir, lang };
  process.exitCode =
    cmd === "watch" ? await watchCommand(io, o) : cmd === "track" ? await trackCommand(io, o) : await ignoreCommand(io, { ...o, remove: args.includes("--remove") });
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
  process.stderr.write("usage: checkback [gui] [--no-open] | checkback mcp | checkback consent | checkback watch | checkback track | checkback ignore [--remove] | checkback scan [--lang ko|en] [--template file.yaml] | checkback sbom [--upload]\n");
  process.exitCode = 2;
}
