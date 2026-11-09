#!/usr/bin/env node
// Entry points: `checkback` / `checkback gui` (local web GUI, opens the browser unless --no-open),
// `checkback mcp` (stdio MCP server), `checkback consent` (TTY only), `scan` (readable report in a
// terminal, JSON otherwise or with --json; --fail-on for CI) and `sbom` (JSON).
import { readFile } from "node:fs/promises";
import { defaultAppDir, readConfig } from "./appdata.js";
import { failOnCount, formatScan, ignoreCommand, parseCli, trackCommand, usage, USAGE_LINE, watchCommand, type FailOn } from "./commands.js";
import { consentCommand } from "./consent.js";
import { buildSbom, loadDefaultTemplate, loadTemplate, readInventory, scan } from "./index.js";
import { runStdioServer } from "./mcp.js";
import { VERSION } from "./net/http.js";
import { osLang } from "./notice.js";
import type { Lang } from "./types.js";

const parsed = parseCli(process.argv.slice(2));
const userLang = async (): Promise<Lang> => (await readConfig(defaultAppDir())).lang ?? osLang();
const tty = () => ({ input: process.stdin, output: process.stdout, error: process.stderr, interactive: !!process.stdin.isTTY && !!process.stdout.isTTY });

if (parsed.kind === "help") {
  process.stdout.write(usage(VERSION));
} else if (parsed.kind === "version") {
  process.stdout.write(`${VERSION}\n`);
} else if (parsed.kind === "error") {
  process.stderr.write(`checkback: ${parsed.message}\n${USAGE_LINE}\nRun "checkback --help" for all commands and options.\n`);
  process.exitCode = 2;
} else {
  const { cmd, opts } = parsed;
  if (cmd === "gui") {
    const { startGui } = await import("./gui/server.js");
    const { openBrowser } = await import("./gui/open.js");
    const lang = await userLang();
    const g = await startGui({ cwd: process.cwd(), onIdle: () => process.exit(0) });
    process.stdout.write(
      lang === "ko"
        ? `checkback 화면: ${g.url}\n(이 주소는 이번 실행에서만 쓸 수 있습니다. 끝내려면 Ctrl+C)\n`
        : `checkback screen: ${g.url}\n(This address works for this run only. Press Ctrl+C to stop.)\n`,
    );
    if (!opts["--no-open"]) openBrowser(g.url);
  } else if (cmd === "mcp") {
    // Plugin MCP servers start in the plugin folder; Claude Code passes the project root here.
    await runStdioServer({ cwd: process.env.CLAUDE_PROJECT_DIR || process.cwd() });
  } else if (cmd === "consent") {
    process.exitCode = await consentCommand(tty(), defaultAppDir(), await userLang());
  } else if (cmd === "watch" || cmd === "track" || cmd === "ignore") {
    const o = { cwd: process.cwd(), appDir: defaultAppDir(), lang: await userLang() };
    process.exitCode =
      cmd === "watch" ? await watchCommand(tty(), o) : cmd === "track" ? await trackCommand(tty(), o) : await ignoreCommand(tty(), { ...o, remove: !!opts["--remove"] });
  } else if (cmd === "scan") {
    const tplPath = opts["--template"];
    const template = typeof tplPath === "string" ? await loadTemplate(await readFile(tplPath)) : await loadDefaultTemplate();
    // Not a terminal (pipes, CI, scripts): JSON as before, so existing parsers keep working.
    const text = !opts["--json"] && (!!opts["--text"] || !!process.stdout.isTTY);
    const lang = (opts["--lang"] as Lang | undefined) ?? (text ? await userLang() : undefined);
    const r = await scan(process.cwd(), template, { ...(lang && { lang }) });
    if (text) {
      const color = !!process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== "dumb";
      process.stdout.write(formatScan(r, template, lang ?? "en", color));
    } else {
      // Drop GUI-only masked values from the terminal.
      process.stdout.write(`${JSON.stringify({ ...r, findings: r.findings.map(({ masked_match: _m, ...f }) => f) }, null, 2)}\n`);
    }
    const failOn = opts["--fail-on"] as FailOn | undefined;
    const n = failOn ? failOnCount(r.findings, failOn) : 0;
    if (n > 0) {
      process.stderr.write(`checkback: ${n} ${n === 1 ? "thing" : "things"} to fix at ${failOn === "low" ? "any severity" : `${failOn} or above`} (--fail-on ${failOn})\n`);
      process.exitCode = 1;
    }
  } else if (cmd === "sbom") {
    process.stdout.write(`${buildSbom(await readInventory(process.cwd()), { forUpload: !!opts["--upload"] })}\n`);
  }
}
