#!/usr/bin/env node
// Development entry point only (stage 2): `checkback scan [--lang ko|en]`.
// The real CLI (GUI server, MCP, consent) arrives in later stages.
import { readFile } from "node:fs/promises";
import { loadDefaultTemplate, loadTemplate, scan } from "./index.js";

const [cmd, ...args] = process.argv.slice(2);
const flag = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};

if (cmd === "scan") {
  const tplPath = flag("--template");
  const template = tplPath ? await loadTemplate(await readFile(tplPath)) : await loadDefaultTemplate();
  const lang = flag("--lang") === "ko" ? "ko" : "en";
  process.stdout.write(`${JSON.stringify(await scan(process.cwd(), template, { lang }), null, 2)}\n`);
} else {
  process.stderr.write("usage: checkback scan [--lang ko|en] [--template file.yaml]\n");
  process.exitCode = 2;
}
