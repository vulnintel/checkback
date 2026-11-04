#!/usr/bin/env node
// Development entry point only (stage 2/3a): `checkback scan [--lang ko|en]`, `checkback sbom [--upload]`.
// The real CLI (GUI server, MCP, consent) arrives in later stages.
import { readFile } from "node:fs/promises";
import { buildSbom, loadDefaultTemplate, loadTemplate, readInventory, scan } from "./index.js";

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
} else if (cmd === "sbom") {
  process.stdout.write(`${buildSbom(await readInventory(process.cwd()), { forUpload: args.includes("--upload") })}\n`);
} else {
  process.stderr.write("usage: checkback scan [--lang ko|en] [--template file.yaml] | checkback sbom [--upload]\n");
  process.exitCode = 2;
}
