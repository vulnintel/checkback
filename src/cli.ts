#!/usr/bin/env node
// Version gate before anything else loads: main.js statically imports Node 20.18+ APIs
// (util.styleText), which fail at module link time on older Node with an unreadable error.
// Keep this file free of imports and of syntax newer than old Node can parse.
const [major, minor] = process.versions.node.split(".").map(Number);
if (major! < 20 || (major === 20 && minor! < 18)) {
  process.stderr.write(`checkback needs Node.js 20.18 or newer (this is ${process.versions.node}). Update Node from https://nodejs.org and try again.\n`);
  process.exit(1);
}
await import("./main.js");

export {};
