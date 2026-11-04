// Manual live-network check (not part of `pnpm test`): real OSV, npm, PyPI and VulnIntel public
// lookups against a throwaway project. Usage: pnpm build && node scripts/live-smoke.mjs
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadDefaultTemplate, scan, updateConfig } from "../dist/index.js";

const dir = mkdtempSync(join(tmpdir(), "checkback-live-"));
const appDir = mkdtempSync(join(tmpdir(), "checkback-live-app-"));
try {
  const deps = { lodash: "4.17.20", "discord-selfbot-v14": "1.0.0" };
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "live", dependencies: { ...deps, "react-ai-helperz-not-real": "^1.0.0" } }));
  writeFileSync(
    join(dir, "package-lock.json"),
    JSON.stringify({
      name: "live",
      lockfileVersion: 3,
      packages: {
        "": { name: "live", dependencies: deps },
        ...Object.fromEntries(Object.entries(deps).map(([n, v]) => [`node_modules/${n}`, { version: v, resolved: `https://registry.npmjs.org/${n}/-/${n}-${v}.tgz` }])),
      },
    }),
  );
  writeFileSync(join(dir, "requirements.txt"), "Django==3.2.0\n");
  await updateConfig(appDir, { consent: { at: new Date().toISOString(), version: 1 } });
  const t0 = Date.now();
  const r = await scan(dir, await loadDefaultTemplate(), { appDir, lang: "ko" });
  console.log(`scan ${Date.now() - t0} ms`);
  for (const f of r.findings) {
    if (f.rule_id === "vulnerable-deps" || f.rule_id === "hallucinated-package") {
      console.log([f.rule_id, f.kind, f.package, f.version, f.severity, f.confidence, f.kev ? "KEV" : "", f.vpi_level ?? "", f.fixed_version ?? "", (f.vuln_ids ?? []).length, (f.notes ?? []).join(",")].join(" | "));
    }
  }
  console.log(r.checked.filter((c) => c.reason));
} finally {
  rmSync(dir, { recursive: true, force: true });
  rmSync(appDir, { recursive: true, force: true });
}
