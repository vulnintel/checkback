// Subpath imports: the package root also loads the optional JSON-schema validator plugins
// (ajv-formats-draft2019 → node:punycode deprecation warning in the user's terminal).
import * as Enums from "@cyclonedx/cyclonedx-library/Enums";
import * as Models from "@cyclonedx/cyclonedx-library/Models";
import * as SPDX from "@cyclonedx/cyclonedx-library/SPDX";
import * as Serialize from "@cyclonedx/cyclonedx-library/Serialize";
import * as Spec from "@cyclonedx/cyclonedx-library/Spec";
import type { Inventory } from "./inventory.js";
import { lookupScope } from "./inventory.js";
import type { Package } from "./locks.js";

export interface SbomOptions {
  /**
   * Upload form (§8-3): public packages only (§7-2 scope), no lockfile names. Default = local
   * export form: every locked package incl. private ones, with `checkback:lockfile` properties.
   */
  forUpload?: boolean;
}

export function purlOf(p: { ecosystem: Package["ecosystem"]; name: string; version: string }): string {
  const name = p.ecosystem === "npm" ? p.name.split("/").map(encodeURIComponent).join("/") : p.name;
  return `pkg:${p.ecosystem === "npm" ? "npm" : "pypi"}/${name}@${encodeURIComponent(p.version)}`;
}

/**
 * CycloneDX 1.6 JSON. Deterministic (§8-3, AC31): no serialNumber, no timestamp, no project name,
 * bom-ref = purl, all lists sorted — the same inventory gives the same bytes.
 * Local (workspace/file/git) and unpinned packages are not components.
 */
export function buildSbom(inv: Inventory, opts: SbomOptions = {}): string {
  const allowed = opts.forUpload
    ? new Set(lookupScope(inv).targets.filter((t) => t.version !== null).map((t) => `${t.ecosystem}\0${t.name}\0${t.version}`))
    : null;
  const comps = new Map<string, { p: Package & { version: string }; lockfiles: Set<string>; dev: boolean }>();
  for (const lf of inv.lockfiles) {
    for (const p of lf.packages) {
      if (p.origin === "local" || p.version === null) continue;
      if (allowed && !allowed.has(`${p.ecosystem}\0${p.name}\0${p.version}`)) continue;
      const purl = purlOf({ ...p, version: p.version });
      const c = comps.get(purl);
      if (c) {
        c.lockfiles.add(lf.path);
        c.dev &&= p.dev;
      } else comps.set(purl, { p: { ...p, version: p.version }, lockfiles: new Set([lf.path]), dev: p.dev });
    }
  }
  const bom = new Models.Bom();
  for (const [purl, { p, lockfiles, dev }] of comps) {
    const scoped = p.ecosystem === "npm" && p.name.startsWith("@");
    const comp = new Models.Component(Enums.ComponentType.Library, scoped ? p.name.slice(p.name.indexOf("/") + 1) : p.name, {
      ...(scoped && { group: p.name.slice(0, p.name.indexOf("/")) }),
      version: p.version,
      purl,
      bomRef: purl,
    });
    if (p.license) {
      const spdx = SPDX.fixupSpdxId(p.license);
      comp.licenses.add(spdx ? new Models.SpdxLicense(spdx) : new Models.NamedLicense(p.license));
    }
    if (dev && p.ecosystem === "npm") comp.properties.add(new Models.Property("cdx:npm:package:development", "true"));
    if (!opts.forUpload) for (const lf of lockfiles) comp.properties.add(new Models.Property("checkback:lockfile", lf));
    bom.components.add(comp);
  }
  const serializer = new Serialize.JsonSerializer(new Serialize.JSON.Normalize.Factory(Spec.Spec1dot6));
  return serializer.serialize(bom, { sortLists: true, space: 2 });
}
