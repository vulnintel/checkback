export { scan, ENGINE_VERSION, type ScanOptions } from "./scan.js";
export { loadTemplate, loadDefaultTemplate, TemplateError, BUILTIN_IDS, FIX_PROMPT_VARS, type TemplateIssue } from "./template.js";
export { addIgnore, removeIgnore, listIgnores, type IgnoreEntry } from "./ignores.js";
export { defaultAppDir } from "./appdata.js";
export { readInventory, lookupScope, type Inventory, type Lockfile, type Manifest, type PrivateConfig, type LookupScope, type LookupTarget } from "./deps/inventory.js";
export { buildSbom, purlOf, type SbomOptions } from "./deps/sbom.js";
export type { Package, Ecosystem } from "./deps/locks.js";
export type * from "./types.js";
