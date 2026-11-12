// Screen state shared by the views. Server data only: the API is the source of truth.

import { api, ApiFail } from "./api.js";
import { setLang, t } from "./i18n.js";
import { toast } from "./dom.js";

export interface TemplateInfo {
  id: string;
  name: string;
  readOnly: boolean;
  imported: boolean;
}

export interface AppState {
  version: string;
  folder: string;
  folder_path: string;
  lang: "ko" | "en";
  theme: "system" | "light" | "dark";
  consent: boolean;
  declined: boolean;
  key: "none" | "env" | "config";
  external: { osv: boolean; registry: boolean; vulnintel: boolean };
  data_table: string;
  disclaimer: string;
  links: { key: string; subscriptions: string; remediations: string };
  templates: TemplateInfo[];
  has_result: boolean;
}

export interface GFinding {
  id: string;
  rule_id: string;
  severity: "critical" | "high" | "medium";
  confidence: "confirmed" | "review" | "info";
  title: string;
  location: { file: string; line: number | null } | null;
  masked_match?: string;
  secret_kind?: string;
  source: string;
  notes?: string[];
  related?: string[];
  ecosystem?: string;
  package?: string;
  version?: string | null;
  fixed_version?: string;
  vuln_ids?: string[];
  kev?: boolean;
  vpi_level?: number;
  epss?: number;
  cvss?: number;
  lockfile?: string;
  recheck?: string;
  recheck_note?: string;
  previous_version?: string;
  carried?: boolean;
  /** Recheck: the baseline finding this one was paired with (moved / same key / version bump). */
  baseline_id?: string;
  name: string;
  summary: string;
  description: string;
  external_text: boolean;
  revoke: boolean;
}

export interface ResolvedItem {
  id: string;
  rule_id: string;
  title: string;
  location: { file: string; line: number | null } | null;
  package?: string;
  version?: string;
  confidence?: "confirmed" | "review" | "info";
  confirm_revocation?: true;
  revoked?: boolean;
}

/** §7-8 comparison with the fix-request snapshot (or the previous scan). Absent on a first scan. */
export interface Compare {
  baseline: "fix_request" | "previous";
  baseline_at: string;
  counts: Record<"resolved" | "remaining" | "new" | "same_key" | "moved" | "downgraded" | "lock_mismatch" | "not_checked", number>;
  resolved: ResolvedItem[];
  requested: string[];
}

export interface ScanView {
  scan_at: string;
  template: { id: string; name: string; imported: boolean };
  findings: GFinding[];
  passed: { rule_id: string; name: string }[];
  not_run: { rule_id: string; name: string; reason: string }[];
  stats: { files: number };
  notices: string[];
  locks: { path: string; packages: number }[];
  manifests: number;
  ai_checks: number;
  compare?: Compare;
}

export type View = "consent" | "start" | "progress" | "result" | "templates" | "sbom" | "settings";

export const S: {
  st: AppState | null;
  view: View;
  result: ScanView | null;
  template: string;
  selected: Set<string>;
  /** CVE → already in the remediation tracker (key mode only). */
  tracked: Map<string, boolean> | null;
} = { st: null, view: "start", result: null, template: "default", selected: new Set(), tracked: null };

let renderer: () => void = () => {};
export const onRender = (fn: () => void): void => {
  renderer = fn;
};

export function go(view: View): void {
  S.view = view;
  renderer();
}

export async function refreshState(): Promise<AppState> {
  S.st = await api<AppState>("GET", "/api/state");
  setLang(S.st.lang);
  // No attribute = the stylesheet follows the OS; "light" / "dark" pin it.
  // shortcut: a pinned theme that differs from the OS shows the OS one until this first response; have the server stamp it into index.html if that flash bothers anyone.
  if (S.st.theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = S.st.theme;
  if (!S.st.templates.some((x) => x.id === S.template)) S.template = "default";
  return S.st;
}

export async function changeTheme(theme: string): Promise<void> {
  try {
    await api("POST", "/api/settings", { theme });
    await refreshState();
  } catch (e) {
    report(e);
  }
  renderer();
}

/** Language switch: server texts (titles, descriptions, notices) come back in the new language. */
export async function changeLang(lang: string): Promise<void> {
  try {
    await api("POST", "/api/settings", { lang });
    await refreshState();
    if (S.result) S.result = await api<ScanView>("GET", "/api/result");
  } catch (e) {
    report(e);
  }
  renderer();
}

/** Report an API failure in the status line; session loss gets its own message. */
export function report(e: unknown): void {
  if (e instanceof ApiFail && e.status === 401) toast(t().sessionLost);
  else toast(t().error);
}
