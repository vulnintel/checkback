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
  name: string;
  summary: string;
  description: string;
  external_text: boolean;
  revoke: boolean;
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
  if (!S.st.templates.some((x) => x.id === S.template)) S.template = "default";
  return S.st;
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
