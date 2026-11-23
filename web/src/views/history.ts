// Scan history (QA-003): every scan of this project, and the latest one against a chosen earlier
// scan (the first scan by default). Local data only; nothing is sent anywhere.

import { api } from "../api.js";
import { h, modal, replace, toast } from "../dom.js";
import { t } from "../i18n.js";
import { report, S } from "../state.js";
import { loc, recheckCounts } from "./recheck.js";
import { startScan } from "./start.js";

/** A rule the scan could not fully run (no consent, lookups off, offline, timeout). */
interface Skipped {
  rule_id: string;
  name: string;
  reason: string;
}

interface HistoryScan {
  scan_id: string;
  scan_at: string;
  seq: number;
  total: number;
  partial: Skipped[];
  prev_seq?: number;
  resolved?: number;
  new?: number;
  not_checked?: number;
}

interface HistoryItem {
  id: string;
  title: string;
  status: string;
  confidence: "confirmed" | "review" | "info";
  location: { file: string; line: number | null } | null;
  severity?: string;
  package?: string;
  version?: string;
}

interface History {
  scans: HistoryScan[];
  compare: {
    base_id: string;
    base_at: string;
    latest_at: string;
    base_partial: Skipped[];
    latest_partial: Skipped[];
    ignored: number;
    items: HistoryItem[];
  } | null;
}

let base: string | undefined; // chosen baseline scan id; undefined = the first scan

export function historyView(): HTMLElement {
  const y = t().history;
  const body = h("div", {}, t().loading);
  const scanBtn = h("button", { class: "btn primary", type: "button", onclick: () => void startScan() }, t().result.rescan);
  const load = (): void => {
    api<History>("POST", "/api/history", { base })
      .then((r) => {
        scanBtn.textContent = r.scans.length ? t().result.rescan : t().start.run;
        replace(body, ...content(r, load));
      })
      .catch(report);
  };
  load();
  return h(
    "div",
    { class: "panel" },
    h("h1", { tabindex: "-1" }, y.title),
    h("p", { class: "muted small" }, y.lead),
    h("p", {}, scanBtn),
    body,
  );
}

/** "Vulnerable packages (offline), …" in the screen language. */
const partialText = (p: Skipped[]): string => p.map((x) => `${x.name}${t().history.paren(t().result.reason[x.reason] ?? x.reason)}`).join(", ");

function content(r: History, reload: () => void): HTMLElement[] {
  const y = t().history;
  const lang = S.st!.lang;
  const when = (iso: string): string => new Date(iso).toLocaleString(lang);
  if (!r.scans.length) return [h("p", { class: "muted" }, y.empty)];
  const last = r.scans.length - 1;
  const label = (i: number): string => `${y.round(r.scans[i]!.seq)} · ${when(r.scans[i]!.scan_at)}${i === 0 ? y.paren(y.first) : ""}`;
  const delta = (s: HistoryScan): string => {
    if (s.resolved === undefined || s.prev_seq === undefined) return "—";
    const d = s.prev_seq === s.seq - 1 ? y.delta(s.resolved, s.new ?? 0) : y.deltaVs(s.prev_seq, s.resolved, s.new ?? 0); // older scans dropped off in between
    return s.not_checked ? `${d} · ${y.notChecked(s.not_checked)}` : d;
  };
  const table = h(
    "div",
    { class: "scroll-x" },
    h(
      "table",
      { class: "rules history" },
      h("thead", {}, h("tr", {}, h("th", {}, "#"), h("th", {}, y.change), h("th", {}, y.total), h("th", {}, y.when))),
      h(
        "tbody",
        {},
        r.scans.map((s, i) =>
          h(
            "tr",
            {},
            h("td", {}, y.round(s.seq), i === 0 ? y.paren(y.first) : i === last ? y.paren(y.latest) : ""),
            h("td", {}, delta(s)), // change before date: the column that matters stays visible at 375px
            h("td", {}, String(s.total)),
            h("td", {}, when(s.scan_at), s.partial.length ? h("div", { class: "warn small" }, y.partial(partialText(s.partial))) : null),
          ),
        ),
      ),
    ),
  );
  const clear = h("button", {
    class: "btn",
    type: "button",
    onclick: () => {
      const d = modal(y.clear, [h("p", {}, y.clearAsk)], [
        h("button", { class: "btn", type: "button", onclick: () => d.close() }, t().cancel),
        h("button", {
          class: "btn primary",
          type: "button",
          onclick: async () => {
            try {
              await api("POST", "/api/history/clear");
              d.close();
              base = undefined;
              toast(y.cleared);
              reload();
            } catch (e) {
              report(e);
            }
          },
        }, y.clear),
      ]);
    },
  }, y.clear);
  return [...compareBlock(r, label, reload), h("h2", { class: "sec" }, y.title), table, h("p", {}, clear)];
}

function compareBlock(r: History, label: (i: number) => string, reload: () => void): HTMLElement[] {
  const y = t().history;
  const c = r.compare;
  if (!c) return [h("p", { class: "muted" }, y.only)];
  const latest = r.scans.length - 1;
  const pick = h(
    "select",
    {
      id: "history-base",
      onchange: (e: Event) => {
        base = (e.target as HTMLSelectElement).value;
        reload();
      },
    },
    r.scans.slice(0, latest).map((s, i) => h("option", { value: s.scan_id, selected: s.scan_id === c.base_id }, label(i))),
  );
  const n = recheckCounts(
    c.items.filter((x) => x.status !== "resolved").map((x) => ({ confidence: x.confidence, recheck: x.status })),
    c.items.filter((x) => x.status === "resolved"),
  );
  const names = t().card.recheck;
  return [
    h("div", { class: "field" }, h("label", { for: "history-base" }, y.base), pick),
    h("p", { class: "muted small" }, y.against(label(r.scans.findIndex((s) => s.scan_id === c.base_id)), label(latest))),
    c.base_partial.length ? h("p", { class: "note" }, y.basePartial(partialText(c.base_partial))) : null,
    c.latest_partial.length ? h("p", { class: "note" }, y.latestPartial(partialText(c.latest_partial))) : null,
    h(
      "p",
      { class: "recheck-counts" },
      h("span", { class: n.resolved ? "badge recheck-resolved" : "badge" }, y.summary(n.resolved, n.remaining, n.new)),
      n.check ? h("span", { class: "badge recheck-lock_mismatch" }, y.check(n.check)) : null,
    ),
    c.ignored ? h("p", { class: "muted small" }, y.ignored(c.ignored)) : null,
    h(
      "ul",
      { class: "plain" },
      c.items.map((x) =>
        h(
          "li",
          {},
          h("span", { class: `badge recheck-${x.status}` }, names[x.status] ?? x.status),
          " ",
          h("span", { class: "strong" }, x.title),
          x.package ? h("span", { class: "muted" }, ` ${x.package}${x.version ? ` ${x.version}` : ""}`) : null,
          loc(x) ? h("span", { class: "loc" }, ` ${loc(x)}`) : null,
        ),
      ),
    ),
  ].filter((x) => x !== null);
}
