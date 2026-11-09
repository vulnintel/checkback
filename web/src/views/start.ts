// First-run notice (§3-1), S1 start and S2 progress.

import { api } from "../api.js";
import { h, replace } from "../dom.js";
import { t } from "../i18n.js";
import { go, refreshState, report, S, type ScanView } from "../state.js";

export function dataTable(text: string): HTMLElement {
  const [lead, ...rows] = text.split("\n");
  return h("div", { class: "data-table" }, h("p", { class: "strong" }, lead), h("ul", {}, rows.map((r) => h("li", {}, r.replace(/^- /, "")))));
}

export function consentView(): HTMLElement {
  const st = S.st!;
  const answer = async (accept: boolean): Promise<void> => {
    try {
      await api("POST", "/api/consent", { accept });
      await refreshState();
      go("start");
    } catch (e) {
      report(e);
    }
  };
  return h(
    "section",
    { class: "panel narrow" },
    h("h1", { tabindex: "-1" }, t().consent.title),
    h("p", {}, t().consent.lead),
    dataTable(st.data_table),
    h(
      "div",
      { class: "row" },
      h("button", { class: "btn primary", type: "button", onclick: () => void answer(true) }, t().consent.accept),
      h("button", { class: "btn", type: "button", onclick: () => void answer(false) }, t().consent.decline),
    ),
  );
}

export function startView(): HTMLElement {
  const st = S.st!;
  const s = t().start;
  const select = h(
    "select",
    { id: "tpl", onchange: (e: Event) => (S.template = (e.target as HTMLSelectElement).value) },
    st.templates.map((x) => h("option", { value: x.id, selected: x.id === S.template }, x.name)),
  );
  return h(
    "section",
    { class: "panel narrow" },
    h("h1", { tabindex: "-1" }, h("span", { class: "muted" }, `${s.folder}: `), h("span", { title: st.folder_path }, st.folder)),
    h("div", { class: "field" }, h("label", { for: "tpl" }, s.template), select),
    h(
      "p",
      {},
      `${s.key}: `,
      st.key === "none" ? s.keyNone : st.key === "env" ? s.keyEnv : s.keyConfig,
      st.key === "none" ? h("button", { class: "btn link", type: "button", onclick: () => go("settings") }, s.keyLink) : null,
    ),
    !st.consent
      ? h("p", { class: "note" }, s.localOnly, " ", h("button", { class: "btn link", type: "button", onclick: () => go("consent") }, s.turnOn))
      : null,
    h(
      "div",
      { class: "row" },
      h("button", { class: "btn primary big", type: "button", onclick: () => void startScan() }, s.run),
      S.result ? h("button", { class: "btn", type: "button", onclick: () => go("result") }, s.lastResult) : null,
    ),
  );
}

export async function startScan(refresh = false): Promise<void> {
  try {
    await api("POST", "/api/scan", { template: S.template, refresh });
    go("progress");
  } catch (e) {
    report(e);
  }
}

const PHASES = ["files", "rules", "deps", "external", "finish"];
const SLOW_MS = 15_000; // external lookups past this get a "what we wait for / can I skip" note

export function progressView(): HTMLElement {
  const p = t().progress;
  const list = h("ul", { class: "steps" });
  const status = h("p", { class: "status" }, t().loading); // ticks every 400 ms: not a live region
  const said = h("p", { class: "visually-hidden", "aria-live": "polite" }); // phase changes only

  const stop = h("button", { class: "btn", type: "button", onclick: () => void api("POST", "/api/scan/stop").catch(report) }, p.stop);
  const slow = h("div", { class: "note", hidden: true }, h("p", {}, p.slow), h("p", {}, p.slowSkip));
  const view = h("section", { class: "panel narrow" }, h("h1", { tabindex: "-1" }, p.title), list, status, said, slow, h("p", { class: "muted small" }, p.offlineNote), stop);

  const tick = async (): Promise<void> => {
    if (S.view !== "progress") return;
    try {
      const j = await api<{ running: boolean; phase?: string; files?: number; elapsed_ms?: number; error?: string }>("GET", "/api/scan");
      const at = PHASES.indexOf(j.phase ?? "files");
      replace(
        list,
        PHASES.map((ph, i) =>
          h("li", { class: i < at || !j.running ? "done" : i === at ? "now" : "" }, h("span", {}, p.phases[ph] ?? ph), h("span", { class: "muted small" }, i < at ? p.done : i === at && j.running ? p.now : "")),
        ),
      );
      status.textContent = [j.files ? p.files(j.files) : "", p.elapsed(Math.round((j.elapsed_ms ?? 0) / 1000))].filter(Boolean).join(" · ");
      const now = j.running ? (p.phases[j.phase ?? "files"] ?? "") : "";
      if (said.textContent !== now) said.textContent = now;
      slow.hidden = !(j.running && j.phase === "external" && (j.elapsed_ms ?? 0) > SLOW_MS);
      if (j.running) return void setTimeout(() => void tick(), 400);
      if (j.error) {
        status.textContent = j.error === "stopped" ? p.stopped : p.failed;
        stop.remove();
        view.append(h("button", { class: "btn", type: "button", onclick: () => go("start") }, t().close));
        return;
      }
      S.result = await api<ScanView>("GET", "/api/result");
      S.selected.clear();
      S.tracked = null;
      go("result");
    } catch (e) {
      report(e);
    }
  };
  void tick();
  return view;
}
