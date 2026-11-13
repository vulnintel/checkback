// checkback local GUI shell: header (brand, navigation, language), main view, footer
// (disclaimer and sources, always visible — §3-1), and an aria-live status line.

import { api, initSession } from "./api.js";
import { h, replace } from "./dom.js";
import { LANG_NAMES, t, type UiLang } from "./i18n.js";
import { changeLang, go, onRender, refreshState, report, S, type View } from "./state.js";
import { resultView } from "./views/results.js";
import { sbomView, settingsView } from "./views/settings.js";
import { consentView, progressView, startView } from "./views/start.js";
import { templatesView } from "./views/templates.js";

const app = document.getElementById("app")!;
const PING_MS = 5 * 60_000; // keeps the server alive while a tab is open (it exits 30 min after the last call)

function header(): HTMLElement {
  const n = t().nav;
  const tab = (view: View, label: string, active: boolean): HTMLElement =>
    h("button", { type: "button", class: `nav-btn${active ? " active" : ""}`, "aria-current": active ? "page" : null, onclick: () => go(view) }, label);
  const scanActive = ["start", "progress", "result", "consent"].includes(S.view);
  return h(
    "header",
    { class: "top" },
    h("div", { class: "brand" }, h("span", { class: "mark", "aria-hidden": "true" }), h("span", { class: "name" }, t().appName), h("span", { class: "by" }, t().by)),
    h(
      "nav",
      { "aria-label": t().appName },
      tab(S.result && S.view !== "start" ? "result" : "start", n.scan, scanActive),
      tab("templates", n.templates, S.view === "templates"),
      tab("sbom", n.sbom, S.view === "sbom"),
      tab("settings", n.settings, S.view === "settings"),
    ),
    h(
      "select",
      {
        class: "lang",
        "aria-label": t().langLabel,
        onchange: (e: Event) => void changeLang((e.target as HTMLSelectElement).value),
      },
      (Object.keys(LANG_NAMES) as UiLang[]).map((l) => h("option", { value: l, selected: S.st?.lang === l }, LANG_NAMES[l])),
    ),
  );
}

function footer(): HTMLElement {
  const [line1, line2] = (S.st?.disclaimer ?? "").split("\n");
  return h("footer", { class: "foot" }, h("p", {}, line1), h("p", { class: "muted" }, line2), h("p", { class: "muted" }, t().by));
}

const VIEWS: Record<View, () => HTMLElement> = {
  consent: consentView,
  start: startView,
  progress: progressView,
  result: () => (S.result ? resultView() : startView()),
  templates: templatesView,
  sbom: sbomView,
  settings: settingsView,
};

function render(): void {
  const main = h("main", { id: "main" }, VIEWS[S.view]());
  replace(app, header(), main, footer());
  // Move focus to the new view's heading (or the recheck summary above it) so keyboard and
  // screen-reader users land at the top of it.
  (main.querySelector("[data-autofocus], h1") as HTMLElement | null)?.focus();
}

async function boot(): Promise<void> {
  onRender(render);
  if (!(await initSession())) {
    replace(app, h("main", { id: "main" }, h("p", { class: "warn" }, t().sessionLost)));
    return;
  }
  try {
    const st = await refreshState();
    S.view = st.consent || st.declined ? "start" : "consent";
    render();
  } catch (e) {
    report(e);
  }
  setInterval(() => void api("GET", "/api/ping").catch(() => {}), PING_MS);
}

void boot();
