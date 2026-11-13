// S6 settings and S7 SBOM export.

import { api, ApiFail } from "../api.js";
import { download, extLink, h, replace, toast } from "../dom.js";
import { LANG_NAMES, t, type UiLang } from "../i18n.js";
import { changeLang, changeTheme, go, refreshState, report, S } from "../state.js";
import { dataTable } from "./start.js";

function section(title: string, ...children: (Node | null)[]): HTMLElement {
  return h("section", { class: "block" }, h("h2", {}, title), ...children);
}

export function settingsView(): HTMLElement {
  const st = S.st!;
  const s = t().settings;

  const keyInput = h("input", { id: "key", type: "password", autocomplete: "off", spellcheck: false, maxlength: 200 });
  const keyMsg = h("p", { class: "status", "aria-live": "polite" });
  const saveKey = async (key: string | null): Promise<void> => {
    try {
      const r = await api<{ status: string }>("POST", "/api/key", { key });
      keyInput.value = "";
      await refreshState();
      keyMsg.textContent = s.keyStatus[r.status] ?? "";
    } catch (e) {
      if (e instanceof ApiFail && e.code === "bad_key_format") keyMsg.textContent = s.keyBad;
      else report(e);
    }
  };

  const ignores = h("div", {}, t().loading);
  api<{ items: { id: string; reason: string; at: string; label?: string }[] }>("GET", "/api/ignores")
    .then((r) =>
      replace(
        ignores,
        r.items.length
          ? h(
              "ul",
              { class: "plain" },
              r.items.map((i) =>
                h(
                  "li",
                  { class: "row" },
                  i.label ? h("div", {}, h("div", { class: "strong" }, i.label), h("div", {}, i.reason)) : h("span", {}, i.reason),
                  h("span", { class: "muted small" }, `${new Date(i.at).toLocaleString(st.lang)} · ${i.id.slice(0, 8)}`),
                  h("button", {
                    class: "btn link",
                    type: "button",
                    onclick: async (e: Event) => {
                      try {
                        await api("POST", "/api/unignore", { id: i.id });
                        (e.target as HTMLElement).closest("li")?.remove();
                        toast(s.unignored);
                      } catch (err) {
                        report(err);
                      }
                    },
                  }, s.unignore),
                ),
              ),
            )
          : h("p", { class: "muted" }, s.ignoresEmpty),
      ),
    )
    .catch(report);

  return h(
    "div",
    { class: "panel" },
    h("h1", { tabindex: "-1" }, s.title),
    section(
      t().langLabel,
      h(
        "select",
        {
          "aria-label": t().langLabel,
          onchange: (e: Event) => void changeLang((e.target as HTMLSelectElement).value),
        },
        (Object.keys(LANG_NAMES) as UiLang[]).map((l) => h("option", { value: l, selected: st.lang === l }, LANG_NAMES[l])),
      ),
    ),
    section(
      t().themeLabel,
      h(
        "select",
        {
          "aria-label": t().themeLabel,
          onchange: (e: Event) => void changeTheme((e.target as HTMLSelectElement).value),
        },
        (["system", "light", "dark"] as const).map((x) => h("option", { value: x, selected: st.theme === x }, t().themeNames[x])),
      ),
    ),
    section(
      s.key,
      h("p", { class: "muted" }, s.keyLead),
      h("p", {}, `${t().start.key}: `, st.key === "none" ? t().start.keyNone : st.key === "env" ? t().start.keyEnv : t().start.keyConfig),
      st.key === "env" ? h("p", { class: "note" }, s.keyEnv) : null,
      h("div", { class: "field" }, h("label", { for: "key" }, s.keyInput), keyInput),
      h(
        "div",
        { class: "row" },
        h("button", { class: "btn primary", type: "button", onclick: () => void (keyInput.value.trim() && saveKey(keyInput.value.trim())) }, s.keySave),
        st.key === "config" ? h("button", { class: "btn", type: "button", onclick: () => void saveKey(null) }, s.keyRemove) : null,
        extLink(st.links.key, s.getKey),
        extLink(st.links.subscriptions, s.subs),
      ),
      keyMsg,
    ),
    section(
      s.external,
      st.consent ? h("p", { class: "muted" }, s.externalLead) : h("p", { class: "note" }, s.noConsent, " ", h("button", { class: "btn link", type: "button", onclick: () => go("consent") }, s.showConsent)),
      h(
        "div",
        {},
        (["osv", "registry", "vulnintel"] as const).map((k) =>
          h(
            "label",
            { class: "check block-check" },
            h("input", {
              type: "checkbox",
              checked: st.consent && st.external[k],
              disabled: !st.consent,
              onchange: async (e: Event) => {
                await api("POST", "/api/settings", { external: { [k]: (e.target as HTMLInputElement).checked } }).catch(report);
                await refreshState().catch(report);
              },
            }),
            ` ${s.ext[k]}`,
          ),
        ),
      ),
    ),
    section(s.dataTable, dataTable(st.data_table)),
    section(s.ignores, ignores),
    section(
      s.baseline,
      h("p", { class: "muted" }, s.baselineLead),
      h("button", { class: "btn", type: "button", onclick: () => void api("POST", "/api/baseline/clear").then(() => toast(s.baselineCleared), report) }, s.baselineClear),
    ),
    section(s.about, h("p", {}, s.version(st.version)), h("p", { class: "muted small" }, t().trademark)),
  );
}

export function sbomView(): HTMLElement {
  const b = t().sbom;
  const body = h("div", {}, t().loading);
  api<{ json: string; components: number; locks: { path: string; kind: string; packages: number }[] }>("GET", "/api/sbom")
    .then((r) =>
      replace(
        body,
        h("p", { class: "strong" }, b.count(r.components)),
        r.locks.length ? h("h2", {}, b.locks) : null,
        r.locks.length ? h("ul", { class: "plain" }, r.locks.map((l) => h("li", {}, h("span", { class: "loc" }, l.path), ` · ${l.kind} · ${l.packages}`))) : h("p", { class: "note" }, b.noLock),
        h("button", { class: "btn primary", type: "button", disabled: r.locks.length === 0, onclick: () => download(`${S.st!.folder || "project"}.cdx.json`, r.json, "application/json") }, b.save),
      ),
    )
    .catch(report);
  return h("section", { class: "panel narrow" }, h("h1", { tabindex: "-1" }, b.title), h("p", { class: "muted" }, b.lead), body);
}
