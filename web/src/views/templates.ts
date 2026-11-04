// S5 templates: list → duplicate → turn items on/off; add / edit / delete ai_check sentences on
// copies (§6-2, D1); import (file content) / export. Pattern, file and config editors are stage 2.

import { api, ApiFail } from "../api.js";
import { download, h, modal, replace, toast } from "../dom.js";
import { t } from "../i18n.js";
import { refreshState, report, S } from "../state.js";

interface RuleRow {
  id: string;
  type: string;
  name: string;
  severity: string | null;
  enabled: boolean;
  check?: string;
  files?: string[];
  mine?: boolean;
  bundled?: boolean;
}
interface Tpl {
  id: string;
  name: string;
  readOnly: boolean;
  imported: boolean;
  rules: RuleRow[];
}

let current = "default";

function storeError(e: unknown): string {
  const m = t().templates;
  if (!(e instanceof ApiFail) || e.status === 401) return t().error;
  const issues = Array.isArray(e.detail) ? (e.detail as { path: string; line?: number; message: string }[]) : [];
  return [m.errors[e.code] ?? t().error, ...issues.slice(0, 20).map((i) => `${i.line ? `${m.line(i.line)} · ` : ""}${i.path}: ${i.message}`)].join("\n");
}

function aiDialog(tpl: Tpl, rule: RuleRow | null, reload: () => void): void {
  const m = t().templates;
  const sentence = h("textarea", { id: "ai-check", rows: 3, maxlength: 300, required: true }, rule?.check ?? "");
  const sev = h("select", { id: "ai-sev" }, (["critical", "high", "medium"] as const).map((s) => h("option", { value: s, selected: (rule?.severity ?? "medium") === s }, t().result.sev[s])));
  const files = h("input", { id: "ai-files", type: "text", value: rule?.files?.join(" ") ?? "" });
  const err = h("p", { class: "warn pre", role: "alert" });
  const d = modal(
    rule ? m.editAi : m.addAi,
    [
      h("div", { class: "field" }, h("label", { for: "ai-check" }, m.aiSentence), sentence),
      h("div", { class: "field" }, h("label", { for: "ai-sev" }, m.aiSeverity), sev),
      h("div", { class: "field" }, h("label", { for: "ai-files" }, m.aiFiles), files),
      err,
    ],
    [
      h("button", {
        class: "btn primary",
        type: "button",
        onclick: async () => {
          try {
            await api("POST", "/api/templates/ai-check", { id: tpl.id, ...(rule && { rule: rule.id }), check: sentence.value, severity: sev.value, files: files.value });
            d.close();
            reload();
          } catch (e) {
            err.textContent = storeError(e);
          }
        },
      }, t().save),
    ],
  );
  sentence.focus();
}

function rulesTable(tpl: Tpl, reload: () => void): HTMLElement {
  const m = t().templates;
  const act = (path: string, body: Record<string, unknown>) => async (): Promise<void> => {
    try {
      await api("POST", path, body);
      reload();
    } catch (e) {
      toast(storeError(e));
    }
  };
  return h(
    "table",
    { class: "rules" },
    h("thead", {}, h("tr", {}, [m.colOn, m.colName, m.colType, m.colSev].map((c) => h("th", { scope: "col" }, c)))),
    h(
      "tbody",
      {},
      tpl.rules.map((r) =>
        h(
          "tr",
          {},
          h("td", {}, h("input", { type: "checkbox", checked: r.enabled, disabled: tpl.readOnly, "aria-label": `${m.colOn}: ${r.name}`, onchange: (e: Event) => void act("/api/templates/toggle", { id: tpl.id, rule: r.id, enabled: (e.target as HTMLInputElement).checked })() })),
          h(
            "td",
            {},
            h("div", {}, r.name),
            r.type === "ai_check"
              ? h(
                  "div",
                  { class: "ai-row" },
                  h("span", { class: `badge ${r.mine ? "mine" : r.bundled ? "" : "ext"}` }, r.mine ? m.mine : r.bundled ? m.bundled : m.external),
                  h("span", { class: "muted small" }, r.check ?? ""),
                  r.files?.length ? h("span", { class: "muted small" }, ` · ${r.files.join(" ")}`) : null,
                  !tpl.readOnly && r.mine ? h("button", { class: "btn link", type: "button", onclick: () => aiDialog(tpl, r, reload) }, m.editAi) : null,
                  !tpl.readOnly ? h("button", { class: "btn link", type: "button", onclick: act("/api/templates/ai-check/delete", { id: tpl.id, rule: r.id }) }, m.deleteAi) : null,
                )
              : null,
          ),
          h("td", {}, m.type[r.type] ?? r.type),
          h("td", {}, r.severity ? (t().result.sev[r.severity] ?? r.severity) : "—"),
        ),
      ),
    ),
  );
}

export function templatesView(): HTMLElement {
  const m = t().templates;
  const root = h("section", { class: "panel" }, h("h1", { tabindex: "-1" }, m.title), h("p", { class: "muted" }, m.lead));
  const body = h("div", {}, t().loading);
  const fileInput = h("input", {
    type: "file",
    accept: ".yaml,.yml",
    class: "visually-hidden",
    id: "tpl-import",
    onchange: async (e: Event) => {
      const input = e.target as HTMLInputElement;
      const file = input.files?.[0];
      input.value = "";
      if (!file) return;
      try {
        const r = await api<{ id: string; renamed: boolean }>("POST", "/api/templates/import", { content: await file.text() });
        current = r.id;
        toast(m.importOk(r.id, r.renamed));
        await load();
      } catch (err) {
        modal(m.importErr, [h("p", { class: "warn pre" }, storeError(err))]);
      }
    },
  });
  root.append(h("div", { class: "row" }, fileInput, h("label", { for: "tpl-import", class: "btn" }, m.import)), body);

  const load = async (): Promise<void> => {
    let data: { templates: Tpl[]; max_ai_checks: number };
    try {
      data = await api("GET", "/api/templates");
      await refreshState();
    } catch (e) {
      return report(e);
    }
    const tpl = data.templates.find((x) => x.id === current) ?? data.templates[0]!;
    current = tpl.id;
    const reload = (): void => void load();
    const act = (path: string, extra: Record<string, unknown> = {}) => async (): Promise<void> => {
      try {
        const r = await api<{ id?: string; filename?: string; content?: string }>("POST", path, { id: tpl.id, ...extra });
        if (r.filename && r.content !== undefined) return download(r.filename, r.content, "application/yaml");
        if (r.id) current = r.id;
        reload();
      } catch (e) {
        toast(storeError(e));
      }
    };
    const aiCount = tpl.rules.filter((r) => r.type === "ai_check").length;
    replace(
      body,
      h(
        "div",
        { class: "tpl-list", role: "list" },
        data.templates.map((x) =>
          h(
            "button",
            { type: "button", role: "listitem", class: `tpl-item${x.id === current ? " current" : ""}`, "aria-current": x.id === current ? "true" : null, onclick: () => ((current = x.id), reload()) },
            h("span", {}, x.name),
            h("span", { class: "badge" }, x.readOnly ? m.builtinRo : x.imported ? m.imported : m.mineTpl),
          ),
        ),
      ),
      h(
        "div",
        { class: "row" },
        h("button", { class: "btn", type: "button", onclick: act("/api/templates/duplicate", { from: tpl.id }) }, m.duplicate),
        h("button", { class: "btn", type: "button", onclick: act("/api/templates/export") }, m.export),
        tpl.readOnly
          ? null
          : h("button", {
              class: "btn",
              type: "button",
              onclick: () => {
                const name = h("input", { id: "tpl-name", type: "text", maxlength: 80, value: tpl.name });
                const d = modal(m.rename, [h("div", { class: "field" }, h("label", { for: "tpl-name" }, m.newName), name)], [
                  h("button", { class: "btn primary", type: "button", onclick: () => (d.close(), void act("/api/templates/rename", { name: name.value })()) }, t().save),
                ]);
                name.focus();
              },
            }, m.rename),
        tpl.readOnly
          ? null
          : h("button", {
              class: "btn danger",
              type: "button",
              onclick: () => {
                const d = modal(m.delete, [h("p", {}, m.confirmDelete(tpl.name))], [
                  h("button", { class: "btn danger", type: "button", onclick: () => (d.close(), (current = "default"), void act("/api/templates/delete")()) }, m.delete),
                ]);
              },
            }, m.delete),
      ),
      tpl.readOnly ? h("p", { class: "note" }, m.roNote) : null,
      tpl.readOnly
        ? null
        : h(
            "div",
            { class: "row" },
            h("button", { class: "btn primary", type: "button", disabled: aiCount >= data.max_ai_checks, onclick: () => aiDialog(tpl, null, reload) }, m.addAi),
            h("span", { class: "muted small" }, m.aiCount(aiCount, data.max_ai_checks)),
          ),
      rulesTable(tpl, reload),
    );
    if (S.template !== current && data.templates.some((x) => x.id === current)) S.template = current;
  };
  void load();
  return root;
}
