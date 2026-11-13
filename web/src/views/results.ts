// S3 result (to-do list) and S4 details. After a recheck the summary (views/recheck.ts) sits on
// top, the fix-request items get their own section, and every card shows its status and note.

import { api } from "../api.js";
import { extLink, h, modal, replace } from "../dom.js";
import { emptyKind } from "../empty.js";
import { t } from "../i18n.js";
import { pickBySeverity } from "../pick.js";
import { go, report, S, type GFinding } from "../state.js";
import { aiCheckDialog, fixDialog, ignoreDialog, pasteToAi, trackDialog, watchDialog } from "./dialogs.js";
import { loc, recheckSummary, requestedHead, requestedOf } from "./recheck.js";
import { startScan } from "./start.js";

const MAX_BATCH = 10;
let updateBar: () => void = () => {};
const boxes = new Map<string, HTMLInputElement>(); // card checkboxes, so quick select can tick them without a re-render
let capped = 0; // how many matched the last quick select when it was cut to MAX_BATCH, else 0
const cves = (f: GFinding): string[] => (f.vuln_ids ?? []).filter((v) => /^CVE-\d{4}-\d{4,}$/.test(v));

function badges(f: GFinding): HTMLElement {
  const c = t().card;
  return h(
    "div",
    { class: "badges" },
    h("span", { class: `sev sev-${f.severity}` }, t().result.sev[f.severity]),
    f.recheck && !(f.confidence === "info" && f.recheck === "remaining") ? h("span", { class: `badge recheck-${f.recheck}` }, c.recheck[f.recheck] ?? f.recheck) : null,
    f.kev ? h("span", { class: "badge kev" }, c.kev) : null,
    f.vpi_level ? h("span", { class: `badge vpi vpi-${f.vpi_level}` }, c.vpi(f.vpi_level)) : null,
    f.notes?.some((n) => n === "priority_pending" || n === "priority_failed") ? h("span", { class: "badge" }, c.priorityUnchecked) : null,
    typeof f.epss === "number" ? h("span", { class: "badge" }, c.epss(Math.round(f.epss * 1000) / 10)) : null,
    f.external_text ? h("span", { class: "badge ext" }, c.externalText) : null,
  );
}

function card(f: GFinding, rerender: () => void): HTMLElement {
  const c = t().card;
  const sel = S.selected.has(f.id);
  const ids = cves(f);
  const box = f.carried
    ? null
    : h("input", {
        type: "checkbox",
        checked: sel,
        "aria-label": t().result.select(f.title),
        onchange: (e: Event) => {
          const el = e.target as HTMLInputElement;
          if (el.checked) S.selected.add(f.id);
          else S.selected.delete(f.id);
          el.closest(".card")?.classList.toggle("selected", el.checked);
          capped = 0;
          updateBar(); // keep keyboard focus on the checkbox: no full re-render
        },
      });
  if (box) boxes.set(f.id, box as HTMLInputElement);
  const trackBtn =
    S.st!.key !== "none" && f.rule_id === "vulnerable-deps"
      ? ids.length === 0
        ? h("span", { class: "muted small" }, c.ghsaOnly)
        : ids.every((x) => S.tracked?.get(x))
          ? h("span", { class: "muted small" }, c.tracked)
          : h("button", { class: "btn", type: "button", onclick: () => trackDialog(ids, `checkback: ${f.package}@${f.version ?? ""}`, rerender) }, c.track)
      : null;
  return h(
    "article",
    { class: `card${sel ? " selected" : ""}`, "aria-label": f.title },
    h(
      "div",
      { class: "card-head" },
      box,
      badges(f),
    ),
    h("h3", { class: "card-title" }, f.title),
    f.package ? h("p", { class: "card-pkg" }, c.pkg(f.package, f.version ?? "", f.fixed_version)) : null,
    f.summary && f.summary !== f.title ? h("p", { class: "card-sum" }, f.summary) : null,
    loc(f) ? h("p", { class: "loc" }, loc(f)) : null,
    f.recheck_note ? h("p", { class: "card-note small" }, recheckText(f)) : null,
    h(
      "div",
      { class: "card-actions" },
      f.carried ? null : h("button", { class: f.confidence === "info" ? "btn" : "btn primary", type: "button", onclick: () => void pasteToAi([f]) }, c.paste),
      h("button", { class: "btn", type: "button", onclick: () => detailDialog(f) }, c.details),
      f.carried ? null : h("button", { class: "btn", type: "button", onclick: () => ignoreDialog(f, rerender) }, c.ignore),
      trackBtn,
    ),
  );
}

function dl(rows: [string, Node | string | null | undefined][]): HTMLElement {
  return h("dl", { class: "kv" }, rows.filter(([, v]) => v !== null && v !== undefined && v !== "").flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
}

function recheckText(f: GFinding): string {
  const d = t().detail;
  if (f.recheck_note === "version_bumped_still_vulnerable" && f.previous_version) return d.bumped(f.previous_version, f.version ?? "", f.fixed_version);
  return d.recheckNote[f.recheck_note ?? ""] ?? f.recheck_note ?? "";
}

/** S4 */
export function detailDialog(f: GFinding): void {
  const d = t().detail;
  const preview = h("pre", { class: "prompt" }, t().loading);
  const pkg = f.package ? `${f.package}${f.version ? `@${f.version}` : ""}` : null;
  modal(
    f.title,
    [
      badges(f),
      h("h3", {}, d.why),
      h("p", {}, f.description || f.summary),
      f.recheck_note ? h("p", { class: "note" }, h("strong", {}, `${d.recheckWhy}: `), recheckText(f)) : null,
      dl([
        [d.where, loc(f) || null],
        [d.related, f.related?.length ? f.related.join(", ") : null],
        [d.masked, f.masked_match ?? null],
        [d.rule, `${f.name} (${f.rule_id}) · ${t().card.conf[f.confidence]}`],
        [d.pkg, pkg],
        [d.fixed, f.package ? (f.fixed_version ?? d.noFix) : null],
        [d.vuln, f.vuln_ids?.length ? f.vuln_ids.join(", ") : null],
        [d.cvss, typeof f.cvss === "number" ? String(f.cvss) : null],
        [d.lock, f.lockfile ?? null],
        [d.source, d.sources[f.source] ?? f.source],
      ]),
      f.notes?.length ? h("ul", { class: "notes" }, f.notes.map((n) => h("li", {}, d.note[n] ?? n))) : null,
      f.carried ? null : h("h3", {}, d.preview),
      f.carried ? null : preview,
    ],
    f.carried ? [] : [h("button", { class: "btn primary", type: "button", onclick: () => void pasteToAi([f]) }, t().card.paste)],
    true,
  );
  if (!f.carried)
    api<{ text: string }>("POST", "/api/fix-prompt", { ids: [f.id] })
      .then((r) => (preview.textContent = r.text))
      .catch(report);
}

function emptyState(): HTMLElement | null {
  const r = S.result!;
  const tr = t().result;
  const kind = emptyKind(r);
  if (!kind) return null;
  const [title, body] = kind === "nothing" ? [tr.nothingTitle, tr.nothingBody] : kind === "nolock" ? [tr.noLockTitle, tr.noLockBody] : [tr.cleanTitle, tr.cleanBody];
  return h("div", { class: `empty ${kind}` }, h("h2", {}, title), h("p", {}, body));
}

export function resultView(): HTMLElement {
  const r = S.result!;
  const tr = t().result;
  const root = h("section", { class: "result" });
  const rerender = (): void => go("result");
  const asked = requestedOf(r.compare, r.findings);
  const rest = r.findings.filter((f) => !asked.includes(f));
  const fix = rest.filter((f) => f.confidence === "confirmed");
  const review = rest.filter((f) => f.confidence === "review");
  const info = rest.filter((f) => f.confidence === "info");
  const allFix = r.findings.filter((f) => f.confidence === "confirmed");
  const count = (s: string): number => allFix.filter((f) => f.severity === s).length;
  boxes.clear();

  // Quick select: tick every "thing to fix" at a severity level in one click (cut to the batch limit).
  const pickable = [...asked, ...fix].filter((f) => f.confidence === "confirmed" && !f.carried);
  const setSelection = (ids: string[], total: number): void => {
    S.selected.clear();
    for (const id of ids) S.selected.add(id);
    for (const [id, box] of boxes) {
      box.checked = S.selected.has(id);
      box.closest(".card")?.classList.toggle("selected", box.checked);
    }
    capped = total > ids.length ? total : 0;
    updateBar();
  };
  let prev = 0;
  const quickBtns = (
    [
      [tr.sev.critical, ["critical"]],
      [`${tr.sev.critical}+${tr.sev.high}`, ["critical", "high"]],
      [tr.quickAll, ["critical", "high", "medium"]],
    ] as [string, string[]][]
  ).flatMap(([label, sevs]) => {
    const p = pickBySeverity(pickable, sevs, MAX_BATCH);
    if (p.total === prev) return []; // nothing new at this level
    prev = p.total;
    return [h("button", { class: "btn", type: "button", onclick: () => setSelection(p.ids, p.total) }, `${label} ${p.total}`)];
  });
  const capNote = h("span", { class: "muted small", "aria-live": "polite" });
  const quick =
    pickable.length > 1
      ? h("div", { class: "quick" }, h("span", { class: "muted small" }, tr.quick), quickBtns, h("button", { class: "btn", type: "button", onclick: () => setSelection([], 0) }, tr.quickClear), capNote)
      : null;

  if (S.st!.key !== "none" && S.tracked === null && r.findings.some((f) => f.rule_id === "vulnerable-deps" && cves(f).length)) {
    S.tracked = new Map();
    api<{ rows: { cve: string; registered: boolean }[] }>("GET", "/api/track")
      .then((x) => {
        S.tracked = new Map(x.rows.map((row) => [row.cve, row.registered]));
        if (S.view === "result") rerender();
      })
      .catch(() => {});
  }

  root.append(
    ...[recheckSummary()].filter((x) => x !== null),
    h(
      "div",
      { class: "summary" },
      h(
        "div",
        {},
        h("h1", { tabindex: "-1" }, tr.fixCount(allFix.length)),
        h("p", { class: "sev-line" }, (["critical", "high", "medium"] as const).map((s) => h("span", { class: `sev sev-${s}` }, `${tr.sev[s]} ${count(s)}`))),
        h("p", { class: "muted" }, `${tr.reviewCount(r.findings.filter((f) => f.confidence === "review").length)} · ${tr.infoCount(r.findings.filter((f) => f.confidence === "info").length)}`),
        h(
          "p",
          { class: "muted small" },
          tr.meta(new Date(r.scan_at).toLocaleString(S.st!.lang), r.template.name, r.stats.files),
          " ",
          h("button", { class: "btn link", type: "button", onclick: () => {
            if (S.st!.templates.some((x) => x.id === r.template.id)) S.template = r.template.id; // start screen opens on the template of this result
            go("start");
          } }, tr.changeTemplate),
        ),
      ),
      h(
        "div",
        { class: "summary-actions" },
        h("button", { class: "btn", type: "button", disabled: r.ai_checks === 0, title: r.ai_checks === 0 ? tr.aiCheckOff : null, onclick: () => void aiCheckDialog(r.template.id) }, tr.aiCheck),
        h("button", { class: "btn", type: "button", onclick: () => void watchDialog() }, tr.watch),
      ),
    ),
    ...r.notices.map((x) => h("p", { class: "note" }, x)),
  );

  const empty = emptyState();
  if (empty) root.append(empty);
  if (quick) root.append(quick);
  if (r.compare?.baseline === "fix_request" && r.compare.requested.length) {
    root.append(...requestedHead(asked.length), h("div", { class: "cards" }, asked.map((f) => card(f, rerender))));
    if (rest.length) root.append(h("h2", { class: "sec others" }, t().recheck.others));
  }
  if (fix.length) root.append(h("h2", { class: "sec" }, tr.secFix), h("div", { class: "cards" }, fix.map((f) => card(f, rerender))));
  if (review.length) root.append(h("h2", { class: "sec" }, tr.secReview), h("p", { class: "muted small" }, tr.secReviewHint), h("div", { class: "cards" }, review.map((f) => card(f, rerender))));
  if (info.length) root.append(h("details", { class: "fold" }, h("summary", {}, tr.secInfo(info.length)), h("div", { class: "cards" }, info.map((f) => card(f, rerender)))));
  if (r.passed.length) root.append(h("details", { class: "fold" }, h("summary", {}, tr.passed(r.passed.length)), h("ul", { class: "plain" }, r.passed.map((p) => h("li", {}, p.name)))));
  if (r.not_run.length)
    root.append(h("details", { class: "fold" }, h("summary", {}, tr.notRun(r.not_run.length)), h("ul", { class: "plain" }, r.not_run.map((p) => h("li", {}, `${p.name} — ${tr.reason[p.reason] ?? p.reason}`)))));
  if (S.st!.key === "none") root.append(h("p", { class: "upsell" }, `${tr.upsell} `, extLink(S.st!.links.key, tr.upsellLink)));

  const bar = h("div", { class: "bar", role: "region", "aria-label": tr.rescan });
  updateBar = () => {
    const n = S.selected.size;
    capNote.textContent = capped && n <= MAX_BATCH ? tr.quickCapped(capped, n) : "";
    replace(
      bar,
      n ? h("span", { "aria-live": "polite" }, tr.selected(n)) : null,
      n ? h("button", { class: "btn primary", type: "button", disabled: n > MAX_BATCH, onclick: () => void fixDialog([...S.selected]) }, tr.batch(n)) : null,
      n > MAX_BATCH ? h("span", { class: "warn small" }, tr.batchMax(MAX_BATCH)) : null,      h("span", { class: "grow" }),
      h("button", { class: "btn primary", type: "button", onclick: () => void startScan() }, tr.rescan),
    );
  };
  updateBar();
  root.append(bar);
  return root;
}
