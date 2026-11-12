// S9 fix prompt, S8 AI deep-review prompt, ignore, S3a watch, remediation tracker.
// Every person-only action here starts from a click in this screen.

import { api, ApiFail } from "../api.js";
import { copyText, extLink, h, modal, replace, toast } from "../dom.js";
import { t } from "../i18n.js";
import { go, report, S, type GFinding, type ScanView } from "../state.js";
import { loc } from "./recheck.js";

interface FixPrompt {
  text: string;
  external: boolean;
  human: string[];
}

/** [Copy]: clipboard, then record the fix-request snapshot (§7-8) — the recheck baseline. */
async function copyAndRecord(text: string, ids: string[], area?: HTMLTextAreaElement): Promise<boolean> {
  const ok = await copyText(text);
  await api("POST", "/api/fix-request", { ids }).catch(report);
  if (!ok && area) {
    area.focus();
    area.select();
    toast(t().copyFailed);
  }
  return ok;
}

/** Card [Paste to AI]: default-template text is copied at once; imported text gets the preview first (§4). */
export async function pasteToAi(findings: GFinding[]): Promise<void> {
  const ids = findings.map((f) => f.id);
  try {
    const p = await api<FixPrompt>("POST", "/api/fix-prompt", { ids });
    if (p.external) return fixDialog(ids, p);
    if (await copyAndRecord(p.text, ids)) toast(`${t().card.copiedTo}${findings.some((f) => f.revoke) ? ` ${t().card.revokeFirst}` : ""}`);
    else await fixDialog(ids, p);
  } catch (e) {
    report(e);
  }
}

/** S9 */
export async function fixDialog(ids: string[], given?: FixPrompt): Promise<void> {
  let p: FixPrompt;
  try {
    p = given ?? (await api<FixPrompt>("POST", "/api/fix-prompt", { ids }));
  } catch (e) {
    return report(e);
  }
  const f = t().fix;
  const area = h("textarea", { class: "prompt", readonly: true, rows: 14, "aria-label": f.title(ids.length) }, p.text);
  const d = modal(
    f.title(ids.length),
    [
      p.human.length
        ? h("fieldset", { class: "human" }, h("legend", {}, f.human), p.human.map((x) => h("label", { class: "check" }, h("input", { type: "checkbox" }), ` ${x}`)))
        : null,
      p.external ? h("p", { class: "warn" }, f.externalWarn) : null,
      area,
      h("p", { class: "muted small" }, f.guide),
    ],
    [
      h("button", {
        class: "btn primary",
        type: "button",
        onclick: async () => {
          if (await copyAndRecord(p.text, ids, area)) {
            d.close();
            toast(t().card.copiedTo);
          }
        },
      }, t().copy),
    ],
    true,
  );
}

/** S8 */
export async function aiCheckDialog(template: string): Promise<void> {
  const a = t().ai;
  let r: { text: string | null; external: boolean; items: { id: string; name: string; check: string; files: string[]; external: boolean }[] };
  try {
    r = await api("POST", "/api/ai-check", { template });
  } catch (e) {
    return report(e);
  }
  if (!r.text) {
    modal(a.title, [h("p", {}, a.none)]);
    return;
  }
  const text = r.text;
  const area = h("textarea", { class: "prompt", readonly: true, rows: 14, "aria-label": a.title }, text);
  const d = modal(
    a.title,
    [
      h("h3", {}, a.items),
      h(
        "ul",
        { class: "plain ai-items" },
        r.items.map((i) =>
          h(
            "li",
            {},
            h("strong", {}, i.name),
            i.external ? h("span", { class: "badge ext" }, t().templates.external) : null,
            h("div", {}, i.check),
            i.files.length ? h("div", { class: "muted small" }, `${a.lookFirst}: ${i.files.join(" ")}`) : null,
          ),
        ),
      ),
      r.external ? h("p", { class: "warn" }, t().fix.externalWarn) : null,
      area,
      h("p", { class: "muted small" }, a.guide),
    ],
    [
      h("button", {
        class: "btn primary",
        type: "button",
        onclick: async () => {
          if (await copyText(text)) {
            d.close();
            toast(t().copied);
          } else {
            area.select();
            toast(t().copyFailed);
          }
        },
      }, t().copy),
    ],
    true,
  );
}

export function ignoreDialog(f: GFinding, done: () => void): void {
  const i = t().ignore;
  const input = h("input", { id: "ignore-reason", type: "text", maxlength: 500, required: true });
  const d = modal(
    i.title,
    [
      h("p", { class: "strong" }, f.title),
      f.package ? h("p", { class: "card-pkg" }, `${f.package}${f.version ? `@${f.version}` : ""}`) : null,
      loc(f) ? h("p", { class: "loc" }, loc(f)) : null,
      h("div", { class: "field" }, h("label", { for: "ignore-reason" }, i.reason), input), h("p", { class: "muted small" }, i.note)],
    [
      h("button", {
        class: "btn primary",
        type: "button",
        onclick: async () => {
          const reason = input.value.trim();
          if (!reason) return input.focus();
          try {
            await api("POST", "/api/ignore", { id: f.id, reason });
            S.result = await api<ScanView>("GET", "/api/result"); // cards and recheck summary from one source
            S.selected.delete(f.id);
            d.close();
            done();
            toast(i.done);
          } catch (e) {
            report(e);
          }
        },
      }, i.submit),
    ],
  );
  input.focus();
}

/** S3a. Without a key: the same upsell as the result footer (§11). */
export async function watchDialog(): Promise<void> {
  const w = t().watch;
  const st = S.st!;
  if (st.key === "none" || !st.consent) {
    modal(w.title, [h("p", {}, st.consent ? w.needKey : w.needConsent)], [
      st.consent ? extLink(st.links.key, t().result.upsellLink) : h("button", { class: "btn primary", type: "button", onclick: (e: Event) => ((e.target as HTMLElement).closest("dialog")!.close(), go("consent")) }, t().settings.showConsent),
    ]);
    return;
  }
  let r: { candidates: { key: string; eco: string; name: string; direct: boolean; vuln: boolean }[]; defaults: number; max: number };
  try {
    r = await api("GET", "/api/watch");
  } catch (e) {
    return report(e);
  }
  if (!r.candidates.length) {
    modal(w.title, [h("p", {}, w.none)]);
    return;
  }
  const picked = new Set(r.candidates.slice(0, r.defaults).map((c) => c.key));
  const startBtn = h("button", { class: "btn primary", type: "button" }, w.start(picked.size));
  const sync = (): void => {
    startBtn.textContent = w.start(picked.size);
    startBtn.disabled = picked.size === 0 || picked.size > r.max;
  };
  const row = (c: (typeof r.candidates)[number]): HTMLElement =>
    h(
      "li",
      {},
      h(
        "label",
        { class: "check" },
        h("input", { type: "checkbox", checked: picked.has(c.key), onchange: (e: Event) => ((e.target as HTMLInputElement).checked ? picked.add(c.key) : picked.delete(c.key), sync()) }),
        ` ${c.name} `,
        h("span", { class: "muted small" }, c.eco),
        c.vuln ? h("span", { class: "badge kev" }, w.vulnerable) : null,
      ),
    );
  const direct = r.candidates.filter((c) => c.direct);
  const transitive = r.candidates.filter((c) => !c.direct);
  const out = h("div", { "aria-live": "polite" });
  const d = modal(
    w.title,
    [
      h("p", {}, w.lead),
      h("p", { class: "note" }, w.sends),
      h("p", { class: "muted small" }, w.max(r.max)),
      h("h3", {}, w.direct),
      h("ul", { class: "plain pick" }, direct.map(row)),
      transitive.length ? h("details", { class: "fold" }, h("summary", {}, w.transitive(transitive.length)), h("ul", { class: "plain pick" }, transitive.map(row))) : null,
      out,
    ],
    [startBtn],
    true,
  );
  sync();
  startBtn.addEventListener("click", async () => {
    startBtn.disabled = true;
    try {
      const res = await api<{ created: string[]; already: string[]; no_data: string[]; not_done: string[]; stopped?: string; limit?: number }>("POST", "/api/watch", { keys: [...picked] });
      replace(
        out,
        h("p", { class: "strong" }, w.result(res.created.length, res.already.length, res.no_data.length, res.not_done.length)),
        res.stopped === "subscription_limit" ? h("p", { class: "warn" }, w.limit(res.limit ?? 0)) : res.stopped ? h("p", { class: "warn" }, w.stopped(res.stopped)) : null,
        extLink(st.links.subscriptions, w.manage),
      );
      startBtn.remove();
    } catch (e) {
      startBtn.disabled = false;
      report(e);
    }
  });
  void d;
}

/** Card [Add to remediation tracker]: show what goes to the account before anything is sent. */
export function trackDialog(cves: string[], note: string, done: () => void): void {
  const k = t().track;
  const d = modal(
    t().card.track,
    [h("p", {}, k.lead), h("ul", { class: "plain" }, cves.map((c) => h("li", { class: "loc" }, c))), h("p", { class: "note" }, k.sends(note))],
    [
      h("button", { class: "btn", type: "button", onclick: () => d.close() }, t().cancel),
      h("button", { class: "btn primary", type: "button", onclick: () => (d.close(), void trackFinding(cves, done)) }, k.submit),
    ],
  );
}

async function trackFinding(cves: string[], done: () => void): Promise<void> {
  try {
    const r = await api<{ registered: number; error?: string }>("POST", "/api/track", { cves });
    if (r.error) toast(t().track.failed);
    else toast(t().track.done(r.registered));
    S.tracked = null;
    done();
  } catch (e) {
    if (e instanceof ApiFail && e.status !== 401) toast(t().track.failed);
    else report(e);
  }
}
