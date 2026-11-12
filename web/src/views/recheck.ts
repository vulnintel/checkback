// S3 recheck summary (§7-8, §7-7-3): counts against the baseline, what the baseline is, and the
// resolved list with the "revoked at the issuer?" tick for secret items (a local note only).

import { api } from "../api.js";
import { h } from "../dom.js";
import { t } from "../i18n.js";
import { go, report, S, type Compare, type GFinding, type ResolvedItem } from "../state.js";

export const loc = (f: Pick<GFinding, "location">): string => (f.location ? `${f.location.file}${f.location.line ? `:${f.location.line}` : ""}` : "");

/** "5 minutes ago" in the screen language, from the platform (no hand-made plural rules). */
function ago(iso: string, lang: string): string {
  const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
  const f = new Intl.RelativeTimeFormat(lang, { numeric: "auto" });
  const a = Math.abs(s);
  if (a < 60) return t().recheck.justNow;
  if (a < 3600) return f.format(Math.round(s / 60), "minute");
  if (a < 86400) return f.format(Math.round(s / 3600), "hour");
  return f.format(Math.round(s / 86400), "day");
}

/** Finding ids of the fix request, matched on the baseline id when the engine paired a changed item. */
export function requestedOf(c: Compare | undefined, findings: GFinding[]): GFinding[] {
  if (c?.baseline !== "fix_request" || !c.requested.length) return [];
  const req = new Set(c.requested);
  return findings.filter((f) => req.has(f.baseline_id ?? f.id));
}

/** Summary bar counts. Info items ("not a thing to fix") are left out so the bar matches the fix count. */
export function recheckCounts(
  findings: Pick<GFinding, "confidence" | "recheck">[],
  resolved: Pick<ResolvedItem, "confidence">[],
): { resolved: number; remaining: number; new: number; check: number } {
  const n = (...s: string[]): number => findings.filter((f) => f.confidence !== "info" && s.includes(f.recheck ?? "")).length;
  return {
    resolved: resolved.filter((x) => x.confidence !== "info").length,
    remaining: n("remaining", "same_key", "moved", "downgraded"),
    new: n("new"),
    check: n("lock_mismatch", "not_checked"),
  };
}

function resolvedItem(x: ResolvedItem): HTMLElement {
  const rc = t().recheck;
  return h(
    "li",
    {},
    h("span", { class: "strong" }, x.title),
    x.package ? h("span", { class: "muted" }, ` ${x.package}${x.version ? ` ${x.version}` : ""}`) : null,
    loc(x) ? h("span", { class: "loc" }, loc(x)) : null,
    x.confirm_revocation
      ? h(
          "label",
          { class: "check block-check" },
          h("input", {
            type: "checkbox",
            checked: !!x.revoked,
            onchange: (e: Event) => {
              const box = e.target as HTMLInputElement;
              api("POST", "/api/revoked", { id: x.id, done: box.checked })
                .then(() => (x.revoked = box.checked))
                .catch((err: unknown) => {
                  box.checked = !box.checked;
                  report(err);
                });
            },
          }),
          rc.revokeAsk,
        )
      : null,
  );
}

export function recheckSummary(): HTMLElement | null {
  const r = S.result!;
  const c = r.compare;
  if (!c) return null; // first scan: nothing to compare with
  const rc = t().recheck;
  const n = recheckCounts(r.findings, c.resolved);
  const parts: [string, number, string][] = [
    [rc.resolved, n.resolved, "recheck-resolved"],
    [rc.remaining, n.remaining, "recheck-remaining"],
    [rc.new, n.new, "recheck-new"],
    [rc.check, n.check, "recheck-lock_mismatch"],
  ];
  const when = ago(c.baseline_at, S.st!.lang);
  const secrets = c.resolved.some((x) => x.confirm_revocation);
  return h(
    "div",
    { class: "recheck", role: "region", "aria-label": rc.label, tabindex: "-1", "data-autofocus": "" },
    h("p", { class: "recheck-counts" }, parts.map(([label, v, cls]) => h("span", { class: v ? `badge ${cls}` : "badge" }, `${label} ${v}`))),
    h(
      "p",
      { class: "muted small" },
      c.baseline === "fix_request" ? rc.baseFix(when, c.requested.length) : rc.basePrev(when),
      " ",
      c.baseline === "fix_request" ? h("button", { class: "btn link", type: "button", onclick: () => go("settings") }, rc.baseClear) : null,
    ),
    c.baseline === "previous" ? h("p", { class: "muted small" }, rc.basePrevHint) : null,
    c.resolved.length
      ? h(
          "details",
          { class: "fold", open: secrets && c.resolved.some((x) => x.confirm_revocation && !x.revoked) },
          h("summary", {}, rc.resolvedList(c.resolved.length)),
          secrets ? h("p", { class: "muted small" }, rc.revokeHint) : null,
          h("ul", { class: "plain" }, c.resolved.map(resolvedItem)),
        )
      : null,
    r.ai_checks ? h("p", { class: "muted small" }, rc.aiNote) : null,
  );
}

/** §7-7-3: the fix-request items first, in their own section, with their status as it is. */
export function requestedHead(shown: number): HTMLElement[] {
  const c = S.result!.compare!;
  const req = new Set(c.requested);
  const done = c.resolved.filter((x) => req.has(x.id)).length;
  return [h("h2", { class: "sec" }, t().recheck.requested(c.requested.length)), h("p", { class: "muted small" }, t().recheck.requestedLine(done, shown))];
}
