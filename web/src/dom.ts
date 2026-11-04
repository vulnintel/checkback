// Tiny DOM helpers. Text always goes in through textContent / text nodes — never as HTML.

import { t } from "./i18n.js";

type Child = Node | string | number | null | undefined | false;
type Attrs = Record<string, string | number | boolean | null | undefined | ((e: Event) => void)>;

export function h<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Attrs = {}, ...children: (Child | Child[])[]): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (typeof v === "function") el.addEventListener(k.replace(/^on/, ""), v);
    else if (k === "class") el.className = String(v);
    else if (k in el && typeof (el as unknown as Record<string, unknown>)[k] === "boolean") (el as unknown as Record<string, unknown>)[k] = !!v;
    else if (k === "value") (el as unknown as { value: string }).value = String(v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  append(el, children);
  return el;
}

export function append(el: Element, children: (Child | Child[])[]): void {
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
}

export function replace(el: Element, ...children: (Child | Child[])[]): void {
  el.replaceChildren();
  append(el, children);
}

/** Modal dialog (native <dialog>: focus trap, Esc to close). Removed from the DOM when closed. */
export function modal(title: string, body: (Child | Child[])[], actions: (Child | Child[])[] = [], wide = false): HTMLDialogElement {
  const id = `dlg-${Math.random().toString(36).slice(2)}`;
  const d = h(
    "dialog",
    { class: wide ? "dlg wide" : "dlg", "aria-labelledby": id },
    h("div", { class: "dlg-head" }, h("h2", { id }, title), h("button", { class: "btn ghost", type: "button", onclick: () => d.close() }, t().close)),
    h("div", { class: "dlg-body" }, ...body),
    actions.length ? h("div", { class: "dlg-actions" }, ...actions) : null,
  );
  d.addEventListener("close", () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

let toastTimer = 0;
/** Status message read out by screen readers (aria-live region in index.html). */
export function toast(msg: string): void {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = msg; // the region stays in the DOM (empty = invisible) so the change is announced
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => (el.textContent = ""), 8000);
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function download(filename: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = h("a", { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** External links open in a new tab without referrer. */
export const extLink = (href: string, text: string): HTMLAnchorElement => h("a", { href, target: "_blank", rel: "noopener noreferrer" }, text);
