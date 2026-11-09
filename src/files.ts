import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, sep } from "node:path";

export interface FileEntry {
  /** CWD-relative, "/"-separated. */
  rel: string;
  abs: string;
  /** Inside browser build output (`.next/static`, `dist`, `build`, `out`). */
  build: boolean;
}

// Never walked. `.next` is special-cased: only `.next/static` (browser bundle) is walked.
const SKIP_DIRS = new Set([
  "node_modules", ".git", ".venv", "venv", "__pycache__", ".turbo", "coverage", ".svelte-kit", ".vercel", ".output",
]);
const BUILD_DIRS = new Set(["dist", "build", "out"]);

/** True for paths the walker never visits (used to filter paths that come from git history). */
export function isSkippedPath(rel: string): boolean {
  const segs = rel.split("/");
  return segs.slice(0, -1).some((s) => SKIP_DIRS.has(s)) || (segs[0] === ".next" && segs[1] !== "static");
}

export const MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_LINE_CHARS = 1024 * 1024;

/**
 * Walk `root` (already realpath'd). Symlinks and junctions are never followed: links that
 * point outside CWD must not be read, and links inside CWD reach files we walk anyway.
 */
export async function collectFiles(root: string): Promise<FileEntry[]> {
  const out: FileEntry[] = [];
  async function walk(abs: string, rel: string, build: boolean): Promise<void> {
    let ents;
    try {
      ents = await readdir(abs, { withFileTypes: true });
    } catch {
      return;
    }
    ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of ents) {
      if (e.isSymbolicLink()) continue;
      const childAbs = join(abs, e.name);
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        if (e.name === ".next") {
          const st = join(childAbs, "static");
          if (await isPlainDirInside(st, root)) await walk(st, `${childRel}/static`, true);
        } else await walk(childAbs, childRel, build || BUILD_DIRS.has(e.name));
      } else if (e.isFile()) {
        out.push({ rel: childRel, abs: childAbs, build });
      }
    }
  }
  await walk(root, "", false);
  return out;
}

/** `.next/static` is opened by name, not via a dirent: refuse links/junctions and anything resolving outside root. */
async function isPlainDirInside(abs: string, root: string): Promise<boolean> {
  try {
    const st = await lstat(abs);
    if (st.isSymbolicLink() || !st.isDirectory()) return false;
    // Catches reparse points Node doesn't report as links.
    return (await realpath(abs)).startsWith(root.endsWith(sep) ? root : root + sep);
  } catch {
    return false;
  }
}

export type SkipReason = "too_large" | "binary" | "utf16" | "long_line" | "unreadable";

/** Read a file as text for regex rules, or say why it is skipped. */
export async function readText(abs: string): Promise<{ text: string } | { skip: SkipReason }> {
  let buf: Buffer;
  try {
    if ((await stat(abs)).size > MAX_FILE_BYTES) return { skip: "too_large" };
    buf = await readFile(abs);
  } catch {
    return { skip: "unreadable" };
  }
  return decode(buf);
}

export function decode(buf: Buffer): { text: string } | { skip: SkipReason } {
  if (buf.length >= 2 && ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff))) {
    return { skip: "utf16" };
  }
  const head = buf.subarray(0, 8000);
  if (head.includes(0)) {
    // UTF-16 without BOM: NULs concentrated on one byte parity (ASCII text). Otherwise binary.
    let even = 0;
    let odd = 0;
    for (let i = 0; i < head.length; i++) if (head[i] === 0) i % 2 ? odd++ : even++;
    return { skip: Math.max(even, odd) > head.length * 0.3 ? "utf16" : "binary" };
  }
  let text = buf.toString("utf8");
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  let start = 0;
  while (start <= text.length) {
    let nl = text.indexOf("\n", start);
    if (nl < 0) nl = text.length;
    if (nl - start > MAX_LINE_CHARS) return { skip: "long_line" };
    start = nl + 1;
  }
  return { text };
}

// ---------- path classes (spec §5) ----------

const base = (rel: string): string => rel.slice(rel.lastIndexOf("/") + 1);

/** `*.example` / `*.sample` / `*.template` (incl. `.env.example`), `README*`, `docs/**\/*.md`. */
export function isExampleOrDoc(rel: string): boolean {
  const b = base(rel);
  return /\.(example|sample|template)(\.|$)/i.test(b) || /^readme/i.test(b) || /(^|\/)docs\/.*\.mdx?$/i.test(rel);
}

export function isTestPath(rel: string): boolean {
  return /(^|\/)(test|tests|__tests__|fixtures)\//.test(rel) || /\.(test|spec)\./.test(base(rel));
}

/** A real (non-example) dotenv file. */
export function isEnvFile(rel: string): boolean {
  return /^\.env(\.|$)/.test(base(rel)) && !isExampleOrDoc(rel);
}

export function lineAt(text: string, index: number): number {
  let n = 1;
  for (let i = text.indexOf("\n"); i >= 0 && i < index; i = text.indexOf("\n", i + 1)) n++;
  return n;
}

export function lineTextAt(text: string, index: number): string {
  const s = text.lastIndexOf("\n", index - 1) + 1;
  let e = text.indexOf("\n", index);
  if (e < 0) e = text.length;
  return text.slice(s, e).replace(/\r$/, "");
}
