import { lstat, readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, sep } from "node:path";
import { ignoredUntracked } from "./git.js";

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
 * Walk `root`. Symlinks and junctions are never followed: links that
 * point outside CWD must not be read, and links inside CWD reach files we walk anyway.
 * Skipped: other checkouts inside the tree (a `.git` file marks a nested worktree or submodule;
 * `.claude/worktrees` is Claude Code's worktree folder) and gitignored untracked paths — except
 * browser build output (gitignored, but deployed) and `.env*` (local-only .env is judged, §5).
 * With `nestedRepos`, folders holding their own repository (a `.git` directory: an independent
 * clone) are skipped too and listed there; without it (root is not a repo) they are walked.
 */
export async function collectFiles(root: string, nestedRepos?: string[]): Promise<FileEntry[]> {
  const out: FileEntry[] = [];
  const ignored = await ignoredUntracked(root);
  async function walk(abs: string, rel: string, build: boolean): Promise<void> {
    let ents;
    try {
      ents = await readdir(abs, { withFileTypes: true });
    } catch {
      return;
    }
    const dotGit = rel ? ents.find((e) => e.name === ".git") : undefined;
    if (dotGit?.isFile()) return;
    if (dotGit?.isDirectory() && nestedRepos) return void nestedRepos.push(rel);
    ents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const e of ents) {
      if (e.isSymbolicLink()) continue;
      const childAbs = join(abs, e.name);
      const childRel = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name) || (e.name === "worktrees" && /(^|\/)\.claude$/.test(rel))) continue;
        if (e.name === ".next") {
          const st = join(childAbs, "static");
          if (await isPlainDirInside(st, root)) await walk(st, `${childRel}/static`, true);
        } else if (BUILD_DIRS.has(e.name)) await walk(childAbs, childRel, true);
        else if (build || !ignored.has(`${childRel}/`)) await walk(childAbs, childRel, build);
      } else if (e.isFile()) {
        if (!build && ignored.has(childRel) && !/^\.env(\.|$)/.test(e.name)) continue;
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
    // Catches reparse points Node doesn't report as links. Resolve root too: it may itself sit behind
    // a symlink or short name (macOS /var → /private/var, Windows RUNNER~1), which made this always false.
    const real = await realpath(root);
    return (await realpath(abs)).startsWith(real.endsWith(sep) ? real : real + sep);
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

/** Tests, fixtures, mocks and load/e2e test scripts (a mock server's `debug=True` is not production). */
export function isTestPath(rel: string): boolean {
  return (
    /(^|\/)(test|tests|__tests__|fixtures|__mocks__|mocks?|e2e|(stress|load)[-_]?tests?)\//.test(rel) ||
    /\.(test|spec)\.|^mock[-_.]|[-_.]mock\./i.test(base(rel))
  );
}

/** Third-party code copied into the repo: vendor folders and prebuilt bundles (`redoc.standalone.js`, `*.min.js`). */
export function isVendorPath(rel: string): boolean {
  return /(^|\/)(vendor|vendors|third[-_]party)\//.test(rel) || /\.(min|standalone|bundle|umd)\.[cm]?js$/.test(base(rel));
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
