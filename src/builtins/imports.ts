// Import names for hallucinated-package (§7-2): only names that pass these filters may be looked up.

import { builtinModules } from "node:module";
import { lineAt, type FileEntry } from "../files.js";
import { normalizePyName } from "../deps/locks.js";

export interface ImportRef {
  ecosystem: "npm" | "PyPI";
  /** Package (npm) or distribution (PyPI) name. */
  name: string;
  file: string;
  line: number;
  /** PyPI: true only when the import name is in the bundled map (lookup allowed). */
  lookup: boolean;
}

const NODE_BUILTIN = new Set(builtinModules.map((m) => m.replace(/^node:/, "")));
// The clause before `from` stops at the next import/export keyword so each match start is bounded (else quadratic).
const JS_RX =
  /(?:^|[^\w.$])(?:import|export)\s(?:(?!\b(?:import|export)\b)[^'"`;])*?from\s*['"]([^'"]+)['"]|(?:^|[^\w.$])import\s*['"]([^'"]+)['"]|\brequire\(\s*['"]([^'"]+)['"]\s*\)|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
const PKG_NAME = /^(@[a-z0-9._-]+\/)?[A-Za-z0-9._-]+$/;

/** JS/TS bare specifiers minus Node builtins, tsconfig paths/baseUrl dirs, bundler aliases, workspace names, same-name local folders/files. */
export async function jsImports(files: FileEntry[], text: (rel: string) => Promise<string | null>, workspace: Set<string>): Promise<ImportRef[]> {
  const aliases: string[] = [];
  const local = new Set<string>();
  for (const f of files) {
    if (f.build) continue;
    const parts = f.rel.split("/");
    parts.slice(0, -1).forEach((d) => local.add(d));
    local.add(parts[parts.length - 1]!.replace(/\.[^.]+$/, ""));
    const b = parts[parts.length - 1]!;
    if (/^[tj]sconfig.*\.json$/.test(b)) {
      const t = (await text(f.rel)) ?? "";
      for (const m of t.matchAll(/"([^"]+?)(?:\/\*)?"\s*:\s*\[/g)) aliases.push(m[1]!);
      const base = /"baseUrl"\s*:\s*"([^"]+)"/.exec(t);
      if (base) {
        // Modules resolvable from baseUrl look like bare specifiers: treat that folder's entries as local.
        const dir = [...parts.slice(0, -1), ...base[1]!.split("/")].filter((x) => x && x !== ".").join("/");
        const prefix = dir ? `${dir}/` : "";
        for (const g of files) if (g.rel.startsWith(prefix)) local.add(g.rel.slice(prefix.length).split("/")[0]!.replace(/\.[^.]+$/, ""));
      }
    }
    if (/^(vite|webpack|vitest|astro|svelte|nuxt)\.config\./.test(b)) {
      const t = (await text(f.rel)) ?? "";
      const alias = /alias\s*:\s*[{[]([\s\S]*?)(?:[}\]]|$)/.exec(t);
      if (alias) for (const m of alias[1]!.matchAll(/(?<![@~$#\w/-])['"]?([@~$#\w/-]+)['"]?\s*:/g)) aliases.push(m[1]!);
      for (const m of t.matchAll(/find\s*:\s*['"]([^'"]+)['"]/g)) aliases.push(m[1]!);
    }
  }
  const out: ImportRef[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (f.build || !/\.(jsx?|tsx?|mjs|cjs|vue|svelte)$/.test(f.rel)) continue;
    const t = await text(f.rel);
    if (!t) continue;
    for (const m of t.matchAll(JS_RX)) {
      const spec = (m[1] ?? m[2] ?? m[3] ?? m[4])!;
      if (/^(\.|\/|node:|[a-z]+:|~|\$|#)/.test(spec) || spec.includes("\\")) continue;
      const segs = spec.split("/");
      const name = spec.startsWith("@") ? segs.slice(0, 2).join("/") : segs[0]!;
      if (!PKG_NAME.test(name) || NODE_BUILTIN.has(name) || workspace.has(name)) continue;
      if (aliases.some((a) => spec === a || name === a || spec.startsWith(`${a.replace(/\/?\*$/, "")}/`))) continue;
      if (!name.startsWith("@") && local.has(name)) continue;
      if (seen.has(name)) continue;
      seen.add(name);
      out.push({ ecosystem: "npm", name, file: f.rel, line: lineAt(t, m.index), lookup: true });
    }
  }
  return out;
}

// Top-level Python standard library modules (3.8–3.13).
const PY_STDLIB = new Set(
  `__future__ abc aifc argparse array ast asynchat asyncio asyncore atexit audioop base64 bdb binascii bisect builtins bz2
  calendar cgi cgitb chunk cmath cmd code codecs codeop collections colorsys compileall concurrent configparser contextlib
  contextvars copy copyreg cProfile crypt csv ctypes curses dataclasses datetime dbm decimal difflib dis distutils doctest
  email encodings ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc getopt
  getpass gettext glob graphlib grp gzip hashlib heapq hmac html http idlelib imaplib imghdr imp importlib inspect io
  ipaddress itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap marshal math mimetypes mmap
  modulefinder msilib msvcrt multiprocessing netrc nis nntplib ntpath numbers opcode operator optparse os ossaudiodev
  pathlib pdb pickle pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint profile pstats pty pwd
  py_compile pyclbr pydoc queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select
  selectors shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver spwd sqlite3 sre_compile
  sre_constants sre_parse ssl stat statistics string stringprep struct subprocess sunau symtable sys sysconfig syslog
  tabnanny tarfile telnetlib tempfile termios textwrap threading time timeit tkinter token tokenize tomllib trace
  traceback tracemalloc tty turtle turtledemo types typing unicodedata unittest urllib uu uuid venv warnings wave
  weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp zipfile zipimport zlib zoneinfo _thread`.split(/\s+/),
);

/**
 * Import name → PyPI distribution for well-known names that differ (self-compiled, U14 open).
 * Only these import names are ever looked up on PyPI (§7-2); everything else is info only.
 */
export const PY_IMPORT_MAP: Record<string, string> = {
  cv2: "opencv-python", PIL: "pillow", yaml: "pyyaml", sklearn: "scikit-learn", skimage: "scikit-image",
  bs4: "beautifulsoup4", dotenv: "python-dotenv", jwt: "pyjwt", jose: "python-jose", dateutil: "python-dateutil",
  MySQLdb: "mysqlclient", Crypto: "pycryptodome", OpenSSL: "pyopenssl", magic: "python-magic", docx: "python-docx",
  pptx: "python-pptx", telegram: "python-telegram-bot", discord: "discord-py", serial: "pyserial", usb: "pyusb",
  git: "gitpython", fitz: "pymupdf", attr: "attrs", zmq: "pyzmq", multipart: "python-multipart", slugify: "python-slugify",
  socketio: "python-socketio", engineio: "python-engineio", Levenshtein: "levenshtein", google: "protobuf",
  win32api: "pywin32", win32con: "pywin32", gi: "pygobject", Bio: "biopython", sentence_transformers: "sentence-transformers",
};

export async function pyImports(files: FileEntry[], text: (rel: string) => Promise<string | null>): Promise<ImportRef[]> {
  const local = new Set<string>();
  for (const f of files) {
    const parts = f.rel.split("/");
    parts.slice(0, -1).forEach((d) => local.add(d));
    if (f.rel.endsWith(".py")) local.add(parts[parts.length - 1]!.slice(0, -3));
  }
  const out: ImportRef[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    if (f.build || !f.rel.endsWith(".py")) continue;
    const t = await text(f.rel);
    if (!t) continue;
    for (const m of t.matchAll(/^[ \t]*(?:from[ \t]+([A-Za-z_][\w.]*)[ \t]+import\b|import[ \t]+([A-Za-z_][\w.]*(?:[ \t]*,[ \t]*[A-Za-z_][\w.]*)*))/gm)) {
      const names = m[1] ? [m[1]] : m[2]!.split(",").map((x) => x.trim().split(/\s+/)[0]!);
      for (const full of names) {
        const top = full.split(".")[0]!;
        if (PY_STDLIB.has(top) || local.has(top) || seen.has(top)) continue;
        seen.add(top);
        const mapped = PY_IMPORT_MAP[top];
        out.push({ ecosystem: "PyPI", name: normalizePyName(mapped ?? top), file: f.rel, line: lineAt(t, m.index), lookup: mapped !== undefined });
      }
    }
  }
  return out;
}
