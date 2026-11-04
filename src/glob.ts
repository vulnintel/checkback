// Minimal glob matcher for CWD-relative "/"-separated paths.
// Supports `**`, `*`, `?`, `{a,b}`, `[...]`/`[!...]`. A pattern without "/" matches the
// basename at any depth (gitignore-style); with "/" it is anchored at the CWD root.

export class GlobError extends Error {}

/** Normalize a template glob; throws GlobError for absolute paths or ".." segments. */
export function normalizeGlob(raw: string): string {
  let g = raw.replace(/\\/g, "/");
  if (g.length === 0 || g.length > 200) throw new GlobError("glob must be 1-200 characters");
  if (g.startsWith("/") || /^[A-Za-z]:/.test(g) || g.startsWith("~")) {
    throw new GlobError(`absolute path not allowed: ${raw}`);
  }
  while (g.startsWith("./")) g = g.slice(2);
  if (g.split("/").some((s) => s === "..")) throw new GlobError(`".." not allowed: ${raw}`);
  return g;
}

const cache = new Map<string, RegExp>();

export function globToRegExp(glob: string): RegExp {
  let re = cache.get(glob);
  if (!re) {
    const body = convert(glob);
    re = new RegExp(`^${glob.includes("/") ? "" : "(?:.*/)?"}${body}$`);
    cache.set(glob, re);
  }
  return re;
}

export function matchGlob(glob: string, path: string): boolean {
  return globToRegExp(glob).test(path);
}

export function matchAny(globs: readonly string[], path: string): boolean {
  return globs.some((g) => matchGlob(g, path));
}

function convert(g: string): string {
  let out = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i]!;
    if (c === "*") {
      if (g[i + 1] === "*") {
        const segStart = i === 0 || g[i - 1] === "/";
        i++;
        if (segStart && g[i + 1] === "/") {
          i++;
          out += "(?:.*/)?";
        } else {
          out += ".*";
        }
      } else {
        out += "[^/]*";
      }
    } else if (c === "?") {
      out += "[^/]";
    } else if (c === "{") {
      const end = closing(g, i);
      if (end < 0) {
        out += "\\{";
        continue;
      }
      out += `(?:${splitTop(g.slice(i + 1, end)).map(convert).join("|")})`;
      i = end;
    } else if (c === "[") {
      const end = g.indexOf("]", i + 2);
      if (end < 0) {
        out += "\\[";
        continue;
      }
      let cls = g.slice(i + 1, end);
      const neg = cls.startsWith("!") || cls.startsWith("^");
      if (neg) cls = cls.slice(1);
      out += `[${neg ? "^/" : ""}${cls.replace(/[\\\]^]/g, "\\$&")}]`;
      i = end;
    } else {
      out += c.replace(/[.+^$()|\\\]]/g, "\\$&");
    }
  }
  return out;
}

function closing(g: string, open: number): number {
  let depth = 0;
  for (let i = open; i < g.length; i++) {
    if (g[i] === "{") depth++;
    else if (g[i] === "}" && --depth === 0) return i;
  }
  return -1;
}

function splitTop(s: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "{") depth++;
    else if (s[i] === "}") depth--;
    else if (s[i] === "," && depth === 0) {
      parts.push(s.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(s.slice(start));
  return parts;
}
