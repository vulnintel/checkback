import { execFile } from "node:child_process";

// Repo-local config can name programs git would run (core.fsmonitor etc.); the scanned repo is
// untrusted, so turn those off. No shell is involved.
const SAFE = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.quotePath=false"];

function git(cwd: string, args: string[], input?: string): Promise<{ code: number; out: string }> {
  return new Promise((resolve) => {
    const child = execFile(
      "git",
      [...SAFE, ...args],
      { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, timeout: 120_000, windowsHide: true, env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" } },
      (err, stdout) => {
        const code = err ? (typeof err.code === "number" ? err.code : -1) : 0;
        resolve({ code, out: stdout ?? "" });
      },
    );
    if (input !== undefined) child.stdin?.end(input);
  });
}

const splitZ = (s: string): string[] => s.split("\0").filter(Boolean);

export interface GitInfo {
  isRepo: boolean;
  /** CWD-relative tracked paths. */
  tracked: Set<string>;
  /** Paths matching `pathspecs` that appear anywhere in history (all refs). */
  historyPaths(pathspecs: string[]): Promise<Set<string>>;
  /** Subset of `paths` that git would ignore. */
  ignored(paths: string[]): Promise<Set<string>>;
  /** Last content of `path` in history (any ref), or null. */
  lastHistoryContent(path: string): Promise<Buffer | null>;
}

export async function gitInfo(cwd: string): Promise<GitInfo> {
  const probe = await git(cwd, ["rev-parse", "--is-inside-work-tree"]);
  const isRepo = probe.code === 0 && probe.out.trim() === "true";
  const tracked = new Set<string>();
  if (isRepo) {
    const ls = await git(cwd, ["ls-files", "-z"]);
    for (const p of splitZ(ls.out)) tracked.add(p);
  }
  const historyCache = new Map<string, Set<string>>();
  return {
    isRepo,
    tracked,
    async historyPaths(pathspecs) {
      if (!isRepo || pathspecs.length === 0) return new Set();
      const key = pathspecs.join("\0");
      let hit = historyCache.get(key);
      if (!hit) {
        const r = await git(cwd, ["log", "--all", "--relative", "--name-only", "--format=", "-z", "--", ...pathspecs]);
        hit = new Set(splitZ(r.out).map((p) => p.replace(/^\n+/, "")));
        historyCache.set(key, hit);
      }
      return hit;
    },
    async ignored(paths) {
      if (!isRepo || paths.length === 0) return new Set();
      const r = await git(cwd, ["check-ignore", "-z", "--stdin"], paths.join("\0") + "\0");
      return new Set(splitZ(r.out));
    },
    async lastHistoryContent(path) {
      if (!isRepo) return null;
      const rev = await git(cwd, ["log", "--all", "-1", "--format=%H", "--diff-filter=AM", "--", path]);
      const sha = rev.out.trim();
      if (rev.code !== 0 || !/^[0-9a-f]{40,64}$/.test(sha)) return null;
      return new Promise((resolve) => {
        execFile(
          "git",
          [...SAFE, "show", `${sha}:./${path}`],
          { cwd, encoding: "buffer", maxBuffer: 16 * 1024 * 1024, timeout: 60_000, windowsHide: true },
          (err, stdout) => resolve(err ? null : stdout),
        );
      });
    },
  };
}

/** Template glob → git pathspecs with the same meaning (basename globs match at any depth; braces expanded). */
export function globToPathspecs(glob: string): string[] {
  return expandBraces(glob).map((g) => `:(glob)${g.includes("/") ? g : `**/${g}`}`);
}

function expandBraces(g: string): string[] {
  const m = /\{([^{}]*)\}/.exec(g);
  if (!m) return [g];
  return m[1]!.split(",").flatMap((alt) => expandBraces(g.slice(0, m.index) + alt + g.slice(m.index + m[0].length)));
}
