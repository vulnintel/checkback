import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

/** The OS command that opens `url` in the default browser: an argument array, never a shell string. */
export function browserCommand(url: string, platform: NodeJS.Platform = process.platform): [string, string[]] {
  // rundll32 hands the URL to the default handler without cmd.exe parsing (no `start`, no quoting rules).
  if (platform === "win32") return ["rundll32.exe", ["url.dll,FileProtocolHandler", url]];
  if (platform === "darwin") return ["open", [url]];
  return ["xdg-open", [url]];
}

/**
 * A 0600 page (in a fresh 0700 temp folder) that redirects to `url`. On Linux/macOS other local users
 * can read process arguments (/proc/<pid>/cmdline, ps), so the browser gets this file path instead of
 * the tokened URL. The URL is ours (`http://127.0.0.1:<port>/#t=<hex>`), nothing to escape.
 */
export function redirectFile(url: string): string {
  const file = join(mkdtempSync(join(tmpdir(), "checkback-open-")), "open.html");
  writeFileSync(file, `<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="0;url=${url}"><title>checkback</title><a href="${url}">checkback</a>\n`, { mode: 0o600 });
  return file;
}

/** Best effort: the URL is printed in the terminal anyway (§10-1). */
export function openBrowser(url: string): void {
  let target = url;
  if (process.platform !== "win32") {
    try {
      target = redirectFile(url);
      // The token dies with this process anyway; remove the page once the browser has had time to load it.
      setTimeout(() => rmSync(dirname(target), { recursive: true, force: true }), 5 * 60_000).unref();
    } catch {
      target = url;
    }
  }
  const [cmd, args] = browserCommand(target);
  try {
    const p = spawn(cmd, args, { detached: true, stdio: "ignore", shell: false, windowsHide: true });
    p.on("error", () => {});
    p.unref();
  } catch {
    // ignore — the URL is in the terminal
  }
}
