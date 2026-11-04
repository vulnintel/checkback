import { spawn } from "node:child_process";

/** The OS command that opens `url` in the default browser: an argument array, never a shell string. */
export function browserCommand(url: string, platform: NodeJS.Platform = process.platform): [string, string[]] {
  // rundll32 hands the URL to the default handler without cmd.exe parsing (no `start`, no quoting rules).
  if (platform === "win32") return ["rundll32.exe", ["url.dll,FileProtocolHandler", url]];
  if (platform === "darwin") return ["open", [url]];
  return ["xdg-open", [url]];
}

/** Best effort: the URL is printed in the terminal anyway (§10-1). */
export function openBrowser(url: string): void {
  const [cmd, args] = browserCommand(url);
  try {
    const p = spawn(cmd, args, { detached: true, stdio: "ignore", shell: false, windowsHide: true });
    p.on("error", () => {});
    p.unref();
  } catch {
    // ignore — the URL is in the terminal
  }
}
