import { open, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";

// §8-5: all api.vulnintelapp.com calls from one machine share a sliding 60-second window of
// at most 50 calls, stored in `<appdata>/checkback/vi-bucket.json` under a lock file so the GUI
// and MCP processes count together. Priority: polling (≤20/min) > key calls > public lookups.

export const VI_LIMIT_PER_MIN = 50;
const POLL_LIMIT_PER_MIN = 20;
/** Slots public lookups leave free for polling/key calls when a key is configured. */
const KEY_RESERVE = 20;
const WINDOW_MS = 60_000;

export type CallKind = "poll" | "key" | "public";
interface State {
  calls: { t: number; k: CallKind }[];
  blocked_until: number;
}

export class ViBudget {
  constructor(
    private readonly appDir: string,
    private readonly opts: { now?: () => number; keyMode?: boolean; limit?: number } = {},
  ) {}

  private get file(): string {
    return join(this.appDir, "vi-bucket.json");
  }

  /** Take one call slot without waiting. False = over budget (caller marks the work "not checked yet"). */
  take(kind: CallKind): Promise<boolean> {
    return this.locked((s, now) => {
      if (now < s.blocked_until) return false;
      const limit = this.opts.limit ?? VI_LIMIT_PER_MIN;
      const used = s.calls.length;
      if (kind === "poll" && s.calls.filter((c) => c.k === "poll").length >= POLL_LIMIT_PER_MIN) return false;
      if (kind === "public" && this.opts.keyMode && used >= limit - KEY_RESERVE) return false;
      if (used >= limit) return false;
      s.calls.push({ t: now, k: kind });
      return true;
    });
  }

  /** On 429: no calls for a minute (§8 failure table). */
  block(ms = WINDOW_MS): Promise<void> {
    return this.locked((s, now) => {
      s.blocked_until = Math.max(s.blocked_until, now + ms);
    });
  }

  private async locked<T>(fn: (s: State, now: number) => T): Promise<T> {
    await mkdir(this.appDir, { recursive: true });
    const lock = join(this.appDir, "vi-bucket.lock");
    for (let i = 0; ; i++) {
      try {
        await (await open(lock, "wx")).close();
        break;
      } catch {
        // Stale lock from a crashed process.
        const st = await stat(lock).catch(() => null);
        if (st && Date.now() - st.mtimeMs > 10_000) await rm(lock, { force: true });
        if (i > 400) throw new Error("vi-bucket lock timeout");
        await new Promise((r) => setTimeout(r, 5));
      }
    }
    try {
      const now = (this.opts.now ?? Date.now)();
      let s: State = { calls: [], blocked_until: 0 };
      try {
        const raw = JSON.parse(await readFile(this.file, "utf8")) as State;
        if (Array.isArray(raw.calls)) s = { calls: raw.calls, blocked_until: Number(raw.blocked_until) || 0 };
      } catch {
        // fresh state
      }
      s.calls = s.calls.filter((c) => now - c.t < WINDOW_MS);
      const r = fn(s, now);
      await writeFile(this.file, JSON.stringify(s), { mode: 0o600 });
      return r;
    } finally {
      await rm(lock, { force: true });
    }
  }
}
