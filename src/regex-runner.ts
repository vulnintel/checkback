import { Worker } from "node:worker_threads";

// Template regexes are user input (imported YAML) and may backtrack catastrophically. They run
// only in a worker thread; a watchdog terminates the worker when one rule×file exceeds the limit
// (spec §10-2). No native dependency (O4: worker_threads + time limit, RE2 not adopted).

export const RULE_FILE_LIMIT_MS = 100;
export const RULE_TOTAL_LIMIT_MS = 5000;
const MAX_MATCHES = 100; // per rule×file

export interface RegexSpec {
  match: string[];
  review: string[];
  allow: string[];
}

export interface RawMatch {
  index: number;
  value: string;
  /** A `review` regex matched the line(s) of this match. */
  review: boolean;
}

export interface RunResult {
  matches: Map<number, RawMatch[]>;
  ms: Map<number, number>;
  timedOut: number[];
}

// Runs as a CommonJS eval worker so it works the same from src (tests) and dist.
const WORKER_SRC = `
const { parentPort, workerData } = require("node:worker_threads");
const st = new Int32Array(workerData.shared);
const rules = workerData.specs.map((s) => ({
  match: s.match.map((p) => new RegExp(p, "gm")),
  review: s.review.map((p) => new RegExp(p, "m")),
  allow: s.allow.map((p) => new RegExp(p, "m")),
}));
function lineOf(t, start, end) {
  const s = t.lastIndexOf("\\n", start - 1) + 1;
  let e = t.indexOf("\\n", Math.max(start, end - 1));
  if (e < 0) e = t.length;
  return t.slice(s, e);
}
parentPort.on("message", ({ text, idxs }) => {
  const out = [];
  for (const k of idxs) {
    Atomics.store(st, 0, k + 1);
    Atomics.add(st, 1, 1);
    const t0 = performance.now();
    const r = rules[k];
    const found = [];
    outer: for (const re of r.match) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (m[0] === "") { re.lastIndex++; continue; }
        const ctx = r.review.length || r.allow.length ? lineOf(text, m.index, m.index + m[0].length) : "";
        if (!r.allow.some((a) => a.test(ctx))) {
          found.push({ index: m.index, value: m[0], review: r.review.some((v) => v.test(ctx)) });
        }
        if (found.length >= ${MAX_MATCHES}) break outer;
      }
    }
    out.push([k, found, performance.now() - t0]);
  }
  Atomics.store(st, 0, 0);
  parentPort.postMessage(out);
});
`;

type Once = { done: [number, RawMatch[], number][] } | { failedAt: number };

export class RegexRunner {
  private worker: Worker | undefined;
  private readonly shared = new SharedArrayBuffer(8);
  private readonly state = new Int32Array(this.shared); // [current rule + 1 (0 = idle), start counter]

  constructor(
    private readonly specs: RegexSpec[],
    private readonly limitMs = RULE_FILE_LIMIT_MS,
  ) {}

  /** Run rules `idxs` over `text`. A rule that times out (or throws) is skipped for this text only. */
  async run(text: string, idxs: number[]): Promise<RunResult> {
    const res: RunResult = { matches: new Map(), ms: new Map(), timedOut: [] };
    let pending = idxs;
    while (pending.length > 0) {
      const r = await this.once(text, pending);
      if ("done" in r) {
        for (const [k, found, ms] of r.done) {
          res.matches.set(k, found);
          res.ms.set(k, ms);
        }
        break;
      }
      // Results of rules that finished before the kill were lost with the worker; rerun them.
      res.timedOut.push(r.failedAt);
      res.ms.set(r.failedAt, this.limitMs);
      pending = pending.filter((k) => k !== r.failedAt);
    }
    return res;
  }

  close(): void {
    void this.worker?.terminate();
    this.worker = undefined;
  }

  private spawn(): Worker {
    if (!this.worker) {
      Atomics.store(this.state, 0, 0);
      this.worker = new Worker(WORKER_SRC, { eval: true, workerData: { specs: this.specs, shared: this.shared } });
      this.worker.unref();
    }
    return this.worker;
  }

  private once(text: string, idxs: number[]): Promise<Once> {
    const w = this.spawn();
    return new Promise((resolve) => {
      let lastSeq = Atomics.load(this.state, 1);
      let lastAt = Date.now();
      const finish = (r: Once, kill: boolean): void => {
        clearInterval(timer);
        w.off("message", onMessage);
        w.off("error", onFail);
        w.off("exit", onFail);
        if (kill) this.close();
        resolve(r);
      };
      const current = (): number => {
        const cur = Atomics.load(this.state, 0);
        return cur > 0 ? cur - 1 : idxs[0]!;
      };
      const onMessage = (done: [number, RawMatch[], number][]): void => finish({ done }, false);
      const onFail = (): void => finish({ failedAt: current() }, true);
      const timer = setInterval(() => {
        const seq = Atomics.load(this.state, 1);
        if (seq !== lastSeq) {
          lastSeq = seq;
          lastAt = Date.now();
        } else if (Atomics.load(this.state, 0) !== 0 && Date.now() - lastAt > this.limitMs) {
          finish({ failedAt: current() }, true);
        }
      }, 10);
      w.on("message", onMessage);
      w.on("error", onFail);
      w.on("exit", onFail);
      w.postMessage({ text, idxs });
    });
  }
}

/**
 * Import-time check (§10-2): every pattern must finish within the limit on a 1KB random sample and
 * on a pathological `aaaa…!` input. Returns the offending pattern or null.
 */
export async function findSlowPattern(patterns: string[]): Promise<string | null> {
  if (patterns.length === 0) return null;
  const runner = new RegexRunner(patterns.map((p) => ({ match: [p], review: [], allow: [] })));
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.:/=\"'\n{}[]()@";
  let sample = "";
  for (let i = 0; i < 1024; i++) sample += chars[Math.floor(Math.random() * chars.length)];
  try {
    for (const text of [sample, `${"a".repeat(10_000)}!`]) {
      const r = await runner.run(text, patterns.map((_, i) => i));
      if (r.timedOut.length > 0) return patterns[r.timedOut[0]!]!;
    }
    return null;
  } finally {
    runner.close();
  }
}
