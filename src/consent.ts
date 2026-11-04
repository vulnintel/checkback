import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import { CONSENT_VERSION, updateConfig } from "./appdata.js";
import { DATA_TABLE } from "./notice.js";
import type { Lang } from "./types.js";

export interface ConsentIO {
  input: Readable;
  output: Writable;
  error: Writable;
  /** Both stdin and stdout are a terminal: a person is there to answer (§3-1). */
  interactive: boolean;
}

/** `checkback consent` — only a person at a terminal can turn external lookups on. Returns the exit code. */
export async function consentCommand(io: ConsentIO, appDir: string, lang: Lang, now = Date.now()): Promise<number> {
  if (!io.interactive) {
    io.error.write(
      lang === "ko"
        ? "consent는 사람이 터미널에서 직접 답해야 합니다(비대화형 실행 거부). 저장하지 않았습니다.\n"
        : "consent must be answered by a person in a terminal (non-interactive run refused). Nothing was saved.\n",
    );
    return 1;
  }
  io.output.write(`${DATA_TABLE[lang]}\n\n`);
  const rl = createInterface({ input: io.input, output: io.output });
  const answer = await rl.question(lang === "ko" ? "위 외부 조회에 동의합니까? [y/N] " : "Allow the external lookups above? [y/N] ");
  rl.close();
  if (!/^\s*(y|yes|예|네)\s*$/i.test(answer)) {
    io.output.write(lang === "ko" ? "동의하지 않았습니다. 로컬 규칙만 실행합니다.\n" : "Not allowed. Only local rules will run.\n");
    return 1;
  }
  await updateConfig(appDir, { consent: { at: new Date(now).toISOString(), version: CONSENT_VERSION } });
  io.output.write(lang === "ko" ? "저장했습니다.\n" : "Saved.\n");
  return 0;
}
