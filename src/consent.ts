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
      {
        ko: "consent는 사람이 터미널에서 직접 답해야 합니다(비대화형 실행 거부). 저장하지 않았습니다.\n",
        en: "consent must be answered by a person in a terminal (non-interactive run refused). Nothing was saved.\n",
        zh: "consent 必须由人在终端中亲自回答（已拒绝非交互式运行）。未保存任何内容。\n",
      }[lang],
    );
    return 1;
  }
  io.output.write(`${DATA_TABLE[lang]}\n\n`);
  const rl = createInterface({ input: io.input, output: io.output });
  const answer = await rl.question({ ko: "위 외부 조회에 동의합니까? [y/N] ", en: "Allow the external lookups above? [y/N] ", zh: "是否允许上述外部查询？[y/N] " }[lang]);
  rl.close();
  if (!/^\s*(y|yes|예|네|是|好)\s*$/i.test(answer)) {
    io.output.write({ ko: "동의하지 않았습니다. 로컬 규칙만 실행합니다.\n", en: "Not allowed. Only local rules will run.\n", zh: "未同意。只运行本地规则。\n" }[lang]);
    return 1;
  }
  await updateConfig(appDir, { consent: { at: new Date(now).toISOString(), version: CONSENT_VERSION } });
  io.output.write({ ko: "저장했습니다.\n", en: "Saved.\n", zh: "已保存。\n" }[lang]);
  return 0;
}
