// Fixed user-facing texts shared by the MCP server and the CLI (§3-1, §11).

import type { Lang, ScanResult } from "./types.js";

export const DATA_TABLE: Record<Lang, string> = {
  ko: [
    "[데이터 전송] 코드·파일 경로는 어떤 서버로도 보내지 않습니다. 파일:줄은 아래 '사용자의 AI' 항목에만 들어갑니다.",
    "- api.osv.dev (취약 의존성·악성 패키지 검사): 외부 조회 대상 패키지의 생태계·이름·버전. 사설 패키지 이름은 보내지 않습니다.",
    "- registry.npmjs.org · api.npmjs.org · pypi.org (없는 패키지 검사): 외부 조회 대상 패키지 이름(lock에 없는 manifest 이름, 판별을 통과한 import 이름 포함).",
    "- api.vulnintelapp.com 공개 조회 (우선순위·설명, 키 불필요): OSV 결과의 CVE/GHSA ID와 화면 언어만. 요청 IP와 ID 목록이 서버 접근 로그에 남을 수 있고, ID 목록으로 사용 중인 취약 구성요소를 추정할 수 있습니다.",
    "- api.vulnintelapp.com 키 연동: 키를 넣은 경우에만(공개 패키지 SBOM, 조치 대장·감시 요청).",
    "- 사용자의 AI: 지시문과 이 도구의 응답(규칙·심각도·파일:줄·패키지·버전·취약점 ID). 비밀값 원문과 마스킹본은 넣지 않습니다.",
    "각 외부 조회는 설정에서 따로 끌 수 있습니다.",
  ].join("\n"),
  en: [
    "[Data transfer] Code and file paths are never sent to any server. File:line appears only in what goes to your AI (below).",
    "- api.osv.dev (vulnerable / malicious dependency check): ecosystem, name and version of packages in the lookup scope. Private package names are not sent.",
    "- registry.npmjs.org · api.npmjs.org · pypi.org (missing package check): names of packages in the lookup scope (incl. manifest names missing from the lock and filtered import names).",
    "- api.vulnintelapp.com public lookup (priority and descriptions, no key): only CVE/GHSA IDs from OSV results and the UI language. The request IP and ID list may stay in server access logs, and the ID list can hint at which vulnerable components you use.",
    "- api.vulnintelapp.com with a key: only if you add a key (public-package SBOM, remediation and watch requests).",
    "- Your AI: prompts and this tool's responses (rule, severity, file:line, package, version, vulnerability IDs). Secret values and masked values are never included.",
    "Each external lookup can be turned off separately in settings.",
  ].join("\n"),
  zh: [
    "[数据传输] 代码和文件路径绝不会发送到任何服务器。文件:行号只会出现在发给你的 AI 的内容中（见下文）。",
    "- api.osv.dev（有漏洞 / 恶意依赖检查）：查询范围内包的生态系统、名称和版本。不会发送私有包名。",
    "- registry.npmjs.org · api.npmjs.org · pypi.org（不存在的包检查）：查询范围内的包名（包括 lock 中没有的清单包名和经过筛选的 import 名称）。",
    "- api.vulnintelapp.com 公开查询（优先级和描述，无需密钥）：只发送 OSV 结果中的 CVE/GHSA ID 和界面语言。请求 IP 和 ID 列表可能留在服务器访问日志中，ID 列表可能暗示你在使用哪些有漏洞的组件。",
    "- api.vulnintelapp.com 密钥连接：仅在你添加密钥时（公开包的 SBOM、处置台账和订阅请求）。",
    "- 你的 AI：提示词和本工具的响应（规则、严重程度、文件:行号、包、版本、漏洞 ID）。绝不包含密钥原文和遮盖后的值。",
    "每项外部查询都可以在设置中单独关闭。",
  ].join("\n"),
};

export const CONSENT_HOWTO: Record<Lang, string> = {
  ko: "외부 조회는 아직 꺼져 있습니다(로컬 규칙만 실행). 켜려면 사람이 터미널에서 `npx checkback consent`를 실행하거나 `npx checkback` 화면에서 동의하세요.",
  en: "External lookups are off until consent (local rules only). To turn them on, a person runs `npx checkback consent` in a terminal or agrees in the `npx checkback` screen.",
  zh: "同意之前外部查询处于关闭状态（仅运行本地规则）。如需开启，请由人在终端运行 `npx checkback consent`，或在 `npx checkback` 页面中同意。",
};

export const KEY_NOTICE: Record<Lang, string> = {
  ko: "이 프로젝트 패키지에 새 취약점이 생기면 알려드릴까요? VulnIntel 무료 키 연결은 `npx checkback` 화면에서 → https://www.vulnintelapp.com/ko/settings/api-keys?src=checkback",
  en: "Want to hear when a new vulnerability hits this project's packages? Connect a free VulnIntel key in the `npx checkback` screen → https://www.vulnintelapp.com/en/settings/api-keys?src=checkback",
  zh: "想在此项目的依赖包出现新漏洞时收到通知吗？在 `npx checkback` 页面中连接免费的 VulnIntel 密钥 → https://www.vulnintelapp.com/zh/settings/api-keys?src=checkback",
};

export const DISCLAIMER: Record<Lang, string> = {
  ko: "통과는 '안전'이 아닙니다. 이 도구가 아는 실수만 찾습니다. AI 판단은 실행마다 다를 수 있고 틀릴 수 있습니다.\n취약점 데이터: OSV.dev(소스별 라이선스, 악성 패키지: OpenSSF Malicious Packages) · 우선순위: VulnIntel(KEV: CISA, EPSS: FIRST.org)",
  en: "Passing is not 'safe'. This tool only finds the mistakes it knows. AI judgments can differ between runs and can be wrong.\nVulnerability data: OSV.dev (per-source licenses; malicious packages: OpenSSF Malicious Packages) · Priority: VulnIntel (KEV: CISA, EPSS: FIRST.org)",
  zh: "通过检查不等于“安全”。本工具只能发现它已知的错误。AI 的判断每次运行可能不同，也可能出错。\n漏洞数据：OSV.dev（各来源许可证；恶意包：OpenSSF Malicious Packages）· 优先级：VulnIntel（KEV：CISA，EPSS：FIRST.org）",
};

export function osLang(locale = Intl.DateTimeFormat().resolvedOptions().locale): Lang {
  const l = locale.toLowerCase();
  return l.startsWith("ko") ? "ko" : l.startsWith("zh") ? "zh" : "en";
}

/** One line about the key-mode VulnIntel scan (§8 failure table), or null. */
export function viNotice(s: import("./builtins/vi-scan.js").ViScanStatus | undefined, lang: Lang): string | null {
  if (!s) return null;
  const L = (t: Record<Lang, string>): string => t[lang];
  if (s.status === "ok" || s.status === "cached")
    return s.history_url ? L({ ko: `VulnIntel 결과(웹 이력): ${s.history_url}`, en: `VulnIntel result (web history): ${s.history_url}`, zh: `VulnIntel 结果（网页历史）：${s.history_url}` }) : null;
  if (s.status === "pending")
    return L({
      ko: "VulnIntel 판정이 진행 중입니다 — 다시 scan하면 이어서 받습니다(이번 결과는 OSV 기준).",
      en: "The VulnIntel check is still running — scan again to pick it up (this result uses OSV).",
      zh: "VulnIntel 判定仍在进行中 — 再次 scan 即可接着获取（本次结果基于 OSV）。",
    });
  if (s.reason === "invalid_key")
    return L({
      ko: "VulnIntel 키가 유효하지 않습니다 — OSV 결과로 표시합니다. 감시 켜기·조치 대장은 쓸 수 없습니다.",
      en: "The VulnIntel key is invalid — showing OSV results. Watch and remediation tracking are unavailable.",
      zh: "VulnIntel 密钥无效 — 显示 OSV 结果。无法使用订阅和处置台账。",
    });
  if (s.reason === "quota_exceeded" || s.reason === "quota_blocked") {
    const reset = s.quota_reset ? L({ ko: ` 초기화: ${s.quota_reset}`, en: ` Resets: ${s.quota_reset}`, zh: ` 重置时间：${s.quota_reset}` }) : "";
    return L({
      ko: `이번 달 무료 판정 100건을 다 썼습니다 — OSV 결과로 표시합니다.${reset}`,
      en: `This month's 100 free checks are used up — showing OSV results.${reset}`,
      zh: `本月 100 次免费判定已用完 — 显示 OSV 结果。${reset}`,
    });
  }
  const reason = s.reason ?? "error";
  return L({
    ko: `VulnIntel 조회 실패(${reason}) — OSV 결과로 표시합니다.`,
    en: `VulnIntel lookup failed (${reason}) — showing OSV results.`,
    zh: `VulnIntel 查询失败（${reason}）— 显示 OSV 结果。`,
  });
}

export const PARTIAL_NOTICE: Record<Lang, string> = {
  ko: "일부 외부 조회는 시간 안에 끝내지 못해 다음 scan에서 이어서 합니다(결과는 캐시로 이어짐).",
  en: "Some external lookups did not finish in time; the next scan continues them (results are cached).",
  zh: "部分外部查询未能按时完成，下次 scan 会继续（结果已缓存）。",
};

export const OFFLINE_NOTICE: Record<Lang, string> = {
  ko: "외부 조회에 실패해 의존성 검사 일부를 하지 못했습니다(오프라인 또는 서비스 오류). 취약 의존성이 빠졌을 수 있으니 네트워크를 확인하고 다시 scan하세요.",
  en: "An external lookup failed, so part of the dependency check did not run (offline or service error). Vulnerable dependencies may be missing; check the network and scan again.",
  zh: "外部查询失败，部分依赖检查没有运行（离线或服务错误）。可能漏掉了有漏洞的依赖，请检查网络后重新 scan。",
};

export const SHALLOW_NOTICE: Record<Lang, string> = {
  ko: "git 이력 검사 일부 생략(shallow clone): 이력에만 남은 .env·키 파일은 보지 못했습니다. 전체 이력으로 검사하려면 `git fetch --unshallow` 후 다시 scan하세요(CI는 fetch-depth: 0).",
  en: "Git history check partly skipped (shallow clone): .env and key files left only in history were not seen. Run `git fetch --unshallow` and scan again (in CI: fetch-depth: 0).",
  zh: "部分跳过 git 历史检查（浅克隆）：只存在于历史中的 .env 和密钥文件没有被检查。请运行 `git fetch --unshallow` 后重新 scan（CI 中设置 fetch-depth: 0）。",
};

/** Folders that hold their own git repository (a `.git` directory) are separate projects and are not scanned. */
export function nestedRepoNotice(paths: string[], lang: Lang): string | null {
  if (!paths.length) return null;
  const more = paths.length - 3;
  const shown = paths.slice(0, 3).join(", ") + (more > 0 ? { ko: ` 외 ${more}곳`, en: ` and ${more} more`, zh: ` 等另外 ${more} 处` }[lang] : "");
  return {
    ko: `하위 폴더의 별도 git 저장소는 검사하지 않았습니다: ${shown}. 그 폴더에서 따로 scan하세요.`,
    en: `Separate git repositories in subfolders were not scanned: ${shown}. Scan them from their own folder.`,
    zh: `未扫描子文件夹中独立的 git 仓库：${shown}。请在各自的文件夹中单独 scan。`,
  }[lang];
}

/** Notices about what this scan could not fully check — the same lines in the CLI report, the GUI and MCP. */
export function scanNotices(r: ScanResult, lang: Lang): string[] {
  const has = (reason: string): boolean => r.checked.some((c) => c.reason === reason);
  const vi = viNotice(r.vulnintel, lang);
  const partial = has("timeout_partial") || r.findings.some((f) => f.notes?.includes("priority_pending"));
  const nested = nestedRepoNotice(r.stats.nested_repos ?? [], lang);
  return [
    ...(has("offline") ? [OFFLINE_NOTICE[lang]] : []),
    ...(partial ? [PARTIAL_NOTICE[lang]] : []),
    ...(vi ? [vi] : []),
    ...(has("shallow_clone") ? [SHALLOW_NOTICE[lang]] : []),
    ...(nested ? [nested] : []),
  ];
}
