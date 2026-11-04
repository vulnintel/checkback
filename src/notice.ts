// Fixed user-facing texts shared by the MCP server and the CLI (§3-1, §11).

import type { Lang } from "./types.js";

export const DATA_TABLE: Record<Lang, string> = {
  ko: [
    "[데이터 전송] 코드·파일 경로는 어디로도 보내지 않습니다.",
    "- api.osv.dev (취약 의존성·악성 패키지 검사): 외부 조회 대상 패키지의 생태계·이름·버전. 사설 패키지 이름은 보내지 않습니다.",
    "- registry.npmjs.org · api.npmjs.org · pypi.org (없는 패키지 검사): 외부 조회 대상 패키지 이름(lock에 없는 manifest 이름, 판별을 통과한 import 이름 포함).",
    "- api.vulnintelapp.com 공개 조회 (우선순위·설명, 키 불필요): OSV 결과의 CVE/GHSA ID와 화면 언어만. 요청 IP와 ID 목록이 서버 접근 로그에 남을 수 있고, ID 목록으로 사용 중인 취약 구성요소를 추정할 수 있습니다.",
    "- api.vulnintelapp.com 키 연동: 키를 넣은 경우에만(공개 패키지 SBOM, 조치 대장·감시 요청).",
    "- 사용자의 AI: 지시문과 이 도구의 응답(규칙·심각도·파일:줄·패키지·버전·취약점 ID). 비밀값 원문과 마스킹본은 넣지 않습니다.",
    "각 외부 조회는 설정에서 따로 끌 수 있습니다.",
  ].join("\n"),
  en: [
    "[Data transfer] Code and file paths are never sent anywhere.",
    "- api.osv.dev (vulnerable / malicious dependency check): ecosystem, name and version of packages in the lookup scope. Private package names are not sent.",
    "- registry.npmjs.org · api.npmjs.org · pypi.org (missing package check): names of packages in the lookup scope (incl. manifest names missing from the lock and filtered import names).",
    "- api.vulnintelapp.com public lookup (priority and descriptions, no key): only CVE/GHSA IDs from OSV results and the UI language. The request IP and ID list may stay in server access logs, and the ID list can hint at which vulnerable components you use.",
    "- api.vulnintelapp.com with a key: only if you add a key (public-package SBOM, remediation and watch requests).",
    "- Your AI: prompts and this tool's responses (rule, severity, file:line, package, version, vulnerability IDs). Secret values and masked values are never included.",
    "Each external lookup can be turned off separately in settings.",
  ].join("\n"),
};

export const CONSENT_HOWTO: Record<Lang, string> = {
  ko: "외부 조회는 아직 꺼져 있습니다(로컬 규칙만 실행). 켜려면 사람이 터미널에서 `npx checkback consent`를 실행하거나 `npx checkback` 화면에서 동의하세요.",
  en: "External lookups are off until consent (local rules only). To turn them on, a person runs `npx checkback consent` in a terminal or agrees in the `npx checkback` screen.",
};

export const KEY_NOTICE: Record<Lang, string> = {
  ko: "이 프로젝트 패키지에 새 취약점이 생기면 알려드릴까요? VulnIntel 무료 키 연결은 `npx checkback` 화면에서 → https://www.vulnintelapp.com/ko/settings/api-keys?src=checkback",
  en: "Want to hear when a new vulnerability hits this project's packages? Connect a free VulnIntel key in the `npx checkback` screen → https://www.vulnintelapp.com/en/settings/api-keys?src=checkback",
};

export const DISCLAIMER: Record<Lang, string> = {
  ko: "통과는 '안전'이 아닙니다. 이 도구가 아는 실수만 찾습니다. AI 판단은 실행마다 다를 수 있고 틀릴 수 있습니다.\n취약점 데이터: OSV.dev(소스별 라이선스, 악성 패키지: OpenSSF Malicious Packages) · 우선순위: VulnIntel(KEV: CISA, EPSS: FIRST.org)",
  en: "Passing is not 'safe'. This tool only finds the mistakes it knows. AI judgments can differ between runs and can be wrong.\nVulnerability data: OSV.dev (per-source licenses; malicious packages: OpenSSF Malicious Packages) · Priority: VulnIntel (KEV: CISA, EPSS: FIRST.org)",
};

export function osLang(): Lang {
  return Intl.DateTimeFormat().resolvedOptions().locale.toLowerCase().startsWith("ko") ? "ko" : "en";
}

/** One line about the key-mode VulnIntel scan (§8 failure table), or null. */
export function viNotice(s: import("./builtins/vi-scan.js").ViScanStatus | undefined, lang: Lang): string | null {
  if (!s) return null;
  const ko = lang === "ko";
  if (s.status === "ok" || s.status === "cached") return s.history_url ? (ko ? `VulnIntel 결과(웹 이력): ${s.history_url}` : `VulnIntel result (web history): ${s.history_url}`) : null;
  if (s.status === "pending") return ko ? "VulnIntel 판정이 진행 중입니다 — 다시 scan하면 이어서 받습니다(이번 결과는 OSV 기준)." : "The VulnIntel check is still running — scan again to pick it up (this result uses OSV).";
  if (s.reason === "invalid_key") return ko ? "VulnIntel 키가 유효하지 않습니다 — OSV 결과로 표시합니다. 감시 켜기·조치 대장은 쓸 수 없습니다." : "The VulnIntel key is invalid — showing OSV results. Watch and remediation tracking are unavailable.";
  if (s.reason === "quota_exceeded" || s.reason === "quota_blocked") {
    const reset = s.quota_reset ? (ko ? ` 초기화: ${s.quota_reset}` : ` Resets: ${s.quota_reset}`) : "";
    return ko ? `이번 달 무료 판정 100건을 다 썼습니다 — OSV 결과로 표시합니다.${reset}` : `This month's 100 free checks are used up — showing OSV results.${reset}`;
  }
  return ko ? `VulnIntel 조회 실패(${s.reason ?? "error"}) — OSV 결과로 표시합니다.` : `VulnIntel lookup failed (${s.reason ?? "error"}) — showing OSV results.`;
}

export const PARTIAL_NOTICE: Record<Lang, string> = {
  ko: "일부 외부 조회는 시간 안에 끝내지 못해 다음 scan에서 이어서 합니다(결과는 캐시로 이어짐).",
  en: "Some external lookups did not finish in time; the next scan continues them (results are cached).",
};
