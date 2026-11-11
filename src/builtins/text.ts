import type { LocalizedText } from "../types.js";

// Titles, plain-language descriptions and fix instructions for builtin judgments (§7-1~7-3).
// Fix texts follow §6-3: no install/add instructions, no alternative package names.

export interface KindText {
  title: LocalizedText;
  description: LocalizedText;
  fix: LocalizedText;
  /** Dependency items whose lock is a uv.lock: the uv commands that regenerate it. */
  fixUv?: LocalizedText;
  /** "Human first" step for the fix prompt (key rotation etc.). */
  human?: LocalizedText;
}

const LOCK_RULE = {
  ko: "패키지 매니저 명령으로 버전을 올려 lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.",
  en: "Upgrade with your package manager so it regenerates the lock file. Do not edit the lock file by hand.",
};
// §6-3: `uv add` only for a package pyproject.toml already declares (a version bump, not a new package).
const UV_RULE = {
  ko: 'uv 프로젝트입니다. pyproject.toml에 이미 선언된 패키지면 `uv add "{package}>={fixed_version}"`로 하한을 올리고, 다른 패키지를 통해 들어온 패키지면 `uv lock --upgrade-package {package}`로 uv.lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.',
  en: 'This is a uv project. If pyproject.toml already declares the package, raise its lower bound with `uv add "{package}>={fixed_version}"`; if it comes in through another package, run `uv lock --upgrade-package {package}` to regenerate uv.lock. Do not edit the lock file by hand.',
};

export const BUILTIN_NAMES: Record<string, LocalizedText> = {
  "supabase-rls": { ko: "Supabase 접근 규칙", en: "Supabase access rules" },
  "firebase-rules": { ko: "Firebase 보안 규칙", en: "Firebase security rules" },
  "hallucinated-package": { ko: "없는·악성 패키지", en: "Missing or malicious package" },
  "vulnerable-deps": { ko: "취약한 의존성", en: "Vulnerable dependency" },
};

export const KIND_TEXT: Record<string, KindText> = {
  // ---- supabase-rls
  "supabase-rls/service_role_client": {
    title: { ko: "브라우저 코드에서 Supabase 서비스 키 사용", en: "Supabase service key used in browser code" },
    description: {
      ko: "브라우저로 가는 코드가 service_role(또는 secret) 키 환경변수를 읽습니다. 이 키는 RLS를 무시하고 DB 전체를 다룹니다.",
      en: "Code that ships to the browser reads the service_role (or secret) key variable. That key bypasses RLS and controls the whole database.",
    },
    fix: {
      ko: "이 키를 쓰는 코드를 서버 쪽(API 라우트·서버 함수)으로 옮기고, 브라우저에서는 anon/publishable 키만 쓰세요.",
      en: "Move the code that uses this key to the server side (API route or server function); the browser should only use the anon/publishable key.",
    },
    human: { ko: "키 값이 배포된 적이 있으면 Supabase에서 키를 폐기하고 새로 발급하세요.", en: "If the key was ever deployed, revoke and reissue it in Supabase." },
  },
  "supabase-rls/rls_disabled": {
    title: { ko: "RLS가 꺼진 테이블", en: "Table without Row Level Security" },
    description: {
      ko: "저장소 마이그레이션 기준으로 이 테이블에 행 수준 보안(RLS)이 켜져 있지 않습니다. anon 키로 누구나 읽고 쓸 수 있습니다.",
      en: "According to the migrations in this repository, Row Level Security is not enabled on this table. Anyone with the anon key can read and write it.",
    },
    fix: {
      ko: "새 마이그레이션에서 이 테이블에 alter table ... enable row level security 를 추가하고, 필요한 접근만 허용하는 정책을 만드세요.",
      en: "In a new migration, add alter table ... enable row level security for this table and create policies that allow only the access you need.",
    },
  },
  "supabase-rls/always_true_write": {
    title: { ko: "항상 허용되는 쓰기 정책", en: "Write policy that always allows" },
    description: {
      ko: "insert/update/delete 정책 조건이 true라 누구나 데이터를 바꿀 수 있습니다.",
      en: "An insert/update/delete policy uses true as its condition, so anyone can change data.",
    },
    fix: {
      ko: "정책 조건을 auth.uid() 같은 실제 소유자 조건으로 바꾸는 새 마이그레이션을 만드세요.",
      en: "Write a new migration that replaces the condition with a real ownership check such as auth.uid().",
    },
  },
  "supabase-rls/public_read": {
    title: { ko: "모두 읽을 수 있는 정책", en: "Policy readable by everyone" },
    description: { ko: "select 정책이 using (true)입니다. 공개 읽기가 의도인지 확인하세요.", en: "A select policy uses using (true). Check that public read access is intended." },
    fix: { ko: "공개가 의도가 아니면 읽기 조건을 소유자 기준으로 좁히세요.", en: "If public read is not intended, restrict the condition to the owner." },
  },
  "supabase-rls/migrations_elsewhere": {
    title: { ko: "다른 곳의 SQL — 실제 적용 확인 필요", en: "SQL outside supabase/migrations — check it was applied" },
    description: {
      ko: "supabase/migrations 밖에 테이블·정책 SQL이 있습니다. 이 SQL이 실제로 적용됐는지 Security Advisor로 확인하세요.",
      en: "There is table/policy SQL outside supabase/migrations. Check in Security Advisor whether it was actually applied.",
    },
    fix: { ko: "Supabase 대시보드 Security Advisor에서 실제 DB 상태를 확인하세요.", en: "Check the real database state in the Supabase dashboard Security Advisor." },
  },
  "supabase-rls/dynamic_sql": {
    title: { ko: "동적 SQL 있음 — 판정 못 함", en: "Dynamic SQL — not judged" },
    description: { ko: "EXECUTE로 만드는 테이블·정책은 판정하지 못합니다. Advisor로 확인하세요.", en: "Tables and policies created via EXECUTE cannot be judged. Check with Advisor." },
    fix: { ko: "Supabase 대시보드 Security Advisor에서 확인하세요.", en: "Check with the Supabase dashboard Security Advisor." },
  },
  "supabase-rls/advisor": {
    title: { ko: "DB에서 직접 확인 필요", en: "Check the database directly" },
    description: {
      ko: "대시보드에서 만든 테이블, 뷰·함수 권한, 컬럼 권한은 저장소만 보고는 알 수 없습니다.",
      en: "Tables created in the dashboard, view/function and column permissions cannot be seen from the repository.",
    },
    fix: {
      ko: "Supabase 대시보드 → Security Advisor를 실행하세요 (https://supabase.com/docs/guides/database/database-advisors).",
      en: "Run Supabase dashboard → Security Advisor (https://supabase.com/docs/guides/database/database-advisors).",
    },
  },
  // ---- firebase-rules
  "firebase-rules/open_rules": {
    title: { ko: "누구나 읽고 쓸 수 있는 Firebase 규칙", en: "Firebase rules open to everyone" },
    description: { ko: "조건 없는 allow 또는 if true 규칙이라 누구나 데이터에 접근합니다.", en: "An unconditional allow or if true rule lets anyone access the data." },
    fix: { ko: "request.auth.uid로 소유자를 확인하는 조건으로 바꾸세요.", en: "Replace it with a condition that checks the owner via request.auth.uid." },
  },
  "firebase-rules/test_mode": {
    title: { ko: "Firebase 테스트 모드 규칙", en: "Firebase test-mode rules" },
    description: { ko: "만료일까지 누구나 접근할 수 있는 테스트 모드 규칙입니다.", en: "Test-mode rules let anyone access the data until the expiry date." },
    fix: { ko: "만료일 조건 대신 request.auth.uid 기반 규칙을 작성하세요.", en: "Replace the date condition with rules based on request.auth.uid." },
  },
  "firebase-rules/test_mode_expired": {
    title: { ko: "만료된 테스트 모드 규칙", en: "Expired test-mode rules" },
    description: { ko: "만료일이 지나 현재 전부 거부 상태입니다.", en: "The expiry date has passed; everything is currently denied." },
    fix: { ko: "실제 접근 규칙을 작성하세요.", en: "Write real access rules." },
  },
  "firebase-rules/auth_only": {
    title: { ko: "로그인만 확인하는 규칙", en: "Rule that only checks sign-in" },
    description: { ko: "로그인한 누구나 다른 사람의 데이터에 접근할 수 있는지 확인하세요.", en: "Check whether any signed-in user can reach other users' data." },
    fix: { ko: "request.auth.uid가 문서 소유자와 같은지 확인하는 조건을 더하세요.", en: "Add a condition that request.auth.uid matches the document owner." },
  },
  "firebase-rules/rtdb_open": {
    title: { ko: "Realtime Database 전체 공개", en: "Realtime Database fully open" },
    description: { ko: 'database.rules.json 루트가 ".read"/".write": true 입니다.', en: 'database.rules.json has ".read"/".write": true at the root.' },
    fix: { ko: "루트 공개를 지우고 경로별로 auth 조건을 거세요.", en: "Remove root-level access and add auth conditions per path." },
  },
  "firebase-rules/rules_missing": {
    title: { ko: "Firebase 규칙 파일 없음", en: "Firebase rules file missing" },
    description: { ko: "firebase.json은 있지만 규칙 파일이 저장소에 없습니다. 콘솔에서 규칙을 확인하세요.", en: "firebase.json exists but no rules file is in the repository. Check the rules in the console." },
    fix: { ko: "Firebase 콘솔에서 현재 규칙을 확인하세요.", en: "Check the current rules in the Firebase console." },
  },
  // ---- hallucinated-package
  "hallucinated-package/malicious": {
    title: { ko: "위험: 악성 패키지", en: "Danger: malicious package" },
    description: { ko: "이 패키지는 악성으로 등록되어 있습니다(OSV MAL- 또는 npm 보안 대체본).", en: "This package is registered as malicious (OSV MAL- or an npm security placeholder)." },
    fix: { ko: "manifest와 lock에서 이 패키지를 제거하세요.", en: "Remove this package from the manifest and the lock file." },
    human: {
      ko: "이 패키지를 설치한 기기에서 쓰던 키·토큰을 전부 교체하고, 설치한 기기를 점검하세요.",
      en: "Rotate every key and token used on machines that installed it, and check those machines.",
    },
  },
  "hallucinated-package/not_found": {
    title: { ko: "레지스트리에 없는 패키지 — AI가 지어낸 이름일 수 있음", en: "Package not in the registry — possibly an AI-invented name" },
    description: { ko: "이 이름은 레지스트리에 없습니다. 나중에 누군가 같은 이름으로 악성 패키지를 올릴 수 있습니다.", en: "This name does not exist in the registry. Someone could later publish a malicious package under it." },
    fix: { ko: "이 이름을 쓰지 말고, 필요한 기능은 사람이 공식 문서에서 확인한 패키지만 쓰세요.", en: "Do not use this name; only use packages a person has confirmed in official documentation." },
  },
  "hallucinated-package/removed": {
    title: { ko: "레지스트리에서 내려간 패키지", en: "Package removed from the registry" },
    description: { ko: "lock에는 공개 레지스트리 패키지로 있지만 지금은 레지스트리에 없습니다.", en: "The lock file lists it from the public registry, but it no longer exists there." },
    fix: { ko: "왜 내려갔는지 사람이 확인하고, 사용을 중단하세요.", en: "Have a person check why it was removed, and stop using it." },
  },
  "hallucinated-package/suspicious": {
    title: { ko: "인기 패키지와 비슷한 새 패키지", en: "New package with a name close to a popular one" },
    description: {
      ko: "인기 패키지와 철자가 한두 글자 다르고, 최근에 올라왔으며 다운로드가 적습니다. 오타를 노린 패키지일 수 있습니다.",
      en: "Its name differs by one or two letters from a popular package, it is new and rarely downloaded. It may be a typosquat.",
    },
    fix: { ko: "사람이 이름 철자와 공식 문서를 확인하기 전까지 쓰지 마세요.", en: "Do not use it until a person checks the spelling and the official documentation." },
  },
  "hallucinated-package/undeclared_import": {
    title: { ko: "의존성에 없는 import — 직접 확인", en: "Import not in dependencies — check it" },
    description: { ko: "코드가 import하지만 manifest·lock에 없는 이름입니다.", en: "The code imports a name that is not in the manifest or lock file." },
    fix: { ko: "이 import가 필요한지 사람이 확인하세요.", en: "Have a person check whether this import is needed." },
  },
  // ---- vulnerable-deps
  "vulnerable-deps/vulnerable": {
    title: { ko: "알려진 취약점이 있는 패키지", en: "Package with known vulnerabilities" },
    description: { ko: "이 버전에 공개된 취약점이 있습니다.", en: "This version has published vulnerabilities." },
    fix: {
      ko: `{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, lock: {lockfile}). ${LOCK_RULE.ko}`,
      en: `Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, lock: {lockfile}). ${LOCK_RULE.en}`,
    },
    fixUv: {
      ko: `{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, lock: {lockfile}). ${UV_RULE.ko}`,
      en: `Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, lock: {lockfile}). ${UV_RULE.en}`,
    },
  },
  "vulnerable-deps/vulnerable_no_fix": {
    title: { ko: "수정 버전이 없는 취약 패키지", en: "Vulnerable package without a fix" },
    description: { ko: "이 버전에 취약점이 있고 아직 수정 버전이 없습니다.", en: "This version is vulnerable and there is no fixed version yet." },
    fix: {
      ko: `수정 버전 없음 — {package} 사용 중단을 검토하세요(취약점: {vuln_ids}). ${LOCK_RULE.ko}`,
      en: `No fixed version — consider stopping use of {package} (vulnerabilities: {vuln_ids}). ${LOCK_RULE.en}`,
    },
    fixUv: {
      ko: `수정 버전 없음 — {package} 사용 중단을 검토하세요(취약점: {vuln_ids}). 이 uv 프로젝트는 pyproject.toml을 고친 뒤 \`uv lock\`으로 uv.lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.`,
      en: `No fixed version — consider stopping use of {package} (vulnerabilities: {vuln_ids}). In this uv project, edit pyproject.toml and run \`uv lock\` to regenerate uv.lock. Do not edit the lock file by hand.`,
    },
  },
  "vulnerable-deps/version_unknown": {
    title: { ko: "버전 미확인 — lock 파일 없음", en: "Versions unknown — no lock file" },
    description: { ko: "lock 파일이 없어 설치되는 버전을 알 수 없고, 취약점을 판정하지 못했습니다.", en: "Without a lock file the installed versions are unknown, so vulnerabilities could not be checked." },
    fix: {
      ko: `패키지 매니저로 설치해 lock 파일을 만들고 저장소에 커밋하세요(Python은 버전을 == 로 고정). lock 파일을 손으로 고치지 마세요.`,
      en: `Install with your package manager to create a lock file and commit it (pin Python versions with ==). Do not edit the lock file by hand.`,
    },
  },
  "vulnerable-deps/version_unpinned": {
    title: { ko: "버전이 고정되지 않음", en: "Versions not pinned" },
    description: { ko: "requirements 파일에 == 로 고정되지 않은 패키지가 있어 설치되는 버전을 알 수 없고, 그 패키지의 취약점을 판정하지 못했습니다.", en: "Some packages in this requirements file are not pinned with ==, so their installed versions are unknown and their vulnerabilities could not be checked." },
    fix: {
      ko: "{file}의 패키지 버전을 지금 쓰는 버전으로 == 고정하세요. 버전을 새로 고르거나 패키지를 추가하지 마세요.",
      en: "Pin the packages in {file} with == to the versions in use now. Do not pick new versions or add packages.",
    },
  },
  "vulnerable-deps/lock_unreadable": {
    title: { ko: "lock 파일을 읽지 못함 — 의존성 검사 안 됨", en: "Lock file could not be read — dependencies not checked" },
    description: { ko: "lock 파일이 깨졌거나(JSON·YAML·TOML 오류, 머지 충돌 표식) 지원하지 않는 형식 버전이라 설치 버전을 확인하지 못했고, 취약점을 판정하지 못했습니다.", en: "The lock file is broken (JSON/YAML/TOML error, merge conflict markers) or uses an unsupported format version, so installed versions and vulnerabilities could not be checked." },
    fix: {
      ko: "{file}에 머지 충돌 표식이 남아 있으면 정리한 뒤, 패키지 매니저로 다시 설치해 lock 파일을 새로 만드세요. lock 파일을 손으로 고치지 마세요.",
      en: "If {file} still has merge conflict markers, resolve them; then reinstall with your package manager so it writes a fresh lock file. Do not edit the lock file by hand.",
    },
  },
  "vulnerable-deps/lock_regenerate": {
    title: { ko: "오래된 lock 형식 — 의존성 검사 안 됨", en: "Old lock format — dependencies not checked" },
    description: { ko: "pnpm 7 이하가 만든 lock 형식(lockfileVersion 5.x 이하)은 읽지 못해 설치 버전과 취약점을 확인하지 못했습니다.", en: "Lock files written by pnpm 7 or earlier (lockfileVersion 5.x or older) cannot be read, so installed versions and vulnerabilities were not checked." },
    fix: {
      ko: "pnpm 8 이상으로 다시 설치해 {file}을 새로 만드세요. lock 파일을 손으로 고치지 마세요.",
      en: "Reinstall with pnpm 8 or later so it rewrites {file}. Do not edit the lock file by hand.",
    },
  },
  "vulnerable-deps/unsupported_lock": {
    title: { ko: "아직 지원하지 않는 lock 형식 — 버전 확인 안 됨", en: "Lock format not supported yet — versions not checked" },
    description: { ko: "이 lock 형식은 아직 읽지 못해 설치 버전과 취약점을 확인하지 못했습니다. 다음 릴리스에서 지원합니다.", en: "This lock format cannot be read yet, so installed versions and vulnerabilities were not checked. Support is planned for the next release." },
    fix: { ko: "다음 릴리스를 기다리거나 지원 형식(npm·pnpm·uv·requirements)으로 다시 검사하세요.", en: "Wait for the next release or check with a supported format (npm, pnpm, uv, requirements)." },
  },
};

export const LOCK_HAND_EDIT = LOCK_RULE;
