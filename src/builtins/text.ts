import type { Finding, FullText, Lang, LocalizedText } from "../types.js";

// Titles, plain-language descriptions and fix instructions for builtin judgments (§7-1~7-3).
// Fix texts follow §6-3: no install/add instructions, no alternative package names.
// Builtin texts are FullText: a missing language fails the build.

export interface KindText {
  title: FullText;
  description: FullText;
  fix: FullText;
  /** Dependency items whose lock is a uv.lock: the uv commands that regenerate it. */
  fixUv?: FullText;
  /** "Human first" step for the fix prompt (key rotation etc.). */
  human?: FullText;
  /** Description and fix naming the item's own {table} / {policy}; used when the finding carries `table`. */
  named?: { description: FullText; fix: FullText };
}

const LOCK_RULE: FullText = {
  ko: "패키지 매니저 명령으로 버전을 올려 lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.",
  en: "Upgrade with your package manager so it regenerates the lock file. Do not edit the lock file by hand.",
  zh: "请用包管理器命令升级版本，让它重新生成 lock 文件。不要手动修改 lock 文件。",
};
// §6-3: `uv add` only for a package pyproject.toml already declares (a version bump, not a new package).
const UV_RULE: FullText = {
  ko: 'uv 프로젝트입니다. pyproject.toml에 이미 선언된 패키지면 `uv add "{package}>={fixed_version}"`로 하한을 올리고, 다른 패키지를 통해 들어온 패키지면 `uv lock --upgrade-package {package}`로 uv.lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.',
  en: 'This is a uv project. If pyproject.toml already declares the package, raise its lower bound with `uv add "{package}>={fixed_version}"`; if it comes in through another package, run `uv lock --upgrade-package {package}` to regenerate uv.lock. Do not edit the lock file by hand.',
  zh: '这是 uv 项目。如果 pyproject.toml 已声明该包，请用 `uv add "{package}>={fixed_version}"` 提高其版本下限；如果它是通过其他包引入的，请运行 `uv lock --upgrade-package {package}` 重新生成 uv.lock。不要手动修改 lock 文件。',
};

/**
 * §6-3 dependency fix sentences chosen by the prompt generator from the lock's package manager and
 * how the package is declared (Finding.dependency). Commands only bump a package the manifest already
 * declares; a transitive package gets "upgrade the parent, else an override floor". {cmd} {manifest}
 * {section} {sel} {major} {why} {overrides} {install} are filled by the generator, never from free text.
 */
export const DEP_FIX = {
  upgrade: {
    ko: "{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, lock: {lockfile}).",
    en: "Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, lock: {lockfile}).",
    zh: "请将 {package} 升级到 {fixed_version} 或更高版本（漏洞：{vuln_ids}，lock：{lockfile}）。",
  },
  direct: {
    ko: "{manifest}의 {section}에 직접 선언된 패키지입니다. `{cmd}`로 버전을 올려 lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.",
    en: "{manifest} declares it directly in {section}. Raise it with `{cmd}` so the lock file is regenerated. Do not edit the lock file by hand.",
    zh: "{manifest} 在 {section} 中直接声明了它。请用 `{cmd}` 升级，让 lock 文件重新生成。不要手动修改 lock 文件。",
  },
  memberDir: {
    ko: "명령은 {manifest}가 있는 폴더에서 실행하세요.",
    en: "Run the command in the folder that holds {manifest}.",
    zh: "请在 {manifest} 所在的文件夹中运行该命令。",
  },
  uvTransitive: {
    ko: "다른 패키지를 통해 들어온 패키지입니다. `uv lock --upgrade-package {package}`로 uv.lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.",
    en: "It comes in through another package. Run `uv lock --upgrade-package {package}` to regenerate uv.lock. Do not edit the lock file by hand.",
    zh: "它是通过其他包引入的。请运行 `uv lock --upgrade-package {package}` 重新生成 uv.lock。不要手动修改 lock 文件。",
  },
  npmTransitive: {
    ko: 'package.json에 직접 선언되지 않고 다른 패키지를 통해 들어온 패키지입니다. 먼저 `{why}`로 이 패키지를 끌어온 상위 패키지를 찾아 그 상위 패키지를 올리세요. 그래도 {package} {major}.x가 {fixed_version} 미만으로 남으면 package.json의 `{overrides}`에 `"{sel}": "^{fixed_version}"`을 넣어 하한을 정하고 `{install}`로 lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.',
    en: 'package.json does not declare it; it comes in through another package. First find the parent package with `{why}` and upgrade that parent. If {package} {major}.x still stays below {fixed_version}, set a floor with `"{sel}": "^{fixed_version}"` under `{overrides}` in package.json and run `{install}` to regenerate the lock file. Do not edit the lock file by hand.',
    zh: 'package.json 没有直接声明它，它是通过其他包引入的。请先用 `{why}` 找到引入它的上层包，并升级那个上层包。如果 {package} {major}.x 仍低于 {fixed_version}，请在 package.json 的 `{overrides}` 中加入 `"{sel}": "^{fixed_version}"` 设定下限，然后运行 `{install}` 重新生成 lock 文件。不要手动修改 lock 文件。',
  },
  // Fixed version is in a later major: an override would force that major on parents that ask for this one.
  npmTransitiveMajor: {
    ko: "package.json에 직접 선언되지 않고 다른 패키지를 통해 들어온 패키지입니다. {major}.x 계열에는 수정 버전이 없습니다. `{why}`로 이 패키지를 끌어온 상위 패키지를 찾아, {package} {fixed_major}.x 이상을 쓰는 버전으로 올리거나 교체하세요. 메이저 버전을 overrides로 강제하면 상위 패키지가 깨질 수 있습니다. 상위 패키지를 올린 뒤 `{install}`로 lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.",
    en: "package.json does not declare it; it comes in through another package. The {major}.x line has no fixed version. Find the parent package with `{why}` and upgrade or replace it with a version that uses {package} {fixed_major}.x or later. Forcing a major version through overrides can break the parent package. After upgrading the parent, run `{install}` to regenerate the lock file. Do not edit the lock file by hand.",
    zh: "package.json 没有直接声明它，它是通过其他包引入的。{major}.x 系列没有修复版本。请用 `{why}` 找到引入它的上层包，把上层包升级或替换为使用 {package} {fixed_major}.x 或更高版本的版本。用 overrides 强制指定主版本可能会让上层包出错。升级上层包后，请运行 `{install}` 重新生成 lock 文件。不要手动修改 lock 文件。",
  },
  majorChange: {
    ko: "메이저 버전이 바뀌므로 변경 내역(breaking changes)을 확인하세요.",
    en: "This changes the major version, so check its breaking changes.",
    zh: "这会改变主版本，请查看其不兼容变更（breaking changes）。",
  },
  otherMajorsNoFix: {
    ko: "이 lock에는 {package}의 다른 메이저 버전도 있습니다. 이 항목은 {major}.x 계열에 대한 것이며, 그 계열에는 수정 버전이 없습니다.",
    en: "This lock also holds another major version of {package}. This item is about the {major}.x line, which has no fixed version.",
    zh: "此 lock 中还有 {package} 的其他主版本。本项针对的是 {major}.x 系列，该系列没有修复版本。",
  },
  otherMajors: {
    ko: "이 lock에는 {package}의 다른 메이저 버전도 있습니다. 이 항목은 {major}.x 계열에만 해당하니 그 계열의 하한만 올리세요.",
    en: "This lock also holds another major version of {package}. This item is about the {major}.x line only, so raise the floor of that line only.",
    zh: "此 lock 中还有 {package} 的其他主版本。本项只针对 {major}.x 系列，请只提高该系列的版本下限。",
  },
  requirements: {
    ko: "{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, 파일: {lockfile}). {lockfile}에서 {package}의 버전 지정을 {fixed_version} 이상으로 고치세요. pip-compile·uv export 같은 도구가 만든 파일이면 원본(.in 파일이나 pyproject.toml)을 고친 뒤 그 도구로 다시 만드세요.",
    en: "Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, file: {lockfile}). Change the version of {package} in {lockfile} to {fixed_version} or later. If a tool such as pip-compile or uv export writes this file, change its source (.in file or pyproject.toml) and regenerate it with that tool.",
    zh: "请将 {package} 升级到 {fixed_version} 或更高版本（漏洞：{vuln_ids}，文件：{lockfile}）。把 {lockfile} 中 {package} 的版本改为 {fixed_version} 或更高。如果该文件由 pip-compile、uv export 等工具生成，请修改其源文件（.in 文件或 pyproject.toml），再用该工具重新生成。",
  },
  requirementsNoFix: {
    ko: "수정 버전 없음 — {package} 사용 중단을 검토하세요(취약점: {vuln_ids}, 파일: {lockfile}). 그만 쓰기로 하면 {lockfile}에서 지우세요.",
    en: "No fixed version — consider stopping use of {package} (vulnerabilities: {vuln_ids}, file: {lockfile}). If you stop using it, remove it from {lockfile}.",
    zh: "暂无修复版本 — 请考虑停止使用 {package}（漏洞：{vuln_ids}，文件：{lockfile}）。如果决定不再使用，请从 {lockfile} 中删除。",
  },
} satisfies Record<string, FullText>;

export const BUILTIN_NAMES: Record<string, FullText> = {
  "supabase-rls": { ko: "Supabase 접근 규칙", en: "Supabase access rules", zh: "Supabase 访问规则" },
  "firebase-rules": { ko: "Firebase 보안 규칙", en: "Firebase security rules", zh: "Firebase 安全规则" },
  "hallucinated-package": { ko: "없는·악성 패키지", en: "Missing or malicious package", zh: "不存在或恶意的包" },
  "vulnerable-deps": { ko: "취약한 의존성", en: "Vulnerable dependency", zh: "有漏洞的依赖" },
};

export const KIND_TEXT: Record<string, KindText> = {
  // ---- supabase-rls
  "supabase-rls/service_role_client": {
    title: { ko: "브라우저 코드에서 Supabase 서비스 키 사용", en: "Supabase service key used in browser code", zh: "浏览器代码中使用了 Supabase 服务密钥" },
    description: {
      ko: "브라우저로 가는 코드가 service_role(또는 secret) 키 환경변수를 읽습니다. 이 키는 RLS를 무시하고 DB 전체를 다룹니다.",
      en: "Code that ships to the browser reads the service_role (or secret) key variable. That key bypasses RLS and controls the whole database.",
      zh: "会发送到浏览器的代码读取了 service_role（或 secret）密钥变量。该密钥会绕过 RLS，可以操作整个数据库。",
    },
    fix: {
      ko: "이 키를 쓰는 코드를 서버 쪽(API 라우트·서버 함수)으로 옮기고, 브라우저에서는 anon/publishable 키만 쓰세요.",
      en: "Move the code that uses this key to the server side (API route or server function); the browser should only use the anon/publishable key.",
      zh: "把使用该密钥的代码移到服务端（API 路由或服务端函数）；浏览器端只使用 anon/publishable 密钥。",
    },
    human: {
      ko: "키 값이 배포된 적이 있으면 Supabase에서 키를 폐기하고 새로 발급하세요.",
      en: "If the key was ever deployed, revoke and reissue it in Supabase.",
      zh: "如果该密钥曾被部署过，请在 Supabase 中吊销并重新签发。",
    },
  },
  "supabase-rls/rls_disabled": {
    title: { ko: "RLS가 꺼진 테이블", en: "Table without Row Level Security", zh: "未开启行级安全（RLS）的表" },
    description: {
      ko: "저장소 마이그레이션 기준으로 이 테이블에 행 수준 보안(RLS)이 켜져 있지 않습니다. anon 키로 누구나 읽고 쓸 수 있습니다.",
      en: "According to the migrations in this repository, Row Level Security is not enabled on this table. Anyone with the anon key can read and write it.",
      zh: "根据本仓库的迁移文件，这张表没有开启行级安全（RLS）。任何拿到 anon 密钥的人都能读写它。",
    },
    fix: {
      ko: "새 마이그레이션에서 이 테이블에 alter table ... enable row level security 를 추가하고, 필요한 접근만 허용하는 정책을 만드세요.",
      en: "In a new migration, add alter table ... enable row level security for this table and create policies that allow only the access you need.",
      zh: "在新的迁移中为这张表添加 alter table ... enable row level security，并创建只允许必要访问的策略。",
    },
    named: {
      description: {
        ko: "저장소 마이그레이션 기준으로 {table} 테이블에 행 수준 보안(RLS)이 켜져 있지 않습니다. anon 키로 누구나 읽고 쓸 수 있습니다.",
        en: "According to the migrations in this repository, Row Level Security is not enabled on the {table} table. Anyone with the anon key can read and write it.",
        zh: "根据本仓库的迁移文件，{table} 表没有开启行级安全（RLS）。任何拿到 anon 密钥的人都能读写它。",
      },
      fix: {
        ko: "새 마이그레이션에서 alter table {table} enable row level security 를 추가하고, {table} 테이블에 필요한 접근만 허용하는 정책을 만드세요.",
        en: "In a new migration, add alter table {table} enable row level security and create policies on {table} that allow only the access you need.",
        zh: "在新的迁移中添加 alter table {table} enable row level security，并在 {table} 上创建只允许必要访问的策略。",
      },
    },
  },
  "supabase-rls/always_true_write": {
    title: { ko: "항상 허용되는 쓰기 정책", en: "Write policy that always allows", zh: "始终放行的写入策略" },
    description: {
      ko: "insert/update/delete 정책 조건이 true라 누구나 데이터를 바꿀 수 있습니다.",
      en: "An insert/update/delete policy uses true as its condition, so anyone can change data.",
      zh: "某个 insert/update/delete 策略的条件是 true，任何人都能修改数据。",
    },
    fix: {
      ko: "정책 조건을 auth.uid() 같은 실제 소유자 조건으로 바꾸는 새 마이그레이션을 만드세요.",
      en: "Write a new migration that replaces the condition with a real ownership check such as auth.uid().",
      zh: "编写新的迁移，把该条件改成真正的所有者检查，例如 auth.uid()。",
    },
    named: {
      description: {
        ko: '{table} 테이블의 "{policy}" 정책 조건이 true라 누구나 데이터를 바꿀 수 있습니다(insert/update/delete).',
        en: 'The "{policy}" policy on {table} uses true as its insert/update/delete condition, so anyone can change data.',
        zh: '{table} 上的 "{policy}" 策略以 true 作为 insert/update/delete 条件，任何人都能修改数据。',
      },
      fix: {
        ko: '{table} 테이블의 "{policy}" 정책 조건을 auth.uid() 같은 실제 소유자 조건으로 바꾸는 새 마이그레이션을 만드세요.',
        en: 'Write a new migration that replaces the condition of the "{policy}" policy on {table} with a real ownership check such as auth.uid().',
        zh: '编写新的迁移，把 {table} 上 "{policy}" 策略的条件改成真正的所有者检查，例如 auth.uid()。',
      },
    },
  },
  "supabase-rls/public_read": {
    title: { ko: "모두 읽을 수 있는 정책", en: "Policy readable by everyone", zh: "所有人可读的策略" },
    description: {
      ko: "select 정책이 using (true)입니다. 공개 읽기가 의도인지 확인하세요.",
      en: "A select policy uses using (true). Check that public read access is intended.",
      zh: "某个 select 策略使用了 using (true)。请确认是否有意公开读取。",
    },
    fix: {
      ko: "공개가 의도가 아니면 읽기 조건을 소유자 기준으로 좁히세요.",
      en: "If public read is not intended, restrict the condition to the owner.",
      zh: "如果并非有意公开读取，请把条件限制为所有者。",
    },
    named: {
      description: {
        ko: '{table} 테이블의 "{policy}" select 정책이 using (true)입니다. 공개 읽기가 의도인지 확인하세요.',
        en: 'The "{policy}" select policy on {table} uses using (true). Check that public read access is intended.',
        zh: '{table} 上的 "{policy}" select 策略使用了 using (true)。请确认是否有意公开读取。',
      },
      fix: {
        ko: '공개가 의도가 아니면 {table} 테이블의 "{policy}" 정책 읽기 조건을 소유자 기준으로 좁히세요.',
        en: 'If public read is not intended, restrict the condition of the "{policy}" policy on {table} to the owner.',
        zh: '如果并非有意公开读取，请把 {table} 上 "{policy}" 策略的条件限制为所有者。',
      },
    },
  },
  "supabase-rls/migrations_elsewhere": {
    title: {
      ko: "다른 곳의 SQL — 실제 적용 확인 필요",
      en: "SQL outside supabase/migrations — check it was applied",
      zh: "supabase/migrations 之外的 SQL — 请确认是否已实际应用",
    },
    description: {
      ko: "supabase/migrations 밖에 테이블·정책 SQL이 있습니다. 이 SQL이 실제로 적용됐는지 Security Advisor로 확인하세요.",
      en: "There is table/policy SQL outside supabase/migrations. Check in Security Advisor whether it was actually applied.",
      zh: "supabase/migrations 之外有表或策略的 SQL。请在 Security Advisor 中确认它是否已实际应用。",
    },
    fix: {
      ko: "Supabase 대시보드 Security Advisor에서 실제 DB 상태를 확인하세요.",
      en: "Check the real database state in the Supabase dashboard Security Advisor.",
      zh: "请在 Supabase 控制台的 Security Advisor 中确认数据库的实际状态。",
    },
  },
  "supabase-rls/dynamic_sql": {
    title: { ko: "동적 SQL 있음 — 판정 못 함", en: "Dynamic SQL — not judged", zh: "动态 SQL — 无法判定" },
    description: {
      ko: "EXECUTE로 만드는 테이블·정책은 판정하지 못합니다. Advisor로 확인하세요.",
      en: "Tables and policies created via EXECUTE cannot be judged. Check with Advisor.",
      zh: "通过 EXECUTE 创建的表和策略无法判定。请用 Advisor 确认。",
    },
    fix: {
      ko: "Supabase 대시보드 Security Advisor에서 확인하세요.",
      en: "Check with the Supabase dashboard Security Advisor.",
      zh: "请在 Supabase 控制台的 Security Advisor 中确认。",
    },
  },
  "supabase-rls/advisor": {
    title: { ko: "DB에서 직접 확인 필요", en: "Check the database directly", zh: "请直接检查数据库" },
    description: {
      ko: "대시보드에서 만든 테이블, 뷰·함수 권한, 컬럼 권한은 저장소만 보고는 알 수 없습니다.",
      en: "Tables created in the dashboard, view/function and column permissions cannot be seen from the repository.",
      zh: "在控制台中创建的表、视图/函数权限和列权限，无法从仓库中看出。",
    },
    fix: {
      ko: "Supabase 대시보드 → Security Advisor를 실행하세요 (https://supabase.com/docs/guides/database/database-advisors).",
      en: "Run Supabase dashboard → Security Advisor (https://supabase.com/docs/guides/database/database-advisors).",
      zh: "请运行 Supabase 控制台 → Security Advisor（https://supabase.com/docs/guides/database/database-advisors）。",
    },
  },
  // ---- firebase-rules
  "firebase-rules/open_rules": {
    title: { ko: "누구나 읽고 쓸 수 있는 Firebase 규칙", en: "Firebase rules open to everyone", zh: "对所有人开放的 Firebase 规则" },
    description: {
      ko: "조건 없는 allow 또는 if true 규칙이라 누구나 데이터에 접근합니다.",
      en: "An unconditional allow or if true rule lets anyone access the data.",
      zh: "无条件的 allow 或 if true 规则让任何人都能访问数据。",
    },
    fix: {
      ko: "request.auth.uid로 소유자를 확인하는 조건으로 바꾸세요.",
      en: "Replace it with a condition that checks the owner via request.auth.uid.",
      zh: "改成通过 request.auth.uid 检查所有者的条件。",
    },
  },
  "firebase-rules/test_mode": {
    title: { ko: "Firebase 테스트 모드 규칙", en: "Firebase test-mode rules", zh: "Firebase 测试模式规则" },
    description: {
      ko: "만료일까지 누구나 접근할 수 있는 테스트 모드 규칙입니다.",
      en: "Test-mode rules let anyone access the data until the expiry date.",
      zh: "测试模式规则在到期日前允许任何人访问数据。",
    },
    fix: {
      ko: "만료일 조건 대신 request.auth.uid 기반 규칙을 작성하세요.",
      en: "Replace the date condition with rules based on request.auth.uid.",
      zh: "把日期条件换成基于 request.auth.uid 的规则。",
    },
  },
  "firebase-rules/test_mode_expired": {
    title: { ko: "만료된 테스트 모드 규칙", en: "Expired test-mode rules", zh: "已过期的测试模式规则" },
    description: {
      ko: "만료일이 지나 현재 전부 거부 상태입니다.",
      en: "The expiry date has passed; everything is currently denied.",
      zh: "已过到期日，目前所有访问都被拒绝。",
    },
    fix: { ko: "실제 접근 규칙을 작성하세요.", en: "Write real access rules.", zh: "请编写真正的访问规则。" },
  },
  "firebase-rules/auth_only": {
    title: { ko: "로그인만 확인하는 규칙", en: "Rule that only checks sign-in", zh: "只检查是否登录的规则" },
    description: {
      ko: "로그인한 누구나 다른 사람의 데이터에 접근할 수 있는지 확인하세요.",
      en: "Check whether any signed-in user can reach other users' data.",
      zh: "请确认任何已登录用户是否都能访问其他用户的数据。",
    },
    fix: {
      ko: "request.auth.uid가 문서 소유자와 같은지 확인하는 조건을 더하세요.",
      en: "Add a condition that request.auth.uid matches the document owner.",
      zh: "添加条件，检查 request.auth.uid 是否与文档所有者一致。",
    },
  },
  "firebase-rules/rtdb_open": {
    title: { ko: "Realtime Database 전체 공개", en: "Realtime Database fully open", zh: "Realtime Database 完全公开" },
    description: {
      ko: 'database.rules.json 루트가 ".read"/".write": true 입니다.',
      en: 'database.rules.json has ".read"/".write": true at the root.',
      zh: 'database.rules.json 的根节点为 ".read"/".write": true。',
    },
    fix: {
      ko: "루트 공개를 지우고 경로별로 auth 조건을 거세요.",
      en: "Remove root-level access and add auth conditions per path.",
      zh: "删除根节点的公开访问，并按路径添加 auth 条件。",
    },
  },
  "firebase-rules/rules_missing": {
    title: { ko: "Firebase 규칙 파일 없음", en: "Firebase rules file missing", zh: "缺少 Firebase 规则文件" },
    description: {
      ko: "firebase.json은 있지만 규칙 파일이 저장소에 없습니다. 콘솔에서 규칙을 확인하세요.",
      en: "firebase.json exists but no rules file is in the repository. Check the rules in the console.",
      zh: "有 firebase.json，但仓库中没有规则文件。请在控制台中检查规则。",
    },
    fix: {
      ko: "Firebase 콘솔에서 현재 규칙을 확인하세요.",
      en: "Check the current rules in the Firebase console.",
      zh: "请在 Firebase 控制台中检查当前规则。",
    },
  },
  // ---- hallucinated-package
  "hallucinated-package/malicious": {
    title: { ko: "위험: 악성 패키지", en: "Danger: malicious package", zh: "危险：恶意包" },
    description: {
      ko: "이 패키지는 악성으로 등록되어 있습니다(OSV MAL- 또는 npm 보안 대체본).",
      en: "This package is registered as malicious (OSV MAL- or an npm security placeholder).",
      zh: "该包已被登记为恶意包（OSV MAL- 或 npm 安全占位包）。",
    },
    fix: {
      ko: "manifest와 lock에서 이 패키지를 제거하세요.",
      en: "Remove this package from the manifest and the lock file.",
      zh: "请从清单文件（manifest）和 lock 文件中移除该包。",
    },
    human: {
      ko: "이 패키지를 설치한 기기에서 쓰던 키·토큰을 전부 교체하고, 설치한 기기를 점검하세요.",
      en: "Rotate every key and token used on machines that installed it, and check those machines.",
      zh: "请轮换安装过该包的机器上用过的所有密钥和令牌，并检查这些机器。",
    },
  },
  "hallucinated-package/not_found": {
    title: {
      ko: "레지스트리에 없는 패키지 — AI가 지어낸 이름일 수 있음",
      en: "Package not in the registry — possibly an AI-invented name",
      zh: "包仓库中不存在的包 — 可能是 AI 编造的名称",
    },
    description: {
      ko: "이 이름은 레지스트리에 없습니다. 나중에 누군가 같은 이름으로 악성 패키지를 올릴 수 있습니다.",
      en: "This name does not exist in the registry. Someone could later publish a malicious package under it.",
      zh: "包仓库中没有这个名称。以后可能有人用这个名称发布恶意包。",
    },
    fix: {
      ko: "이 이름을 쓰지 말고, 필요한 기능은 사람이 공식 문서에서 확인한 패키지만 쓰세요.",
      en: "Do not use this name; only use packages a person has confirmed in official documentation.",
      zh: "不要使用这个名称；只使用经人工在官方文档中确认过的包。",
    },
  },
  "hallucinated-package/removed": {
    title: { ko: "레지스트리에서 내려간 패키지", en: "Package removed from the registry", zh: "已从包仓库下架的包" },
    description: {
      ko: "lock에는 공개 레지스트리 패키지로 있지만 지금은 레지스트리에 없습니다.",
      en: "The lock file lists it from the public registry, but it no longer exists there.",
      zh: "lock 文件中记录它来自公共包仓库，但它现在已不在那里。",
    },
    fix: {
      ko: "왜 내려갔는지 사람이 확인하고, 사용을 중단하세요.",
      en: "Have a person check why it was removed, and stop using it.",
      zh: "请由人工确认下架原因，并停止使用。",
    },
  },
  "hallucinated-package/suspicious": {
    title: { ko: "인기 패키지와 비슷한 새 패키지", en: "New package with a name close to a popular one", zh: "名称与热门包相近的新包" },
    description: {
      ko: "인기 패키지와 철자가 한두 글자 다르고, 최근에 올라왔으며 다운로드가 적습니다. 오타를 노린 패키지일 수 있습니다.",
      en: "Its name differs by one or two letters from a popular package, it is new and rarely downloaded. It may be a typosquat.",
      zh: "它的名称与某个热门包只差一两个字母，而且是新发布的，下载量很少。可能是利用拼写错误的仿冒包。",
    },
    fix: {
      ko: "사람이 이름 철자와 공식 문서를 확인하기 전까지 쓰지 마세요.",
      en: "Do not use it until a person checks the spelling and the official documentation.",
      zh: "在人工核对拼写和官方文档之前，不要使用它。",
    },
  },
  "hallucinated-package/undeclared_import": {
    title: { ko: "의존성에 없는 import — 직접 확인", en: "Import not in dependencies — check it", zh: "依赖中没有的 import — 请确认" },
    description: {
      ko: "코드가 import하지만 manifest·lock에 없는 이름입니다.",
      en: "The code imports a name that is not in the manifest or lock file.",
      zh: "代码 import 了一个清单文件（manifest）和 lock 文件中都没有的名称。",
    },
    fix: {
      ko: "이 import가 필요한지 사람이 확인하세요.",
      en: "Have a person check whether this import is needed.",
      zh: "请由人工确认是否需要这个 import。",
    },
  },
  // ---- vulnerable-deps
  "vulnerable-deps/vulnerable": {
    title: { ko: "알려진 취약점이 있는 패키지", en: "Package with known vulnerabilities", zh: "存在已知漏洞的包" },
    description: {
      ko: "이 버전에 공개된 취약점이 있습니다.",
      en: "This version has published vulnerabilities.",
      zh: "该版本存在已公开的漏洞。",
    },
    fix: {
      ko: `{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, lock: {lockfile}). ${LOCK_RULE.ko}`,
      en: `Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, lock: {lockfile}). ${LOCK_RULE.en}`,
      zh: `请将 {package} 升级到 {fixed_version} 或更高版本（漏洞：{vuln_ids}，lock：{lockfile}）。${LOCK_RULE.zh}`,
    },
    fixUv: {
      ko: `{package}를 {fixed_version} 이상으로 올리세요(취약점: {vuln_ids}, lock: {lockfile}). ${UV_RULE.ko}`,
      en: `Upgrade {package} to {fixed_version} or later (vulnerabilities: {vuln_ids}, lock: {lockfile}). ${UV_RULE.en}`,
      zh: `请将 {package} 升级到 {fixed_version} 或更高版本（漏洞：{vuln_ids}，lock：{lockfile}）。${UV_RULE.zh}`,
    },
  },
  "vulnerable-deps/vulnerable_no_fix": {
    title: { ko: "수정 버전이 없는 취약 패키지", en: "Vulnerable package without a fix", zh: "没有修复版本的漏洞包" },
    description: {
      ko: "이 버전에 취약점이 있고 아직 수정 버전이 없습니다.",
      en: "This version is vulnerable and there is no fixed version yet.",
      zh: "该版本存在漏洞，目前还没有修复版本。",
    },
    fix: {
      ko: `수정 버전 없음 — {package} 사용 중단을 검토하세요(취약점: {vuln_ids}). ${LOCK_RULE.ko}`,
      en: `No fixed version — consider stopping use of {package} (vulnerabilities: {vuln_ids}). ${LOCK_RULE.en}`,
      zh: `暂无修复版本 — 请考虑停止使用 {package}（漏洞：{vuln_ids}）。${LOCK_RULE.zh}`,
    },
    fixUv: {
      ko: `수정 버전 없음 — {package} 사용 중단을 검토하세요(취약점: {vuln_ids}). 이 uv 프로젝트는 pyproject.toml을 고친 뒤 \`uv lock\`으로 uv.lock을 다시 만드세요. lock 파일을 손으로 고치지 마세요.`,
      en: `No fixed version — consider stopping use of {package} (vulnerabilities: {vuln_ids}). In this uv project, edit pyproject.toml and run \`uv lock\` to regenerate uv.lock. Do not edit the lock file by hand.`,
      zh: `暂无修复版本 — 请考虑停止使用 {package}（漏洞：{vuln_ids}）。这是 uv 项目，请修改 pyproject.toml 后运行 \`uv lock\` 重新生成 uv.lock。不要手动修改 lock 文件。`,
    },
  },
  "vulnerable-deps/version_unknown": {
    title: { ko: "버전 미확인 — lock 파일 없음", en: "Versions unknown — no lock file", zh: "版本未知 — 没有 lock 文件" },
    description: {
      ko: "lock 파일이 없어 설치되는 버전을 알 수 없고, 취약점을 판정하지 못했습니다.",
      en: "Without a lock file the installed versions are unknown, so vulnerabilities could not be checked.",
      zh: "没有 lock 文件，无法得知实际安装的版本，因此无法检查漏洞。",
    },
    fix: {
      ko: `패키지 매니저로 설치해 lock 파일을 만들고 저장소에 커밋하세요(Python은 버전을 == 로 고정). lock 파일을 손으로 고치지 마세요.`,
      en: `Install with your package manager to create a lock file and commit it (pin Python versions with ==). Do not edit the lock file by hand.`,
      zh: `请用包管理器安装以生成 lock 文件并提交到仓库（Python 用 == 固定版本）。不要手动修改 lock 文件。`,
    },
  },
  "vulnerable-deps/version_unpinned": {
    title: { ko: "버전이 고정되지 않음", en: "Versions not pinned", zh: "版本未固定" },
    description: {
      ko: "requirements 파일에 == 로 고정되지 않은 패키지가 있어 설치되는 버전을 알 수 없고, 그 패키지의 취약점을 판정하지 못했습니다.",
      en: "Some packages in this requirements file are not pinned with ==, so their installed versions are unknown and their vulnerabilities could not be checked.",
      zh: "该 requirements 文件中有些包没有用 == 固定版本，无法得知实际安装的版本，因此无法检查这些包的漏洞。",
    },
    fix: {
      ko: "{file}의 패키지 버전을 지금 쓰는 버전으로 == 고정하세요. 버전을 새로 고르거나 패키지를 추가하지 마세요.",
      en: "Pin the packages in {file} with == to the versions in use now. Do not pick new versions or add packages.",
      zh: "请用 == 把 {file} 中的包固定为当前正在使用的版本。不要选择新版本，也不要添加包。",
    },
  },
  "vulnerable-deps/lock_unreadable": {
    title: {
      ko: "lock 파일을 읽지 못함 — 의존성 검사 안 됨",
      en: "Lock file could not be read — dependencies not checked",
      zh: "无法读取 lock 文件 — 未检查依赖",
    },
    description: {
      ko: "lock 파일이 깨졌거나(JSON·YAML·TOML 오류, 머지 충돌 표식) 지원하지 않는 형식 버전이라 설치 버전을 확인하지 못했고, 취약점을 판정하지 못했습니다.",
      en: "The lock file is broken (JSON/YAML/TOML error, merge conflict markers) or uses an unsupported format version, so installed versions and vulnerabilities could not be checked.",
      zh: "lock 文件已损坏（JSON/YAML/TOML 错误、合并冲突标记）或使用了不支持的格式版本，因此无法检查安装版本和漏洞。",
    },
    fix: {
      ko: "{file}에 머지 충돌 표식이 남아 있으면 정리한 뒤, 패키지 매니저로 다시 설치해 lock 파일을 새로 만드세요. lock 파일을 손으로 고치지 마세요.",
      en: "If {file} still has merge conflict markers, resolve them; then reinstall with your package manager so it writes a fresh lock file. Do not edit the lock file by hand.",
      zh: "如果 {file} 中还有合并冲突标记，请先解决；然后用包管理器重新安装，让它写出新的 lock 文件。不要手动修改 lock 文件。",
    },
  },
  "vulnerable-deps/lock_regenerate": {
    title: { ko: "오래된 lock 형식 — 의존성 검사 안 됨", en: "Old lock format — dependencies not checked", zh: "旧版 lock 格式 — 未检查依赖" },
    description: {
      ko: "pnpm 7 이하가 만든 lock 형식(lockfileVersion 5.x 이하)은 읽지 못해 설치 버전과 취약점을 확인하지 못했습니다.",
      en: "Lock files written by pnpm 7 or earlier (lockfileVersion 5.x or older) cannot be read, so installed versions and vulnerabilities were not checked.",
      zh: "无法读取 pnpm 7 及更早版本生成的 lock 文件（lockfileVersion 5.x 或更旧），因此未检查安装版本和漏洞。",
    },
    fix: {
      ko: "pnpm 8 이상으로 다시 설치해 {file}을 새로 만드세요. lock 파일을 손으로 고치지 마세요.",
      en: "Reinstall with pnpm 8 or later so it rewrites {file}. Do not edit the lock file by hand.",
      zh: "请用 pnpm 8 或更高版本重新安装，让它重写 {file}。不要手动修改 lock 文件。",
    },
  },
  "vulnerable-deps/unsupported_lock": {
    title: {
      ko: "아직 지원하지 않는 lock 형식 — 버전 확인 안 됨",
      en: "Lock format not supported yet — versions not checked",
      zh: "暂不支持的 lock 格式 — 未检查版本",
    },
    description: {
      ko: "이 lock 형식은 아직 읽지 못해 설치 버전과 취약점을 확인하지 못했습니다. 다음 릴리스에서 지원합니다.",
      en: "This lock format cannot be read yet, so installed versions and vulnerabilities were not checked. Support is planned for the next release.",
      zh: "暂时无法读取这种 lock 格式，因此未检查安装版本和漏洞。计划在下一个版本中支持。",
    },
    fix: {
      ko: "다음 릴리스를 기다리거나 지원 형식(npm·pnpm·uv·requirements)으로 다시 검사하세요.",
      en: "Wait for the next release or check with a supported format (npm, pnpm, uv, requirements).",
      zh: "请等待下一个版本，或改用支持的格式（npm、pnpm、uv、requirements）重新检查。",
    },
  },
};

export const LOCK_HAND_EDIT = LOCK_RULE;

const pickL = (t: LocalizedText | undefined, lang: Lang): string | undefined => t?.[lang] ?? t?.en ?? t?.ko;

/**
 * The kind text of a builtin finding, with `named` description/fix filled when the finding carries its
 * table (and policy). `safe` cleans the repository names first (prompts pass their data-text filter).
 */
export function namedKindText(f: Pick<Finding, "rule_id" | "kind" | "table" | "policy">, safe: (s: string) => string = (s) => s): KindText | undefined {
  const kt = KIND_TEXT[`${f.rule_id}/${f.kind}`];
  if (!kt?.named || !f.table) return kt;
  const v: Record<string, string> = { table: safe(f.table), policy: safe(f.policy ?? "") };
  const fill = (t: FullText): FullText =>
    Object.fromEntries(Object.entries(t).map(([l, s]) => [l, s.replace(/\{(table|policy)\}/g, (_, k: string) => v[k]!)])) as FullText;
  return { ...kt, description: fill(kt.named.description), fix: fill(kt.named.fix) };
}

const MOST_SEVERE: Record<Lang, (id: string) => string> = {
  ko: (id) => `가장 위험한 취약점 ${id}:`,
  en: (id) => `Most severe, ${id}:`,
  zh: (id) => `最严重的漏洞 ${id}：`,
};

/**
 * Description of a builtin finding for people (GUI "why it matters", terminal): the kind text with its
 * own names, plus the VulnIntel description of a vulnerable package's most severe vulnerability.
 * That server text is external: fix prompts and MCP use `namedKindText` only.
 */
export function findingDescription(f: Pick<Finding, "rule_id" | "kind" | "table" | "policy" | "vuln_description">, lang: Lang): string | undefined {
  const d = pickL(namedKindText(f)?.description, lang);
  const v = f.vuln_description;
  return v ? [d, MOST_SEVERE[lang](v.id), v.text].filter(Boolean).join(" ") : d;
}
