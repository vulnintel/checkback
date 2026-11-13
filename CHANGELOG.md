# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2] - 2026-11-13

### Changed

- A vulnerable dependency's severity follows the VulnIntel priority (VPI) again, as before 0.2.1
  (KEV → critical, VPI 5–6 critical, 4 high, 1–3 medium). While a package's priority lookup has not
  finished or failed, it keeps its OSV/CVSS severity marked provisional (web page, `scan --text`, MCP
  `notes`), and the critical and critical+high quick select leave it out.

## [0.2.1] - 2026-11-13

### Fixed

- Code and config rules (CORS, debug settings and the like) no longer fire in AI-assistant
  instruction files (`.claude/`, `.codex/`, `.cursor/`, `.windsurf/`, `.github/copilot-instructions.md`,
  `AGENTS.md`, `CLAUDE.md`, `*.mdc`, …), which name those settings in prose. Secret-key rules still do.
- A vulnerable dependency with no fixed version whose installed version was released after every
  advisory was published is now "needs review" with a note: an open-ended advisory range (for example
  one hijacked release) may not cover it. The release time comes from npm / PyPI, only for these items.
- A vulnerable dependency's severity no longer depends on whether the VulnIntel priority lookup
  finished: it comes from KEV, else the advisory's OSV severity or CVSS. VPI is a badge and a sort key,
  and a card whose priority was not checked says so.
- A re-check no longer counts items as "new" when the previous scan did not run their rule (no
  consent yet, offline, timed out, disabled); they get no re-check status. Same in the web page,
  `scan --text` and MCP `compare`.

## [0.2.0] - 2026-11-13

### Added

- Simplified Chinese (`zh`, 简体中文) everywhere English and Korean are: the web screen, `scan --text
  --lang zh`, fix prompts, the AI review checklist, MCP output, built-in rule texts and the default
  template, and the consent and notice texts. A system locale starting with `zh` picks it by
  default. User templates may add an optional `zh` text; without one, Chinese falls back to English.
- README in Korean (`README.ko.md`) and Simplified Chinese (`README.zh-CN.md`); the npm package
  description is in English, Korean and Chinese.

### Fixed

- The `bin` path no longer triggers npm's "auto-corrected package.json" warning on publish.

## [0.1.0] - 2026-11-12

First public release.

### Added

- Local scan with the read-only default template: secret keys in code and build output, committed
  `.env` and key files (including git history), `.gitignore` without an `.env` rule, Supabase RLS
  and policies, Firebase rules, CORS, debug settings and production source maps.
- Dependency checks from `package-lock.json`, `pnpm-lock.yaml`, `uv.lock` and `requirements*.txt`: vulnerable
  and malicious packages (OSV.dev), non-existent and typo-like package names (npm, PyPI), with KEV,
  VPI level and EPSS priority from the VulnIntel public lookup. External lookups run only after
  first-run consent.
- Re-check against the fix-request baseline: resolved, still there, new, same key remains, possibly
  moved, confidence lowered, lock mismatch, not checked. Notes for a package upgraded to a version
  that is still vulnerable, and for a manifest changed without regenerating the lock.
- Plain-language fix instructions for one finding or up to 10 at once, and a read-only review
  checklist (`ai_check` items) for the user's own AI.
- Local web screen (`npx checkback`, `--no-open`) on `127.0.0.1` with a per-run token, an HttpOnly
  session cookie and Host/Origin checks. English and Korean; light and dark, following the OS or
  the choice in Settings. Quick select ticks every thing to fix
  at a severity level (Critical, Critical+High, All) in one click, up to the 10-item limit.
- MCP server over stdio (`checkback mcp`) with `scan`, `explain`, `fix_prompts`, `ai_check_prompt`
  and `export_sbom`. Responses never carry secret or masked values.
- Claude Code plugin (one skill plus the MCP server) and the `vulnintel` plugin marketplace.
- Command line: `checkback scan` prints a readable report in a terminal and JSON when piped
  (`--text`, `--json`), `--fail-on <severity>` for CI gates, `--help`, `--version` and suggestions
  for mistyped commands.
- CycloneDX SBOM export (`checkback sbom`). `--upload-preview` prints what a VulnIntel key would
  send without uploading anything (`--upload` still works as an alias).
- Optional VulnIntel key: watch packages for new vulnerabilities, remediation tracker, 30-day
  result history.
- Template duplicate, rule on/off, import/export, custom AI checklist sentences, and an ignore list
  stored outside the project.

### Reliability

- The text report lists what could not be checked (offline, no consent, time limit, pending
  priority, shallow clone, nested repositories) at the top, and names each package with its
  current and recommended version.
- Recommended upgrade versions are checked against every known vulnerability of the package, so
  the tool no longer recommends a version that is itself vulnerable.
- A lock file that cannot be read (syntax error, merge conflict, unsupported format) is reported
  instead of silently producing no dependency findings.
- Supabase anon keys are shown as public keys that are fine in the browser, not as service keys.
- Key files that remain only in git history are reported, like `.env` files.
- Workspace, path and catalog packages are no longer reported as AI-invented names.
- External lookups stop after 90 seconds (20 in the MCP server) and continue on the next scan;
  severities no longer change between scans while priority lookups are pending.
- Nested git worktrees, `.claude/worktrees`, git-ignored folders and independent nested clones are
  skipped, so the same key is not reported several times.
- Fix instructions for a vulnerable package follow how it is declared: the right `npm`, `pnpm` or
  `uv add` command for its section (dev group, named group, optional extra), "upgrade the parent,
  else an override floor" for a package that comes in through another one (per major line when the
  lock holds several; when the only fix is a later major, no override — upgrade or replace the
  parent instead), and a version edit for `requirements` files. Fewer false alarms: dependency
  files under test fixtures are "to review", Markdown files are not checked for public-prefix
  secret names, a placeholder value no longer asks to revoke a key, and credentialed CORS is
  reported only for `*`, an all-origins pattern or an echoed request Origin.
- A key that was moved instead of revoked stays "same key remains" through later fix requests,
  until the value is gone.
- Findings say what they are about: Supabase items name the table and policy, resolved items, the
  ignore list and the AI checklist name the package and version, and a vulnerable package shows the
  VulnIntel description of its most severe vulnerability. Each vulnerability is listed once (its
  CVE instead of the CVE plus GHSA and PYSEC aliases).
- The text report shows the re-check comparison, and `--fail-on` messages follow `--lang`.
- Re-check counts leave out "for information" items, so they agree with the number of things to fix.
- `.gitignore` is also reported when its rule leaves an untracked `.env` file out (for example only
  `.env*.local` while `.env` exists).
- Adding CVEs to the remediation tracker asks for confirmation before anything is sent.
- Fix instructions say "revoke and reissue" once, and the lock-file warning only on dependency items.

### Security

Hardening from a self-audit before the first release:

- Scanning a project can no longer run a program named in that project's own `.git/config` (for
  example a signature-check helper). checkback runs git with hooks, pagers and such helpers turned
  off, and without your VulnIntel key in its environment.
- Symbolic links and junctions that point outside the project folder are not followed, including
  inside `.next/static`.
- Built-in rules no longer stall on crafted files: their regular expressions run in linear time.
  Patterns from custom templates keep running with a time limit.
- File names and paths from the scanned project reach your AI as quoted data, with a note that they
  are not instructions. Wording from an imported template is marked as such in the MCP server too.
- Private registries set up outside the project (`~/.npmrc`, pnpm and Yarn user config, pip config,
  `npm_config_*` and `PIP_INDEX_URL` environment variables) are recognized, so those private package
  names are not looked up on public registries.
- Smaller fixes: size limits on lookup responses, keyed VulnIntel calls never follow redirects,
  `requirements` includes (`-r`) follow only `.txt` and `.in` files, and the browser is opened
  without the session token on its command line (outside Windows).
- Runtime dependencies are pinned to exact versions.

[Unreleased]: https://github.com/vulnintel/checkback/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vulnintel/checkback/releases/tag/v0.1.0
