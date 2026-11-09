# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - Unreleased

First public release.

### Added

- Local scan with the read-only default template: secret keys in code and build output, committed
  `.env` and key files (including git history), `.gitignore` without an `.env` rule, Supabase RLS
  and policies, Firebase rules, CORS, debug settings and production source maps.
- Dependency checks from `package-lock.json`, `pnpm-lock.yaml` and `requirements*.txt`: vulnerable
  and malicious packages (OSV.dev), non-existent and typo-like package names (npm, PyPI), with KEV,
  VPI level and EPSS priority from the VulnIntel public lookup. External lookups run only after
  first-run consent.
- Re-check against the fix-request baseline: resolved, still there, new, same key remains, possibly
  moved, confidence lowered, lock mismatch, not checked. Notes for a package upgraded to a version
  that is still vulnerable, and for a manifest changed without regenerating the lock.
- Plain-language fix instructions for one finding or up to 10 at once, and a read-only review
  checklist (`ai_check` items) for the user's own AI.
- Local web screen (`npx checkback`, `--no-open`) on `127.0.0.1` with a per-run token, an HttpOnly
  session cookie and Host/Origin checks. English and Korean.
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
