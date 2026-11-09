# Contributing to checkback

Thanks for helping. Bug reports, false positive reports, new rules and fixes are all welcome.
By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Security vulnerabilities in checkback itself: please do not open an issue, see [SECURITY.md](SECURITY.md).

## Setup

You need Node.js 20.18 or later and git. pnpm is pinned in `package.json` (`packageManager`).

```sh
corepack enable
pnpm install
pnpm build      # TypeScript → dist/ (engine, CLI, MCP, GUI server) and dist/web/ (screen)
pnpm test       # vitest, no network
```

Run your build against any folder:

```sh
cd path/to/some/project
node /path/to/checkback/dist/cli.js --no-open   # web screen
node /path/to/checkback/dist/cli.js scan        # JSON result
```

`pnpm e2e:docker` packs the package and checks the installed CLI, MCP server and web screen in
clean `node:20-slim` and `node:22-slim` containers, with and without network
([`docker/e2e/`](docker/e2e)). Run it for changes to the CLI, MCP, GUI server or packaging. It needs
Docker and bash (Git Bash on Windows).

## Where things are

| Path | What |
|---|---|
| `src/scan.ts`, `src/regex-runner.ts`, `src/refine.ts` | Scan pipeline, regex workers with time limits, rule-specific judgments |
| `src/builtins/` | Supabase/Firebase, dependency and import checks |
| `src/deps/` | Lock file parsers, lookup scope, CycloneDX |
| `src/recheck.ts` | Fix-request baseline and re-check states |
| `src/prompts.ts` | Fix instructions and the AI review checklist |
| `src/mcp.ts` | MCP server (stdio) |
| `src/gui/`, `web/` | Local web server and screen |
| `src/net/` | OSV, registries, VulnIntel clients and call budget |
| `templates/default.yaml` | Default rules |
| `plugin/`, `.claude-plugin/` | Claude Code plugin and marketplace |
| `test/` | Tests; `test/helpers.ts` builds fake keys |

## Changing rules

- Every rule change needs a positive and a negative test with the expected severity and confidence.
- **Never commit a secret-shaped string**, not even a fake one. Build fake keys from fragments at run
  time like `test/helpers.ts` (`K.openai()` and friends) so that secret scanners and push protection
  do not fire on this repository.
- Prefer missing a rare case over a noisy rule. Placeholders, examples, docs and public keys must
  stay quiet (see the tests for `.env.example`, README code blocks and publishable keys).
- Regular expressions run in worker threads with a time limit. Avoid nested quantifiers; the
  template loader rejects patterns that are slow on its sample inputs.
- Fix instructions (`fix_prompt`) must not quote values, must not tell the AI to install a package
  that is not already in the project, and must not tell it to edit lock files by hand.
- User-facing text comes in English and Korean.

## Wording

checkback re-checks the items its rules know about (secret keys, settings, dependency versions). Do
not describe it as verifying AI fixes, app logic or what an AI judged.

Claude Code may be named only in plain descriptions ("a plugin for Claude Code"). Do not use Claude
or Anthropic in product, feature, plugin or marketplace names.

## Pull requests

- Keep a pull request to one change. Explain what and why, and how you tested it.
- `pnpm build` and `pnpm test` must pass. CI runs them on Linux, Windows and macOS with Node 20 and
  22, plus the Docker check.
- No new runtime dependency without a good reason in the description.
- Add a line to `CHANGELOG.md` under "Unreleased".
- Commit messages follow `type: summary` (`feat`, `fix`, `docs`, `test`, `chore`, `ci`, `refactor`).

## License

Contributions are accepted under the [Apache License 2.0](LICENSE), the project's license.
