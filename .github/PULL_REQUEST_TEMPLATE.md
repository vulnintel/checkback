## What and why

<!-- What does this change, and which issue does it address? -->

## How it was tested

- [ ] `pnpm build` and `pnpm test` pass
- [ ] New or changed rules have positive and negative tests (fake keys assembled at run time, never committed as one string)
- [ ] `pnpm e2e:docker` passes (needed for CLI, MCP, web screen or packaging changes)

## Checklist

- [ ] No real secrets, tokens or personal paths in code, tests, images or this description
- [ ] No new runtime dependency, or the reason is explained above
- [ ] User-facing text exists in both English and Korean (`web/src/i18n.ts`, template `en`/`ko`)
- [ ] Wording does not claim more than the rules check (checkback does not verify app logic or what an AI judged)
- [ ] `CHANGELOG.md` updated under "Unreleased"
