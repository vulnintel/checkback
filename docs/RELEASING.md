# Releasing checkback

Releases are published from GitHub Actions (`.github/workflows/release.yml`) with npm trusted
publishing. No npm token is stored anywhere.

## One-time setup (before the first release)

Do these in order. Steps 3 and 4 have a deadline: an npm trusted publisher setting expires if it has
not published within 2 days of being created, so create it (step 3) only after every item that
blocks the release is closed.

0. **Check commit author emails before going public.** List them with
   `git log --all --format='%an <%ae>%n%cn <%ce>' | sort -u`. No personal email may remain
   (maintainer decision); use a GitHub `noreply` or project address, and rewrite history before the
   repository is made public if one does.
1. **Make the repository public.** npm adds provenance only for public repositories, and
   `/plugin marketplace add vulnintel/checkback` needs a public repository for users without access.
2. **GitHub settings** (Settings of `vulnintel/checkback`):
   - Environments → create `npm` → add required reviewers (the people who approve each publish).
   - Code security → enable **Private vulnerability reporting** (`SECURITY.md` points there).
   - Branches → protect `main` (require the CI workflow to pass, no force push).
   - About → description and topics (suggested below).
3. **npm trusted publisher** (npmjs.com → package `checkback` → Settings → Trusted publishing):
   - Provider: GitHub Actions. Organization `vulnintel`, repository `checkback`,
     workflow `release.yml`, environment `npm`.
   - Tick **Allow npm publish**. Without it the setting allows only `npm stage publish`, and the
     workflow's `npm publish` is rejected.
4. **Push the release tag** within 2 days (see below).
5. After the first successful publish: package Settings → Publishing access →
   **Require two-factor authentication and disallow tokens**. Trusted publishing keeps working.

Suggested GitHub description: "Local security check for AI-built apps: finds leaked keys, open
Supabase/Firebase rules and risky packages, writes fix prompts for your AI, then re-checks. Web UI,
CLI, MCP server and a Claude Code plugin."

Suggested topics: `security`, `secret-scanning`, `vibe-coding`, `ai-coding`, `supabase`,
`firebase`, `nextjs`, `sbom`, `cyclonedx`, `osv`, `mcp`, `mcp-server`, `claude-code-plugin`,
`devsecops`, `cli`.

## Every release

1. Update the version in three places (the workflow checks they match the tag):
   `package.json` `version`, `plugin/.claude-plugin/plugin.json` `version`, and the
   `checkback@<version>` pin in `plugin/.mcp.json`.
2. Move the `[Unreleased]` notes in `CHANGELOG.md` under the new version with today's date.
3. Locally: `pnpm install --frozen-lockfile && pnpm build && pnpm test && pnpm e2e:docker`.
4. Commit, then tag and push:

   ```sh
   git tag v0.1.0
   git push origin main v0.1.0
   ```

5. Actions → Release → the `verify` job runs build, tests and the Docker clean-room e2e. Approve the
   `npm` environment when it asks.
6. Check the result: `npm view checkback version`, the provenance badge on npmjs.com, and a fresh
   `npx checkback@<version> --version`.
7. Create a GitHub release from the tag with the changelog section.

## If something goes wrong

- `E_STAGE_REQUIRED` or a 403 on publish: the trusted publisher does not allow `npm publish`
  (step 3), or the workflow file name, environment or repository does not match it exactly.
- No provenance on npmjs.com: the repository was private when the tag was pushed.
- A broken version cannot be overwritten. Publish a fixed patch version, then
  `npm deprecate checkback@<bad> "<reason>"`.
