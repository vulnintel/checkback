# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[Private vulnerability reporting](../../security/advisories/new)
("Security" tab → "Report a vulnerability"). Do not open a public issue.

Include the affected version or commit, reproduction steps, and the impact.

## What to expect

- We confirm that we received your report within 3 business days.
- We aim to release a fix for critical and high severity issues within 30 days of confirming them,
  and keep you updated until then.
- We credit you in the advisory unless you prefer not to be named.

## Scope

In scope: checkback itself, meaning the npm package (CLI, local web page, MCP server), the Claude
Code plugin in `plugin/`, and the release workflows in this repository. Examples: code execution
or file reads triggered by scanning a crafted project, secret values leaking into output, the local
page being reachable from other sites, or data sent somewhere the README does not list.

Out of scope: false positives and missed findings in scan results. Please use the
[false positive report](https://github.com/vulnintel/checkback/issues/new?template=false_positive.yml)
or a regular issue for those.

## Safe harbor

We will not take legal action against good-faith research that follows this policy, avoids harm to
other people's data and systems, and gives us reasonable time to fix the issue before disclosure.

## Supported versions

Only the latest release receives security fixes.
