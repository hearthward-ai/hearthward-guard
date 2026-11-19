# Security policy

Hearthward Guard is pre-release software, offered as is and without warranty (see the README disclaimer).
It lowers risk; it does not make an AI agent safe.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** button on the Security tab of this repository
(a private advisory), or go straight to the
[private report form](https://github.com/hearthward-ai/hearthward-guard/security/advisories/new).
Do not open a public issue for a bypass or a leak. If you cannot use the button,
use the public project contact listed in the
[contact section of the project website](https://hearthward-ai.github.io/privacy.html#contact).

Please give me a reasonable time to fix the problem before you disclose it publicly.

Expect an acknowledgement within about 7 days. This is a one-person project, so fixes are best effort.
A bypass of Threshold, Knock or Gatehouse that comes with a reproducible text or file is especially welcome.
Ordinary bugs can go in normal issues.

## Supported versions

Only the latest release on `main`.

## Scope notes

- The attack test set in `bench/` contains hostile text on purpose. That is not a vulnerability.
- Never post real tokens, personal data or private messages in an issue, even to illustrate a bug.
