# Security policy

Hearthward Guard is pre-release software, offered as is and without warranty (see the README disclaimer).
It lowers risk; it does not make an AI agent safe.

## Reporting a vulnerability

Please use GitHub's **Report a vulnerability** button on the Security tab of this repository
(a private advisory). Do not open a public issue for a bypass or a leak. If you cannot use the button,
write to the public project contact listed on the project website.

Expect an acknowledgement within about 7 days. This is a one-person project, so fixes are best effort.
A bypass of Threshold, Knock or Gatehouse that comes with a reproducible text or file is especially welcome.
Ordinary bugs can go in normal issues.

## Supported versions

Only the latest release on `main`.

## Scope notes

- The attack test set in `bench/` contains hostile text on purpose. That is not a vulnerability.
- Never post real tokens, personal data or private messages in an issue, even to illustrate a bug.
