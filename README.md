# Hearthward guard

Hearthward is a hobby project: a private AI assistant that runs on your own computer, for you or your
family, for planning and everyday personal help (calendar, messages, deadlines). This repository holds its
**guard**, the part that lets an assistant read outside text (chat, email, attachments, web pages, tool
output) while lowering the chance that the text takes control of it.

The guard is a plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent) (Nous Research, MIT
licence). It has three parts:

- **Threshold**: untrusted text is scanned (rules, plus an optional tool-less local model check) and
  suspicious messages are held for the owner, who answers `follow <id>` or `ignore <id>`.
- **Knock**: a policy on tool calls. A never-allowed list, a taint rule (an agent that has seen outside text
  may not act on its own) and tool allowlists decide which actions run and which ask the owner first.
- **Gatehouse**: a filter on replies (secrets, hidden characters, data-carrying links).

Pictures can also be read (Tesseract OCR) and checked for common scam signs, in English and Chinese.

## Install and settings

- **[Install guide](guard/INSTALL.md)** ([简体中文](guard/INSTALL.zh-CN.md)): step by step, from an empty
  computer (Linux, or Windows with WSL) to a running, checked guard. No programming knowledge needed.
- **[Settings reference](guard/SETTINGS.md)** ([简体中文](guard/SETTINGS.zh-CN.md)): every setting, with
  its default, what it does, when to change it and a recommendation.

## What is here

| Folder | Contents |
|---|---|
| `guard/` | The plugin (`guard/hearthward_guard/`, with `plugin.yaml`), its tests, `tools/preflight.py`, and the guard's own [README](guard/README.md) with settings and limits. |
| `bench/` | A benchmark kit: `bench/attacks/` generates and runs prompt-injection and scam test cases against the guard; the rest measures a local model's speed as an agent brain. See [bench/README.md](bench/README.md) and [bench/attacks/README.md](bench/attacks/README.md). |
| `DATASETS.md` | Public attack datasets the benchmark can import. None are included; sources, licences and download steps are listed. |

## Status

Pre-release (guard 0.9.3). It has been developed against Hermes Agent 0.23.1 and tested on 0.23.1 and 0.23.3 (`requires_hermes`
in `plugin.yaml`) on one setup, and the tests use stand-ins for Hermes, not a live gateway. Expect rough edges.

## Run the tests

Python 3.10 or newer, standard library only:

```
cd guard
python -m unittest discover -s tests -t .
```

(The Tesseract integration tests skip themselves when the engine is not installed.)

## What the guard cannot do

It is best-effort. Rules and a small local model catch many attacks and some scams, and miss others;
rewordings, new tricks and unusual file types can get past it. It lowers the risk of prompt injection. It
does not remove it, and "no clear signs" is not a promise that something is safe. Check anything important
yourself.

## Disclaimer

- A personal hobby project, provided as-is with no warranty of any kind (see the Apache-2.0 licence).
- Not financial, legal, medical or professional advice.
- Local AI models make mistakes. Check anything important yourself.
- The guard is best-effort: it lowers prompt-injection risk but cannot promise to stop every attack.
- You are responsible for your own data, your own accounts, and following each service's terms.
- Not affiliated with or endorsed by Nous Research / Hermes Agent, Google, or any model maker.
- The guard never asks for your passwords. Keys and logins stay on your machine and are entered by you.

## Licence

Apache-2.0, see [LICENSE](LICENSE).

Exception: `bench/prompts/hermes_prompt.json` and the quoted Hermes strings listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) are MIT (Copyright (c) 2025 Nous Research); see that file.

Comments in the code such as `(review M5)` or `(lab re-test 2 bug 3)` refer to internal review and test rounds; those reports are not published.