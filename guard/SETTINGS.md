**English** | [简体中文](SETTINGS.zh-CN.md)

# Hearthward guard: settings reference

Guard version 0.9.3. Settings checked against the code on 2026-11-18.

This page lists every setting the guard reads: its own settings, the Hermes Agent settings it needs, and
the environment variables it looks at. For each one you get the default, what it does, when to change it,
and a recommendation. To install the guard, start with the [install guide](INSTALL.md).

## Before you change anything

**Where the settings live.** Hermes Agent keeps its settings in one file, `~/.hermes/config.yaml`
(`~` means your home folder). That file is written in YAML, a plain-text format where indentation
(spaces at the start of a line) shows what belongs to what. The guard's own settings sit under
`plugins` → `entries` → `hearthward-guard` → `settings`. In this page, a name such as
`threshold.weak_action` means the key `weak_action` inside the `threshold` block of those settings.

**How to change one.** Use the `hermes config set` command. It edits the file for you, so you do not
have to get the indentation right. For a guard setting, put `plugins.entries.hearthward-guard.settings.`
in front of the name. For example, to set `holds.timeout_min` to 60:

```bash
hermes config set plugins.entries.hearthward-guard.settings.holds.timeout_min 60
```

You should see a line that starts with `✓`. A list is written in square brackets with quotes, inside
single quotes:

```bash
hermes config set plugins.entries.hearthward-guard.settings.ocr.languages '["eng", "chi_sim"]'
```

**After every change**, restart Hermes ([install guide, step 4.7](INSTALL.md#47-restart-hermes)) and
run the preflight check again ([step 5.1](INSTALL.md#51-run-the-preflight-check)):

```bash
bash ~/hearthward-preflight.sh
```

To undo a change and go back to the default, remove the setting:

```bash
hermes config unset plugins.entries.hearthward-guard.settings.holds.timeout_min
```

**The guard is strict about its settings.** A misspelled key, a wrong type (text where a number belongs)
or a value outside the allowed range does not get ignored: the guard then refuses every message until
you fix it, and the preflight check prints `FAIL: guard: ...` naming the key. It does not print most
values; a few Knock and `safe_link_hosts` messages quote the wrong entry so you can find it. This is on
purpose: a typo must not quietly switch a protection off.

**But a correctly typed setting that switches a protection off takes effect without any question.**
Only Knock asks for a confirmation (`knock.unsafe_override`). These settings weaken the guard as soon
as Hermes restarts, and the preflight check still prints `OK`:

| Setting | Weakens the guard when set to |
|---|---|
| `mode` | `report` (nothing is enforced) |
| `require_no_hook_timeout` | `false` |
| `threshold.unscanned_media` | `owners` or `allow` |
| `threshold.weak_action_content` | `pass` |
| `threshold.scan_attachments`, `scan_tool_results`, `scan_reply_context`, `fence_tool_results` | `false` |
| `second_check.probes` | `false` |
| `second_check.tamper_retry` | `true` |
| `second_check.allow_remote` | `true` (message text may leave your computer) |
| `gatehouse.strip_invisible`, `withhold_secrets`, `block_media_directives`, `block_markdown_images`, `block_query_links` | `false` |
| `log.raw_text` | `true` (message text is written to the log) |

Change these only on purpose, and check `/guard` and this page afterwards.

**Leave a setting out to keep its default.** You only need to write the settings you want to change.

## The four decisions

Most people only make these four choices. Everything else can stay at its default.

| Decision | Setting | Recommended |
|---|---|---|
| Who is the owner | `owners`, `owner_chats` | Your own account on your chat app, and your private chat with the assistant |
| Model check on or off | `second_check.endpoint` | On, if you can run a local model server; off (rules only) is fine to start |
| Which local model server | `second_check.endpoint`, `json_mode`, `model` | llama.cpp's `llama-server` (the one we tested) |
| How strict | `threshold.weak_action`, `threshold.unscanned_media`, `holds.timeout_min` | The defaults |

The [install guide](INSTALL.md) walks you through each one in a "Your choice" box.

## Hermes Agent settings the guard needs

These are Hermes's own settings, not the guard's. The preflight check fails until they are right.

| Setting | Must be | Why |
|---|---|---|
| `plugins.enabled` | lists `hearthward-guard` | Hermes only runs plugins you switched on. `hermes plugins enable hearthward-guard` adds it. |
| `plugins.disabled` | does not list `hearthward-guard` | A name on this list always wins over `plugins.enabled`. |
| `plugins.hook_callback_timeout` | `0` | Hermes's default is 30 seconds. If a check took longer, Hermes would let the message through unchecked. `0` turns that time limit off. |
| `gateway.strict` | `true` | Limits which files the assistant can send out. Hermes's default is `false`. |
| `gateway.trust_recent_files` | `false` | Stops the assistant from sending files just because they are new. Hermes's default is `true`. |
| `platform_toolsets.<platform>` | present for every chat app you use, naming only allowed toolsets | Without an entry, Hermes gives the assistant its default tools on that chat app. The preflight check allows only `no_mcp` unless you pass `--allow-toolset NAME`. |
| `approvals.mode` | `manual` (recommended) | Hermes 0.23.1 defaults to `smart`, where a model answers tool approval requests. The guard's tool policy (Knock) only asks you when a person answers them. Without `manual`, every "ask" becomes "deny", and preflight prints a `NOTE`. |
| `approvals.approvers` | set, and only owners (needed only if your chat app has tools) | On a chat app, Knock asks you only when this names owners and nobody else. Unset (Hermes's default `*`, anyone) means every tool call that needs your approval is refused. Set it with your own user ID: `hermes config set approvals.approvers '["123456789"]'`. |
| `gateway.platforms.<platform>` admin lists, such as `extra.allow_admin_from` | only owners | Hermes lets admins answer approval requests too. Knock checks that every admin is an owner; if not, "ask" becomes "deny". |

**Recommendation:** set all of these exactly as the install guide shows. Keep `platform_toolsets` at
`["no_mcp"]` (no tools on your chat app) until you have used the guard for a while.

## Environment variables

An environment variable is a named value that a program receives from the shell that starts it.
Some of Hermes's environment variables override its settings file, so the guard checks them too.

| Variable | What the guard does with it | Recommendation |
|---|---|---|
| `HERMES_MEDIA_DELIVERY_STRICT` | If it is set to anything other than on (`1`, `true`, `yes`, `on`), it overrides `gateway.strict` and preflight fails. | Do not set it. |
| `HERMES_MEDIA_TRUST_RECENT_FILES` | If it is set to anything other than off (`0`, `false`, `no`, `off`), it overrides `gateway.trust_recent_files` and preflight fails. | Do not set it. |
| `HERMES_MEDIA_ALLOW_DIRS` | If it is set to anything but an empty value, preflight fails (it widens the folders files can be sent from). | Do not set it. |
| `HERMES_YOLO_MODE` | If it is on, Hermes approves every tool call by itself, so Knock turns every "ask" into "deny". | Do not set it. |
| `HERMES_HOME` | The guard keeps its files in `$HERMES_HOME/hearthward-guard` (normally `~/.hermes/hearthward-guard`). | Leave it as Hermes sets it. |
| `HEARTHWARD_GUARD_HEARTBEAT` | `1` forces the heartbeat file on, `0` forces it off. Unset: on only in the gateway process. | Leave it unset. |
| `<PLATFORM>_ALLOW_ADMIN_FROM`, `<PLATFORM>_GROUP_ALLOW_ADMIN_FROM`, `<PLATFORM>_ADMIN_USERS`, `<PLATFORM>_ADMINS`, `<PLATFORM>_ADMIN_IDS`, `<PLATFORM>_ADMIN_USER_IDS` (for example `DISCORD_ADMINS`) | Read as admin lists, like the admin settings above: every admin must be an owner, or "ask" becomes "deny". | Only owners in them, or leave them unset. |
| The variable named in `second_check.api_key_env` | Its value is sent as the key to your model server. | Only if your model server needs a key. |
| `PATH` and `TESSDATA_PREFIX` | Used to find the picture reader (Tesseract) and its language data. Only folders written as full paths count. | Leave them as they are. |

**Limit:** the preflight check only sees the variables of the terminal it runs in. Hermes also reads
variables from its own file `~/.hermes/.env` (and a background service can set its own), and the
running guard does not check the three `HERMES_MEDIA_*` variables. So a `HERMES_MEDIA_*` line in
`~/.hermes/.env` weakens file sending while preflight still prints `OK`. Check that file yourself:
`grep -c '^HERMES_MEDIA_' ~/.hermes/.env` should print `0` (the install guide does this in step 5.1).

## Guard settings: top level

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `mode` | `enforce` | `enforce`: the guard acts (holds, filters, blocks). `report`: it only writes down what it would have done and enforces nothing. | Use `report` only for a short trial to see what would be held. | `enforce` |
| `owners` | `[]` (nobody) | Who may answer holds (`follow <id>`, `ignore <id>`), see `/guard`, and approve tool calls. Each entry is `platform:user_id`, for example `discord:123456789` (made-up number). | Set it once at install. Add a second entry for another chat app you use. | Your own account only |
| `owner_chats` | `{}` (none) | Where the guard sends notices to the owner: one chat ID per platform, for example `{discord: "987654321"}` (made-up number). Without it, notices about other people's held messages only go to the guard log and `/guard`. | Set it at install. The [install guide](INSTALL.md#owner-chat) shows how to find the chat ID. | Your private chat with the assistant |
| `require_no_hook_timeout` | `true` | Refuse to run unless `plugins.hook_callback_timeout` is `0`. | Never. | `true` |

## Guard settings: `threshold` (checking incoming text)

The rules give each message one of three levels: **pass** (no sign), **weak** (one faint sign) or
**hold** (clear signs).

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `scan_attachments` | `true` | Read text attachments and check them. | Never. | `true` |
| `scan_tool_results` | `true` | Check what tools bring back (web pages, files) before the model sees it. | Never. | `true` |
| `scan_reply_context` | `true` | Check text you quote or reply to. | Never. | `true` |
| `scan_local_turns` | `false` | Also check what you type in Hermes on your own computer (the `hermes` command, its terminal UI and desktop app). | Turn on if other people can type at your computer. | `false` |
| `window_messages` | `6` (1 to 50) | How many recent messages in one chat are checked together, to catch instructions split over several messages. | Rarely. | `6` |
| `window_minutes` | `1440` (1 to 10080) | How long (in minutes) messages stay in that window. | Rarely. | `1440` (one day) |
| `max_scan_chars` | `120000` (1000 to 2000000) | Longest text checked. A longer message or attachment is held; a longer tool result is cut, and the rest is not shown to the model. | Raise only if long documents are held or cut. | `120000` |
| `max_attachment_bytes` | `2000000` (1000 to 50000000) | Largest text attachment read, in bytes (2000000 is about 2 MB). | Raise only if your attachments are larger. | `2000000` |
| `max_attachments` | `8` (1 to 50) | More attachments than this in one message: the message is held. | Rarely. | `8` |
| `unscanned_media` | `hold` | What happens to attachments the guard cannot read (audio, video, unknown files, and pictures when the picture reader is off). `hold` (or `skip`, the same): the message is held. `owners`: let them through from owners only. `allow`: let them through from everyone. | Only if you need to send such files to the assistant yourself. | `hold` |
| `weak_action` | `pass` | What one faint sign in a direct chat message does. `pass`: it goes through (and the model check looks at it, if on). `hold`: it is held. | Use `hold` if strangers can write to your assistant and you want fewer risks. | `pass` |
| `weak_action_content` | `hold` | The same for attachments, quoted text and tool results. | Rarely. `pass` lets more hidden instructions through. | `hold` |
| `fence_tool_results` | `true` | Wrap tool results in markers that tell the model "this is data, not instructions". | Never. | `true` |
| `scan_timeout_s` | `10.0` (0.5 to 120) | A check that takes longer than this many seconds holds the message. | Raise on a very slow computer if ordinary messages are held for taking too long. | `10.0` |

## Guard settings: `holds` (held messages)

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `timeout_min` | `30` (1 to 10080) | Minutes a held message waits for your `follow` or `ignore`. No answer counts as ignore. | Raise if you often answer late. | `30` |
| `default` | `ignore` | What happens with no answer. `ignore` is the only allowed value: silence never lets a message through. | Never. | `ignore` |
| `max_pending` | `50` (1 to 1000) | Most held messages waiting at once; past this, the oldest is dropped. | Rarely. | `50` |
| `notices_per_sender_10min` | `3` (0 to 100) | Most "your message is waiting" replies one sender gets in 10 minutes. | Rarely. | `3` |
| `owner_notices_10min` | `10` (1 to 1000) | Most hold notices you get in 10 minutes, for all senders together. The rest stay pending; the next notice says how many, and `/guard` lists them all. | Lower if you get too many notices. | `10` |
| `notice_excerpt_chars` | `160` (0 to 1000) | How much of a held message your notice shows (links and hidden characters are made harmless). `0` shows none. | Lower for more privacy in notices. | `160` |
| `tell_sender` | `true` | Tell a sender that their message is waiting for review. | Set `false` if you prefer silence. | `true` |

## Guard settings: `second_check` (the optional model check)

The model check asks a local AI model, with no tools, whether a text tries to give the assistant
orders. It is off while `endpoint` is empty. It can only add holds, never remove them; if the model
server is down or answers in the wrong shape, the message is held.

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `endpoint` | `""` (off) | Web address of the model server's OpenAI-style API, ending in `/v1`, for example `http://127.0.0.1:9931/v1` for `llama-server` started with `--port 9931` (recent llama.cpp builds use 9931 by default, older ones 8080, so always pass the port). | Set it to turn the model check on. | A server on your own computer |
| `model` | `local` | Model name sent with each request. llama.cpp ignores it; Ollama needs the exact name (for example `qwen3:8b`). | Set it for Ollama or LM Studio. | Your server's model name |
| `json_mode` | `schema` | How the answer's shape is requested. `schema`: llama.cpp (tested) and LM Studio (not tested by us). `json_object`: Ollama (not tested by us). `none`: no request. | Match it to your server. | `schema`, except `json_object` for Ollama |
| `allow_remote` | `false` | Allow an endpoint that is not on this computer. That sends message text off your computer. | Only if you trust that machine and the network to it. | `false` |
| `api_key_env` | `""` | The NAME of an environment variable that holds a key for the server. Never the key itself. | Only if your server needs a key. | `""` |
| `timeout_s` | `8.0` (0.5 to 600) | Seconds to wait for one answer. Too slow means held. | Raise on a slow computer if messages are held as "not available". | `8.0` |
| `tool_timeout_s` | `8.0` (0.5 to 600) | The same for tool results. | As above. | `8.0` |
| `scope` | `all` | `all`: check every text that is not already held. `weak`: only texts with one faint sign. | Use `weak` if your computer is too slow to check everything. | `all` |
| `channels` | `["chat", "attachment", "reply_context", "tool_result"]` | Which kinds of text are checked: chat messages, attachments, quoted text, tool results. | Rarely. | All four |
| `owner_chat` | `weak` | Your own chat messages: `off` never checked, `weak` only when the rules saw a faint sign, `all` always. | Use `all` if others use your account. | `weak` |
| `max_chunks` | `4` (1 to 16) | Long texts are checked in parts; this many parts at most. | Raise if long texts are held as "too long to check in full". | `4` |
| `chunk_tokens` | `1500` (200 to 8000) | Size of one part, in estimated tokens (pieces of words). | Lower for a model with a small context. | `1500` |
| `max_chars` | `6000` (500 to 100000) | Most characters in one part. | Rarely. | `6000` |
| `oversize` | `hold` | Text too long to check in full. `hold`: held (your own typed chat passes, marked as unchecked). `taint`: what you forward passes, marked as unchecked so risky tools need approval; a stranger's text is still held. | Use `taint` if you often forward long texts. | `hold` |
| `calls_per_sender_10min` | `12` (1 to 10000) | Most model checks one other person can cause in 10 minutes. Over that, their message is held without a check. You are never limited. | Rarely. | `12` |
| `calls_all_10min` | `60` (1 to 100000) | The same for all other people together. | Rarely. | `60` |
| `probes` | `true` | Before checks, send the model one harmless and one hostile test text with known answers. A wrong answer marks the check unreliable, and messages are held. | Never. | `true` |
| `probe_every_min` | `30` (5 to 1440) | Minutes between those tests. | Rarely. | `30` |
| `pause_flag` | `""` | Full path of a file. While it exists, the check counts as paused (messages are held). For example a file a game launcher creates. | Only if you have such a file. | `""` |
| `slot` | `-1` (-1 to 64) | llama.cpp only: which slot to use; `-1` = any free one. | Only if you reserve a slot for the guard. | `-1` |
| `recheck_unavailable` | `false` | Re-check your own messages that were held only because the model was down, for a few minutes. Not verified in a live gateway. | Leave off. | `false` |
| `recheck_attempts` | `3` (1 to 3) | Tries for that re-check. | Only with `recheck_unavailable`. | `3` |
| `recheck_window_min` | `10` (1 to 10) | Minutes the re-check keeps trying. | Only with `recheck_unavailable`. | `10` |
| `tamper_retry` | `false` | After an answer in the wrong shape, ask once more. This gives a hijack a second try. | Leave off. | `false` |
| `prompt_variant_dir` | `""` | Advanced: a folder with your own checker instructions (`content.txt`, `chat.txt`, `probes.json`). | Only for testing other wordings. | `""` |
| `score_mode` | `false` | Ask the server for word probabilities and log a score. For tuning only. | Only for tuning. | `false` |
| `on_error` | `hold` | What a failed check does. `hold` is the only allowed value. | Never. | `hold` |

## Guard settings: `gatehouse` (checking replies)

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `strip_invisible` | `true` | Remove hidden and control characters from replies. | Never. | `true` |
| `withhold_secrets` | `true` | A reply that contains something shaped like a password, key or token is not sent at all. | Never. | `true` |
| `block_media_directives` | `true` | Remove file-sending instructions and local file paths from replies. | Never. | `true` |
| `block_markdown_images` | `true` | Turn images in replies into their text label (your chat app would otherwise load them from the web, which can leak data). | Never. | `true` |
| `block_query_links` | `true` | Remove links that look like they carry data out (encoded pieces, or words from your conversation). | Never. | `true` |
| `safe_link_hosts` | `[]` (up to 64) | Exact host names whose links are never removed, for example `["docs.python.org"]`. Sites where anyone can publish pages or forms (such as `docs.google.com` or `github.io`) are not allowed here: listing one is a settings error, so the guard refuses every message until you remove it. | If a site you trust keeps losing its links. | Empty |
| `id_patterns` | `[]` (up to 32) | Regular expressions (text patterns) for your own ID formats; matches become `(id removed)`. | If you want an ID format kept out of replies. | Empty |

## Guard settings: `ocr` (pictures and the scam shield)

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `enabled` | `auto` | `auto`: on when Tesseract is found (always off on Windows). `true`: on; with no Tesseract every picture is held. `false`: off; pictures follow `threshold.unscanned_media`. | Set `false` to switch pictures off. | `auto` |
| `engine_path` | `""` | Full path to the Tesseract program. Empty: look for `tesseract` in the folders of `PATH` (Linux, macOS). | Only if Tesseract is somewhere unusual. | `""` |
| `tessdata_dir` | `""` | Folder of Tesseract's language data. Empty: Tesseract's own. | Only if you installed language data elsewhere. | `""` |
| `languages` | `["eng", "chi_sim"]` | Languages to read (Tesseract codes). Every one must be installed, or every picture is held. | Match it to the languages you receive. | `["eng", "chi_sim"]` |
| `timeout_s` | `20` (1 to 120) | Seconds per picture. | Raise on a slow computer. | `20` |
| `memory_mb` | `1024` (128 to 8192) | Memory limit for Tesseract (Linux and macOS). | Rarely. | `1024` |
| `max_bytes` | `10000000` (10000 to 50000000) | Larger picture files are held unread. | Rarely. | `10000000` (about 10 MB) |
| `max_pixels` | `40000000` (10000 to 200000000) | Larger pictures are held unread. | Rarely. | `40000000` |
| `max_pictures` | `4` (1 to 10) | Pictures read per message. | Rarely. | `4` |
| `max_text_chars` | `20000` (500 to 200000) | Most characters of text taken from one picture. | Rarely. | `20000` |
| `read_metadata` | `true` | Also check text stored inside the picture file. | Never. | `true` |
| `locale` | `en` | Language of the picture verdicts and alerts: `en`, `zh` or `both`. | Set `zh` or `both` for Chinese readers. | Your readers' language |
| `alert_owner` | `true` | Tell you when someone else sends a picture that is likely a scam. | Set `false` if you do not want these alerts. | `true` |
| `alerts_per_10min` | `6` (0 to 100) | Most scam alerts in 10 minutes. | Rarely. | `6` |

## Guard settings: `log` and `heartbeat`

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `log.raw_text` | `false` | Write message text into the guard log. `false` keeps message text out of it. | Only while you debug, then switch it back. | `false` |
| `log.path` | `""` | Where the guard log is written. Empty: `~/.hermes/hearthward-guard/events.jsonl`. | Rarely. | `""` |
| `heartbeat.dir` | `""` | Folder for the heartbeat file (a small file the running guard rewrites to show it is alive and healthy). Empty: `~/.hermes/hearthward-guard/status`. | Rarely. | `""` |
| `heartbeat.interval_s` | `15` (2 to 3600) | Seconds between heartbeat updates. `preflight --heartbeat` accepts a heartbeat up to 60 seconds old (`--max-age`), so above about 50 it fails unless you raise `--max-age` too. | Rarely. | `15` |

## Guard settings: `knock` (tool policy)

Knock decides which tool calls run, which are refused, and which ask you first. "Outside content"
means text that did not come from you: other people's messages, attachments, web pages, tool output.
A conversation that has seen outside content is called **tainted**.

Some Knock settings switch checks off. Those need `knock.unsafe_override: true` as well, and `/guard`
lists them. This confirmation exists for Knock only; see
[the list above](#before-you-change-anything) for the other settings that weaken the guard without
asking.

| Setting | Default | What it does | When to change | Recommendation |
|---|---|---|---|---|
| `enabled` | `true` | Knock on or off. `false` needs `unsafe_override`. | Never. | `true` |
| `taint` | `deny` | A tool with effects (writing, sending, running) after outside content from elsewhere: `deny` or `ask` you. Tools whose effect lasts (memory, skills, schedules) are denied even with `ask`. | Use `ask` only if you read every approval request carefully. | `deny` |
| `local_taint` | `ask` | The same after output from your own computer only (terminal, your files): `ask` or `deny`. | Use `deny` for a stricter setup. | `ask` |
| `unknown_tools` | `deny` | A tool Knock has no class for (every MCP tool included): `deny` or `ask`. | Use `ask` if you use tools Knock does not know, or classify them with `tools`. | `deny` |
| `untainted_acts` | `allow` | A tool with effects in a clean conversation: `allow` or `ask`. | Use `ask` for a stricter setup. | `allow` |
| `untainted_exec` | `ask` | A code-running tool in a clean conversation: `ask` or `allow`. | Rarely. | `ask` |
| `ask_scope` | `call` | What "always" on an approval request covers. `call`: this exact call. `tool`: this tool for this conversation, today only (needs `unsafe_override`). | Rarely. | `call` |
| `tools` | `{}` | Your own classes for tools, `{tool name or pattern: class}`. Classes: `read` (no effects, output trusted), `source` (no effects, output is outside content), `source:private` (reads your private data), `source:net` (sends text off the computer), `act` (has effects), `act+source` (both). Making a built-in tool less strict needs `unsafe_override`. | When you add tools Knock does not know. | Empty |
| `job_allowlists` | `{}` | Lists of the only tools allowed, per key: `*` (everything), `cron:*` (all scheduled jobs), `cron:<job id>`, `platform:<name>`. | To limit a scheduled job or a chat app to a few tools. | Empty |
| `trusted_cron_jobs` | `[]` | Scheduled jobs whose prompt counts as yours, not as outside content. `<job id>:<sha256 of its prompt>` trusts only that exact prompt: if the prompt changes, it counts as outside content again. A bare `<job id>` without the hash is also accepted, but then trusts **any** future prompt of that job, including one changed by a tool or an attacker. | Only for jobs you wrote yourself. | Empty; if used, always with the hash |
| `never_allow` | `[]` (up to 100) | Your own never-allowed rules: `{id, tools: [names], args: [patterns], label}`. | To forbid more actions outright. | Empty |
| `never_allow_disable` | `[]` | Built-in never-allowed rules to switch off: `money`, `trades`, `passwords`, `id_numbers`, `vault`, `sign_in`, `guard_off`. Needs `unsafe_override`. | Not recommended. | Empty |
| `unsafe_override` | `false` | Required by the settings above that switch checks off. | Only together with such a setting. | `false` |
| `local_skills` | `[]` | Skills you wrote yourself, as `<skill name>:<sha256 of its SKILL.md>`; reading them is not outside content. Never list a downloaded skill. | Only for your own skills. | Empty |
| `chat_grants_and_partial` | `false` | Allow time-limited grants and partly shown approval requests on chat apps. On Discord, long requests do not fit and are refused anyway. | Leave off. | `false` |
| `max_sessions` | `20000` (100 to 1000000) | Conversations Knock remembers. | Rarely. | `20000` |

After a gateway restart, Knock has not seen how existing conversations started, so risky tools in them
are refused ("history not seen"). Start a fresh conversation in that chat with `/new` (Hermes asks you
to confirm with `/approve`).

## Preflight options

The preflight check (`tools/preflight.py`) takes these command-line options. The shortcut from the
install guide (`bash ~/hearthward-preflight.sh`) already passes `--plugin-dir` and passes on any
option you add, for example `bash ~/hearthward-preflight.sh --heartbeat`.

| Option | What it does |
|---|---|
| `--plugin-dir DIR` | The installed guard folder to check. The install guide uses `~/.hermes/plugins/hearthward-guard`. |
| `--platform NAME` | Also check this chat platform (it is added from `owners` and `owner_chats` anyway). Can be repeated. |
| `--allow-toolset NAME` | Accept this toolset in `platform_toolsets` (default: only `no_mcp`). Can be repeated. |
| `--tools-cli` | Also run `hermes tools list --platform NAME` and fail if any tool is switched on there. |
| `--heartbeat` | Also check that a running gateway's guard wrote a fresh, healthy heartbeat. |
| `--heartbeat-dir DIR`, `--max-age SECONDS`, `--pid PID` | Where the heartbeat is, how old it may be (default 60), and which gateway process it must come from. |

Exit code 0 means every check passed, 1 means at least one `FAIL` line, 2 means the check itself could not
run.
