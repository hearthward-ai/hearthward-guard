# hearthward-guard

A Hermes Agent plugin that checks what reaches the model and what leaves it, and fails closed:

- **Threshold** checks inbound chat, quoted text, attachments, picture text and tool results for text
  aimed at the AI (rules, plus an optional tool-less model check).
- **Holds** keep suspicious messages for the owner, who answers `follow <id>` or `ignore <id>`.
- **Gatehouse** filters replies (secrets, hidden characters, data-carrying links).
- **Knock** decides which tool calls may run.

Settings live under `plugins.entries.hearthward-guard.settings`. The full reference is in
`hearthward_guard/common/config.py` (and `knock/config.py`). Run `tools/preflight.py` before the first start.

## Model check: limits

- **Partly checked text is held.** A long item is checked in up to `second_check.max_chunks` chunks
  (the first, the last, then the ones with the most rule signals; equal scores in random order). When
  some text was not checked, the item is held (`oversize: hold`, the default). The only exception is
  the owner's own typed chat, which is passed with taint. `oversize: taint` also taints (instead of
  holding) content the owner forwards; a stranger's partly checked text is always held.
- **Budgets.** Each non-owner may cause `calls_per_sender_10min` checker calls (default 12) and all
  non-owners together `calls_all_10min` (default 60). Over budget, the message is held without a call,
  so one sender cannot flood a shared local model. The owner is never refused. Scans, picture reading
  and model checks each run in their own small worker pool, and a check whose time ran out stops
  before its next call.
- **The check code is not a defence against a takeover.** The checker copies a one-time code back,
  which catches clumsy hijacks. A text that talks the checker into answering "none" and copying the
  code passes that test. Words aimed at a checker add a weak sign, but rewordings get past it. The
  model check lowers the risk; it is not proof.
- **A bad checker answer is held.** An answer that is not in the agreed shape (wrong check code, not one
  JSON object, cut off) counts as a hijacked checker, and the item is held without a retry.
  `second_check.tamper_retry: true` (off by default) allows ONE retry per message with a fresh code, only
  when the rules saw no sign at all, the text has no words aimed at a checker, and, for a non-owner's
  message, one more call fits the budget (owner messages and tool results get the retry without a budget
  check); a reply that asks for a tool is never retried, and a second bad answer is held. Turning it on gives a hijack a second try, aimed at
  exactly the texts the rules cannot see, so it is **not recommended**: leave it off.
- **Taking back your own message is not an attack.** Since prompt revision 3 (`prompt_id` `r3-...`) the
  checker is told that an explicit first-person retraction with nothing else asked ("ignore my last
  message, that was a typo", "我上一条发错了，请忽略") is fine. Without "my"/"我" ("ignore the previous
  one", "忽略上一条") outside content is at least suspicious, and when any inject rule applies (telling
  an AI what to do or how to summarise, a fake system message, a request for data) it is inject.
- **A lone "suspicious" answer taints inbound text; it does not hold it.** When the checker answers
  `suspicious` and the rules saw nothing, a quote or a file someone sends is passed on, and that turn
  is marked tainted, so Knock's taint rule blocks risky tools in it. A tool result (a web page or an
  email the agent fetched itself) with the same answer is withheld (`threshold.weak_action_content`).
  The reason: `weak_action_content` acts on rule signs, and a checker-only sign on inbound text counts
  like a chat sign (`weak_action`). Option, not built: count a `suspicious` answer from the content
  check as a content sign, so `weak_action_content: hold` also holds those quotes and files (more
  holds on ordinary forwarded text).
- **Fake system headers.** "【系统消息】", "系统通知：" and "System notice:" lines are a weak sign alone
  (shops and chat apps print them); with an approval claim or words about the assistant or its rules on
  the same line they are a medium sign, which holds attached or fetched text.

## Pictures: the scam shield

A picture never reaches the model while `threshold.unscanned_media` is `hold` (the default). With
`owners` or `allow` and no picture reader, pictures pass to the model unread. When a message carries a
picture and the reader is on, the guard:

1. reads the picture's text with an OCR engine (Tesseract), plus any text stored in the file itself
   (EXIF, XMP, PNG text chunks, JPEG comments);
2. checks that text like an attachment (rules, and the model check when one is configured) and for
   common scam signs in English and Chinese (payment or gift-card requests, codes and passwords,
   "click to verify", pressure, impersonation, prizes, investment promises and more);
3. skips the message and answers the sender with a short verdict: likely a scam (with the reasons in
   plain words), some warning signs, no clear signs, or no text found. When someone other than the
   owner sends a likely scam, the owner gets an alert (rate-limited).

"Likely a scam" needs strong evidence: an ask that honest notices do not make (codes, passwords, gift
cards, crypto, remote access, a log-in link), or pressure together with payment redirection or
impersonation. Bills, receipts, flyers and notices with an amount, a due date, "late fees" and a phone
number are not called scams (a fixed set of everyday zh/en examples is a test gate). A payment request
with a clickable link gets "some warning signs".

Text aimed at the AI, or a picture that cannot be read (a reader failure, a timeout, an unknown or
oversized file), is **held** for the owner like any other hold. Text stored in the file itself is held
on ONE weak sign (a role marker such as `assistant:`, many invisible or tag characters): ordinary picture files have no
reason to address an AI, while other attached text needs two. When the model check is down, paused or
busy, the sender is told the picture "can't be checked right now"; when the picture had too much text to
double-check in full, that it "has too much text to check in full". `follow <id>` passes the picture's
text on as data; the picture itself is never passed on. File reading, metadata and the engine run off
the gateway's event loop, in a small pool with one deadline; text stored in the file is read within a
fixed budget (characters, bytes inflated, items), so a crafted file cannot make the guard work for long.

**Engine.** Install Tesseract with the English and Simplified Chinese data, for example on Debian or
Ubuntu: `apt install tesseract-ocr tesseract-ocr-eng tesseract-ocr-chi-sim`. No Python OCR package is
needed. The engine runs as its own process: a fixed argument list (never a shell), the picture bytes
on stdin, a minimal environment, a time limit, and on Linux and macOS memory, CPU and no-file-write
limits. The file type and pixel count are checked from the header first (for GIF, every frame at its
own size, all frames together). The engine is found by absolute path only, never in the working folder.

**Windows.** The engine process has no memory limit on Windows, only the time and size limits. So under
`enabled: auto` the reader is **off** on Windows. To use it anyway, set `enabled: true` and
`engine_path` to the full path of `tesseract.exe` (only an `.exe` is accepted); `/guard` then says the
reader runs without a memory limit.

**Settings** (`ocr:`):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `auto` | `auto` = on when the engine is found (off on Windows); `true` = on (no engine: every picture is held); `false` = off |
| `engine_path` | `""` | Full path to the engine; empty = `tesseract` in an absolute PATH folder (Linux, macOS) |
| `tessdata_dir` | `""` | Language data folder; empty = the engine's own |
| `languages` | `[eng, chi_sim]` | Engine language codes; all must be installed |
| `timeout_s` | `20` | Time limit per picture |
| `memory_mb` | `1024` | Engine memory limit (Linux and macOS) |
| `max_bytes` / `max_pixels` | 10 MB / 40 M | Larger pictures are held unread |
| `max_pictures` | `4` | Per message (an SVG is scanned as text, not read by the picture reader) |
| `read_metadata` | `true` | Check text stored in the file too |
| `locale` | `en` | Verdicts and alerts: `en`, `zh` or `both` |
| `alert_owner` / `alerts_per_10min` | `true` / `6` | Owner alerts for likely scams from others |

With OCR off or no engine under `auto`, pictures follow `threshold.unscanned_media` (default: held).
`/guard` shows which applies, and `tools/preflight.py` prints an `OCR:` line: engine found or not,
where it came from (`ocr.engine_path` or PATH, never the path itself), its version and whether the
language data is installed.

**Limits.** OCR misses text that is very faint, tiny, rotated or handwritten, and it does not read QR
codes. A "no clear signs" verdict never means a picture is safe; the replies say so.

## Holds: notices to the owner

Each sender gets at most `holds.notices_per_sender_10min` hold notices, and the owner gets at most
`holds.owner_notices_10min` (default 10) for all senders together. Holds past the limit stay pending
without a notice; the next notice that goes out says how many were not announced, and `/guard` lists
every pending hold.

## Knock: "history not seen" after a restart

Knock keeps each conversation's state in memory. After a gateway restart it has not seen how the
existing conversations started, so it marks them "history not seen", and risky tool calls (act and exec)
in those chats are denied. This is on purpose: a conversation Knock did not watch from its start may
already carry outside text. To clear it, the owner starts a fresh conversation in that chat with `/new`
(Hermes asks to confirm with `/approve`). New chats after the restart are not affected.

## Version

0.9.3 (2026-11-18): fixes from the 0.9.2 lab run. A picture held only because its text was too long to
double-check in full now tells the sender so (en/zh), instead of "tries to give the assistant
instructions". One weak sign in text stored inside a picture file (EXIF, XMP, PNG text, JPEG comment)
now holds the picture. The inject canary probe is reworded without a hide-from-user phrase, so the
Hermes plugin scanner rates the plugin "safe" again (still answered `inject` by the local model).
Checker prompt revision 3 (`r3-...`): an explicit first-person retraction of the writer's own message is
not an attack; inject rules win, and content rule 8 covers summary steering. Fake system header rules.
A lone checker "suspicious" on inbound text taints the turn instead of holding it (documented above).
Invisible and tag characters in picture metadata are kept for the scan (they were blanked), and XMP
packet framing is no longer read as text. New opt-in `second_check.tamper_retry` (off by default, not
recommended): one retry after a bad checker answer. The
`ocr` setting description in `plugin.yaml` no longer says pictures never reach the model: in enforce
mode that holds while the reader is on or `threshold.unscanned_media` is `hold` (the default), not with
`owners` or `allow` and no reader, and not in report mode.

0.9.2 (2026-11-17): model-check prompt revision 1 (`prompt_id` `r1-...`: the checker is asked for
one-line JSON, to cut its answer time), preflight `OCR:` line, fictional phone numbers in every test
fixture.

## Review reports

Some test docstrings name review or lab reports (`reviews/...`). Those reports are not published; the
tests themselves state what they check.

## Licence

Apache-2.0.
