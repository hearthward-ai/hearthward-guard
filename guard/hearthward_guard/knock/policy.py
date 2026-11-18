"""Knock: a policy layer over Hermes's own tool approvals (documented pre_tool_call hook).

Knock never approves anything itself and never builds its own approval prompt. For each tool call
it returns one of:
  None                         let the call through (Hermes's own checks still apply)
  {"action": "block", ...}     deny, with a fixed message the model sees as the tool result
  {"action": "approve", ...}   hand the call to Hermes's native approval card (approvals.*)

Order of checks (first hit wins):
  1. guard unhealthy, Knock settings invalid, or any error  -> block (fail closed)
  2. never-allowed list (money, trading, passwords, ID numbers, saved logins, switching the guard
     off) -> block. It catches the plain forms of these actions; it is a net, not a boundary
     (review K-09). The real boundary for money is not giving the agent payment tools or keys.
  3. per-job / per-platform tool allowlists                 -> block if the tool is not listed
  4. the strictest of these that applies:
     - unsure (unknown tool, arguments too big to check, encoded commands) -> knock.unknown_tools
     - a tool with side effects after REMOTE outside content -> knock.taint (deny); tools whose
       effect outlives the session (memory, skills, schedules) are denied even under "ask"
     - a tool with side effects after LOCAL outside content only -> knock.local_taint (ask)
     - a private read (files, past sessions, home devices) in a stranger's turn -> knock.taint
     - a web fetch/search after private data was read in a tainted session -> as a side effect
     - a code-running tool in a clean session              -> knock.untainted_exec (ask)
     - another side-effect tool in a clean session         -> knock.untainted_acts (allow)
"ask" becomes the native card only when the owner really decides: the turn came from an owner
or a local surface, it is not a cron run, on a chat platform approvals.approvers names only
owners, approvals.mode is manual, no YOLO, no auto-approving unattended mode or room policy.
Otherwise "ask" is a block, and the block tells the owner which setting is missing.

Taint (Rule of Two). REMOTE outside content: a turn from someone who is not an owner, a cron
prompt not marked trusted, attachments and quoted/forwarded/channel text (also when Threshold
saw it at the gateway), a held message the owner released, a tainted parent agent, history Knock
did not see start or that changed outside a turn, and the output of every tool that brings in
text from elsewhere (web, other people, unknown tools). LOCAL outside content: the output of the
owner's own machine (terminal, local files, saved memory). A tool taints when it is let through,
before it runs. Nothing the model writes can clear taint.

The terminal rule (owner decision, fix round): terminal output is outside content, but the taint
follows its strength, not a blanket "one command per session". A read-only command (a short list
of reading commands, no redirection, chaining or substitution; git is not on it, recheck R-01) is
a private read: allowed in an owner's session even after outside content, and it marks the
session LOCAL. Any other terminal command, and any write or send after that, goes to the owner's
card. After REMOTE content the same steps are denied.

Origin (fix round 2, recheck R-04): LOCAL means "data from the owner's machine". A command or
script that names a network fetch (curl, git clone, pip install, a URL, an HTTP library), and a
read of a file such a command wrote (or of a downloads/attachment folder), is REMOTE. This is a
net, not a boundary: under LOCAL taint the owner's card is the only control, so read the card.
Every LOCAL mark also sets the "private data was read" flag (R-03).

What Knock cannot see (so "clean" means "nothing seen", not "nothing there", review K-02):
saved memory, context files, Honcho context and skill text that Hermes puts in the system
prompt; piped input and file references on local surfaces; text that Hermes mirrors into a
transcript without a turn (partly caught by the history check).
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict
from typing import Any, Mapping

from ..common import compat, messages
from ..common.config import ConfigError
from . import config as kconfig
from . import never, taint, tools
from . import state as kstate

LOCAL_SURFACES = frozenset({"cli", "tui", "desktop", "acp", "local"})
CRON = "cron"
_JOB_RX = re.compile(r"[A-Za-z0-9_-]{1,64}")
_CRON_SESSION_RX = re.compile(r"cron_([A-Za-z0-9-]{1,64})_\d{8}_\d{6}")
_GUARD_MARKER_RX = re.compile(r"<<<(?:end\s+)?(?:released|tool-output)\s+[0-9a-f]{12}>>>")
# text the gateway may inline into the owner's message: quotes, forwards, file contents, media
# descriptions (K-02; recheck R-06 added the quote line, "Replying to x:" and bracket notes about
# media). The real formats are a lab item: this is a guess that errs towards "outside text".
_INLINED_RX = re.compile(
    r"(?im)^\s*\[(?:replying\s+to|in\s+reply\s+to|quot(?:e|ed|ing)|forwarded|"
    r"content\s+of|contents\s+of|attach(?:ed|ment)|file|document|channel\s+context)\b"
    r"|^\s*\[[^\]\n]{0,60}\b(?:sent|shared|forwarded|attached|uploaded)\b[^\]\n]{0,60}\b(?:document|file|image|photo|"
    r"picture|video|voice|audio|sticker|attachment|location|contact|poll)"
    r"|^\s*\[(?:image|photo|picture|video|voice|audio|sticker)[^\]\n]{0,40}\b(?:description|transcript|caption|"
    r"message|note|text)\b"
    r"|^\s*\[(?:transcript|transcription|ocr)\b"
    r"|^\s*>(?!>)"
    r"|^\s*(?:replying\s+to|in\s+reply\s+to|quoting|forwarded\s+from)\s+[^\n]{1,80}:")
# Hermes 0.23.1 puts this line in front of the current gateway message (lab re-test 2026-11-17).
# Its real Discord form (gateway/run_inbound.py, discord_triggering_note; lab re-test 2 bug 1):
#   [Triggering message id: `<id>` — use as `message_id` for reply/react/pin via the discord tools.]
# followed by a blank line. Also the plain "[Triggering message id: <id>]". Exactly these, as a
# whole first line: the id is quoted with backticks or bare, the suffix is that exact text or absent.
_TRIGGER_ID = r"[0-9A-Za-z_.:-]{1,128}"
_TRIGGER_RX = re.compile(
    r"\[Triggering message id: (?:`" + _TRIGGER_ID + r"`|" + _TRIGGER_ID + r")"
    r"(?: — use as `message_id` for reply/react/pin via the discord tools\.)?\]"
    r"[ \t]*(?:\r?\n[ \t]*)*(?:\r?\n|\Z)")
# Hermes wraps a cron job's stored prompt in one bracketed note (lab re-test bug 9), then puts a
# run-time line after it (lab re-test 2 bug 4; cron/scheduler_prompt.py _run_time_line):
#   [CURRENT RUN TIME: Tuesday, 2026-11-17 15:35 CST (UTC-06:00)]
_CRON_WRAP_HEAD = "[IMPORTANT: You are running as a scheduled cron job"
_CRON_RUN_TIME_RX = re.compile(
    r"\[CURRENT RUN TIME: [A-Za-z]{3,9}, \d{4}-\d{2}-\d{2} \d{2}:\d{2}(?: [A-Za-z0-9+_/-]{1,32})?"
    r"(?: \(UTC[+-]\d{2}:\d{2}\))?\][ \t]*(?:\r?\n|\Z)")
_PERSON_MODES = frozenset({"deny", "manual"})
_MISSING = object()
RULE_PREFIX = "hw-knock"
CARD_MAX = 1500
OUTSIDE_NOTE_TTL = 1800.0          # a queued message can wait longer than 10 minutes (recheck R-06)
# one approved file edit covers a few more edits of the same file (recheck R-16, fix round 2)
GRANT_USES = 5
GRANT_TTL = 900.0
_DENIED_RX = re.compile(r"(?i)\b(denied|not approved|rejected|declined|blocked|cancell?ed|timed?\s*out|"
                        r"was not run|not allowed)\b")
_AUTORUN_PATH_RX = re.compile(r"(?i)(\.(service|timer|socket|desktop|plist|path)$|crontab|(^|/)\.?(bash_profile|"
                              r"bashrc|profile|zshrc|zprofile|login|xinitrc|xprofile|inputrc)$|(^|/)bin/|"
                              r"\.git/(hooks|config|info)|\.gitattributes$|\.gitmodules$|(^|/)etc/|autostart/|"
                              r"\.ssh/|\.pth$|sitecustomize\.py$|usercustomize\.py$|\.npmrc$|\.pypirc$)")
# Build and config-execution files (decision review picks 1 and 2): they run on a routine command
# later (make, npm install, pytest, a CI push), and that command's card does not show what they now do.
# Never granted, never shown IN PART.
_BUILD_PATH_RX = re.compile(
    r"(?i)(^|/)(makefile|gnumakefile|[^/]+\.mk|justfile|cmakelists\.txt|[^/]+\.cmake|package(-lock)?\.json|"
    r"pyproject\.toml|setup\.py|setup\.cfg|conftest\.py|pytest\.ini|tox\.ini|noxfile\.py|manage\.py|"
    r"requirements[^/]*\.(txt|in)|pipfile|gemfile|rakefile|build\.gradle(\.kts)?|settings\.gradle(\.kts)?|pom\.xml|"
    r"build\.rs|cargo\.toml|dockerfile|containerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml|\.envrc|"
    r"\.pre-commit-config\.ya?ml|\.gitlab-ci\.ya?ml|\.travis\.ya?ml|jenkinsfile|azure-pipelines\.ya?ml|"
    r"\.vscode/(tasks|launch|settings)\.json|\.devcontainer/.+|\.github/(workflows|actions)/.+|\.circleci/.+|"
    r"\.cargo/config(\.toml)?|\.bazelrc|build\.bazel|workspace(\.bazel)?|[^/]+\.config\.[cm]?[jt]s)$")
# ways a code-running call can start a file without naming its full name (decision review pick 5)
_IMPORT_RX = re.compile(r"(?:^|[\s;(:'\"])(?:from\s+([\w.]+)\s+import\s+\(?\s*([\w.,\s*]+)|"
                        r"import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*))")
_DYN_IMPORT_RX = re.compile(r"(?:__import__|import_module|run_module|run_path|find_spec|SourceFileLoader|"
                            r"spec_from_file_location|load_source)\s*\(\s*(?:['\"][\w.]*['\"]\s*,\s*)?"
                            r"['\"]([^'\"]{1,300})['\"]")
_MODULE_FLAG_RX = re.compile(r"(?:^|\s)-m\s*['\"]?([\w.]+)")
_RUN_FILE_RX = re.compile(r"(?:^|[;&|\s(`])(?:bash|sh|zsh|dash|ksh|fish|source|\.|exec|python[0-9.]*|py|pypy3?|"
                          r"perl|ruby|node|deno|bun|php|lua|Rscript|pwsh|powershell)\s+(?:-{1,2}[\w-]+\s+)*"
                          r"['\"]?([^\s;&|'\"`)]+)")
_TEST_RUNNER_RX = re.compile(r"(?:^|[;&|\s(/`])(?:pytest|py\.test|nose2|nosetests|tox|nox|ward|trial|make|just|"
                             r"(?:npm|pnpm|yarn|bun)\s+(?:test|t|run|install|i|ci)|"
                             r"-m\s*['\"]?(?:pytest|unittest|nose2|doctest|tox|nox))(?=$|[\s;&|)'\"`])")
_DOT_SLASH_RX = re.compile(r"(?:^|[;&|\s(`])\./([^\s;&|'\"`)]+)")
_TESTABLE_RX = re.compile(r"\.py[wi]?$")
_SAME_SERVICE = ("spotify_", "ha_", "kanban_")       # recheck R-16: a read and an act of one service
_CARD_FIRST = ("command", "cmd", "code", "script", "input", "url", "urls", "image_url", "path", "file_path",
               "target", "goal", "task", "context", "query", "to", "recipient", "channel_id", "chat_id", "text",
               "content", "body", "message", "old", "new")

BLOCK_NEVER = ("[Knock: the tool '{tool}' was not run. It looks like {label}, which this assistant is never "
               "allowed to do, even with approval. Tell the user you can't do this and that they should do it "
               "themselves.]")
BLOCK_LIST = ("[Knock: the tool '{tool}' was not run. It is not on the list of tools allowed here. "
              "Tell the user which tool you wanted to use.]")
BLOCK_TAINT = ("[Knock: the tool '{tool}' was not run. This conversation contains outside content ({why}), "
               "and this step is not allowed after that. Tell the user what you wanted to do "
               "so they can do it themselves or start a new conversation.]")
BLOCK_UNSURE = ("[Knock: the tool '{tool}' was not run because it could not be checked ({why}). "
                "Tell the user what you wanted to do.]")
BLOCK_NO_HUMAN = ("[Knock: the tool '{tool}' needs the owner's approval ({why}), but no owner can approve it "
                  "here ({gate}). Tell the user what you wanted to do.]")
BLOCK_NO_APPROVER = ("[Knock: the tool '{tool}' needs the owner's approval ({why}), but {gate}, so it was not run. "
                     "Tell the owner: to approve actions in this chat, set approvals.approvers in the Hermes "
                     "config to the owner's own id (owners only, not '*'), and keep the platform's admin lists "
                     "empty or owners only. Until then Knock refuses these actions here.]")
BLOCK_LONG = ("[Knock: the tool '{tool}' was not run: its arguments are too long to show in full on an approval "
              "card. Tell the user what you wanted to do, in smaller steps.]")
BLOCK_ERROR = "[Knock: the tool '{tool}' was not run because the safety check failed.]"
BLOCK_DOWN = "[Knock: the tool '{tool}' was not run because the safety guard is not running correctly.]"
ASK_TEXT = ("Knock: '{tool}' wants to run ({why}). Full arguments ({n} characters, untrusted, links "
            "defanged, check {sha}): {args}. Approve only if you asked for exactly this.")
# a file write too long for a card (recheck R-11): the file content is shown in part; commands,
# code and files that run by themselves (autorun, config, git hooks) are never shown in part
ASK_TEXT_PART = ("Knock: '{tool}' wants to write a file ({why}). Arguments ({n} characters, untrusted, links "
                 "defanged, check {sha}; the file content is shown IN PART, {hidden} characters not shown): "
                 "{args}. Approve only if you asked for this change.")
GRANT_NOTE = (" Approving also lets up to {uses} more edits of this same file in this conversation through "
              "without a card for {mins} minutes (not after content from outside).")
# Chat cards (lab re-test bug 3): Hermes cuts the card text on chat platforms (Discord: 300
# characters, _EA_REASON_BUDGET in 0.23.1) and still shows Approve. On a chat platform the whole
# card text must fit the platform's budget; the short wording below is tried, and when the full
# arguments still do not fit (a file write: its IN PART form) the call is refused, never cut.
ASK_COMPACT = ("Knock: '{tool}' wants to run ({why}). Full args, untrusted, check {sha}: {args}. "
               "Approve only if you asked for exactly this.")
ASK_COMPACT_PART = ("Knock: '{tool}' writes a file ({why}). Args, untrusted, check {sha}, content IN PART "
                    "({hidden} chars hidden): {args}. Approve only if you asked for this.")
GRANT_SHORT = " Approving also lets {uses} more edits of this file through for {mins} min."
BLOCK_LONG_CHAT = ("[Knock: the tool '{tool}' was not run: its arguments are too long to show in full on an "
                   "approval card in this chat (about {limit} characters fit here). Tell the user what you wanted "
                   "to do, in smaller steps; the owner can also run it from the terminal, where the card shows "
                   "more.]")
# card budget per chat platform, in characters, with room for markup escapes; an unknown chat
# platform gets the smallest known budget (all 0.23.1 adapters share the base renderer)
CHAT_CARD_LIMIT = 280
CARD_LIMITS = {"discord": 280}
_ESCAPED = "\\*_~|`>"


def default_card_limit(platform: str) -> int | None:
    """The most card text this platform shows in full; None = no limit below CARD_MAX (local
    surfaces: the CLI card showed 1,388 characters uncut in the lab)."""
    if platform in LOCAL_SURFACES:
        return None
    return CARD_LIMITS.get(platform, CHAT_CARD_LIMIT)


def _fits(msg: str, limit: int | None) -> bool:
    """Counts each character a chat renderer may escape twice."""
    return limit is None or len(msg) + sum(msg.count(c) for c in _ESCAPED) <= limit
NO_APPROVER = "no approver is set up for this chat"


def cron_job_id(task_id: str, session_id: str) -> str | None:
    """The cron job id from Hermes's cron task id ("cron:<job>:<run>") or session id."""
    if isinstance(task_id, str) and task_id.startswith("cron:"):
        parts = task_id.split(":")
        if len(parts) == 3 and _JOB_RX.fullmatch(parts[1]):
            return parts[1]
        return None
    if isinstance(session_id, str):
        m = _CRON_SESSION_RX.fullmatch(session_id)
        if m:
            return m.group(1)
    return None


def is_cron(platform: str, task_id: str, session_id: str) -> bool:
    return (platform == CRON or (isinstance(task_id, str) and task_id.startswith("cron:"))
            or (isinstance(session_id, str) and session_id.startswith("cron_")))


def _sha_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def cron_inner_prompt(text: str) -> str | None:
    """The job's own prompt inside Hermes's cron wrapper: the text after ONE leading bracketed note
    that starts with Hermes's cron wording (brackets inside it, such as "[SILENT]", are balanced),
    and after the one "[CURRENT RUN TIME: …]" line that may follow it. Nothing else is taken off
    (a script's output or a skill block stays, so the hash does not match). None when the text
    does not start that way."""
    if not isinstance(text, str):
        return None
    t = text.lstrip()
    if not t.startswith(_CRON_WRAP_HEAD):
        return None
    depth = 0
    for i, ch in enumerate(t[:4000]):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                rest = t[i + 1:].strip()
                m = _CRON_RUN_TIME_RX.match(rest)      # at most one run-time line, by its fixed shape
                return rest[m.end():].strip() if m else rest
    return None


# skill_manage in Hermes 0.23.1 (tools/skill_manager_tool.py): the advertised shape is
# {operations: [{action, name, ...}, ...]} (an op without a name uses the top-level name); the
# legacy flat shape {action, name, ...} is still accepted. Every action writes (lab re-test 2 bug 2).
_SKILL_ACTIONS = frozenset({"create", "edit", "patch", "delete", "write_file", "remove_file"})
_SKILL_NAME_KEYS = ("name", "skill", "skill_name", "absorbed_into", "new_name")
_SKILL_OPS_MAX = 64


def _skill_ops_touch(args, names) -> bool:
    """True when any skill_manage operation may change a pinned skill: an op that names one (also
    as "category/name", or as the skill a delete is absorbed into), or a file path that steps into
    one or upwards. Unknown shapes (operations not a list, an op that is not a mapping, an unknown
    or missing action, no skill name) also give True: a card, never a silent pass."""
    def named(v) -> bool:
        return isinstance(v, str) and v.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip() in names

    def path_hits(v) -> bool:
        if v in (None, ""):
            return False
        if not isinstance(v, str):
            return True
        segs = [s.strip() for s in v.replace("\\", "/").split("/")]
        return ".." in segs or any(s in names for s in segs)

    flat = "operations" not in args
    ops = [args] if flat else args.get("operations")
    if not isinstance(ops, (list, tuple)) or not ops or len(ops) > _SKILL_OPS_MAX:
        return True
    default = args.get("name")
    if any(named(args.get(k)) for k in _SKILL_NAME_KEYS):
        return True
    for op in ops:
        if not isinstance(op, Mapping):
            return True
        if op.get("action") not in _SKILL_ACTIONS:
            return True
        nm = op.get("name") or default
        if not isinstance(nm, str) or not nm.strip():
            return True
        if named(nm) or any(named(op.get(k)) for k in _SKILL_NAME_KEYS):
            return True
        if path_hits(op.get("file_path")):
            return True
    return False


def _shown_name(path: str) -> str:
    """A file edited under a grant, as shown on a card and in /guard: its folder and name
    ("kt-r2/notes.md", or "./notes.md"), so the name sits after a "/" and keeps its dot
    (lab re-test 2 bug 8: a bare "notes.md" was shown as "notes[.]md")."""
    segs = [s for s in str(path).replace("\\", "/").split("/") if s]
    if not segs:
        return "./"
    return "/".join(segs[-2:]) if len(segs) > 1 else "./" + segs[-1]


def _cron_prompt_matches(text: str, want: str) -> bool:
    """A trusted cron job's prompt hash matches the whole text, or the prompt inside Hermes's
    wrapper (lab re-test bug 9). Anything else Hermes adds (skills, script output) does not match."""
    if _sha_hex(text).startswith(want):
        return True
    inner = cron_inner_prompt(text)
    return bool(inner) and _sha_hex(inner).startswith(want)


def user_message_text(user_message) -> tuple[str, bool]:
    """(text, carries media or parts Knock cannot read). Any part that is not plain text counts
    as an attachment (review K-02 item 3)."""
    if user_message is None:
        return "", False
    if isinstance(user_message, str):
        return user_message, False
    if isinstance(user_message, (list, tuple)):
        out, media = [], False
        for part in user_message:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, Mapping):
                t = part.get("text")
                if part.get("type") != "text" or not isinstance(t, str):
                    media = True
                if isinstance(t, str):
                    out.append(t)
            else:
                media = True
        return "\n".join(out), media
    return str(user_message), True


_CALL_BLOCKS = frozenset({"tool_use", "tool_call", "function_call"})


def _calls_tools(m) -> bool:
    """An assistant message that calls tools: a tool_calls list, or content blocks of tool use."""
    if m.get("tool_calls"):
        return True
    c = m.get("content")
    return isinstance(c, (list, tuple)) and any(isinstance(b, Mapping) and b.get("type") in _CALL_BLOCKS for b in c)


def history_check(hist) -> tuple[int | None, str | None]:
    """(user messages in the history, reason if it looks changed outside a turn). A turn adds one
    user message, assistant messages that call tools (each followed by its results), interim
    assistant messages (an empty tool_calls list) and at most one plain assistant reply; a system
    message only at the start. Anything else was put there some other way (review K-02 item 2,
    recheck R-07)."""
    if hist is None:
        return 0, None
    if not isinstance(hist, (list, tuple)):
        return None, "history unreadable"
    changed = "history changed outside a turn"
    users, plain, prev = 0, 0, None
    for i, m in enumerate(hist):
        if not isinstance(m, Mapping):
            return users, "history unreadable"
        role = m.get("role")
        calls_prev = prev is not None and prev.get("role") == "assistant" and _calls_tools(prev)
        if calls_prev and role not in ("tool", "function"):
            if role == "assistant":                    # tool calls with no results, then more text
                return users, changed
        if role == "user":
            users, plain = users + 1, 0
        elif role == "assistant":
            if not _calls_tools(m) and "tool_calls" not in m:
                plain += 1
                if plain > 1:
                    return users, changed
        elif role in ("tool", "function"):
            if prev is None or not (calls_prev or prev.get("role") in ("tool", "function")):
                return users, changed                  # a result nobody asked for
        elif role == "system":
            if i != 0:
                return users, changed
        else:
            return users, changed
        prev = m
    return users, None


def _msg_text(m) -> str:
    c = m.get("content") if isinstance(m, Mapping) else None
    if isinstance(c, str):
        return c.strip()
    if isinstance(c, (list, tuple)):
        return "\n".join(str(b.get("text", "")) if isinstance(b, Mapping) else str(b) for b in c).strip()
    return ""


def _strip_trigger(text: str) -> str:
    """The user text without the one "[Triggering message id: …]" line Hermes puts in front of the
    current message (lab re-test 2026-11-17: the next turn stores the text without it). Only that
    exact prefix, once, at the very start."""
    m = _TRIGGER_RX.match(text)
    return text[m.end():].strip() if m else text


def _user_text(m) -> str:
    return _strip_trigger(_msg_text(m))


def _split_current(hist, text: str) -> tuple[Any, bool]:
    """(the history before this turn, the history ended with this turn's own message). Hermes
    0.23.1 passes the current user message as the last history entry (lab re-test 2026-11-17).
    Only that exact shape is taken off: a last user message whose text (trigger prefix aside) is
    this turn's text. Anything else stays and is counted and compared as history."""
    if not isinstance(hist, (list, tuple)) or not hist:
        return hist, False
    last = hist[-1]
    if not isinstance(last, Mapping) or last.get("role") != "user" or "tool_calls" in last:
        return hist, False
    want = _strip_trigger(text.strip()) if isinstance(text, str) else ""
    if not want or _user_text(last) != want:
        return hist, False
    return list(hist[:-1]), True


def _history_digest(hist) -> list:
    """Per message: a hash of the user and assistant text (tool results and a leading system
    message may be rewritten by Hermes itself, so they are not compared). User text is compared
    without Hermes's trigger prefix (lab re-test bug 2)."""
    out = []
    for i, m in enumerate(hist):
        role = m.get("role") if isinstance(m, Mapping) else None
        if role in ("user", "assistant"):
            body = _user_text(m) if role == "user" else _msg_text(m)
            out.append(hashlib.blake2b((role + "\0" + body).encode("utf-8", "surrogatepass"),
                                       digest_size=8).digest())
        else:
            out.append(b"")
    return out


def _text_hash(text) -> bytes:
    return hashlib.blake2b(" ".join(str(text).split()).encode("utf-8", "surrogatepass"), digest_size=8).digest()


def _approval_mode(v) -> str:
    """Mirror of Hermes's approvals.mode normalisation (YAML off = False; unknown word = manual).
    A missing value is Hermes 0.23.1's default, "smart" (lab re-test 2026-11-17), not manual."""
    if isinstance(v, bool):
        return "manual" if v else "off"
    if isinstance(v, str):
        s = v.strip().lower()
        return s if s in ("manual", "smart", "off") else "manual"
    return "smart" if v is None else "unknown"


MODE_FIX = "set it to manual with: hermes config set approvals.mode manual (then restart the gateway)"


def approvals_mode_problem(cfg) -> str | None:
    """A plain sentence for the owner when approvals.mode does not let a person answer the card,
    else None. Knock never changes the setting itself (lab re-test bug 12)."""
    ap = cfg.get("approvals") if isinstance(cfg, Mapping) else None
    if ap is None:
        ap = {}
    if not isinstance(ap, Mapping):
        return "the approvals settings in the Hermes config are unreadable"
    mode = _approval_mode(ap.get("mode"))
    if mode == "manual":
        return None
    if mode == "smart" and ap.get("mode") is None:
        return "approvals.mode is not set, so Hermes uses 'smart' (a model answers approval cards); " + MODE_FIX
    return f"approvals.mode is '{mode}' (no person answers approval cards); " + MODE_FIX


def default_gate_check() -> tuple[bool, str]:
    """Is the native approval card answered by a person right now? (False, why) when not or unsure.
    Runs on every ask: the answer depends on the session and turn (review K-06). A value counts as
    "a person decides" only when it is on a short list of known values; a boolean, an unknown word
    or a missing attribute means "not a person"."""
    cfg = compat.read_hermes_config()
    ap = cfg.get("approvals") or {}
    if not isinstance(ap, Mapping):
        return False, "approvals settings unreadable"
    mode = _approval_mode(ap.get("mode"))
    if mode != "manual":
        return False, f"approvals.mode is {mode}; {MODE_FIX}"
    for key in ("cron_mode", "single_query_mode", "unattended_mode"):
        v = ap.get(key, "deny")
        if not (isinstance(v, str) and v.strip().lower() in _PERSON_MODES):
            return False, f"approvals.{key} may auto-approve"
    if compat.yolo_env_on():
        return False, "YOLO mode"
    if compat.session_yolo():
        return False, "YOLO mode (session)"
    if compat.unattended_turn():
        return False, "unattended turn"
    room = compat.room_policy()
    if room is not None and _approval_mode(getattr(room, "approval_mode", _MISSING)) != "manual":
        return False, "room policy"
    return True, ""


def _approver_entries(raw, platform: str) -> list[str] | None:
    """User ids named in approvals.approvers for this platform; None when the setting is missing,
    '*' or unreadable. Accepts a list ('<id>' or '<platform>:<id>') or {platform: [ids]}."""
    if isinstance(raw, Mapping):
        raw = [f"{p}:{u}" for p, ids in raw.items() if isinstance(ids, (list, tuple)) for u in ids]
    if not isinstance(raw, (list, tuple)) or not raw:
        return None
    out = []
    for e in raw:
        if isinstance(e, bool) or not isinstance(e, (str, int)):
            return None
        s = str(e).strip()
        if not s or s == "*" or s.endswith(":*"):
            return None
        p, _, u = s.rpartition(":")
        if p and p.lower() != platform:
            continue
        out.append(u)
    return out or None


_ADMIN_KEY_RX = re.compile(r"(?i)admin")
# environment variables that may name platform admins (read one by one, never listed)
_ADMIN_ENV = ("_ALLOW_ADMIN_FROM", "_GROUP_ALLOW_ADMIN_FROM", "_ADMIN_USERS", "_ADMINS", "_ADMIN_IDS",
              "_ADMIN_USER_IDS")


def _id_list(v) -> list[str] | None:
    """User ids from a list or a comma/space separated string; None when unreadable."""
    if v is None or v is False or v == "" or v == [] or v == ():
        return []
    if isinstance(v, bool):              # "admins: true" and the like: cannot tell who
        return None
    if isinstance(v, (str, int)):
        v = [x for x in re.split(r"[,\s]+", str(v)) if x]
    if not isinstance(v, (list, tuple, set, frozenset)):
        return None
    out = []
    for e in v:
        if isinstance(e, bool) or not isinstance(e, (str, int)):
            return None
        s = str(e).strip()
        if s:
            out.append(s)
    return out


def _admin_entries(cfg, platform: str, env=None) -> list[str] | None:
    """Every user id that Hermes may treat as an admin of this platform (admins may answer approval
    cards, lab re-test R-14): any key with "admin" in its name under gateway.platforms.<p>,
    platforms.<p> or <p>, and inside their "extra"; plus the <PLATFORM>_ALLOW_ADMIN_FROM style
    environment variables in _ADMIN_ENV.
    '*' and '<platform>:<id>' entries are kept as written ('*' is never an owner). None when a value
    cannot be read (fail closed)."""
    import os
    out: list[str] = []
    bases = []
    if isinstance(cfg, Mapping):
        gw = cfg.get("gateway")
        for root in ((gw.get("platforms") if isinstance(gw, Mapping) else None), cfg.get("platforms"), cfg):
            if isinstance(root, Mapping):
                for k, v in root.items():
                    if str(k).lower() == platform and isinstance(v, Mapping):
                        bases.append(v)
    for b in list(bases):
        ex = b.get("extra")
        if isinstance(ex, Mapping):
            bases.append(ex)
    for b in bases:
        for k, v in b.items():
            if isinstance(k, str) and _ADMIN_KEY_RX.search(k):
                ids = _id_list(v)
                if ids is None:
                    return None
                out += ids
    pre = platform.upper()
    for name in _ADMIN_ENV:
        k = pre + name
        v = os.getenv(k) if env is None else env.get(k)
        if v:
            ids = _id_list(v)
            if ids is None:
                return None
            out += ids
    res = []
    for s in out:
        p, sep, u = s.rpartition(":")
        if sep and p and p.lower() == platform:
            s = u
        res.append(s)
    return res


class Knock:
    def __init__(self, settings: Any, guard, *, gate_check=default_gate_check, approver_check=None):
        self.guard = guard
        self.events = guard.events
        self.gate_check = gate_check
        self.approver_check = approver_check or self.default_approver_check
        self._lock = threading.Lock()
        self.counters = {"allowed": 0, "denied": 0, "never": 0, "asked": 0, "errors": 0, "turns": 0,
                         "args_changed": 0}
        self._outside: "OrderedDict[tuple, list]" = OrderedDict()
        self._checked: "OrderedDict[str, tuple]" = OrderedDict()
        # files whose content matched a never rule (or shown in part / edited under a grant), by path,
        # process-wide and kept on disk (recheck R-09, decision review pick 5)
        self._armed: "OrderedDict[str, tuple[str, str]]" = OrderedDict()
        # paths written by network fetches, process-wide and kept on disk: reading them is REMOTE
        # (recheck R-04, decision review pick 3)
        self._remote_paths: "OrderedDict[str, None]" = OrderedDict()
        # edits that went through under a grant, not yet shown on a card: session key -> [path, ...]
        self._grant_unshown: "OrderedDict[str, list]" = OrderedDict()
        self.grant_edits = 0
        self._last_grant_edit = ""
        # listed local skills whose SKILL.md no longer matches its pin (shown in /guard)
        self.skills_changed: set = set()
        data_dir = getattr(guard, "data_dir", "") or ""
        self.skills_dir = os.path.join(os.path.dirname(data_dir.rstrip("/\\")), "skills") if data_dir else ""
        self.state_path = kstate.path_for(data_dir)
        try:
            armed, remote = kstate.load(self.state_path)
            self._armed.update(armed)
            self._remote_paths.update((p, None) for p in remote)
        except kstate.StateError as e:
            guard.problems.append(f"knock state file {self.state_path}: {e}; fix it or move it away"[:300])
        # per session key: the history digest Knock saw at the last turn, and the replies it saw (R-07)
        self._hist: "OrderedDict[str, list]" = OrderedDict()
        self._replies: "OrderedDict[str, list]" = OrderedDict()
        # approved file edits: (session key, path) -> [uses left, expires] (recheck R-16)
        self._grants: "OrderedDict[tuple, list]" = OrderedDict()
        self._told_no_approver = False
        self.card_limit = default_card_limit          # characters a card shows in full, per platform
        self.setup_notice = None                      # approvals.mode notice for the owner (check_setup)
        raw = settings.get("knock") if isinstance(settings, Mapping) else None
        try:
            self.cfg = kconfig.parse(raw)
            self.ok = True
        except ConfigError as e:
            self.cfg, self.ok = kconfig.KnockConfig(), False
            guard.problems.append(f"config: {e}"[:300])
        except Exception as e:
            self.cfg, self.ok = kconfig.KnockConfig(), False
            guard.problems.append(f"config: knock unreadable ({type(e).__name__})")
        self.store = taint.TaintStore(self.cfg.max_sessions, clock=guard.clock)
        if self.cfg.unsafe:
            self.events.write("knock-unsafe-override", settings=list(self.cfg.unsafe),
                              disabled=list(self.cfg.disabled_builtins))
        if not self.cfg.enabled:
            self.events.write("knock-off")

    def _count(self, k: str) -> None:
        with self._lock:
            self.counters[k] = self.counters.get(k, 0) + 1

    # ------------------------------------------------------------------ Threshold -> Knock (K-02)
    def note_outside(self, platform, sender, why: str, text=None) -> None:
        """Threshold let a message through that carried outside text (quote, channel context,
        attachment, extra fields, weak score). With the message text (recheck R-06) the note is
        used up only by the turn that carries that text; until then every turn of this sender
        starts tainted too (fail closed: the owner's other chat may start first). Without the
        text the sender's next turn uses it up."""
        if not isinstance(platform, str) or sender in (None, ""):
            return
        key = (platform.lower(), str(sender))
        fp = " ".join(text.split())[:300] if isinstance(text, str) and text.strip() else None
        with self._lock:
            notes = [n for n in self._outside.pop(key, []) if n[0] >= self.guard.clock()][-20:]
            notes.append((self.guard.clock() + OUTSIDE_NOTE_TTL, why[:60], fp))
            self._outside[key] = notes
            while len(self._outside) > 5000:
                self._outside.popitem(last=False)

    def _take_outside(self, platform: str, sender, text: str = "") -> str | None:
        if sender in (None, ""):
            return None
        key = (platform.lower(), str(sender))
        flat = " ".join(text.split()) if isinstance(text, str) else ""
        now = self.guard.clock()
        with self._lock:
            notes = [n for n in self._outside.pop(key, []) if n[0] >= now]
            if not notes:
                return None
            hit = next((n for n in notes if n[2] is not None and n[2] in flat), None)
            if hit is None:
                hit = next((n for n in notes if n[2] is None), None)
            if hit is not None:
                notes.remove(hit)
                why = hit[1]
            else:                                   # the note's own turn has not come yet
                why = notes[-1][1] + ", pending for another message"
            if notes:
                self._outside[key] = notes
        return why

    # ------------------------------------------------------------------ pre_llm_call (observer)
    def on_pre_llm_call(self, session_id="", user_message=None, conversation_history=None, is_first_turn=False,
                        model="", platform="", sender_id="", task_id="", parent_session_id="", **kwargs):
        """Records who and what started this turn. Always returns None (never changes the turn)."""
        ks = []
        try:
            if not self.cfg.enabled:
                return None
            self._count("turns")
            exact = (platform if isinstance(platform, str) else "") or "?"
            plat = exact.lower()                      # lists compare lower case (review K-13)
            ks = taint.keys(session_id if isinstance(session_id, str) else "", "",
                            task_id if isinstance(task_id, str) else "")
            reasons: list[str] = []
            owner_turn = False
            text, media = user_message_text(user_message)
            if is_cron(plat, task_id, session_id):
                job = cron_job_id(task_id, session_id)
                if job is None or job not in self.cfg.trusted_cron_jobs:
                    reasons.append("cron prompt")
                else:
                    want = dict(self.cfg.trusted_cron_hashes).get(job)
                    if want and not _cron_prompt_matches(text, want):
                        reasons.append("cron prompt changed")          # review K-21
            elif exact in LOCAL_SURFACES:              # exact: "ACP" or "cli2" are not local
                owner_turn = True
            elif sender_id not in (None, "") and self.guard.cfg.is_owner(exact, sender_id):
                owner_turn = True
            else:
                reasons.append(taint.STRANGER)
            if media:
                reasons.append("attachment")
            if _GUARD_MARKER_RX.search(text):
                reasons.append("released or quoted guarded text")
            if _INLINED_RX.search(text):
                reasons.append("quoted or attached text")
            note = self._take_outside(plat, sender_id, text)
            if note:
                reasons.append("outside text in the message (" + note + ")")
            # the current message as the last history entry is Hermes's own shape (lab re-test bug 1):
            # it is not history. Counting and "seen from its start" use the history before it; the
            # digest keeps it, so a later rewrite of this message is still caught (bug 2: prefix).
            before, _own = _split_current(conversation_history, text)
            users, odd = history_check(before)
            if not odd:
                odd = history_check(conversation_history)[1]
            if not odd and ks:
                odd = self._history_changed(ks[0], conversation_history)
            if odd:
                reasons.append(odd)
            fresh = is_first_turn is True and not before
            parent = taint.keys(parent_session_id) if isinstance(parent_session_id, str) and parent_session_id else ()
            self.store.start_turn(ks, fresh=fresh, platform=plat, owner_turn=owner_turn, reasons=reasons,
                                  parent_keys=parent, history_users=users)
            if not ks:
                self.events.write("knock-turn-no-id", platform=plat)
            st = self.store.state(ks)
            self.events.write("knock-turn", platform=plat, state=st.label, reasons=st.reasons, owner=owner_turn)
        except Exception as e:
            self._count("errors")
            self.events.write("knock-turn-error", error=type(e).__name__)
            try:
                self.store.mark(ks, taint.CHECK_FAILED)        # counts as a stranger's turn (R-05)
            except Exception:
                pass
        return None

    # ---- history seen at the last turn, and the replies seen since (recheck R-07)
    def _history_changed(self, skey: str, hist) -> str | None:
        """Compare the history with what Knock saw: the part it saw at the last turn must be
        unchanged, and the last plain assistant reply must be one Knock saw go out (when it saw
        any reply for this session; transform_llm_output may not run on every surface)."""
        if not isinstance(hist, (list, tuple)) or not skey.startswith("s:"):
            return None
        digest = _history_digest(hist)
        with self._lock:
            prev = self._hist.get(skey)
            replies = list(self._replies.get(skey, []))
            self._hist[skey] = digest
            self._hist.move_to_end(skey)
            while len(self._hist) > 5000:
                self._hist.popitem(last=False)
        changed = "history changed outside a turn"
        if prev is not None:
            if len(digest) < len(prev) or any(a != b for a, b in zip(prev, digest) if a and b) or \
                    any(bool(a) != bool(b) for a, b in zip(prev, digest)):
                return changed
        if replies:
            last = next((m for m in reversed(hist) if isinstance(m, Mapping) and m.get("role") == "assistant"
                         and not _calls_tools(m) and _msg_text(m)), None)
            if last is not None and _text_hash(_msg_text(last)) not in replies:
                return changed
        return None

    def note_reply(self, session_id, *texts) -> None:
        """The final reply of a turn (transform_llm_output), before and after the guard's filter."""
        if not isinstance(session_id, str) or not session_id:
            return
        skey = "s:" + session_id[:256]
        hs = [_text_hash(t) for t in texts if isinstance(t, str) and t.strip()]
        if not hs:
            return
        with self._lock:
            lst = self._replies.get(skey, [])
            lst = (lst + [h for h in hs if h not in lst])[-8:]
            self._replies[skey] = lst
            self._replies.move_to_end(skey)
            while len(self._replies) > 5000:
                self._replies.popitem(last=False)

    # ------------------------------------------------------------------ pre_tool_call (policy)
    def on_pre_tool_call(self, tool_name="", args=None, task_id="", session_id="", tool_call_id="", turn_id="",
                         conversation_id="", **kwargs):
        tool = "?"
        try:
            tool = messages.defuse(str(tool_name or "?"), 60) or "?"
            return self._decide(tool_name, args, task_id, session_id, conversation_id, tool, tool_call_id)
        except Exception as e:
            self._count("errors")
            self.events.write("knock-error", tool=tool, error=type(e).__name__)
            if not self.guard.enforce:
                return None
            return {"action": "block", "message": BLOCK_ERROR.format(tool=tool)}

    def _block(self, kind: str, message: str, tool: str, **log):
        self._count("never" if kind == "never" else "denied")
        self.events.write("knock", decision="block", why=kind, tool=tool, **log)
        if not self.guard.enforce:
            return None
        return {"action": "block", "message": message}

    def _decide(self, tool_name, args, task_id, session_id, conversation_id, tool, tool_call_id=""):
        g = self.guard
        g.late_probe()
        if not g.healthy or not self.ok:
            return self._block("down", BLOCK_DOWN.format(tool=tool), tool)
        if not self.cfg.enabled:
            return None
        c = self.cfg
        name = tool_name if isinstance(tool_name, str) else ""
        task_id = task_id if isinstance(task_id, str) else ""
        session_id = session_id if isinstance(session_id, str) else ""
        conversation_id = conversation_id if isinstance(conversation_id, str) else ""
        if args is None:
            args = {}
        mapping = isinstance(args, Mapping)
        ks = taint.keys(session_id, conversation_id, task_id)
        skey = ks[0] if ks and ks[0].startswith("s:") else ""
        if session_id and conversation_id and conversation_id != session_id:
            self.store.adopt("s:" + session_id[:256], "s:" + conversation_id[:256])
        self.store.link(ks)
        st = self.store.state(ks)
        cls = tools.classify(name, c.tools)
        user_cls = tools.user_classed(name, c.tools)
        # reads that start nothing new: a read-only command reads the owner's machine (a private
        # read, not an action); so does listing or polling an approved background process (R-16)
        ro_cmd = cls == tools.ACT_SOURCE and not user_cls and tools.read_only_command(name, args)
        proc_read = cls == tools.ACT_SOURCE and not user_cls and tools.process_read(name, args)
        reads = ro_cmd or proc_read
        trivial = ro_cmd and tools.trivial_command(name, args)
        # a web tool aimed at a local file, loopback or the home network reads the owner's own
        # machine (recheck R-05)
        net_local = cls == tools.NET and not user_cls and tools.local_target(args)
        eff = tools.PRIVATE if reads else cls
        acts = tools.acts(eff)
        # inner calls of execute_code arrive without a session id (lab item 8): fail closed
        no_sid = not session_id
        tainted = (not st.clean) or no_sid
        remote = st.remote or no_sid
        # a session Knock never saw a turn for counts as a stranger's (recheck R-05)
        stranger = st.stranger or no_sid or not st.seen_turn
        log = {"cls": eff, "state": "no-session" if no_sid else st.label, "taint": st.reasons}

        # 1. never-allowed list (no approval unlocks it)
        unsure = []
        if not mapping:
            unsure.append("arguments are not a mapping")
        soft = None
        try:
            ex = False if reads else tools.executes(cls, name, args, c.tools)
            found = never.check_rule(c.never_rules, name, args, ex, cls == tools.READ, acts=acts)
        except never.Unscannable as e:
            found = None
            unsure.append(str(e))
        # a file whose content looks like an action that runs elsewhere (a payment call in shop
        # code, a password form in a test): writing it does not run it. It goes to the card, and
        # running it later in this session is never allowed (recheck R-10, review K-09)
        if found and not found[1] and name in tools.FILE_WRITERS and found[0].arg_scope == "exec" and found[0].builtin                 and mapping and not _autorun_path(args) and not _config_path(args):
            soft, found = found[0], None
        hit = (found[0].rid, found[0].label) if found else None
        if hit is None and name in tools.CODE_RUNNERS and mapping and not reads:
            hit = self._runs_armed_file(args)
        if hit:
            return self._block("never", BLOCK_NEVER.format(tool=tool, label=hit[1]), tool, rule=hit[0], **log)

        # 2. allowlists
        listed, key = self._allowlisted(name, task_id, session_id, st.platform)
        if not listed:
            return self._block("allowlist", BLOCK_LIST.format(tool=tool), tool, list=key, **log)

        # 3. decide deny / ask / allow (the strictest that applies)
        if cls == tools.UNKNOWN:
            unsure.append("unknown tool")
        elif name in tools.CODE_RUNNERS and acts and not unsure:
            try:
                if never.obfuscated(args):
                    unsure.append("encoded command")
            except never.Unscannable as e:
                unsure.append(str(e))
        why_taint = self._why(st.reasons, no_sid)
        wants = []                                   # (policy, kind, why)
        if unsure:
            wants.append((c.unknown_tools, "unsure", "; ".join(unsure)))
        if soft is not None:
            wants.append(("ask", "content", f"the file content looks like {soft.label}; writing it does not run it"))
        if mapping and self._edits_local_skill(name, args):
            wants.append(("ask", "act", "changes a skill listed in knock.local_skills (its pin must be updated)"))
        if acts and tainted:
            if remote:
                lasting = name in tools.PERSISTENT or (name in tools.FILE_WRITERS and
                                                       (_config_path(args) or _autorun_path(args)))
                if lasting:
                    wants.append(("deny", "taint", why_taint))
                elif self._same_service(name, st):
                    wants.append((c.local_taint, "taint", why_taint + "; same service"))
                else:
                    wants.append((c.taint, "taint", why_taint))
            else:
                wants.append((c.local_taint, "taint", why_taint))
        elif acts and name in tools.CODE_RUNNERS:
            wants.append((c.untainted_exec, "exec", "runs a command or code"))
        elif acts:
            wants.append((c.untainted_acts, "act", "action with side effects"))
        if eff == tools.PRIVATE and stranger:
            wants.append((c.taint, "private", "reads private data in a turn from someone who is not an owner"))
        if net_local:
            if stranger:
                wants.append((c.taint, "private", "reads the owner's machine or home network in a turn from "
                                                  "someone who is not an owner"))
            elif tainted:
                wants.append((c.taint if remote else c.local_taint, "send",
                              "reaches the owner's machine or home network after outside content; " + why_taint))
        if eff == tools.NET and tainted and st.private_read:
            wants.append((c.taint if remote else c.local_taint, "send",
                          "sends text off the machine after private data was read; " + why_taint))
        if eff == tools.NET and mapping:
            try:
                sk = _net_secret(args)
            except never.Unscannable as e:
                sk = None
                wants.append((c.unknown_tools, "unsure", str(e)))
            if sk:
                wants.append(("deny", "send", "the request carries what looks like a secret (" + sk + ")"))
        decision, kind, why = "allow", "", ""
        for pol, k, w in wants:
            if pol == "deny":
                decision, kind, why = "deny", k, w
                break
            if pol == "ask" and decision == "allow":
                decision, kind, why = "ask", k, w
        if decision == "deny":
            msg = (BLOCK_UNSURE if kind == "unsure" else BLOCK_TAINT).format(tool=tool, why=messages.defuse(why, 200))
            return self._block(kind, msg, tool, **log)
        only_local_taint = decision == "ask" and all(k == "taint" for p, k, _w in wants if p != "allow") \
            and not remote and not stranger and not no_sid
        # grants and IN PART cards: only where the whole card is shown (CLI, TUI; chat platforms only
        # when the owner switched them on after the lab check), never for a file that runs or builds
        # (decision review picks 1 and 2)
        extras_ok = st.platform in LOCAL_SURFACES or c.chat_grants_and_partial
        runs_later = name in tools.FILE_WRITERS and mapping and _runs_later(cls, name, args, c.tools)
        grant = self._grant_key(skey, name, args) if (only_local_taint and extras_ok and not runs_later) else None
        if grant is not None and self._use_grant(grant):
            decision = "allow"                       # the owner approved this file's edits (R-16)
            log["grant"] = True
            self._note_grant_edit(skey, grant[1])
        card = ""
        if decision == "ask":
            if no_sid:
                return self._block("no-human", BLOCK_NO_HUMAN.format(tool=tool, why=messages.defuse(why, 200),
                                                                     gate="no session id"), tool, **log)
            ok, no, approver = self._human_gate(st, task_id, session_id)
            if not ok:
                tmpl = BLOCK_NO_APPROVER if approver else BLOCK_NO_HUMAN
                return self._block("no-approver" if approver else "no-human",
                                   tmpl.format(tool=tool, why=messages.defuse(why, 200), gate=no), tool, gate=no, **log)
            part_ok = name in tools.FILE_WRITERS and mapping and extras_ok and not runs_later
            if name in tools.CODE_RUNNERS and mapping:
                kinds = self._runs_partial_file(args)
                if "granted" in kinds:
                    why = "it runs a file that was edited without a card, under a grant; " + why
                if "partial" in kinds:
                    why = "it runs a file whose content an earlier card showed only in part; " + why
            unshown = self._grant_edits(skey)
            if unshown:
                why = (f"{len(unshown)} earlier edit(s) went through without a card, under a grant: "
                       + ", ".join(dict.fromkeys(_shown_name(p) for p in unshown)) + "; " + why)
            card = self._card_message(tool, why, _args_sha(args), args, part_ok,
                                      grant is not None and bool(tool_call_id), st.platform)
            if card is None:
                if self._card(args, part_ok) is None:
                    return self._block("too-long", BLOCK_LONG.format(tool=tool), tool, **log)
                limit = self._safe_limit(st.platform)
                return self._block("too-long", BLOCK_LONG_CHAT.format(tool=tool, limit=limit), tool,
                                   platform_limit=limit, **log)
            if unshown:
                self._grant_edits(skey, clear=True)          # shown on this card

        # allowed or escalated: a tool that brings in outside content taints the session first
        if name == "delegate_task" and ks:
            self.store.snapshot_for_children(ks)           # the child gets the state from before (K-05)
        if ks and not trivial:
            fetch = name in tools.CODE_RUNNERS and mapping and not reads and tools.fetches(args)
            if fetch:
                self._add_remote_paths(args)
            from_net = fetch or self._names_remote_path(name, args)
            reason = self._taint_reason(name, eff, from_net, args)
            if tools.taints(eff) or name in tools.RETURNS_LOCAL or name in tools.RETURNS_REMOTE or net_local:
                self.store.mark(ks, reason)
                if eff == tools.PRIVATE or net_local or taint.is_local(reason):
                    self.store.mark_private_read(ks)       # every LOCAL mark (recheck R-03)
        if name in tools.FILE_WRITERS and mapping:
            self._arm_file(args, "granted" if log.get("grant") else ("partial" if card and card[1] > 0 else None))
        sha = _args_sha(args)
        # a grant starts only when the card that was shown said so
        offer = grant if (decision == "ask" and grant is not None and tool_call_id and card and card[2]) else None
        self._remember(tool_call_id, sha, ks, offer)
        if decision == "ask":
            self._count("asked")
            rule_key = self._rule_key(name, kind, sha, session_id, st.clean and not no_sid)
            self.events.write("knock", decision="ask", why=kind, tool=tool, **log)
            if not g.enforce:
                return None
            return {"action": "approve", "rule_key": rule_key, "message": card[0]}
        self._count("allowed")
        self.events.write("knock", decision="allow", tool=tool, **log)
        return None

    # ---- a payload written to a file, then run (review K-09): the write may be fine (a note may
    # mention paying a bill), running a file whose content matches a never rule is not. Only for
    # writes that were let through or put on a card (recheck R-09); read-only commands (wc, cat) are
    # not running it. Decision review pick 5: by path, process-wide and kept on disk (a new
    # conversation or a restart does not forget), and every way of starting the file counts: its name
    # with or without the extension, python -m, import/from in the code that runs, bash/source, a test
    # runner or build command over its folder, and a file the bot wrote that imports it.
    def _arm_file(self, args, kind: str | None = None) -> None:
        try:
            hit = never.check(self.cfg.never_rules, "", args, True, False, acts=True)
        except never.Unscannable:
            hit = ("unsure", "running a file that could not be checked")
        paths = [p for p in tools.arg_paths(args) if len(p.rsplit("/", 1)[-1]) >= 3]
        if not paths:
            return
        if not hit:
            # a file that imports an armed file runs it too (main.py with "import pay")
            try:
                text = never.flatten(args)
            except Exception:
                text = ""
            with self._lock:
                armed = list(self._armed.items())
            inherited = next((h for p, h in armed if h[0] not in ("partial", "granted")
                              and _stem(p) in _imported_stems(text)), None)
            hit = inherited or ((kind, "") if kind else None)
        if not hit:
            return
        with self._lock:
            for p in paths:
                old = self._armed.get(p)
                self._armed[p] = hit if (old is None or old[0] in ("partial", "granted")) else old
                self._armed.move_to_end(p)
            while len(self._armed) > kstate.MAX_ARMED:
                self._armed.popitem(last=False)
        self._save_state()

    def _armed_hits(self, args):
        with self._lock:
            armed = list(self._armed.items())
        if not armed:
            return []
        words = tools.path_words(args)[:2000]
        try:
            text = never.flatten(args)[:200_000]
        except Exception:
            text = ""
        stems = _imported_stems(text) | _imported_stems_on_disk(text, args)
        run_targets = {_stem(t) for t in _RUN_FILE_RX.findall(text) + _DOT_SLASH_RX.findall(text)} | \
            {_stem(w) for w in words if w.startswith(("./", "/", "~/")) and "." not in w.rsplit("/", 1)[-1]}
        runner_roots = _runner_roots(text, args)
        out = []
        for path, hit in armed:
            base = path.rsplit("/", 1)[-1]
            stem = _stem(path)
            if any(w == path or w == base or w.endswith("/" + base) or
                   (any(ch in w for ch in "*?[") and (fnmatch.fnmatchcase(base, w.rsplit("/", 1)[-1])
                                                      or fnmatch.fnmatchcase(path, w))) for w in words):
                out.append(hit)
            elif len(stem) >= 2 and (stem in stems or stem in run_targets):
                out.append(hit)
            elif runner_roots is not None and _TESTABLE_RX.search(base) and _in_scope(path, runner_roots):
                out.append(hit)
        return out

    def _runs_armed_file(self, args):
        return next((h for h in self._armed_hits(args) if h[0] not in ("partial", "granted")), None)

    def _runs_partial_file(self, args) -> set:
        return {h[0] for h in self._armed_hits(args) if h[0] in ("partial", "granted")}

    # ---- edits under a grant are shown (decision review pick 1)
    def _note_grant_edit(self, skey: str, path: str) -> None:
        with self._lock:
            self.grant_edits += 1
            self._last_grant_edit = path
            lst = self._grant_unshown.pop(skey, [])
            lst.append(path)
            self._grant_unshown[skey] = lst[-50:]
            while len(self._grant_unshown) > 2000:
                self._grant_unshown.popitem(last=False)
        self.events.write("knock-grant-edit", path=messages.defuse(path, 120, keep_paths=True))

    def _grant_edits(self, skey: str, clear: bool = False) -> list:
        with self._lock:
            if clear:
                return self._grant_unshown.pop(skey, [])
            return list(self._grant_unshown.get(skey, []))

    # ---- the owner's own skills, pinned by name and SKILL.md hash (decision review pick 4)
    def _edits_local_skill(self, name: str, args) -> bool:
        names = self.cfg.local_skills
        if not names:
            return False
        if name == "skill_manage":
            return _skill_ops_touch(args, names)
        if name in tools.FILE_WRITERS:
            for p in tools.arg_paths(args):
                segs = p.split("/")
                if "skills" in segs and any(sg in names for sg in segs[segs.index("skills") + 1:]):
                    return True
        return False

    def _local_skill_ok(self, args) -> bool:
        if not isinstance(args, Mapping) or set(args) - {"name", "file_path"}:
            return False
        nm = args.get("name")
        pins = dict(self.cfg.local_skill_pins)
        if not isinstance(nm, str) or nm not in pins:
            return False
        if args.get("file_path") not in (None, ""):
            return False                              # a skill's sub-file is outside content
        h = self._skill_hash(nm)
        ok = h is not None and h.startswith(pins[nm])
        with self._lock:
            (self.skills_changed.discard if ok else self.skills_changed.add)(nm)
        if not ok:
            self.events.write("knock-local-skill-changed", skill=nm, found=h is not None)
        return ok

    def _skill_hash(self, name: str) -> str | None:
        """sha256 of the one SKILL.md that belongs to this name (its folder name or its front-matter
        name) under the Hermes skills folder; None when there is none, or more than one."""
        root = self.skills_dir
        if not root or not os.path.isdir(root):
            return None
        found, seen = [], 0
        for d, subdirs, files in os.walk(root):
            if d[len(root):].count(os.sep) >= 4:
                subdirs[:] = []
            if "SKILL.md" not in files:
                continue
            seen += 1
            if seen > 2000:
                return None
            f = os.path.join(d, "SKILL.md")
            try:
                with open(f, "rb") as fh:
                    head = fh.read(2048)
            except OSError:
                continue
            fm = re.search(rb"(?m)^name:\s*['\"]?([^'\"\r\n]+?)['\"]?\s*$", head)
            if os.path.basename(d) == name or (fm and fm.group(1).decode("utf-8", "replace") == name):
                found.append(f)
        if len(found) != 1:
            return None
        try:
            with open(found[0], "rb") as fh:
                return hashlib.sha256(fh.read(5_000_001)).hexdigest()
        except OSError:
            return None

    # ---- on-disk memory (decision review picks 3 and 5)
    def _save_state(self) -> None:
        if not self.state_path:
            return
        with self._lock:
            armed = list(self._armed.items())
            remote = list(self._remote_paths)
        try:
            kstate.save(self.state_path, armed, remote)
        except Exception as e:
            self.events.write("knock-state-write-error", error=type(e).__name__)

    # ---- data origin (recheck R-04)
    def _add_remote_paths(self, args) -> None:
        outs = tools.fetch_outputs(args)
        wd = args.get("workdir") or args.get("cwd")
        if isinstance(wd, str) and wd.strip():
            wd = tools.norm_path(wd)
            outs += [wd + "/" + p for p in outs if not p.startswith(("/", "~"))]
        if not outs:
            return
        with self._lock:
            for p in outs:
                self._remote_paths[p] = None
                self._remote_paths.move_to_end(p)
            while len(self._remote_paths) > kstate.MAX_REMOTE:
                self._remote_paths.popitem(last=False)
        self._save_state()

    def _is_remote_path(self, p: str, entries) -> bool:
        if tools.REMOTE_DIR_RX.search(p):
            return True
        for e in entries:
            if p == e or p.startswith(e + "/"):
                return True
            if not e.startswith(("/", "~")) and (p.endswith("/" + e) or ("/" + e + "/") in p):
                return True
        return False

    def _names_remote_path(self, name: str, args) -> bool:
        if not isinstance(args, Mapping):
            return False
        if name in tools.CODE_RUNNERS:
            words = [w for w in tools.path_words(args)[:300] if "/" in w or "." in w]
        elif name in tools.LOCAL_SOURCES or name in tools.BUILTIN and tools.BUILTIN[name] == tools.PRIVATE:
            words = tools.arg_paths(args)
        else:
            return False
        with self._lock:
            entries = list(self._remote_paths)
        return any(self._is_remote_path(w, entries) for w in words)

    @staticmethod
    def _same_service(name: str, st) -> bool:
        """After a read of one service (Spotify search, Home Assistant states, kanban), an act of the
        same service goes to the card instead of being denied (recheck R-16). Only when every
        REMOTE reason is that service's own output."""
        pre = next((p for p in _SAME_SERVICE if name.startswith(p)), None)
        if pre is None or st.stranger or not st.reasons or len(st.reasons) >= taint.MAX_REASONS:
            return False
        return all(taint.is_local(r) or r.startswith("output of " + pre) for r in st.reasons)

    # ---- one approved file edit covers a few more edits of the same file (recheck R-16)
    @staticmethod
    def _grant_key(skey: str, name: str, args):
        if not skey or name not in tools.FILE_WRITERS or not isinstance(args, Mapping):
            return None
        paths = tools.arg_paths(args)
        if len(paths) != 1 or _config_path(args) or _autorun_path(args):
            return None
        return (skey, paths[0])

    def _use_grant(self, key) -> bool:
        now = self.guard.clock()
        with self._lock:
            g = self._grants.get(key)
            if g is None or g[1] < now or g[0] <= 0:
                self._grants.pop(key, None)
                return False
            g[0] -= 1
            return True

    @staticmethod
    def _why(reasons, no_sid: bool) -> str:
        if no_sid:
            return "call without a session id"
        if not reasons:
            return "history not seen from its start"
        return ", ".join(r[len(taint.LOCAL_PREFIX):] if taint.is_local(r) else r for r in reasons)

    def _taint_reason(self, name: str, cls: str, from_net: bool = False, args=None) -> str:
        label = name if tools._NAME_OK.fullmatch(name or "") else f"a tool of class {cls}"   # K-08: no raw text
        if from_net:
            return "output of " + label + " (network or downloaded data)"
        if name in tools.LOCAL_SOURCES or name in tools.RETURNS_LOCAL:
            return taint.LOCAL_PREFIX + "output of " + label
        if name == "skill_view" and self._local_skill_ok(args):
            return taint.LOCAL_PREFIX + "output of " + label          # pinned and unchanged (pick 4)
        return "output of " + label

    def _allowlisted(self, name: str, task_id: str, session_id: str, platform: str) -> tuple[bool, str]:
        lists = self.cfg.job_allowlists
        if not lists:
            return True, ""
        cron = is_cron(platform, task_id, session_id)
        job = cron_job_id(task_id, session_id) if cron else None
        plat_known = platform not in ("", "?")
        named = {k[9:] for k, _g in lists if k.startswith("platform:")}
        for key, globs in lists:
            if key == "*":
                applies = True
            elif key.startswith("platform:"):
                # an unknown or mistyped platform gets every platform list (review K-13)
                applies = (not plat_known) or key[9:] == platform or (platform not in named and
                                                                      platform not in LOCAL_SURFACES)
            elif key == "cron:*":
                applies = cron
            else:                                    # cron:<job id>; unknown job id -> every job list applies
                applies = cron and (job is None or key[5:] == job)
            if applies and not any(fnmatch.fnmatchcase(name, gl) for gl in globs):
                return False, key
        return True, ""

    def default_approver_check(self, platform: str) -> tuple[bool, str]:
        """Owner decision (b): on a chat platform the card may only go out when approvals.approvers
        is set and names owners only. Hermes defaults it to '*' (any member answers, lab item 5)."""
        if platform in LOCAL_SURFACES:
            return True, ""
        cfg = compat.read_hermes_config()
        ap = cfg.get("approvals") or {}
        ids = _approver_entries(ap.get("approvers") if isinstance(ap, Mapping) else None, platform)
        if ids is None:
            return False, NO_APPROVER
        if not all(self.guard.cfg.is_owner(platform, u) for u in ids):
            return False, "approvals.approvers names someone who is not an owner"
        # Hermes also lets platform admins answer a card (lab re-test R-14): every admin list for
        # this platform must be empty or owners only, in DMs and in groups
        admins = _admin_entries(cfg, platform)
        if admins is None:
            return False, f"an admin setting for {platform} could not be checked (admins may answer cards)"
        if not all(self.guard.cfg.is_owner(platform, u) for u in admins):
            return False, (f"a {platform} admin list (allow_admin_from / group_allow_admin_from) names someone "
                           "who is not an owner, and admins may answer cards")
        return True, ""

    def _human_gate(self, st, task_id: str, session_id: str) -> tuple[bool, str, bool]:
        """(a person decides, why not, the missing piece is the approver setting)."""
        if is_cron(st.platform, task_id, session_id):
            return False, "cron run", False
        if not st.owner_turn:
            return False, "turn not from an owner", False
        try:
            ok, no = self.approver_check(st.platform)
            ok, no = ok is True, str(no)[:200]
        except Exception as e:
            ok, no = False, f"approver settings unverifiable ({type(e).__name__})"
        if not ok:
            if not self._told_no_approver:
                self._told_no_approver = True
                self.events.write("knock-no-approver", platform=st.platform, why=no)
            return False, no, True
        try:                         # no cache: the answer depends on this session and turn (K-06)
            res = self.gate_check()
            return bool(res[0] is True), str(res[1])[:200], False
        except Exception as e:
            return False, f"approval settings unverifiable ({type(e).__name__})", False

    def _safe_limit(self, platform: str):
        try:
            return self.card_limit(platform) or CARD_MAX
        except Exception:
            return CHAT_CARD_LIMIT

    def check_setup(self) -> str | None:
        """At load (real Hermes only): does approvals.mode let a person answer the card? The answer
        is kept as a plain notice for /guard, the event log and one message to the owner. Knock
        keeps refusing cards until the owner fixes it; it never changes the setting itself."""
        if not self.cfg.enabled or not self.cfg.asks:
            return None
        try:
            note = approvals_mode_problem(compat.read_hermes_config())
        except Exception as e:
            note = f"the Hermes approval settings could not be read ({type(e).__name__})"
        self.setup_notice = ("Knock refuses every action that needs your approval: " + note) if note else None
        if self.setup_notice:
            self.events.write("knock-setup", notice=self.setup_notice)
        return self.setup_notice

    def _rule_key(self, name: str, kind: str, sha: str, session_id: str, clean: bool = False) -> str:
        """Hermes stores an "always" answer for good in config.yaml (lab item 6). call scope: the key
        is bound to these exact arguments plus a nonce, so "always" never matches again. tool scope
        (needs unsafe_override): this session, this tool, today only; never for taint asks (K-08)
        and only while the session is clean (recheck R-12)."""
        safe = name if tools._NAME_OK.fullmatch(name or "") else "x" + hashlib.sha256(
            (name or "").encode("utf-8", "surrogatepass")).hexdigest()[:12]
        if self.cfg.ask_scope == "tool" and kind != "taint" and clean:
            sess = hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()[:10]
            return f"{RULE_PREFIX}:{safe}:{kind}:{sess}:{time.strftime('%Y%m%d')}"
        return f"{RULE_PREFIX}:{safe}:{kind}:{sha[:12]}:{secrets.token_hex(6)}"

    @staticmethod
    def _card(args, part_ok: bool = False) -> tuple[int, str, int] | None:
        """(characters, card text, characters not shown). All arguments, the fields that matter
        first, defanged and on one line; None when they do not fit on a card (review K-07: the
        Hermes card shows only this text, lab item 6). A file write (part_ok: not a command, not
        code that runs by itself, not a config file) may show long values in part: start, end,
        length and hash (recheck R-11)."""
        raw, hidden = _render_args(args, None)
        n = len(raw)
        if n > CARD_MAX:
            if not part_ok:
                return None
            for cut in ((700, 300), (400, 150), (200, 80)):
                raw, hidden = _render_args(args, cut)
                if len(raw) <= CARD_MAX:
                    break
            else:
                return None
        text = messages.defuse(raw, CARD_MAX * 4, keep_paths=True) or "(none)"
        if len(text) > CARD_MAX * 2:
            return None
        return n, text, hidden

    def _card_message(self, tool: str, why: str, sha: str, args, part_ok: bool, offer: bool,
                      platform: str) -> tuple[str, int, bool] | None:
        """(card text, characters not shown, the grant note is on it), or None when the arguments
        cannot be shown on this platform's card (lab re-test bug 3: never offer Approve for text
        the approver cannot see; a file write may be shown IN PART, owner choice (b))."""
        try:
            limit = self.card_limit(platform)
        except Exception:
            limit = CHAT_CARD_LIMIT
        card = self._card(args, part_ok)
        if card is not None:
            n, text, hidden = card
            msg = (ASK_TEXT_PART if hidden else ASK_TEXT).format(
                tool=tool, why=messages.defuse(why, 200, keep_paths=True), n=n, sha=sha[:12], args=text, hidden=hidden)
            grant = GRANT_NOTE.format(uses=GRANT_USES, mins=int(GRANT_TTL // 60))
            if offer and _fits(msg + grant, limit):
                return msg + grant, hidden, True
            if _fits(msg, limit) and not offer:
                return msg, hidden, False
        if limit is None:
            return None
        # short wording for a chat card; a file write may shrink to its IN PART form
        cuts = [None] + ([(80, 40), (40, 20), (20, 10)] if part_ok else [])
        for cut in cuts:
            raw, hidden = _render_args(args, cut, short=True)
            if cut is None and len(raw) > CARD_MAX:
                continue
            text = messages.defuse(raw, CARD_MAX * 4, keep_paths=True) or "(none)"
            for wlen in (80, 40, 20):
                msg = (ASK_COMPACT_PART if hidden else ASK_COMPACT).format(
                    tool=tool, why=messages.defuse(why, wlen, keep_paths=True), sha=sha[:12], args=text, hidden=hidden)
                grant = GRANT_SHORT.format(uses=GRANT_USES, mins=int(GRANT_TTL // 60))
                if offer and _fits(msg + grant, limit):
                    return msg + grant, hidden, True
                if _fits(msg, limit):
                    return msg, hidden, False
        return None

    # ------------------------------------------------------------------ arguments changed after the check
    def _remember(self, tool_call_id, sha: str, ks, grant=None) -> None:
        if not isinstance(tool_call_id, str) or not tool_call_id:
            return
        with self._lock:
            self._checked[tool_call_id[:200]] = (sha, list(ks), grant)
            while len(self._checked) > 2000:
                self._checked.popitem(last=False)

    def args_changed(self, args, tool_call_id, result=None) -> bool:
        """After the tool ran: were its final arguments different from the ones Knock checked?
        (Another plugin's "modify" is merged after every pre_tool_call hook, lab item 12.) On a
        change the session is tainted for good and the caller withholds the result. A file edit
        the owner approved on a card that offered it starts its grant here (it ran, so it was
        approved; a result that reads like a refusal does not count)."""
        if not self.cfg.enabled or not isinstance(tool_call_id, str) or not tool_call_id or args is None:
            return False
        with self._lock:
            rec = self._checked.pop(tool_call_id[:200], None)
        if rec is None:
            return False
        if _args_sha(args) == rec[0]:
            grant = rec[2] if len(rec) > 2 else None
            if grant is not None and isinstance(result, str) and not _DENIED_RX.search(result[:500]):
                with self._lock:
                    self._grants[grant] = [GRANT_USES, self.guard.clock() + GRANT_TTL]
                    self._grants.move_to_end(grant)
                    while len(self._grants) > 2000:
                        self._grants.popitem(last=False)
            return False
        self._count("args_changed")
        self.events.write("knock-args-changed")
        self.store.mark(rec[1], "arguments changed after the check")
        return True

    def status(self) -> dict:
        from . import KNOCK_VERSION
        return {"version": KNOCK_VERSION, "enabled": self.cfg.enabled, "ok": self.ok, "taint": self.cfg.taint,
                "local_taint": self.cfg.local_taint, "unsafe_override": list(self.cfg.unsafe),
                "disabled_builtins": list(self.cfg.disabled_builtins), "sessions": len(self.store),
                "counters": dict(self.counters), "setup_notice": self.setup_notice,
                "chat_grants_and_partial": self.cfg.chat_grants_and_partial, "grant_edits": self.grant_edits,
                "armed_files": len(self._armed), "downloaded_paths": len(self._remote_paths),
                "local_skills_changed": sorted(self.skills_changed)}

    def status_line(self) -> str:
        if not self.ok:
            return "knock: settings invalid (refusing tools)"
        if not self.cfg.enabled:
            return "knock: OFF"
        from . import KNOCK_VERSION
        s = f"knock {KNOCK_VERSION}: on (taint {self.cfg.taint}, local {self.cfg.local_taint})"
        if self.cfg.unsafe:
            s += "; UNSAFE OVERRIDE: " + ", ".join(self.cfg.unsafe[:5])
        if self.grant_edits:
            s += (f"; {self.grant_edits} file edit(s) went through under a grant (last: "
                  f"{messages.defuse(_shown_name(self._last_grant_edit), 60, keep_paths=True)})")
        if self.skills_changed:
            s += ("; local skill changed: " + ", ".join(sorted(self.skills_changed)[:5])
                  + " (now outside content; update its sha256 in knock.local_skills)")
        if self.setup_notice:
            s += "; " + self.setup_notice
        return s


def _render_args(args, cut, short: bool = False) -> tuple[str, int]:
    """(all arguments on one line, the fields that matter first; characters not shown). With
    cut=(head, tail), a long string value shows its start, end, length and sha256 only (short:
    the same in fewer words, for chat cards)."""
    if not isinstance(args, Mapping):
        return str(args), 0
    keys = [k for k in _CARD_FIRST if k in args] + sorted((k for k in args if k not in _CARD_FIRST), key=str)
    parts, hidden = [], 0
    for k in keys:
        v = args[k]
        if cut and isinstance(v, str) and len(v) > cut[0] + cut[1] + 60:
            h = len(v) - cut[0] - cut[1]
            hidden += h
            vsha = hashlib.sha256(v.encode("utf-8", "surrogatepass")).hexdigest()[:12]
            if short:
                parts.append(f"{k}=({len(v)} chars, sha256 {vsha}) " + json.dumps(v[:cut[0]], ensure_ascii=False)
                             + " [...] " + json.dumps(v[-cut[1]:], ensure_ascii=False))
                continue
            parts.append(f"{k}=({len(v)} characters, sha256 {vsha}) "
                         + json.dumps(v[:cut[0]], ensure_ascii=False)
                         + f" [... {h} characters not shown ...] "
                         + json.dumps(v[-cut[1]:], ensure_ascii=False))
            continue
        try:
            s = json.dumps(v, ensure_ascii=False, default=str)
        except Exception:
            s = str(v)
        parts.append(f"{k}={s}")
    return "; ".join(parts), hidden


def _args_sha(args) -> str:
    try:
        s = json.dumps(args, ensure_ascii=False, default=str, sort_keys=True)
    except Exception:
        s = repr(args)
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


_CONFIG_PATH_RX = re.compile(r"(?i)(^|/)(\.hermes/|\.config/|\.bashrc|\.profile|\.zshrc|agents\.md|claude\.md|"
                             r"\.cursorrules|soul\.md|memory\.md|config\.ya?ml)")


def _config_path(args) -> bool:
    """A write to a context or config file: its effect outlives the session (review K-03)."""
    if not isinstance(args, Mapping):
        return True
    for k in ("path", "file", "file_path", "filename", "target"):
        v = args.get(k)
        if isinstance(v, str) and _CONFIG_PATH_RX.search(v.replace("\\", "/")):
            return True
    return False


def _build_path(args) -> bool:
    """A build or config-execution file (Makefile, package.json, conftest.py, CI workflows ...)."""
    if not isinstance(args, Mapping):
        return True
    return any(_BUILD_PATH_RX.search(p) for p in tools.arg_paths(args))


def _runnable_on_disk(args) -> bool:
    """The file being edited already exists and runs: executable bit (POSIX) or a #! first line."""
    for p in tools.arg_paths(args):
        try:
            fp = os.path.expanduser(p)
            if not os.path.isfile(fp):
                continue
            if os.name == "posix" and os.stat(fp).st_mode & 0o111:
                return True
            with open(fp, "rb") as f:
                if f.read(2) == b"#!":
                    return True
        except (OSError, ValueError):
            continue
    return False


def _runs_later(cls: str, name: str, args, user_tools=()) -> bool:
    """A file write whose file runs or builds later: code (by extension or #!), an autorun, config
    or build file, or an existing executable file. No grant and no IN PART card (picks 1 and 2)."""
    return (tools.executes(cls, name, args, user_tools) or _autorun_path(args) or _config_path(args)
            or _build_path(args) or _runnable_on_disk(args))


def _stem(path: str) -> str:
    base = tools.norm_path(path).rsplit("/", 1)[-1]
    return base.rsplit(".", 1)[0] if "." in base[1:] else base


def _imported_stems(text: str) -> set:
    """Module names (every dotted part) that code imports or runs as a module: import x, from a.b
    import c, python -m x, __import__('x'), importlib.import_module('x'), runpy.run_path('x.py')."""
    out = set()
    if not text:
        return out
    for m in _IMPORT_RX.finditer(text):
        if m.group(1):
            out.update(m.group(1).split("."))
            out.update(w for w in re.split(r"[\s,()*]+", m.group(2) or "") if w and w != "as")
        else:
            for item in (m.group(3) or "").split(","):
                out.update(item.strip().split(" ")[0].split("."))
    for m in _MODULE_FLAG_RX.finditer(text):
        out.update(m.group(1).split("."))
    for m in _DYN_IMPORT_RX.finditer(text):
        out.update(_stem(x) for x in re.split(r"[./\\]", m.group(1)[:-3] if m.group(1).endswith(".py")
                                               else m.group(1)) if x)
    out.discard("")
    return out


def _imported_stems_on_disk(text: str, args) -> set:
    """Imports inside the script files a command runs (python main.py, where main imports pay),
    read from disk when they exist (best effort, 256 KB each, at most 5 files)."""
    out = set()
    wd = args.get("workdir") or args.get("cwd") if isinstance(args, Mapping) else None
    n = 0
    for t in _RUN_FILE_RX.findall(text):
        if not t.endswith((".py", ".pyw")) or n >= 5:
            continue
        n += 1
        for cand in ([t] if t.startswith(("/", "~")) or not isinstance(wd, str) or not wd.strip()
                     else [os.path.join(wd, t), t]):
            try:
                fp = os.path.expanduser(cand)
                if os.path.isfile(fp):
                    with open(fp, encoding="utf-8", errors="replace") as f:
                        out |= _imported_stems(f.read(262_144))
                    break
            except (OSError, ValueError):
                continue
    return out


def _runner_roots(text: str, args):
    """None when no test runner or build command runs; else the folders it may import from ([] =
    unknown: every armed Python file counts)."""
    if not _TEST_RUNNER_RX.search(text or ""):
        return None
    roots = []
    wd = args.get("workdir") or args.get("cwd") if isinstance(args, Mapping) else None
    if isinstance(wd, str) and wd.strip():
        roots.append(tools.norm_path(wd))
    for m in re.finditer(r"(?:^|[;&|]\s*)cd\s+['\"]?([^\s;&|'\"]+)", text):
        roots.append(tools.norm_path(m.group(1)))
    return roots


def _in_scope(path: str, roots) -> bool:
    """Could a runner started in one of these folders import this file? Unknown means yes."""
    if not roots:
        return True
    p = tools.norm_path(path)
    if not p.startswith(("/", "~")):
        return True                                    # written by a relative path: folder unknown
    pdir = p.rsplit("/", 1)[0]
    for r in roots:
        if not r.startswith(("/", "~")):
            return True
        if p.startswith(r.rstrip("/") + "/") or r == pdir or r.startswith(pdir + "/"):
            return True
    return False


def _autorun_path(args) -> bool:
    """A file that runs by itself or changes how things run: shell start files, services, git
    hooks and config, ssh, Python start files (recheck R-01, R-11)."""
    if not isinstance(args, Mapping):
        return True
    return any(_AUTORUN_PATH_RX.search(p) for p in tools.arg_paths(args))


def _net_secret(args) -> str | None:
    """Gatehouse's secret shapes over the text a web tool sends out (review K-01 item 4): the
    whole text and its decoded forms (base64, URL and escape encoding; recheck R-13)."""
    from ..gatehouse.output import secret_kind
    text = never.flatten(args)
    for form in [text] + never.decoded_forms(text)[:50]:
        k = secret_kind(form)
        if k:
            return k
    return None
