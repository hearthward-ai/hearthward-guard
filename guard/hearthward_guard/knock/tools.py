"""Tool classes for Knock (built-in Hermes tools reviewed at v0.23.1, plus user classes).

  read            no side effects, output is not outside content -> always allowed
  source          no side effects, output is outside content     -> allowed; taints the session
  source:private  reads the owner's private data (files, past sessions, home devices)
                                                                  -> denied in a stranger's turn
  source:net      sends model-chosen text off the machine (web fetch/search)
                                                                  -> checked like an action once
                                                                     private data was read in a
                                                                     tainted session (review K-01)
  act             side effects (writes, sends, runs, spends)     -> denied/asked when tainted
  act+source      both                                           -> both rules
Anything not listed (including every MCP tool, mcp__<server>__<tool>) is unknown: Knock treats it
as act+source and applies knock.unknown_tools (deny by default).

Taint strength (owner decision, fix round): output of the owner's own machine (terminal, local
files) is LOCAL outside content; everything else (web, other people, attachments, cron, unknown
tools) is REMOTE. policy.py says what each strength allows.
"""
from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Mapping

READ, SOURCE, ACT, ACT_SOURCE, UNKNOWN = "read", "source", "act", "act+source", "unknown"
PRIVATE, NET = "source:private", "source:net"
CLASSES = (READ, SOURCE, PRIVATE, NET, ACT, ACT_SOURCE)
SOURCES = (SOURCE, PRIVATE, NET)
_NAME_OK = re.compile(r"[A-Za-z0-9_.:-]{1,128}")      # always used with fullmatch (review K-16)

BUILTIN: dict[str, str] = {}


def _add(cls: str, names: str) -> None:
    for n in names.split():
        BUILTIN[n] = cls


_add(READ, "clarify skills_list todo_list")
_add(SOURCE, """skill_view feishu_drive_list_comments feishu_drive_list_comment_replies spotify_devices
    yb_query_group_info yb_query_group_members a2a_list""")
_add(PRIVATE, """read_file search_files session_search feishu_doc_read kanban_show kanban_list kanban_attachments
    read_terminal read_window_below honcho_profile honcho_search honcho_context honcho_reasoning
    ha_list_entities ha_get_state ha_list_services a2a_history""")
_add(NET, """web_search web_extract x_search vision_analyze video_analyze spotify_search yb_search_sticker
    a2a_discover""")
_add(ACT, """write_file patch memory skill_manage cronjob_manage image_generate text_to_speech video_generate
    xai_video_edit xai_video_extend kanban_complete kanban_block kanban_request_review kanban_request_changes
    kanban_heartbeat kanban_comment kanban_create kanban_link kanban_unblock kanban_attach
    feishu_drive_add_comment feishu_drive_reply_comment desktop_project react_to_message gui_tour show_tip
    set_theme focus_pane close_terminal annotate_preview honcho_conclude ha_call_service spotify_playback
    spotify_queue spotify_playlists spotify_albums spotify_library yb_send_dm yb_send_sticker
    kanban_schedule setup_beat""")
_add(ACT_SOURCE, """terminal process_manage execute_code browser_exec browser_cdp browser_dialog browser_vault
    computer_use delegate_task discord discord_admin drive_preview desktop_preview kanban_attach_url
    manage_catalog manage_connections a2a_call a2a_orchestrate""")
# Live v0.23.1 tools classified in the fix round (lab item 11): a2a_call / a2a_orchestrate send to
# other agents and return their text; a2a_history is other agents' text; a2a_discover reaches out;
# kanban_schedule and setup_beat create future actions. Anything else stays unknown = risky.

# Tools that run code: encoded content in their arguments counts as "unsure", and in a clean
# session they still go to the card by default (knock.untainted_exec; bench 2026-11-17).
CODE_RUNNERS = frozenset({"terminal", "process_manage", "execute_code", "browser_exec", "browser_cdp",
                          "computer_use"})
# Tools whose output comes from the owner's own machine: LOCAL outside content, unless the call
# names a network fetch or a file that came from the network (recheck R-04: taint follows the
# data's origin, not the tool). read_terminal, read_window_below and skill_view are REMOTE: a
# screen can show any program's output (a browser, curl) and a skill may come from the hub.
# skill_view of a skill the owner listed in knock.local_skills is LOCAL.
LOCAL_SOURCES = frozenset({"terminal", "process_manage", "execute_code", "read_file", "search_files"})
# Act tools whose result carries text back (review K-03): the owner's own stored data (LOCAL) or
# text other people wrote (REMOTE). Marked after the call is let through, like a source.
RETURNS_LOCAL = frozenset({"patch", "memory", "cronjob_manage"})
RETURNS_REMOTE = frozenset({"kanban_complete", "kanban_block", "kanban_request_review", "kanban_request_changes",
                            "kanban_heartbeat", "kanban_comment", "kanban_create", "kanban_link", "kanban_unblock",
                            "kanban_attach"})
# Tools whose effect outlives the session: never put on a card after REMOTE outside content (K-03).
PERSISTENT = frozenset({"memory", "skill_manage", "cronjob_manage", "kanban_schedule", "setup_beat"})


def classify(name, user_tools=()) -> str:
    """Class of a tool name. User classes first (exact name, then globs, in config order), then the
    built-in table. Names are matched exactly: a look-alike, odd-case or padded name is unknown."""
    if not isinstance(name, str) or not _NAME_OK.fullmatch(name):
        return UNKNOWN
    for pat, cls in user_tools:
        if pat == name:
            return cls
    for pat, cls in user_tools:
        if any(ch in pat for ch in "*?") and fnmatch.fnmatchcase(name, pat):
            return cls
    return BUILTIN.get(name, UNKNOWN)


def user_classed(name, user_tools=()) -> bool:
    """Does a user setting (not the built-in table) decide this tool's class?"""
    if not isinstance(name, str) or not _NAME_OK.fullmatch(name):
        return False
    return any(pat == name or (any(ch in pat for ch in "*?") and fnmatch.fnmatchcase(name, pat))
               for pat, _c in user_tools)


# "act" tools that create future actions (schedules, skills): checked like code-running tools.
PLANS_ACTIONS = frozenset({"cronjob_manage", "skill_manage", "kanban_schedule", "setup_beat"})
# File writers: checked like code-running tools when the file looks like code.
FILE_WRITERS = frozenset({"write_file", "patch"})
_CODE_EXT = re.compile(r"(?i)(\.(sh|bash|zsh|fish|py|pyw|js|mjs|cjs|ts|ps1|psm1|bat|cmd|vbs|rb|pl|php|lua|"
                       r"service|timer|desktop|plist)|crontab|/bin/[^/]*|(^|/)\.?(bashrc|profile|zshrc))\Z")


def executes(cls: str, name: str, args, user_tools=()) -> bool:
    """Can this call make something happen on another system (now or later)? A tool the owner
    classed in settings keeps the full argument rules (review K-12)."""
    if cls in (ACT_SOURCE, UNKNOWN) or name in PLANS_ACTIONS:
        return True
    if cls != READ and user_classed(name, user_tools):
        return True
    if name in FILE_WRITERS and isinstance(args, Mapping):
        for k, v in args.items():
            if isinstance(v, str) and ((str(k).lower() in ("path", "file", "file_path", "filename", "target")
                                        and _CODE_EXT.search(v.strip())) or v.lstrip().startswith("#!")):
                return True
    return False


def acts(cls: str) -> bool:
    return cls in (ACT, ACT_SOURCE, UNKNOWN)


def taints(cls: str) -> bool:
    return cls in (SOURCE, PRIVATE, NET, ACT_SOURCE, UNKNOWN)


# ---- read-only terminal commands (owner decision: they stay allowed after outside content)
# git is NOT on the list (recheck R-01): status/diff/log/show/blame run programs named in the
# repository's own config (core.fsmonitor, diff.external, textconv, gpg.program, filter drivers),
# and no command-line switch turns all of them off. git goes to the card like any other command.
_RO_CMDS = frozenset("ls cat head tail wc grep egrep fgrep pwd echo date whoami id uname which file stat du df "
                     "diff cut basename dirname realpath readlink true nl md5sum sha1sum sha256sum".split())
# commands whose output is not the owner's data and cannot carry outside text: no taint, no
# "private data was read" flag (recheck R-16: "date" must not end web search)
TRIVIAL_CMDS = frozenset("date pwd echo whoami uname which true".split())
_RO_FIND_BAD = frozenset(("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"))
_META = re.compile(r"[;&><`$(){}\\\n\r]|\|\|")
_RO_ARG_KEYS = frozenset({"command", "timeout", "workdir", "cwd"})
_DATE_VALUE_FLAGS = ("-d", "--date", "-r", "--reference", "-f", "--file")
_UNC = ("//", "\\\\")


def _short_has(w: str, letters: str) -> bool:
    return w.startswith("-") and not w.startswith("--") and any(ch in w[1:] for ch in letters)


def _ro_words_ok(head: str, rest: list) -> bool:
    """Writing, clock-setting, never-ending and host-name forms of the listed commands (R-01)."""
    for w in rest:
        if w.startswith(_UNC):                            # SMB / UNC: a host name can carry data
            return False
        if w.startswith("/dev/") and w != "/dev/null":    # /dev/zero, /dev/tcp/... never end or connect
            return False
    if head == "date":
        skip = False
        for w in rest:
            if skip:
                skip = False
                continue
            if w in _DATE_VALUE_FLAGS:
                skip = True
                continue
            if w.startswith(("--date=", "--reference=", "--file=", "-I", "--iso", "--rfc", "-R", "-u", "--utc",
                             "--universal")):
                continue
            if w.startswith("--set") or _short_has(w, "s") or not w.startswith(("-", "+")):
                return False                              # -s / --set / date MMDDhhmm set the clock
    elif head == "file":
        if any(w.startswith("--compile") or _short_has(w, "C") for w in rest):
            return False
    elif head == "tail":
        if any(w.startswith(("--follow", "--retry", "--pid")) or _short_has(w, "fF") for w in rest):
            return False
    return True


def read_only_command(name: str, args) -> bool:
    """A terminal call that only reads: one command, or a pipe of commands, from a short list; no
    redirection, substitution, chaining, background, globbing tricks or writing flags. Anything
    else is not read-only. (Reading can still pull in outside text: the call still taints.)"""
    if name != "terminal" or not isinstance(args, Mapping) or set(map(str, args)) - _RO_ARG_KEYS:
        return False
    if any(args.get(k) not in (None, "") and not isinstance(args.get(k), (str, int, float)) for k in args):
        return False
    for k in ("workdir", "cwd"):
        v = args.get(k)
        if isinstance(v, str) and v.strip().startswith(_UNC):
            return False
    cmd = args.get("command")
    if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 500 or _META.search(cmd):
        return False
    for seg in cmd.split("|"):
        try:
            words = shlex.split(seg)
        except ValueError:
            return False
        if not words:
            return False
        head, rest = words[0], words[1:]
        if any(w.startswith(("--output", "--pre", "--ext-diff", "--textconv")) for w in rest):
            return False
        if head == "find":
            if any(w in _RO_FIND_BAD for w in rest):
                return False
        elif head not in _RO_CMDS:
            return False
        if not _ro_words_ok(head, rest):
            return False
    return True


def trivial_command(name: str, args) -> bool:
    """A read-only command whose output is not the owner's data (date, pwd, echo ...)."""
    if not read_only_command(name, args):
        return False
    cmd = args.get("command", "")
    try:
        words = shlex.split(cmd)
    except ValueError:
        return False
    return "|" not in cmd and bool(words) and words[0] in TRIVIAL_CMDS


# ---- process_manage reads (recheck R-16): listing or polling a background process the owner
# already approved is a read, not a new command. Argument names are a lab item; anything else
# (kill, write, submit, unknown keys) is not a read and goes to the card.
_PROC_READ_ACTIONS = frozenset({"list", "poll", "log", "status", "wait"})
_PROC_KEYS = frozenset({"action", "process_id", "session_id", "id", "pid", "lines", "offset", "limit", "timeout",
                        "tail"})


def process_read(name: str, args) -> bool:
    if name != "process_manage" or not isinstance(args, Mapping) or set(map(str, args)) - _PROC_KEYS:
        return False
    if any(isinstance(v, bool) or not isinstance(v, (str, int, float, type(None))) for v in args.values()):
        return False
    a = args.get("action")
    return isinstance(a, str) and a.strip().lower() in _PROC_READ_ACTIONS


# ---- data origin (recheck R-04). A net, not a boundary: code can always fetch in a way no
# pattern sees. Under LOCAL taint the owner's card is the only control.
_PROG = (r"curl|wget|wget2|aria2c|xh|httpie|scp|sftp|rsync|ssh|ftp|lftp|tftp|nc|ncat|netcat|socat|telnet|lynx|"
         r"w3m|elinks|yt-dlp|youtube-dl|gallery-dl|huggingface-cli|hf|npx|pipx|bunx|uvx|gh|"
         r"invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer")
_GIT_OPTS = r"(?:(?:-c\s+\S+|-C\s+\S+|--?[\w-]+(?:=\S+)?)\s+)*"
_FETCH_RX = re.compile(
    r"(?i)(?:^|(?<=[\s;&|(`'\"/]))(?:" + _PROG + r")(?=$|[\s;&|)`'\"])"
    r"|\bgit\s+" + _GIT_OPTS + r"(?:clone|pull|fetch|submodule|ls-remote|remote|lfs|archive\s+--remote)\b"
    r"|\b(?:pip3?|python3?\s+-m\s+pip|uv(?:\s+pip)?|conda|mamba|micromamba|npm|pnpm|yarn|bun|cargo|gem|go|apt|"
    r"apt-get|dnf|yum|pacman|zypper|apk|brew|winget|choco|scoop|docker|podman|snap|flatpak|ollama|composer|"
    r"nix|nix-env)\s+(?:-\S+\s+)*(?:install|add|i|pull|download|get|update|upgrade|run|clone|fetch|create|sync|"
    r"search|show|info|view|exec|dlx)\b"
    r"|[a-z][a-z0-9+.-]{1,15}://"
    r"|\b(?:requests|httpx|aiohttp|urllib3?|urllib\.request|http\.client|socket|websockets?|paramiko|ftplib|"
    r"smtplib|imaplib|poplib|telnetlib|pycurl|webbrowser|selenium|playwright)\b"
    r"|\burlopen\s*\(|\bfetch\s*\(|\bxmlhttprequest\b|\bnet\.webclient\b|\bdownloadstring\b|\bdownloadfile\b")
# folders that hold what came from elsewhere: downloads and the gateway attachment caches. Hermes
# 0.23.1 uses cache/images, cache/audio, cache/documents, cache/videos, cache/screenshots (lab re-test
# bug 6); the older *_cache names are still used when those folders exist
REMOTE_DIR_RX = re.compile(r"(?i)(^|/)(downloads|document_cache|image_cache|audio_cache|video_cache|attachments|"
                           r"inbox_files|cache/(?:images?|audio|voice|documents?|videos?|screenshots?|"
                           r"attachments?|files|media|stickers?))(/|$)")
_OUT_FLAG_RX = re.compile(r"(?:^|\s)(?:-o|-O|-P|-d|--output|--output-document|--output-dir|--directory-prefix|"
                          r"--dest|--target|-OutFile|-Destination)(?:\s+|=)(['\"]?)([^\s'\";|&]+)\1")
_REDIR_RX = re.compile(r">{1,2}\s*(['\"]?)([^\s'\";|&]+)\1")
_URL_RX = re.compile(r"[a-z][a-z0-9+.-]{1,15}://[^\s'\"<>;|&]+", re.I)
_CLONE_RX = re.compile(r"\bgit\s+" + _GIT_OPTS + r"clone\s+(?:--?[\w-]+(?:=\S+)?\s+)*"
                       r"(['\"]?)([^\s'\";|&]+)\1(?:[ \t]+(['\"]?)([^\s'\";|&-][^\s'\";|&]*)\3)?")


def fetches(args) -> bool:
    """Does a code-running call name a network fetch (a program, package manager, URL or library)?"""
    from .never import flatten
    return bool(_FETCH_RX.search(flatten(args)))


def norm_path(p: str) -> str:
    p = p.strip().strip("'\"").replace("\\", "/")
    while "//" in p[1:]:
        p = p[0] + p[1:].replace("//", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.rstrip("/") or p


def fetch_outputs(args) -> list:
    """Paths a fetching command writes (best effort): -o/-O/-P/--output values, redirection
    targets, the folder of a git clone, a URL's file name, node_modules."""
    from .never import flatten
    text = flatten(args)
    out = [m.group(2) for m in _OUT_FLAG_RX.finditer(text)] + [m.group(2) for m in _REDIR_RX.finditer(text)]
    for m in _CLONE_RX.finditer(text):
        name = m.group(2).rstrip("/").rsplit("/", 1)[-1]
        out.append(m.group(4) or (name[:-4] if name.endswith(".git") else name))
    for m in _URL_RX.finditer(text):
        path = m.group(0).split("://", 1)[1].split("?", 1)[0].split("#", 1)[0].rstrip("/")
        tail = path.rsplit("/", 1)[-1] if "/" in path else ""
        if tail and "." in tail and ":" not in tail:
            out.append(tail)
    if re.search(r"\b(npm|pnpm|yarn|bun)\s+(install|add|i)\b", text):
        out.append("node_modules")
    return [norm_path(p) for p in out if p and p not in ("-", "/dev/null") and len(p) <= 512]


_PATH_KEYS = ("path", "file", "file_path", "filename", "target", "paths", "files", "dir", "directory")


def arg_paths(args) -> list:
    """Path-like argument values (for origin checks and file grants)."""
    out = []
    if isinstance(args, Mapping):
        for k in _PATH_KEYS:
            v = args.get(k)
            for x in (v if isinstance(v, (list, tuple)) else [v]):
                if isinstance(x, str) and x.strip():
                    out.append(norm_path(x))
    return out


def path_words(args) -> list:
    """Every word of the arguments that could name a file (for commands and scripts)."""
    from .never import flatten
    return [norm_path(w) for w in re.split(r"[\s'\"=;|&()<>,]+", flatten(args)) if w and len(w) <= 512]


# ---- web tools aimed at the owner's own machine or network (recheck R-05)
_URL_KEYS = ("url", "urls", "image_url", "image_urls", "video_url", "audio_url", "src", "source", "link", "links",
             "path", "file", "file_path", "image", "images", "video", "uri", "target", "page")
_LOCAL_SUFFIXES = (".localhost", ".local", ".lan", ".home", ".internal", ".intranet", ".corp", ".home.arpa",
                   ".localdomain")


def _local_host(host: str) -> bool:
    import ipaddress
    import socket
    h = host.strip("[]").lower().rstrip(".")
    if not h or h == "localhost" or h.endswith(_LOCAL_SUFFIXES) or ("." not in h and ":" not in h):
        return True
    ip = None
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if re.fullmatch(r"[0-9a-fx.]+", h):           # 2130706433, 0x7f.1, 0177.0.0.1 (inet_aton forms)
            try:
                ip = ipaddress.ip_address(socket.inet_aton(h))
            except (OSError, ValueError):
                return True
    if ip is None:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return not ip.is_global or ip.is_multicast


def local_target(args) -> bool:
    """Does a web tool name a local file, a file: URL, or a loopback, private or link-local host?"""
    import urllib.parse
    if not isinstance(args, Mapping):
        return False
    for k in _URL_KEYS:
        v = args.get(k)
        for x in (v if isinstance(v, (list, tuple)) else [v]):
            if not isinstance(x, str) or not x.strip():
                continue
            s = x.strip()
            if s.startswith(("/", "~", "./", "../") + _UNC) or re.match(r"[A-Za-z]:[\\/]", s):
                return True
            if s.lower().startswith(("file:", "smb:")):
                return True
            if "://" not in s:
                continue
            try:
                u = urllib.parse.urlsplit(s)
                host = u.hostname or ""
            except ValueError:
                return True
            scheme = u.scheme.lower()
            if scheme not in ("http", "https", "data", "blob"):
                return True
            if scheme in ("http", "https") and _local_host(host):
                return True
    return False
