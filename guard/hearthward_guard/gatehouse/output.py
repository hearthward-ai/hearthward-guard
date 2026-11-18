"""Gatehouse: filter for the assistant's final reply (transform_llm_output with hold_stream=True).

- secret-shaped strings withhold the whole reply (nothing partial goes out). Known token formats are
  also looked for after removing spacing, markup and escapes, reversed, and inside decoded layers
  (base64, hex, percent, rot13 ...); everyday shapes (KEY=value lines, JSON "password" fields,
  table rows, labelled values in a code fence, connection strings, private keys, labelled seed
  phrases, cookies) are recognised by their label AND a value that looks like a secret: a call, an
  attribute, a variable name or an ordinary word is not one (review H7, recheck R3);
- invisible, bidi, TAG, control and stray selector characters are removed;
- attachment directives are removed: "MEDIA:<anything>" / "ATTACH:<anything>" (any case, look-alike
  letters folded, only the directive itself is cut from the line), and local paths: all of them
  outside code, sensitive ones (home folders, hidden files, keys) inside code too;
- outside code, markdown, reference-style and HTML images or media are reduced to their alt text (the
  gateway or chat app would fetch them);
- links shaped like data leaving are removed (see _exfil_links): an encoded or random-looking piece
  anywhere in the host, path, query or fragment, small pieces that add up across links to one site,
  or five words in a row taken from the conversation. Ordinary links (YouTube, Maps, a search, an
  article slug, a commit) stay (recheck item 7);
- operator-supplied id patterns become "(id removed)".
Every pattern here runs in linear time (recheck R2) and the whole filter has a time limit; the caller
treats any exception, and a timeout, as "withhold".
"""
from __future__ import annotations

import bisect
import math
import re
import time
import unicodedata
import urllib.parse

from ..threshold import decode, normalize

REPLY_DEADLINE_S = 5.0


class _Timeout(Exception):
    pass


class _Clock:
    def __init__(self, seconds: float | None):
        self.end = None if not seconds else time.monotonic() + seconds

    def check(self) -> None:
        if self.end is not None and time.monotonic() > self.end:
            raise _Timeout()


_B = r"(?<![A-Za-z0-9])"
# (name, regex, also used on the squeezed copy, body must look random). Squeezed = spacing, dashes,
# commas and quotes removed: only distinctive prefixes are matched there, so ordinary prose run
# together cannot look like a token. "Random" = letters and digits mixed in a long run, so
# hf_hub_download or a CSS class named like a key are not tokens (recheck R3).
TOKEN_RX = [
    ("discord-token", re.compile(r"(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{22,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])"), False, False),
    ("discord-webhook", re.compile(r"(?i)discord(?:app)?\.com/api/webhooks/\d{5,}/[A-Za-z0-9_-]{30,}"), False, False),
    ("telegram-token", re.compile(_B + r"\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])"), False, False),
    ("google-oauth", re.compile(_B + r"ya29\.[A-Za-z0-9_-]{20,}"), True, True),
    ("google-api-key", re.compile(_B + r"AIza[0-9A-Za-z_-]{35}"), True, False),
    ("github-token", re.compile(_B + r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"), True, True),
    ("gitlab-token", re.compile(_B + r"glpat-[A-Za-z0-9_-]{20,}"), False, True),
    ("api-key", re.compile(_B + r"sk-(?:proj-|ant-|or-|live-|test-)?[A-Za-z0-9_-]{20,}"), False, True),
    ("slack-token", re.compile(_B + r"xox[abprse]-[A-Za-z0-9-]{10,}"), False, True),
    ("aws-key", re.compile(_B + r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"), True, False),
    ("stripe-key", re.compile(_B + r"[rs]k_(?:live|test)_[A-Za-z0-9]{20,}"), True, True),
    ("hf-token", re.compile(_B + r"hf_[A-Za-z0-9]{30,}"), True, True),
    ("npm-token", re.compile(_B + r"npm_[A-Za-z0-9]{36}"), True, True),
    ("pypi-token", re.compile(_B + r"pypi-AgE[A-Za-z0-9_-]{50,}"), True, False),
    ("sendgrid-key", re.compile(_B + r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), False, False),
    ("pem", re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}(?:PRIVATE KEY|OPENSSH|PGP PRIVATE)[A-Z0-9 ]{0,20}-----"), False, False),
    ("jwt", re.compile(_B + r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False, False),
    # the start of a token in a known format, cut or split over lines ("part 1: ghp_...")
    ("token-fragment", re.compile(_B + r"(?:gh[pousr]_|github_pat_|glpat-|xox[abprse]-|sk-(?:proj|ant|or|live|test)-|"
                                       r"hf_|npm_|pypi-AgE|AKIA|ASIA|AIza|ya29\.)[A-Za-z0-9]{12,}"), False, True),
]
_ALNUM_RUN_RX = re.compile(r"[A-Za-z0-9]{10,}")


def _randomish(tok: str) -> bool:
    """A run of 10+ letters and digits that mixes letters with digits (or both cases): a token body,
    not words joined by underscores or hyphens."""
    for run in _ALNUM_RUN_RX.findall(tok):
        has_d = any(c.isdigit() for c in run)
        has_l = any(c.isalpha() for c in run)
        if has_d and has_l:
            return True
        if any(c.isupper() for c in run[1:]) and any(c.islower() for c in run) and sum(
                1 for a, b in zip(run, run[1:]) if a.islower() != b.islower()) >= 4:
            return True
    return False


# Labels. Password-type labels accept shorter values than the rest.
_PW_WORDS = (r"pass(?:word|wd|phrase|code)|pwd|passwort|kennwort|contrase(?:ñ|n)a|senha|mot[ _]de[ _]passe")
_PW_KEY_RX = re.compile(r"(?i)(?:" + _PW_WORDS + r")|[_.-]pass$")
_KEYS = (r"(?:[A-Za-z0-9]{1,30}[_.-]){0,4}(?:pass(?:word|wd|phrase|code)?|pwd|secret|client[_-]?secret|"
         r"secret[_-]?(?:access[_-]?)?key|api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|private[_-]?key|"
         r"(?:auth|access|refresh|bearer|bot|session|csrf)[_-]?token|token|session(?:[_-]?id)?|sessid|"
         r"cookie|credentials?|auth)")
# key, optional quote, one separator, then the value: on the same line, or on the next line, or inside
# a code fence that starts there ("Password:\n```\nvalue\n```"). One whitespace run per gap (R2).
_ASSIGN_RX = re.compile(r"(?i)" + _B + "(" + _KEYS + r")[\"']?[ \t]*(?::=|=>|[:=])[ \t]*(?:\r?\n[ \t]*)?"
                        r"(?:```[\w+-]*[ \t]*\r?\n[ \t]*|`)?[\"'`]?([^\s\"'`,;<>]{3,300})")
# "| Password | value |" table rows
_TABLE_RX = re.compile(r"(?im)^[ \t]*(?:\|[ \t]*)?(?:\*\*)?(" + _KEYS + r")(?:\*\*)?[ \t]*\|[ \t]*`?([^|\s`][^|\n`]{2,200}?)`?[ \t]*\|")
_SAID_RX = re.compile(r"(?i)\b(?:password|passphrase|passcode|pin|pwd|passwort|mot de passe|contraseña)"
                      r"(?:\s+(?:is|was|would\s+be)(?:[ \t]*:)?|[ \t]*[=:])\s+[\"'`]?([^\s\"'`]{6,100})")
_CJK_PW_RX = re.compile(r"(?:密码|密碼|口令|パスワード|비밀번호|암호|暗証番号)[ \t]*(?:是|为|為|:|=|：)[ \t]*[\"'`「『]?"
                        r"([!-~]{6,100})")      # a label, a separator, then printable ASCII
CONTEXT_RX = [
    ("bearer", re.compile(r"(?i)\b(?:authorization|auth)[ \t]*[:=][ \t]*(?:bearer|bot|token|basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}")),
    ("private-key-hex", re.compile(r"(?i)(?:private|secret|priv)[ \t_-]{0,3}key\W{0,10}(?:0x)?[0-9a-f]{64}(?![0-9a-f])")),
    ("cookie", re.compile(r"(?i)\b(?:set-)?cookie[ \t]*:[ \t]*[^\s=;]{1,64}=[^\s;]{12,}")),
]
# Wallet seed phrase: a label, then 12-24 short lower-case words (also one per line or numbered).
_SEED_RX = re.compile(r"(?i)(?:\b(?:seed|recovery|mnemonic|backup|secret|wallet|token|key)|助记词|种子|恢复短语|私钥|密钥)"
                      r"(?:[ \t]+(?:phrase|words?|seed|key))?"
                      r"(?:[ \t]*(?:is|:|=))?\s*"
                      r"((?:(?:\d{1,2}[.):][ \t]*)?[a-z]{3,8}(?:[ \t,]+(?:\r?\n[ \t]*)?|\r?\n[ \t]*)){11,23}"
                      r"(?:\d{1,2}[.):][ \t]*)?[a-z]{3,8})(?![A-Za-z])")
_STOP = frozenset("the and you that for are with this have not but they was all can her his one our out "
                  "has had how its may new now see two who did get him let say she too use any few own why "
                  "from your what when will been more some than them then were here into just like only over "
                  "also each very such much most many where which there their these those would could should".split())
_CARD_RX = re.compile(r"(?<![0-9])(?:[3-6][0-9]{3})(?:[ -]?[0-9]{3,4}){3}(?:[ -]?[0-9]{1,3})?(?![0-9])")
_CARD_LABEL_RX = re.compile(r"(?i)(?:card|visa|master|amex|credit|debit|\bcc\b|卡号|卡號|信用卡)")
_SPACED_CHARS_RX = re.compile(r"(?<!\S)(?:\S[ \t]{1,3}){5,}\S(?!\S)")
_CONN_RX = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://([^\s:/@]{0,64}):([^\s@/]{3,128})@[^\s/]{2,}")
_PLACEHOLDER_RX = re.compile(r"(?i)^(?:[<{\[($%*#]|your|my[_-]?|example|sample|dummy|placeholder|xxx|\.\.\.|"
                             r"(?:required|optional|none|null|nil|true|false|undefined|redacted|hidden|secret|"
                             r"password|passwd|pass|token|string|value|en[v]|here|changeit|\*+)$)")
# a variable or constant name, camelCase name or one capitalised word: not a value
_IDENT_RX = re.compile(r"^(?:[a-z][a-z]*(?:_[a-z]+)*|[A-Z][A-Z]*(?:_[A-Z0-9]+)+|[A-Z]+|[a-z]+(?:[A-Z][a-z]+)+|[A-Z][a-z]+)$")
_CODE_VALUE_RX = re.compile(r"[A-Za-z_][\w.]*\s*\(|\w\[|^\$\{?[A-Za-z_]\w*\}?$|^%[A-Za-z_]\w*%$|\{\{|^(?:os|process|en[v]|self|this|config|settings|"
                            r"request|req|args|params|props|data|ctx|context)[.\[]|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$|://")

# Hermes turns "MEDIA:<path>" (any case, optionally quoted or emphasised) into an attachment.
# After a space, anything with a slash or a file extension counts (recheck M7).
_DIRECTIVE_RX = re.compile(r"""(?i)[`"'*_\[(]{0,3}(?:media|attach(?:ment)?)[^\S\n]*:"""
                           r"""(?:[^\s:]|[^\S\n]+(?:[~/\\.$"'`]|[a-z]:[/\\]|file:|https?:|[^\s:/\\]{1,200}[/\\]"""
                           r"""|[^\s:]{1,200}\.[a-z0-9]{1,8}(?=[\s\])"'`*,;]|$)))[^\n]*?(?=[\s\])]|$)""")
_DIRECTIVE_HINT_RX = re.compile(r"(?i)media|attach")
# Local paths (Hermes may attach a local file the reply mentions).
_PATH_STOP = r"""[^\s'"`<>()\[\]]"""
_PATH_RX = re.compile(
    r"(?<![A-Za-z0-9/.\\-])(?:file://\S+"
    r"|~[A-Za-z_][\w.-]{0,31}/" + _PATH_STOP + "*"
    r"|~/" + _PATH_STOP + "+"
    r"|[A-Za-z]:[/\\]" + _PATH_STOP + "+"
    r"|\\\\[^\s\\]+\\" + _PATH_STOP + "+"
    r"|/[\w.@+-]+/" + _PATH_STOP + "*"
    r"|/[\w@+-]+\.[A-Za-z0-9]{1,5}\b)")
_SENSITIVE_PATH_RX = re.compile(r"(?i)^file://|/\.|\\\.|~/\.|/proc/|/etc/(?:shadow|sudoers|ssh)"
                                r"|id_rsa|id_ed25519|\.pem\b|\.key\b|\.env\b|secret|token|credential|\.hermes")
_CODE_RX = re.compile(r"```.*?```|`[^`\n]+`", re.S)
_ALT = r"((?:[^\[\]]|\[[^\[\]]{0,100}\]){0,300})"
_URL_START = r"<?\s*(?:[a-z][a-z0-9+.-]{1,10}:)?(?:\\?/){2}"
# the URL part runs to the first ")" or space; an optional "title" and the closing ")" follow
_MD_IMAGE_RX = re.compile(r"(?i)!\[" + _ALT + r"\]\(\s*" + _URL_START + r"[^)\s]*(?:[ \t]+\"[^\"\n]{0,200}\")?[ \t]*\)?")
_REF_IMAGE_RX = re.compile(r"!\[" + _ALT + r"\]\[[^\]\n]{0,100}\]")
_REF_DEF_RX = re.compile(r"(?im)^[ \t]{0,3}\[[^\]\n]{1,100}\]:[ \t]*<?(?:[a-z][a-z0-9+.-]{1,10}:)?//[^\n]*$")
_HTML_MEDIA_RX = re.compile(r"(?i)<(?:img|video|audio|source|iframe|embed|object|track|image|input|link|script|picture)\b[^<>]{0,2000}>")
_TOOL_NAMES = r"(tool_call|function_call|tool_use|invoke)"
_TOOL_OPEN_RX = re.compile(r"(?i)<\s*" + _TOOL_NAMES + r"\b[^<>]{0,200}>")
_TOOL_CLOSE_RX = re.compile(r"(?i)<\s*/\s*" + _TOOL_NAMES + r"\s*>")
_TOOL_STRAY_RX = re.compile(r"(?i)<\s*/?\s*(?:tool_call|function_call|tool_use)\s*>")
_DASHES = str.maketrans({c: "-" for c in "\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe58\ufe63\uff0d"})
_MD_ESC_RX = re.compile(r"\\(?=[_\-*`~\\|#.!+])")
_TAG_RX = re.compile(r"<[^<>\n]{0,60}>")
_WS_RUN_RX = re.compile(r"[^\S\n]{2,}")
_NL_RUN_RX = re.compile(r"\n(?:[^\S\n]*\n){2,}")
_SQUEEZE_RX = re.compile(r"[\s\-,;|+'\"]+")

WITHHELD = ("I didn't send my reply: it contained something shaped like a password, token or key. "
            "Nothing was shared. Ask again in other words if you need that answer.")
EMPTY = "(reply removed by the guard)"


def _outside_code(text: str, fn, inside=None) -> str:
    """Apply fn to the parts of text outside closed code fences and inline code (and *inside*, if
    given, to the code parts). An unclosed fence is not code (review M7)."""
    out, last = [], 0
    for m in _CODE_RX.finditer(text):
        out.append(fn(text[last:m.start()]))
        out.append(inside(m.group(0)) if inside else m.group(0))
        last = m.end()
    out.append(fn(text[last:]))
    return "".join(out)


def _fold_map(line: str) -> tuple[str, list[int]]:
    """Look-alike-folded copy of *line* with, for every folded character, its index in *line*."""
    if line.isascii():
        return line, list(range(len(line)))
    chars, idx = [], []
    for i, ch in enumerate(line):
        f = ch if ch.isascii() else normalize.fold_confusables(
            unicodedata.normalize("NFKC", normalize.HIDDEN_RX.sub("", ch)))
        for c in f:
            chars.append(c)
            idx.append(i)
    return "".join(chars), idx


def strip_directives(text: str) -> str:
    """MEDIA:/ATTACH: tags are removed everywhere (also inside code), found on a look-alike-folded copy
    of each line but cut from the line as written (review L7); paths are removed outside code, and
    sensitive paths inside code too."""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        quick = normalize.fold_confusables(unicodedata.normalize("NFKC", normalize.HIDDEN_RX.sub("", line)))
        if not _DIRECTIVE_HINT_RX.search(quick):
            continue
        probe, idx = _fold_map(line)
        spans = [(idx[m.start()], idx[m.end() - 1] + 1) for m in _DIRECTIVE_RX.finditer(probe) if m.end() > m.start()]
        for a, b in reversed(spans):
            line = line[:a] + "[attachment removed]" + line[b:]
        lines[i] = line
    t = "\n".join(lines)

    def code_paths(code: str) -> str:
        return _PATH_RX.sub(lambda m: "[path removed]" if _SENSITIVE_PATH_RX.search(m.group(0)) else m.group(0), code)

    return _outside_code(t, lambda s: _PATH_RX.sub("[path removed]", s), code_paths)


def _strip_tool_calls(text: str) -> str:
    """<tool_call>...</tool_call> blocks (up to 4,000 characters) and stray tags, in linear time: the
    closing tags are indexed once instead of searched for from every opener (recheck R2)."""
    if "<" not in text:
        return text
    closes: dict[str, list[tuple[int, int]]] = {}
    for m in _TOOL_CLOSE_RX.finditer(text):
        closes.setdefault(m.group(1).lower(), []).append((m.start(), m.end()))
    starts = {k: [a for a, _b in v] for k, v in closes.items()}
    out, last = [], 0
    for m in _TOOL_OPEN_RX.finditer(text):
        if m.start() < last:
            continue
        name = m.group(1).lower()
        lst = starts.get(name, [])
        j = bisect.bisect_left(lst, m.end())
        if j < len(lst) and lst[j] - m.end() <= 4000:
            out.append(text[last:m.start()])
            out.append("[tool call removed]")
            last = closes[name][j][1]
    out.append(text[last:])
    return _TOOL_STRAY_RX.sub("[tool call removed]", "".join(out))


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _seed(text: str) -> str | None:
    for m in _SEED_RX.finditer(text):
        words = re.findall(r"[A-Za-z]+", m.group(1))
        if (12 <= len(words) <= 24 and all(w.islower() for w in words) and not any(w in _STOP for w in words)
                and len(set(words)) >= len(words) // 2):
            return "seed-phrase"
    return None


def _card(text: str, spaced_in: str | None = None) -> str | None:
    """15-16 digits passing the card checksum, written in groups or next to a card label (an order
    number is neither). *spaced_in*: text is a copy with whitespace removed; a number that was
    spaced out in that original counts as grouped."""
    for m in _CARD_RX.finditer(text):
        d = re.sub(r"[ -]", "", m.group(0))
        if 15 <= len(d) <= 16 and _luhn(d) and ((spaced_in is not None and d not in spaced_in) or d != m.group(0)
                                                or _CARD_LABEL_RX.search(text, max(0, m.start() - 40), m.start())):
            return "card-number"
    return None


def _seed_or_card(text: str) -> str | None:
    return _seed(text) or _card(text)


def _join_spaced(text: str) -> str:
    """Letter-spaced runs joined back ("s k - p r o j - a C" -> "sk-proj-aC")."""
    return _SPACED_CHARS_RX.sub(lambda m: re.sub(r"[ \t]+", "", m.group(0)), text)


def _rejoin(text: str, sep: str) -> str:
    """Lines joined with *sep*, spaces and tabs around each line break removed (linear: split, not a
    regex with two whitespace runs, recheck R2). With sep=" " blank lines are dropped."""
    parts = text.split("\n")
    if len(parts) == 1:
        return text
    parts = [parts[0].rstrip(" \t\r")] + [p.strip(" \t\r") for p in parts[1:-1]] + [parts[-1].lstrip(" \t\r")]
    return sep.join(p for p in parts if p) if sep else "".join(parts)


def _classes(v: str) -> int:
    return (any(c.islower() for c in v) + any(c.isupper() for c in v) + any(c.isdigit() for c in v)
            + any(not c.isalnum() for c in v))


def _secret_value(key: str, v: str) -> bool:
    """Does *v*, written after the label *key*, look like a secret? Not a placeholder, a call or
    expression, an attribute, a variable name or one ordinary word (recheck R3). Password labels
    accept shorter values ("hunter2"); other labels need a token-like value."""
    v = v.strip().rstrip(".,;:)]}'\"`")
    if len(v) < 6 or _PLACEHOLDER_RX.match(v) or len(set(v)) <= 2 or _CODE_VALUE_RX.search(v) or _IDENT_RX.match(v):
        return False
    letters = sum(c.isalpha() for c in v)
    digits = sum(c.isdigit() for c in v)
    if _PW_KEY_RX.search(key):
        return _classes(v) >= 2 or len(v) >= 10
    if letters < 4:
        return False                    # a date, a time, a number, a version
    return (len(v) >= 12 and digits >= 1) or (len(v) >= 10 and _classes(v) >= 3) or (len(v) >= 20 and _randomish(v))


def _probes(text: str, rv: normalize.Revealed | None = None) -> tuple[str, str]:
    """(NFKC with hidden characters removed and long blank runs collapsed, the same with markup,
    escapes and dashes undone and look-alikes folded)."""
    rv = rv or normalize.reveal(text or "")
    t0 = unicodedata.normalize("NFKC", rv.text + ("\n" + rv.alt if rv.alt else ""))
    t0 = _NL_RUN_RX.sub("\n\n", _WS_RUN_RX.sub(" ", t0))
    t1 = t0.translate(_DASHES)
    t1 = _MD_ESC_RX.sub("", t1)
    t1 = _TAG_RX.sub("", t1)
    t1 = re.sub(r"\*\*|__|~~", "", t1)
    t1 = normalize.fold_confusables(t1)
    return t0, t1


# literal text each token rule needs somewhere in the input: a cheap skip for long replies
_TOKEN_NEEDS = {
    "discord-token": (".",), "discord-webhook": ("",), "telegram-token": (":",),
    "google-oauth": ("ya29.",), "google-api-key": ("AIza",), "github-token": ("gh", "github_pat_"), "gitlab-token": ("glpat-",),
    "api-key": ("sk-",), "slack-token": ("xox",), "aws-key": ("AKIA", "ASIA"), "stripe-key": ("k_live_", "k_test_"),
    "hf-token": ("hf_",), "npm-token": ("npm_",), "pypi-token": ("pypi-AgE",), "sendgrid-key": ("SG.",),
    "pem": ("-----BEGIN",), "jwt": ("eyJ",),
    "token-fragment": ("gh", "github_pat_", "glpat-", "xox", "sk-", "hf_", "npm_", "pypi-AgE", "AKIA", "ASIA", "AIza", "ya29."),
}


def _token(text: str, squeezed: bool = False) -> str | None:
    for name, rx, sq, rnd in TOKEN_RX:
        if not any(lit in text for lit in _TOKEN_NEEDS[name]):
            continue
        if sq or not squeezed:
            for m in rx.finditer(text):
                if not rnd or _randomish(m.group(0)):
                    return name
    return None


def _context(text: str) -> str | None:
    for name, rx in CONTEXT_RX:
        if rx.search(text):
            return name
    for rx in (_ASSIGN_RX, _TABLE_RX):
        for m in rx.finditer(text):
            if _secret_value(m.group(1), m.group(2)):
                return "assigned-secret"
    for m in _SAID_RX.finditer(text):
        v = m.group(1).rstrip(".,;:!?)")
        if _secret_value("password", v) and re.search(r"[0-9\W_]", v) and re.search(r"[A-Za-z]", v):
            return "stated-password"
    for m in _CJK_PW_RX.finditer(text):
        if _secret_value("password", m.group(1)):
            return "stated-password"
    for m in _CONN_RX.finditer(text):
        v = m.group(2)
        if len(v) >= 3 and not _PLACEHOLDER_RX.match(v) and len(set(v)) > 2:
            return "conn-string"
    return _seed(text)


def secret_kind(text: str, clock: _Clock | None = None, rv: normalize.Revealed | None = None) -> str | None:
    clock = clock or _Clock(None)
    t0, t1 = _probes(text, rv)
    for t in (t0, t1):
        clock.check()
        k = _token(t) or _context(t) or _card(t)
        if k:
            return k
    spaced = _join_spaced(t1)                                 # letter-spaced secrets
    lines = _rejoin(t1, "")                                   # secrets wrapped over fixed-width lines
    lines_sp = _rejoin(t1, " ")
    for t in (spaced, lines):
        clock.check()
        k = _token(t) or _context(t) if t != t1 else None
        if k:
            return k + " (rearranged)"
    for t in (lines_sp, t1[::-1], lines_sp[::-1], _join_spaced(t1[::-1])):
        clock.check()
        k = _seed_or_card(t) or _token(t)
        if k:
            return k + " (rearranged)"
    squeezed = _SQUEEZE_RX.sub("", t1)
    k = _token(squeezed, squeezed=True) or _token(_SQUEEZE_RX.sub("", t1[::-1]), squeezed=True)
    if not k:
        digits = re.sub(r"\s+", "", t1)
        k = _card(digits, spaced_in=t1) if digits != t1 else None
    if k:
        return k + " (rearranged)"
    if len(t0) <= 200_000:
        for path, dec in decode.expand(t0, max_depth=2):
            clock.check()
            if not dec or path in ("words-reversed", "caesar"):
                continue
            if path == "rot13" or path.endswith(">rot13") or path == "reversed":
                k = _token(dec) or _token(normalize.fold_confusables(dec))      # strict formats only
            else:
                d0, d1 = _probes(dec)
                k = _token(d0) or _token(d1) or _context(d1) or _card(d1)
            if k:
                return k + " (encoded)"
    return None


# ---------------------------------------------------------------- links (recheck item 7)
# Destinations whose request logs an outsider cannot read: a link there is never a way out, whatever
# its query says. Decision review 2026-11-17 (pick 7): EXACT host names from a fixed list (no "google.<any
# country>" heuristic: google.qzx.invalid is not Google), whole first path segments ("/search", never
# "/searchbyimage"), no redirect paths (/url, /l/, click trackers), no DuckDuckGo (/l/ and !bangs are open
# redirects). Operators can add exact hosts (gatehouse.safe_link_hosts), never whole domains.
_GOOGLE_CC = ("com", "co.uk", "ca", "com.au", "co.nz", "ie", "de", "at", "ch", "fr", "be", "nl", "es", "pt", "it",
              "se", "no", "dk", "fi", "pl", "cz", "gr", "com.mx", "com.br", "com.ar", "cl", "co.in", "co.jp",
              "co.kr", "com.hk", "com.tw", "com.sg", "co.za")
_GOOGLE_HOSTS = frozenset(h for cc in _GOOGLE_CC for h in ("google." + cc, "www.google." + cc))
_YOUTUBE_FIRST = frozenset({"watch", "shorts", "embed", "playlist", "results", "channel"})
SAFE_LINKS = {
    **{h: "google" for h in _GOOGLE_HOSTS},
    "maps.google.com": "google-maps",
    "youtube.com": "youtube", "www.youtube.com": "youtube", "m.youtube.com": "youtube",
    "youtu.be": "any",
    "github.com": "any",
}
_REDIRECT_KEYS = frozenset({"btni", "url", "q_url", "continue", "redirect", "redirect_uri", "next", "dest",
                            "target", "u", "uddg"})
_LINK_RX = re.compile(r"(?i)(?:\b(?:https?|ftp):(?:\\?/){2}|(?<![\w@/.-])www\.)[^\s<>\"'`]{1,2048}")
_PIECE_SPLIT_RX = re.compile(r"[/?&=#;,.:@+~!*'()\[\]{}|\s]+")
_WORDS_RX = re.compile(r"[a-z0-9]{2,}|[\u3040-\u30ff\u3400-\u9fff\uac00-\ud7af]")
LINK_BLOB_CHARS = 24          # one encoded or random piece this long removes the link
LINK_SMALL_CHARS = 12         # random pieces this long add up across the links to one site ...
LINK_SMALL_TOTAL = 40         # ... and remove them all at this total
LINK_SHINGLE = 5              # words in a row from the conversation
MAX_LINKS = 300               # links checked one by one; beyond this every unsafe link is removed


def _entropy(s: str) -> float:
    n = len(s)
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def _wordy(piece: str) -> bool:
    """An article slug or name ("how-to-bake-bread-2024"): mostly lower-case words and short numbers."""
    parts = [p for p in re.split(r"[-_]+", piece) if p]
    if len(parts) < 2:
        return piece.isalpha() and (piece.islower() or piece.istitle())
    ok = sum(len(p) for p in parts if (p.isalpha() and (p.islower() or p.istitle())) or (p.isdigit() and len(p) <= 4))
    return ok >= 0.7 * sum(len(p) for p in parts)


_UUID_RX = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _blobbish(piece: str) -> bool:
    """Encoded or random-looking: base64/base32/hex/url-safe data, not a word, slug, number or date."""
    if _wordy(piece) or piece.isdigit() or _UUID_RX.fullmatch(piece):
        return False                    # a UUID is an id the site made, 16 bytes at most
    core = re.sub(r"[-_=%]", "", piece)
    if len(core) < 8:
        return False
    letters = sum(c.isalpha() for c in core)
    digits = sum(c.isdigit() for c in core)
    if re.fullmatch(r"[0-9a-fA-F]+", core) and digits >= 3 and letters >= 3:
        return True                                                # hex
    mixed_case = sum(1 for a, b in zip(core, core[1:]) if a.isalpha() and b.isalpha() and a.islower() != b.islower())
    return (letters >= 3 and (digits >= 2 or mixed_case >= 3)) and _entropy(core) >= 2.8


def _registrable(host: str) -> str:
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])                               # example.co.uk
    return ".".join(labels[-2:])


def _safe_link(host: str, path: str, extra: tuple, query: str = "") -> bool:
    """Exact host match only (decision review pick 7). The first path segment is compared whole."""
    if host in extra:
        return True
    rule = SAFE_LINKS.get(host)
    if rule is None and host.endswith(".wikipedia.org") and host.count(".") == 2:
        rule = "wikipedia"                                         # en., zh., ... (one label, dot boundary)
    if rule is None:
        return False
    segs = path.split("/")
    first = segs[1] if len(segs) > 1 else ""
    if rule == "any":
        return True
    if query and rule != "wikipedia":
        keys = {k.lower() for k, _v in urllib.parse.parse_qsl(query, keep_blank_values=True)}
        if keys & _REDIRECT_KEYS:                                  # I'm-feeling-lucky and redirect parameters
            return False
    if rule == "google":
        return first in ("search", "maps")
    if rule == "google-maps":
        return path in ("", "/") or first == "maps"
    if rule == "youtube":
        return first in _YOUTUBE_FIRST or (first.startswith("@") and len(first) > 1)
    if rule == "wikipedia":                                        # articles only: no Special:, no interwiki
        title = urllib.parse.unquote(segs[2]) if len(segs) > 2 else ""
        return first == "wiki" and bool(title) and ":" not in title
    return False


def _shingles(text: str, n: int = LINK_SHINGLE, limit: int = 40_000) -> set:
    w = _WORDS_RX.findall(text[-limit:].lower())
    return {tuple(w[i:i + n]) for i in range(len(w) - n + 1)}


def _link_parts(url: str) -> tuple[str, str, list[str], str] | None:
    u = url.replace("\\/", "/")
    if not re.match(r"(?i)[a-z][a-z0-9+.-]*://", u):
        u = "http://" + u
    try:
        sp = urllib.parse.urlsplit(u)
        host = (sp.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if not host:
        return None
    labels = host.split(".")
    sub = labels[:-2] if len(labels) > 2 else []
    texts = sub + [sp.username or "", sp.password or ""]
    texts.append(urllib.parse.unquote_plus(sp.path))
    for k, v in urllib.parse.parse_qsl(sp.query, keep_blank_values=True):
        texts += [k, v]
    if not sp.query.count("="):
        texts.append(urllib.parse.unquote_plus(sp.query))
    texts.append(urllib.parse.unquote_plus(sp.fragment))
    return host, sp.path or "/", [t for t in texts if t], sp.query


def _exfil_links(text: str, context: str, extra_safe: tuple, clock: _Clock) -> str:
    """Remove links shaped like data leaving the conversation. A link is removed when
    (1) any piece of its host, path, query or fragment is 24+ characters of encoded or random-looking
        data (base64, hex, ...), or
    (2) its random-looking pieces of 12+ characters, added up over all links to the same site in this
        reply, reach 40 characters (data split over several links), or
    (3) it carries five words in a row that also appear in the conversation (the context passed in:
        recent messages, files and tool results; not this reply, whose link text often repeats a slug).
    Links to destinations an outsider cannot read logs of (SAFE_LINKS, gatehouse.safe_link_hosts) are
    never removed: YouTube, Google search and Maps, Wikipedia articles, GitHub (exact hosts only)."""
    found = []
    for m in _LINK_RX.finditer(text):
        url = m.group(0)
        while url and url[-1] in ".,;:!?)]}*_~" and not (url[-1] == ")" and url.count("(") >= url.count(")")):
            url = url[:-1]
        if url:
            found.append((m.start(), m.start() + len(url), url))
    if not found:
        return text
    bad: set[int] = set()
    small: dict[str, list[tuple[int, int]]] = {}
    shingles = None
    for i, (_a, _b, url) in enumerate(found):
        clock.check()
        parts = _link_parts(url)
        if parts is None:
            continue
        host, path, texts, query = parts
        if _safe_link(host, path, extra_safe, query):
            continue
        if i >= MAX_LINKS:
            bad.add(i)
            continue
        pieces = [p for t in texts for p in _PIECE_SPLIT_RX.split(t) if p]
        if any(len(p) >= LINK_BLOB_CHARS and _blobbish(p) for p in pieces):
            bad.add(i)
            continue
        n_small = sum(len(p) for p in pieces if len(p) >= LINK_SMALL_CHARS and _blobbish(p))
        if n_small:
            small.setdefault(_registrable(host), []).append((i, n_small))
        if context:
            if shingles is None:
                shingles = _shingles(context)
            if _shingles(" ".join(texts)) & shingles:
                bad.add(i)
    for _site, lst in small.items():
        if sum(n for _i, n in lst) >= LINK_SMALL_TOTAL:
            bad.update(i for i, _n in lst)
    if not bad:
        return text
    out, last = [], 0
    for i, (a, b, _url) in enumerate(found):
        if i in bad:
            out.append(text[last:a])
            out.append("[link removed]")
            last = b
    out.append(text[last:])
    return "".join(out)


def filter_reply(text: str, cfg, context: str = "", deadline: float | None = REPLY_DEADLINE_S) -> tuple[str | None, list[str]]:
    """-> (replacement or None if unchanged, notes). cfg = config.Gatehouse. *context* = recent
    conversation text, for the link rule. Running past *deadline* seconds withholds the reply."""
    if not isinstance(text, str):
        raise TypeError("reply is not text")
    clock = _Clock(deadline)
    try:
        return _filter(text, cfg, context or "", clock)
    except _Timeout:
        return WITHHELD, ["timeout"]


def _filter(text: str, cfg, context: str, clock: _Clock) -> tuple[str | None, list[str]]:
    notes: list[str] = []
    rv = normalize.reveal(text)
    if cfg.withhold_secrets:
        kind = secret_kind(text, clock, rv)
        if kind:
            return WITHHELD, ["secret:" + kind]
    clock.check()
    t = text
    if cfg.strip_invisible:
        if rv.text != t:
            t = rv.text
            notes.append("invisible")
            if rv.hidden_payloads:
                notes.append("hidden-text")
    clock.check()
    if cfg.block_media_directives:
        t2 = strip_directives(_strip_tool_calls(t))
        if t2 != t:
            t = t2
            notes.append("media-directive")
    clock.check()
    if cfg.block_markdown_images:
        def images(s: str) -> str:
            s = _MD_IMAGE_RX.sub(lambda m: f"[image: {normalize.collapse_ws(m.group(1)) or 'link removed'}]", s)
            s = _REF_IMAGE_RX.sub(lambda m: f"[image: {normalize.collapse_ws(m.group(1)) or 'link removed'}]", s)
            s = _REF_DEF_RX.sub("", s)
            return _HTML_MEDIA_RX.sub("[media removed]", s)
        t2 = _outside_code(t, images)            # code is shown as text, never fetched (recheck R3)
        if t2 != t:
            t = t2
            notes.append("remote-image")
    clock.check()
    if getattr(cfg, "block_query_links", True):
        t2 = _exfil_links(t, context, tuple(getattr(cfg, "safe_link_hosts", ()) or ()), clock)
        if t2 != t:
            t = t2
            notes.append("data-link")
    for rx in cfg.id_patterns:
        t2 = rx.sub("(id removed)", t)
        t2n = unicodedata.normalize("NFKC", t2)
        if rx.search(t2n):          # a look-alike id spread over full-width characters
            t2 = rx.sub("(id removed)", t2n)
        if t2 != t:
            t = t2
            if "id" not in notes:
                notes.append("id")
    if t == text:
        return None, notes
    if not t.strip():
        return EMPTY, notes + ["empty"]
    return t, notes
