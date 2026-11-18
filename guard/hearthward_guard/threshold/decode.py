"""Find and decode encoded payloads so the pattern families can see what they say.

Handled: base64 (standard, URL-safe, chunked, word by word), base32 (either case), base85/ascii85,
hex (plain, separated, \\x41, 0x41), one combined "unescape" layer (JSON/C/JS string escapes, octal,
percent and %u escapes, HTML entities with or without ';', quoted-printable incl. soft line breaks),
8-bit binary groups, decimal character codes, and the transforms rot13, other Caesar shifts,
reversed text and reversed words.

Decoding is recursive up to MAX_DEPTH and bounded in candidate count and total output size. Every
limit is REPORTED as a ("limit:<kind>", "") layer: the scan treats "could not fully check" as a
hold (review H2), so stacking or padding can never push a payload past the decoder unseen.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import quopri
import re
import urllib.parse

from . import normalize

MAX_DEPTH = 4
MAX_CANDIDATES = 256           # distinct successful decodes per text
MIN_BUDGET = 200_000           # decoded characters per expand(); at least BUDGET_FACTOR x the input
BUDGET_FACTOR = 4
TRANSFORM_MAX_CHARS = 200_000  # rot13 / reversed / Caesar / reversed words only for texts up to this size

# base64 wrapped or split into chunks by whitespace (each chunk 8+ characters)
_B64_CHUNKED_RX = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/_-]{8,}[ \t]*\r?\n?[ \t]*){2,}[A-Za-z0-9+/_-]*={0,2}")
_B32_RX = re.compile(r"(?<![A-Za-z0-9])(?:[A-Z2-7]{16,}|[a-z2-7]{16,})={0,6}(?![A-Za-z0-9])")
_B64_RX = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_B64_LOOSE_RX = re.compile(r"[A-Za-z0-9+/_-]{16,}")
_B64_WORD_RX = re.compile(r"[A-Za-z0-9+/]{4,}={0,2}")
_B85_RX = re.compile(r"(?<!\S)(?:<~)?[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~.,:\[\]/\\\"']{20,}(?:~>)?(?!\S)")
_HEX_RX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[\s:,\-]?){8,}(?![0-9A-Fa-f])")
_XHEX_RX = re.compile(r"(?:0x[0-9A-Fa-f]{2}[\s,]*){4,}")
_BIN_RX = re.compile(r"(?<![01])(?:[01]{8}[\s,]?){4,}(?![01])")
_DEC_RX = re.compile(r"(?<!\d)(?:(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])[\s,;]+){7,}(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])(?!\d)")

# unescape triggers
_PCT_RX = re.compile(r"(?:%[0-9A-Fa-f]{2}[^%\s]{0,24}){3,}|(?:%u[0-9A-Fa-f]{4}){2,}")
_PCTU_RX = re.compile(r"%u([0-9A-Fa-f]{4})")
# named entities need ';' except the legacy ones HTML also reads without it ("&nbsp" between words, recheck H4)
_ENTITY_RX = re.compile(r"&(?:#\d{1,7};?|#[xX][0-9A-Fa-f]{1,6};?|[A-Za-z]{2,10};|(?:nbsp|amp|lt|gt|quot|shy|copy|reg)(?![;]))")
_ENTITY_HUGE_RX = re.compile(r"&#(?:[xX]0*[0-9A-Fa-f]{7,}|0*\d{8,});?")
_BSLASH_RX = re.compile(r"\\(?:u\{[0-9A-Fa-f]{1,6}\}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|x[0-9A-Fa-f]{2}|[0-7]{2,3}|[nrtbfv\"'/\\])")
_BYTES_ESC_RX = re.compile(r"(?:\\x[0-9A-Fa-f]{2}|\\[0-3][0-7]{2})+")
_QP_RX = re.compile(r"(?:=[0-9A-F]{2}){3,}|(?:=\r?\n[^\n]{0,200}){3,}")
_SIMPLE_ESC = {"n": "\n", "r": "\r", "t": "\t", "b": " ", "f": " ", "v": " ", '"': '"', "'": "'", "/": "/", "\\": "\\"}


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return ok / len(s)


def _texty(b: bytes) -> str | None:
    """Decode bytes as text if they look like text (UTF-8 or UTF-16 with BOM), else None."""
    if not b:
        return None
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encs: tuple = ("utf-16",)
    elif len(b) >= 8 and b.count(0) * 3 >= len(b):
        encs = ("utf-16-le", "utf-16-be")         # BOM-less UTF-16
    else:
        encs = ("utf-8",)
    for enc in encs:
        try:
            s = b.decode(enc)
        except UnicodeDecodeError:
            continue
        if _printable_ratio(s) >= 0.85 and sum(c.isalpha() for c in s) >= 3:
            return s
        # text hidden in invisible characters (tags, variation selectors) inside an encoding
        visible = normalize.HIDDEN_RX.sub("", s)
        if len(s) - len(visible) >= 4 and (not visible or _printable_ratio(visible) >= 0.85):
            return s
    return None


def _b64(token: str) -> str | None:
    t = token.strip()
    pad = "=" * (-len(t.rstrip("=")) % 4)
    core = t.rstrip("=") + pad
    for fn in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = _texty(fn(core.encode("ascii")))
        except (binascii.Error, ValueError):
            continue
        if out:
            return out
    return None


def _b32(token: str) -> str | None:
    core = token.rstrip("=").upper()
    try:
        return _texty(base64.b32decode(core + "=" * (-len(core) % 8)))
    except (binascii.Error, ValueError):
        return None


def _b85(token: str) -> str | None:
    t = token
    fns = []
    if t.startswith("<~") and t.endswith("~>"):
        t = t[2:-2]
        fns = [base64.a85decode]
    else:
        fns = [base64.b85decode, base64.a85decode]
    for fn in fns:
        try:
            out = _texty(fn(t.encode("ascii")))
        except (binascii.Error, ValueError, UnicodeEncodeError):
            continue
        if out:
            return out
    return None


def _hex(token: str) -> str | None:
    h = re.sub(r"[^0-9A-Fa-f]", "", token.replace("0x", "").replace("\\x", ""))
    if len(h) % 2:
        h = h[:-1]
    try:
        return _texty(bytes.fromhex(h))
    except ValueError:
        return None


def _bin(token: str) -> str | None:
    bits = re.sub(r"[^01]", "", token)
    data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))
    return _texty(data)


def _dec(token: str) -> str | None:
    nums = [int(x) for x in re.findall(r"\d+", token)]
    s = "".join(chr(x) for x in nums)
    return s if sum(c.isalpha() for c in s) >= 4 else None


def _rot13(s: str) -> str:
    return codecs.decode(s, "rot13")


def _esc_bytes(m: re.Match) -> str:
    raw = m.group(0)
    data = bytes(int(x[1:], 16) if x.startswith("x") else int(x, 8)
                 for x in re.findall(r"x[0-9A-Fa-f]{2}|[0-3][0-7]{2}", raw))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def _esc_one(m: re.Match) -> str:
    e = m.group(0)[1:]
    if e in _SIMPLE_ESC:
        return _SIMPLE_ESC[e]
    if e.startswith("u{"):
        cp = int(e[2:-1], 16)
    elif e[0] in "uUx":
        cp = int(e[1:], 16)
    else:
        cp = int(e, 8)
    return chr(cp) if cp <= 0x10FFFF else "\ufffd"


def unescape(text: str) -> str | None:
    """One combined layer for whole-text escapes (review C1, M3): HTML entities (also without ';'),
    percent and %u escapes, JSON/C/JS backslash escapes (\\n \\t \\" \\/, single \\uXXXX incl.
    surrogate pairs, \\u{..}, \\xNN and octal byte runs), quoted-printable. None = nothing to undo."""
    t = text
    if "&" in t and _ENTITY_RX.search(t):
        t = _ENTITY_HUGE_RX.sub("\ufffd", t)       # html.unescape would hit int() digit limits
        try:
            t = html.unescape(t)
        except (ValueError, OverflowError):
            pass
    if "%" in t and _PCT_RX.search(t):
        t = _PCTU_RX.sub(lambda m: chr(int(m.group(1), 16)), t)
        t = urllib.parse.unquote(t)
    if "\\" in t and _BSLASH_RX.search(t):
        t = _BYTES_ESC_RX.sub(_esc_bytes, t)
        t = _BSLASH_RX.sub(_esc_one, t)
        if any(0xD800 <= ord(c) <= 0xDFFF for c in t):
            t = t.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
    if "=" in t and _QP_RX.search(t):
        try:
            t = quopri.decodestring(t.encode("utf-8", "replace")).decode("utf-8", "replace")
        except (ValueError, binascii.Error):
            pass
    return t if t != text else None


def _b64_words(text: str) -> str | None:
    """Base64 word by word: 3+ consecutive tokens that each decode to plain ASCII text."""
    best: list[str] = []
    run: list[str] = []
    for tok in text.split():
        dec = None
        if len(tok) % 4 == 0 and _B64_WORD_RX.fullmatch(tok):
            try:
                b = base64.b64decode(tok, validate=True)
                if b and all(32 <= x < 127 for x in b) and any(chr(x).isalpha() for x in b):
                    dec = b.decode("ascii")
            except (binascii.Error, ValueError):
                dec = None
        if dec is not None:
            run.append(dec)
        else:
            if len(run) >= 3:
                best.extend(run + ["\n"])
            run = []
    if len(run) >= 3:
        best.extend(run)
    joined = " ".join(best).strip()
    return joined or None


def candidates_ex(text: str) -> tuple[list[tuple[str, str]], bool]:
    """One level of decoding: ([(kind, decoded text)], capped). Identical tokens are decoded once;
    capped=True when MAX_CANDIDATES distinct decodes were reached and the rest was not looked at."""
    out: list[tuple[str, str]] = []
    seen_tok: set = set()
    seen_out: set = set()
    capped = False

    def add(kind: str, s: str | None) -> bool:
        nonlocal capped
        if not s or not s.strip() or s == text or s in seen_out:
            return True
        if len(out) >= MAX_CANDIDATES:
            capped = True
            return False
        seen_out.add(s)
        out.append((kind, s))
        return True

    def tokens(rx, kind):
        for m in rx.finditer(text):
            tok = m.group(0)
            if (kind, tok) in seen_tok:
                continue
            seen_tok.add((kind, tok))
            yield tok

    add("unescape", unescape(text))
    steps = [
        (_B64_RX, "base64", lambda t: _b64(t) if not re.fullmatch(r"[A-Za-z]+|[0-9]+|[a-z_-]+|[A-Z_-]+", t) else None),
        (_B64_CHUNKED_RX, "base64", lambda t: (lambda c: _b64(c) if len(c) >= 24 and c != t else None)(re.sub(r"\s+", "", t))),
        (_B32_RX, "base32", _b32),
        (_HEX_RX, "hex", _hex),
        (_XHEX_RX, "hex", _hex),
        (_BIN_RX, "binary", _bin),
        (_DEC_RX, "charcodes", _dec),
        (_B85_RX, "base85", lambda t: _b85(t) if re.search(r"[A-Za-z]", t) and re.search(r"[^A-Za-z0-9]", t) else None),
    ]
    for rx, kind, fn in steps:
        for tok in tokens(rx, kind):
            if not add(kind, fn(tok)):
                return out, True
    add("base64-words", _b64_words(text) if len(text) <= TRANSFORM_MAX_CHARS else None)
    return out, capped


def candidates(text: str) -> list[tuple[str, str]]:
    return candidates_ex(text)[0]


# English letter frequencies (per mille) for picking the most likely Caesar shift.
_FREQ = [82, 15, 28, 43, 127, 22, 20, 61, 70, 2, 8, 40, 24, 67, 75, 19, 1, 60, 63, 91, 28, 10, 24, 2, 20, 1]


def caesar_guess(text: str) -> str | None:
    """The best-looking Caesar shift other than 0 and 13 (rot13 has its own layer), when it reads
    clearly more like English than the text as written."""
    counts = [0] * 26
    for c in text.lower():
        o = ord(c) - 97
        if 0 <= o < 26:
            counts[o] += 1
    total = sum(counts)
    if total < 20:
        return None

    def chi(shift: int) -> float:
        x = 0.0
        for i in range(26):
            exp = _FREQ[i] * total / 1000 + 0.1
            obs = counts[(i + shift) % 26]
            x += (obs - exp) ** 2 / exp
        return x

    scores = {s: chi(s) for s in range(26)}
    best = min((s for s in scores if s not in (0, 13)), key=scores.get)
    if scores[best] >= 0.5 * scores[0]:
        return None
    return "".join(chr((ord(c) - 97 - best) % 26 + 97) if "a" <= c <= "z"
                   else chr((ord(c) - 65 - best) % 26 + 65) if "A" <= c <= "Z" else c for c in text)


def transforms(text: str) -> list[tuple[str, str]]:
    """Whole-text transforms of the input: rot13, reversed, each word reversed, a likely Caesar shift."""
    if len(text) > TRANSFORM_MAX_CHARS:
        return [("rot13", _rot13(text)), ("reversed", text[::-1])]
    out = [("rot13", _rot13(text)), ("reversed", text[::-1]),
           ("words-reversed", " ".join(w[::-1] for w in text.split()))]
    c = caesar_guess(text)
    if c:
        out.append(("caesar", c))
    return out


def expand(text: str, max_depth: int = MAX_DEPTH, budget: int | None = None) -> list[tuple[str, str]]:
    """All decoded layers [(path, text)], e.g. ("base64>hex", "..."), plus the whole-text transforms
    of the original. Any limit that stopped decoding is reported as ("limit:<kind>", "")."""
    budget = max(MIN_BUDGET, BUDGET_FACTOR * len(text)) if budget is None else budget
    layers: list[tuple[str, str]] = transforms(text)
    used = 0     # the budget counts decoded output (rot13 and reversed copies of decoded layers are not charged)
    frontier: list[tuple[str, str]] = [("", text)]
    seen = {text}
    # two steps in either order: rot13 or reversed text that is itself encoded (recheck M3)
    if len(text) <= TRANSFORM_MAX_CHARS and _B64_LOOSE_RX.search(text):
        for kind, t in layers[:2]:
            if t not in seen:
                seen.add(t)
                frontier.append((kind, t))
    limits: list[str] = []
    for depth in range(max_depth + 1):
        nxt: list[tuple[str, str]] = []
        for path, t in frontier:
            cands, capped = candidates_ex(t)
            if capped and "candidates" not in limits:
                limits.append("candidates")
            for kind, dec in cands:
                if dec in seen:
                    continue
                if depth == max_depth:
                    if "depth" not in limits:
                        limits.append("depth")
                    break
                if used + len(dec) > budget:
                    limits.append("budget")
                    return layers + [("limit:" + k, "") for k in limits]
                seen.add(dec)
                used += len(dec)
                p = f"{path}>{kind}" if path else kind
                layers.append((p, dec))
                nxt.append((p, dec))
                for suffix, r in ((">rot13", _rot13(dec)), (">reversed", dec[::-1])):
                    if r not in seen:
                        seen.add(r)
                        layers.append((p + suffix, r))
        if not nxt:
            break
        frontier = nxt
    return layers + [("limit:" + k, "") for k in limits]
