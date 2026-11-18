"""Threshold scan: one verdict for one piece of untrusted text (or for all parts of one message).

Layers: the visible text (also with removed characters read as spaces, and squashed to letters
only), text hidden in invisible characters, one combined "unescape" layer (JSON/C string escapes,
entities, percent, quoted-printable), decoded payloads (base64, hex, base32/85 ...) and whole-text
transforms (rot13, Caesar, reversed). Every layer is matched in several normalised forms. A family
hit inside a hidden or decoded layer weighs more: people do not encode ordinary requests. Signals
from hidden characters add to the score on their own.

Fail closed: a decode limit, a time limit or an internal error HOLDS (review H1, H2, L2).
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field

from . import decode, normalize, patterns

HOLD, WEAK, PASS = "hold", "weak", "pass"
HOLD_AT, WEAK_AT = 1.0, 0.4
LAYER_BONUS = 0.5
DEFAULT_DEADLINE_S = 10.0
JOIN_EDGE_CHARS = 4000      # when joined parts are too long, each part keeps this much at both ends
SIGNAL_WEIGHTS = {
    "tag-text": 1.0, "vs-smuggling": 1.0, "zero-width-bits": 1.0, "decode-limit": 1.0, "check-timeout": 1.0,
    "check-error": 1.0, "bidi-override": 0.4, "many-invisible": 0.4, "mixed-script": 0.4,
}
_ORDER = {PASS: 0, WEAK: 1, HOLD: 2}
_NON_ASCII_RX = re.compile(r"[^\x00-\x7f]+")


class _Timeout(Exception):
    pass


class Deadline:
    """A shared time limit for one scan (or all parts of one message)."""

    def __init__(self, seconds: float | None):
        self.end = None if not seconds else time.monotonic() + seconds

    def check(self) -> None:
        if self.end is not None and time.monotonic() > self.end:
            raise _Timeout()


@dataclass
class Verdict:
    level: str = PASS
    score: float = 0.0
    families: dict = field(default_factory=dict)      # family -> best weight
    reasons: list = field(default_factory=list)       # "family@layer"
    signals: list = field(default_factory=list)
    channel: str = "chat"
    chars: int = 0
    sha: str = ""
    notes: list = field(default_factory=list)
    snippets: list = field(default_factory=list)      # matched text (visible layers), for the owner's notice
    content_level: str = PASS                         # strongest level among non-chat parts (scan_many)

    @property
    def hold(self) -> bool:
        return self.level == HOLD

    def raise_to(self, level: str, reason: str) -> None:
        """Raise (never lower) the verdict."""
        if _ORDER[level] > _ORDER[self.level]:
            self.level = level
        if reason not in self.reasons:
            self.reasons.append(reason)

    def summary(self) -> str:
        fams = sorted(self.families) + [s for s in self.signals if s not in self.families]
        return ", ".join(fams + [n for n in self.notes if n not in fams])[:200] or "no details"


def text_sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _level(score: float) -> str:
    return HOLD if score >= HOLD_AT - 1e-9 else WEAK if score >= WEAK_AT - 1e-9 else PASS


def _match_layer(fam: dict, reasons: list, layer: str, text: str, forms: list[str], chat: bool, bonus: float,
                 raw: bool = True, snippets: list | None = None, dl: Deadline | None = None) -> None:
    for i, form in enumerate(forms):
        if dl is not None:
            dl.check()
        for family, w, snip in patterns.match(form, raw=text if (raw and i == 0) else None, chat=chat):
            w = min(1.0, w + bonus) if bonus and w >= patterns.WEAK else w
            if w > fam.get(family, 0.0):
                fam[family] = w
            r = f"{family}@{layer}"
            if r not in reasons:
                reasons.append(r)
            if snippets is not None and len(snippets) < 5 and snip not in snippets:
                snippets.append(snip)


def _match_squashed(fam: dict, reasons: list, layer: str, text: str, chat: bool, bonus: float) -> None:
    for sq in normalize.squashed(text):
        for family, w, _p in patterns.match_squashed_whole(sq, chat):
            w = min(1.0, w + bonus) if bonus else w
            if w > fam.get(family, 0.0):
                fam[family] = w
            if f"{family}@{layer}" not in reasons:
                reasons.append(f"{family}@{layer}")


def _forms(rv: normalize.Revealed) -> list[str]:
    out = normalize.variants(rv.text)
    for extra in (rv.spaced, rv.alt):         # alt: escape sequences read as text (recheck R1)
        if extra:
            out += [v for v in normalize.variants(extra) if v not in out]
    return out


def _sources(fam: dict, signals: list) -> int:
    return sum(1 for w in fam.values() if w > 0) + sum(1 for s in dict.fromkeys(signals) if SIGNAL_WEIGHTS.get(s, 0.0))


def _lone_weak(level: str, fam: dict, signals: list) -> bool:
    """A weak score made of ONE weak sign (a 0.4 family or any 0.4 signal): soft evidence that an
    ordinary document often shows (a YAML "system:" key, a "New instructions:" heading, zero-width
    spaces, a Greek symbol). Content needs two signs, or one medium-or-stronger family such as
    a plain override phrase, to be held (recheck R5)."""
    return (level == WEAK and _sources(fam, signals) == 1
            and all(w < patterns.MEDIUM - 1e-9 for w in fam.values()))


def scan_text(text, channel: str = "chat", max_chars: int = 120_000,
              deadline: "float | Deadline | None" = DEFAULT_DEADLINE_S) -> Verdict:
    """Scan untrusted text. Never raises: non-str input, oversized input, a decode or time limit and
    any internal error all give a HOLD verdict."""
    v = Verdict(channel=channel)
    if not isinstance(text, str):
        v.raise_to(HOLD, "not-text")
        v.notes.append("not-text")
        return v
    v.chars = len(text)
    v.sha = text_sha(text)
    if len(text) > max_chars:
        v.raise_to(HOLD, "oversized")
        v.notes.append("too long to check")
        return v
    dl = deadline if isinstance(deadline, Deadline) else Deadline(deadline)
    try:
        return _scan(v, text, channel, dl)
    except _Timeout:
        return _fail(v, "check-timeout", "took too long to check")
    except Exception as e:  # noqa: BLE001  (fail closed on anything unexpected)
        return _fail(v, "check-error", f"could not check ({type(e).__name__})")


def _fail(v: Verdict, signal: str, note: str) -> Verdict:
    v.level, v.score = HOLD, max(v.score, 1.0)
    v.signals.append(signal)
    v.reasons.append("signal:" + signal)
    v.notes.append(note)
    return v


def _scan(v: Verdict, text: str, channel: str, dl: Deadline) -> Verdict:
    chat = channel == "chat"
    fam: dict[str, float] = {}
    reasons: list[str] = []
    snippets: list[str] = []

    rv = normalize.reveal(text)
    signals = list(rv.flags)
    if normalize.mixed_script_words(rv.text) >= 2:
        signals.append("mixed-script")

    # visible layer: every normalised form (also with removed characters read as spaces), squashed
    _match_layer(fam, reasons, "visible", rv.text, _forms(rv), chat, 0.0, snippets=snippets, dl=dl)
    dl.check()
    _match_squashed(fam, reasons, "squashed", rv.text, chat, 0.0)
    if rv.alt:
        _match_squashed(fam, reasons, "squashed", rv.alt, chat, 0.0)
    # letter-spaced runs, squashed
    for src in [rv.text] + list(rv.hidden_payloads):
        for sq in normalize.spaced_runs(src):
            for family, w, _p in patterns.match_squashed(sq):
                fam[family] = max(fam.get(family, 0.0), w)
                if f"{family}@spaced" not in reasons:
                    reasons.append(f"{family}@spaced")
    # hidden payloads: full forms, with the layer bonus
    for p in rv.hidden_payloads:
        _match_layer(fam, reasons, "hidden", p, normalize.variants(p), False, LAYER_BONUS, dl=dl)
        _match_squashed(fam, reasons, "hidden", p, False, LAYER_BONUS)
    # decoded layers (of the visible text and of hidden payloads)
    for src in [rv.text] + list(rv.hidden_payloads):
        dl.check()
        for path, dec in decode.expand(src):
            dl.check()
            if path.startswith("limit:"):
                signals.append("decode-limit")
                if "could not fully decode" not in v.notes:
                    v.notes.append("could not fully decode")
                continue
            if not dec:
                continue
            if path in ("rot13", "reversed", "words-reversed", "caesar"):
                if path in ("rot13", "caesar"):
                    # these change Latin letters only: the rest would be the visible text read again,
                    # without the chat discount and with the bonus (recheck R4)
                    dec = _NON_ASCII_RX.sub(" ", dec)
                    if sum(c.isalpha() for c in dec) < 4:
                        continue
                if normalize.collapse_ws(dec) == normalize.collapse_ws(rv.text):
                    continue
                _match_layer(fam, reasons, path, dec, [normalize.collapse_ws(dec), normalize.words_only(dec)],
                             False, LAYER_BONUS, raw=False, dl=dl)
                continue
            inner = normalize.reveal(dec)
            if path == "unescape":
                # escaped text is ordinary text in another notation (a JSON tool result): read it like
                # the visible layer, same weights, and keep its hidden-character signals
                signals += [f for f in inner.flags if f not in signals]
                _match_layer(fam, reasons, path, inner.text, _forms(inner), chat, 0.0, snippets=snippets, dl=dl)
                _match_squashed(fam, reasons, path, inner.text, chat, 0.0)
                for p in inner.hidden_payloads:
                    _match_layer(fam, reasons, path + ">hidden", p, normalize.variants(p), False, LAYER_BONUS, dl=dl)
                continue
            for p in inner.hidden_payloads:
                _match_layer(fam, reasons, path + ">hidden", p, [normalize.collapse_ws(p)], False, LAYER_BONUS, dl=dl)
            forms = normalize.variants(inner.text)
            if len(inner.text) > 20_000:
                forms = forms[:1] + forms[5:7]
            _match_layer(fam, reasons, path, inner.text, forms, False, LAYER_BONUS, dl=dl)
            _match_squashed(fam, reasons, path, inner.text, False, LAYER_BONUS)

    score = sum(fam.values())
    for s in dict.fromkeys(signals):
        w = SIGNAL_WEIGHTS.get(s, 0.0)
        if w:
            score += w
            if s not in v.signals:
                v.signals.append(s)
    v.families = fam
    v.reasons = reasons + [f"signal:{s}" for s in v.signals]
    v.snippets = snippets
    v.score = round(min(score, 9.0), 3)
    v.level = _level(v.score)
    if not chat and _lone_weak(v.level, fam, v.signals):
        v.level = PASS
        v.notes.append("one weak sign only")
    return v


# Sender display names and file names ("name" parts) go last: between the quoted text, the message
# and the file text they would break an instruction split over those parts (recheck H3).
_READ_ORDER = {"reply_context": 0, "chat": 1, "attachment": 2, "name": 9}


def _joined(parts: list[tuple[str, str]], max_chars: int) -> str:
    texts = [t for _c, t in sorted(parts, key=lambda p: _READ_ORDER.get(p[0], 3))]
    if sum(len(t) for t in texts) + len(texts) > max_chars:
        texts = [t if len(t) <= 2 * JOIN_EDGE_CHARS else t[:JOIN_EDGE_CHARS] + "\n" + t[-JOIN_EDGE_CHARS:] for t in texts]
    return "\n".join(texts)[:max_chars]


def scan_many(parts: list[tuple[str, str]], max_chars: int,
              deadline: "float | Deadline | None" = DEFAULT_DEADLINE_S) -> Verdict:
    """Scan the (channel, text) parts of one message. Each part is scanned on its own, then the parts
    are read together in the order the model reads them (quoted text, message, attachments), and
    family weights add up across parts (review H3). The result is never weaker than any part."""
    dl = deadline if isinstance(deadline, Deadline) else Deadline(deadline)
    out = Verdict(channel="mixed")
    level = PASS
    signals: list[str] = []
    for channel, text in parts:
        v = scan_text(text, channel, max_chars, dl)
        for f, w in v.families.items():
            if w > out.families.get(f, 0.0):
                out.families[f] = w
        out.reasons += [f"{channel}:{r}" for r in v.reasons]
        signals += [s for s in v.signals if s not in signals]
        out.notes += [n for n in v.notes if n not in out.notes]
        out.snippets += [s for s in v.snippets if s not in out.snippets][:5 - len(out.snippets)]
        out.chars += v.chars
        if _ORDER[v.level] > _ORDER[level]:
            level = v.level
        if channel != "chat" and _ORDER[v.level] > _ORDER[out.content_level]:
            out.content_level = v.level
    texts = [(c, t) for c, t in parts if isinstance(t, str) and t.strip()]
    if len(texts) >= 2 and level != HOLD:
        has_chat = any(c == "chat" for c, _t in texts)
        jv = scan_text(_joined(texts, max_chars), "chat" if has_chat else "attachment", max_chars, dl)
        for f, w in jv.families.items():
            if w > out.families.get(f, 0.0):
                out.families[f] = w
                out.reasons.append(f"joined:{f}")
        signals += [s for s in jv.signals if s not in signals]
        out.notes += [n for n in jv.notes if n not in out.notes]
        out.snippets += [s for s in jv.snippets if s not in out.snippets][:5 - len(out.snippets)]
        if jv.level == HOLD and any(s in ("check-timeout", "check-error") for s in jv.signals):
            level = HOLD
        if has_chat and any(c != "chat" for c, _t in texts) and level != HOLD:
            # a line split between the message and a file or quote is file text too: read the join at
            # content weights, and count what the message alone does not already show (recheck H3)
            chat_text = "\n".join(t for c, t in texts if c == "chat")
            alone = scan_text(chat_text, "attachment", max_chars, dl).families
            jc = scan_text(_joined(texts, max_chars), "attachment", max_chars, dl)
            for f, w in jc.families.items():
                if w > max(out.families.get(f, 0.0), alone.get(f, 0.0)) + 1e-9:
                    out.families[f] = w
                    out.reasons.append(f"joined:{f}")
            if jc.level == HOLD and any(s in ("check-timeout", "check-error") for s in jc.signals):
                level = HOLD
    score = sum(out.families.values()) + sum(SIGNAL_WEIGHTS.get(s, 0.0) for s in signals)
    out.signals = signals
    out.score = round(min(score, 9.0), 3)
    combined = _level(out.score)
    if _lone_weak(combined, out.families, signals):
        combined = PASS                       # parts already carry their own (chat) weak level
    out.level = combined if _ORDER[combined] > _ORDER[level] else level
    if out.level != PASS and level == PASS:
        out.notes.append("parts read together")
    return out
