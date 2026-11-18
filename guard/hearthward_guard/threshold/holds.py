"""Held messages waiting for an owner's follow / ignore.

In memory only (v1): a restart drops every pending hold, which equals "ignore". So the owner hears
about it, the NUMBER of pending holds (never their content) is kept in a small state file; after a
restart the guard tells the owner how many were dropped (see hooks). Timeouts are resolved lazily
(on the next event or command), because Hermes has no documented way for a plugin to send outside a
hook. Ids use an alphabet without look-alike characters, always contain a digit (so ordinary words
like "follow thread" are never commands) and are matched strictly in ASCII, so a full-width or
zero-width copy of an id never matches.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field

ID_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
ID_DIGITS = "23456789"
ID_LEN = 6
ID_RX = re.compile(r"^(?=[a-z2-9]*[2-9])[a-hjkmnp-z2-9]{6}$")
# "follow abc123", "/follow abc123", "/follow@botname abc123" (ASCII only, whole message).
COMMAND_RX = re.compile(r"^[ \t]*/?((?i:follow|ignore))(?:@[A-Za-z0-9_]{1,64})?[ \t]+([a-z0-9]{6})[ \t]*$", re.ASCII)
KEEP_TEXT_CHARS = 60_000        # per hold: message text kept for a release (review M12)
KEEP_ATTACHMENT_CHARS = 20_000  # per attachment
KEEP_TOTAL_CHARS = 60_000       # all attachments of one hold together


@dataclass
class Hold:
    hold_id: str
    created: float
    platform: str
    chat_id: str
    user_id: str
    text: str                      # the message text as received (kept in memory only, capped)
    attachment_texts: list = field(default_factory=list)   # [(name, text)] of scanned text attachments (capped)
    had_media: bool = False
    summary: str = ""
    sha: str = ""
    snippet: str = ""              # the matched part, for the owner's notice
    cut: bool = False              # text or attachments were cut to the keep limits


@dataclass
class Resolution:
    ok: bool
    verb: str = ""
    hold: Hold | None = None
    message: str = ""


def cap_texts(text: str, attachment_texts: list) -> tuple[str, list, bool]:
    """Cut what a hold keeps to the limits above. -> (text, attachment_texts, cut)."""
    cut = len(text) > KEEP_TEXT_CHARS
    text = text[:KEEP_TEXT_CHARS]
    out, total = [], 0
    for name, body in attachment_texts:
        room = max(0, min(KEEP_ATTACHMENT_CHARS, KEEP_TOTAL_CHARS - total))
        if len(body) > room:
            cut = True
        body = body[:room]
        total += len(body)
        out.append((name, body))
    return text, out, cut


class HoldStore:
    def __init__(self, timeout_min: int = 30, max_pending: int = 50, notices_per_sender_10min: int = 3,
                 clock=time.monotonic, state_path: str = ""):
        self.timeout = timeout_min * 60
        self.max_pending = max_pending
        self.notice_limit = notices_per_sender_10min
        self.clock = clock
        self.state_path = state_path
        self._lock = threading.Lock()
        self._holds: "OrderedDict[str, Hold]" = OrderedDict()
        self._expired: "OrderedDict[str, float]" = OrderedDict()   # id -> when (for a clear 'expired' reply)
        self._notices: dict[tuple, deque] = {}
        self.dropped_at_start = self._read_state()
        self._write_state()

    # ---- pending-count state file (numbers only, never content)
    def _read_state(self) -> int:
        if not self.state_path:
            return 0
        try:
            with open(self.state_path, encoding="utf-8") as f:
                n = json.load(f).get("pending", 0)
            return n if isinstance(n, int) and n > 0 else 0
        except (OSError, ValueError, AttributeError):
            return 0

    def _write_state(self) -> None:
        if not self.state_path:
            return
        try:
            d = os.path.dirname(self.state_path)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
            tmp = f"{self.state_path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"pending": len(self._holds), "ts": round(time.time(), 3)}, f)
            os.replace(tmp, self.state_path)
        except OSError:
            pass       # the restart notice is a courtesy; holds work without it

    def _new_id(self) -> str:
        while True:
            chars = [secrets.choice(ID_ALPHABET) for _ in range(ID_LEN)]
            if not any(c in ID_DIGITS for c in chars):
                chars[secrets.randbelow(ID_LEN)] = secrets.choice(ID_DIGITS)
            hid = "".join(chars)
            if hid not in self._holds and hid not in self._expired:
                return hid

    def expire(self) -> list[Hold]:
        """Resolve timed-out holds as ignored. Returns them."""
        now = self.clock()
        gone = []
        with self._lock:
            for hid in list(self._holds):
                h = self._holds[hid]
                if now - h.created >= self.timeout:
                    gone.append(self._holds.pop(hid))
                    self._remember_expired(hid, now)
            if gone:
                self._write_state()
        return gone

    def _remember_expired(self, hid: str, now: float) -> None:
        self._expired[hid] = now
        while len(self._expired) > 500:
            self._expired.popitem(last=False)

    def add(self, **kw) -> tuple[Hold, list[Hold]]:
        """Create a hold. Returns (hold, holds dropped to make room: oldest first, as ignored)."""
        self.expire()
        text, atts, cut = cap_texts(kw.pop("text", ""), kw.pop("attachment_texts", []) or [])
        with self._lock:
            hid = self._new_id()
            h = Hold(hold_id=hid, created=self.clock(), text=text, attachment_texts=atts, cut=cut, **kw)
            self._holds[hid] = h
            dropped = []
            while len(self._holds) > self.max_pending:
                _k, old = self._holds.popitem(last=False)
                self._remember_expired(old.hold_id, self.clock())
                dropped.append(old)
            self._write_state()
        return h, dropped

    def may_notify(self, platform: str, user_id: str, kind: str = "hold") -> bool:
        """Rate limit for notices per sender (a flood of held messages must not flood the owner)."""
        now = self.clock()
        key = (kind, platform, user_id)
        with self._lock:
            dq = self._notices.setdefault(key, deque())
            while dq and now - dq[0] > 600:
                dq.popleft()
            if len(dq) >= self.notice_limit:
                return False
            dq.append(now)
            if len(self._notices) > 2000:
                for k in list(self._notices)[:1000]:
                    self._notices.pop(k, None)
            return True

    def is_pending(self, hold_id: str) -> bool:
        with self._lock:
            return hold_id in self._holds

    def resolve(self, verb: str, hold_id: str) -> Resolution:
        """Pop a hold for follow/ignore. The caller has already checked the actor is an owner."""
        self.expire()
        if verb not in ("follow", "ignore", "release") or not isinstance(hold_id, str) or not ID_RX.match(hold_id):
            return Resolution(False, verb, None, "unknown")
        with self._lock:
            h = self._holds.pop(hold_id, None)
            if h is None:
                return Resolution(False, verb, None, "expired" if hold_id in self._expired else "unknown")
            self._remember_expired(hold_id, self.clock())
            self._write_state()
        return Resolution(True, verb, h, "")

    def restore(self, h: Hold) -> None:
        """Put back a hold that a late release could not deliver (it stays held for the owner)."""
        with self._lock:
            self._expired.pop(h.hold_id, None)
            self._holds[h.hold_id] = h
            self._write_state()

    def pending(self) -> list[Hold]:
        self.expire()
        with self._lock:
            return list(self._holds.values())

    def __len__(self) -> int:
        return len(self._holds)


def parse_command(text) -> tuple[str, str] | None:
    """('follow'|'ignore', id) for a strict ASCII hold command, else None. An id without a digit is
    an ordinary word ("follow thread"), not a command."""
    if not isinstance(text, str) or len(text) > 120:
        return None
    m = COMMAND_RX.match(text)
    if not m:
        return None
    verb, hid = m.group(1).lower(), m.group(2)
    if not any(c.isdigit() for c in hid):
        return None
    return (verb, hid) if ID_RX.match(hid) else ("bad", hid)
