"""Event log: JSON lines with hashes and categories, never message text (unless log.raw_text).

Writing an event must never break the guard: failures are counted and swallowed here, and the
caller's decision (hold, withhold, block) stands regardless.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time

MAX_BYTES = 5_000_000
# Ids are hashed with a random key made at start (review L4): a numeric chat or user id cannot be
# found again by hashing guesses. Hashes are stable within one gateway run only.
_KEY = secrets.token_bytes(16)


def anon(value) -> str:
    """Short stable hash for ids (user, chat) so the log carries no raw identifiers."""
    if value is None or value == "":
        return ""
    return hmac.new(_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:12]


class EventLog:
    def __init__(self, path: str = "", raw_text: bool = False):
        self.path = path
        self.raw_text = raw_text
        self.failures = 0
        self.recent: list[dict] = []          # last few events in memory (for /guard and tests)
        self._lock = threading.Lock()

    def write(self, kind: str, text: str | None = None, **fields) -> None:
        """Never raises: a logging problem must not change a guard decision."""
        try:
            self._write(kind, text, fields)
        except Exception:
            self.failures += 1

    def _write(self, kind: str, text, fields: dict) -> None:
        rec = {"ts": round(time.time(), 3), "kind": str(kind)}
        for k, v in fields.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                rec[k] = v
            elif isinstance(v, (list, tuple, set)):
                rec[k] = [str(x)[:120] for x in list(v)[:40]]
            elif isinstance(v, dict):
                rec[k] = {str(a)[:60]: (b if isinstance(b, (int, float, bool)) else str(b)[:120])
                          for a, b in list(v.items())[:40]}
            else:
                rec[k] = str(v)[:200]
        if text is not None and self.raw_text:
            rec["text"] = str(text)[:4000]
        with self._lock:
            self.recent.append(rec)
            del self.recent[:-50]
            if not self.path:
                return
            try:
                d = os.path.dirname(self.path)
                if d:
                    os.makedirs(d, mode=0o700, exist_ok=True)
                try:
                    if os.path.getsize(self.path) > MAX_BYTES:
                        os.replace(self.path, self.path + ".1")
                except OSError:
                    pass
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            except Exception:
                self.failures += 1
