"""Recheck queue for messages held only because the model check was unavailable (design 3.3.1).

Hard rules (decision review 2026-11-17, pick 8), enforced here and in hooks.recheck_tick:
  1. Only an outage enters the queue (CheckUnavailable: timeout, connection error, HTTP 5xx, pause flag).
  2. A bad answer (CheckTampered) is a hijack sign: the item stays held, never retried.
  3. Clean means "none" only: "suspicious" (or a checker-words sign, or a partial check) stays held.
  4. Nothing is released while the canary probes report a fault: the item waits or times out.
  5. Inbound messages only: the tool-result path never adds items.
  6. A released message reaches the bot marked as late (messages.LATE_RELEASE).
At most `attempts` re-checks within `window_s`; after that the item stays held for the owner. Memory only:
after a restart the holds are dropped as before, and the queue with them.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

MAX_ITEMS = 50
SPACING = (0.1, 0.3, 0.7)        # fractions of the window: 60 s, 180 s, 420 s for 10 minutes


@dataclass
class Item:
    hold_id: str
    platform: str
    chat_id: str
    user_id: str
    jobs: list                     # [(variant, text, decoded)]: exactly what the first check would have sent
    added: float
    deadline: float
    attempts: int = 0
    next_at: float = 0.0
    last: str = ""


class RecheckQueue:
    def __init__(self, attempts: int = 3, window_s: float = 600.0, clock=time.monotonic, max_items: int = MAX_ITEMS):
        self.attempts = max(1, min(3, int(attempts)))
        self.window_s = float(window_s)
        self.clock = clock
        self.max_items = max_items
        self._items: "OrderedDict[str, Item]" = OrderedDict()
        self._busy: set = set()
        self._lock = threading.Lock()
        self.finished: "OrderedDict[str, str]" = OrderedDict()      # hold id -> final outcome (bounded)

    def __len__(self) -> int:
        return len(self._items)

    def add(self, item: Item) -> bool:
        with self._lock:
            if item.hold_id in self._items or len(self._items) >= self.max_items:
                return False
            item.attempts = 0
            item.next_at = item.added + SPACING[0] * self.window_s
            self._items[item.hold_id] = item
            return True

    def due(self) -> list:
        """Items whose next attempt is due; each is handed out once until finish() or retry()."""
        now = self.clock()
        with self._lock:
            out = [i for k, i in self._items.items() if i.next_at <= now and k not in self._busy]
            self._busy.update(i.hold_id for i in out)
            return out

    def next_wake(self) -> float | None:
        with self._lock:
            return min((i.next_at for i in self._items.values()), default=None)

    def retry(self, item: Item, why: str) -> str:
        """Another outage (or a fault, rule 4). Schedule the next attempt, or give up (stays held)."""
        with self._lock:
            self._busy.discard(item.hold_id)
            item.attempts += 1
            item.last = why
            if item.attempts >= self.attempts:
                return self._end(item, "gave-up")
            nxt = item.added + SPACING[min(item.attempts, len(SPACING) - 1)] * self.window_s
            nxt = max(nxt, self.clock() + 1.0)
            if nxt > item.deadline:
                return self._end(item, "gave-up")
            item.next_at = nxt
            return "retry"

    def finish(self, item: Item, outcome: str) -> str:
        with self._lock:
            self._busy.discard(item.hold_id)
            return self._end(item, outcome)

    def _end(self, item: Item, outcome: str) -> str:
        self._items.pop(item.hold_id, None)
        self.finished[item.hold_id] = outcome
        while len(self.finished) > 200:
            self.finished.popitem(last=False)
        return outcome
