"""Budgets for expensive work (fix round, review MC-4): checker calls per sender and for everyone.

The model check runs on a shared local model (one slot, both bots). A stranger must not be able to buy
unlimited checker calls with long messages. charge(key, n) books n calls in a 10-minute sliding window
for that sender and for the global pool; when either is full nothing is booked and False comes back
(the caller then holds the message without calling the checker). The owner is never refused here.
Memory only, bounded (at most MAX_KEYS senders are remembered).
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque

WINDOW_S = 600.0
MAX_KEYS = 2000


class CallBudget:
    def __init__(self, per_sender: int, overall: int, clock=time.monotonic):
        self.per_sender, self.overall, self.clock = per_sender, overall, clock
        self._lock = threading.Lock()
        self._keys: "OrderedDict[str, deque]" = OrderedDict()
        self._all: deque = deque()
        self.refused = 0

    @staticmethod
    def _used(q: deque, now: float) -> int:
        while q and now - q[0][0] >= WINDOW_S:
            q.popleft()
        return sum(n for _t, n in q)

    def charge(self, key: str, n: int, count_refusal: bool = True) -> bool:
        """Book n calls for `key` (a non-owner sender). False = over budget, nothing booked.
        count_refusal False: a refusal is not counted in `refused` (a declined tamper retry is a tamper
        hold, not a message "held over budget")."""
        if n <= 0:
            return True
        now = self.clock()
        with self._lock:
            q = self._keys.get(key)
            if q is None:
                q = self._keys[key] = deque()
                while len(self._keys) > MAX_KEYS:
                    self._keys.popitem(last=False)
            else:
                self._keys.move_to_end(key)
            if self._used(q, now) + n > self.per_sender or self._used(self._all, now) + n > self.overall:
                if count_refusal:
                    self.refused += 1
                return False
            q.append((now, n))
            self._all.append((now, n))
            return True

    def note(self, n: int) -> None:
        """Owner and tool-result calls: counted in the global window (so strangers see a busier pool),
        never refused."""
        if n > 0:
            with self._lock:
                self._all.append((self.clock(), n))

    def status(self) -> dict:
        now = self.clock()
        with self._lock:
            return {"calls_10min": self._used(self._all, now), "refused": self.refused}
