"""Recent-message window: catches instructions split across several messages (or across a
message and its attachment), in order, in reverse order, and split mid-word."""
from __future__ import annotations

import time
from collections import OrderedDict, deque

from . import normalize, patterns, scan

MAX_KEYS = 1000
PART_CHARS = 4000     # messages up to 2x this are kept whole; longer ones keep both ends (review M1)
JOIN_MAX_CHARS = 24_000   # the joined window covers the most recent messages up to this size
PAIR_MESSAGES = 30        # older messages kept for pair checks: their end + the new message's start (recheck M1)
PAIR_EDGE_CHARS = 200


def _edges(text: str) -> str:
    if len(text) <= 2 * PART_CHARS:
        return text
    return text[:PART_CHARS] + " " + text[-PART_CHARS:]


class Window:
    def __init__(self, messages: int = 6, minutes: int = 30, clock=time.monotonic):
        self.messages = messages
        self.keep = max(messages, PAIR_MESSAGES)
        self.seconds = minutes * 60
        self.clock = clock
        self._data: "OrderedDict[tuple, deque]" = OrderedDict()

    def _items(self, key) -> deque:
        now = self.clock()
        dq = self._data.get(key)
        if dq is None:
            dq = deque(maxlen=self.keep)
            self._data[key] = dq
            while len(self._data) > MAX_KEYS:
                self._data.popitem(last=False)
        else:
            self._data.move_to_end(key)
        while dq and now - dq[0][0] > self.seconds:
            dq.popleft()
        return dq

    @staticmethod
    def _families(text: str, forms: list | None = None) -> dict:
        fam: dict[str, float] = {}
        for form in normalize.variants(text) if forms is None else forms:
            for family, w, _s in patterns.match(form, raw=None, chat=True):
                fam[family] = max(fam.get(family, 0.0), w)
        for sq in normalize.squashed(text):          # words run together across the join (recheck M1)
            for family, w, _p in patterns.match_squashed_whole(sq, True):
                fam[family] = max(fam.get(family, 0.0), w)
        return fam

    @classmethod
    def _quick(cls, text: str) -> dict:
        folded = normalize.fold_confusables(normalize.strip_marks(text))
        return cls._families(text, [normalize.collapse_ws(text), normalize.words_only(folded)])

    def check(self, key, text: str) -> scan.Verdict | None:
        """Add *text* for *key*; return a hold verdict if the recent messages together hold an
        instruction that no single one did (a new family, or a stronger hit), else None. A held
        message is not kept."""
        dq = self._items(key)
        rv = normalize.reveal(text)
        part = _edges(rv.spaced or rv.text)      # removed characters read as spaces (recheck M1)
        own = self._families(part)
        entries = list(dq) + [(self.clock(), part, own)]
        verdict = None
        total, start = 0, len(entries)
        while start > max(0, len(entries) - self.messages) and total + len(entries[start - 1][1]) <= JOIN_MAX_CHARS:
            start -= 1
            total += len(entries[start][1])
        recent = entries[min(start, len(entries) - 1):]
        if len(recent) >= 2:
            entries_used = recent
            texts = [t for _ts, t, _f in entries_used]
            single: dict[str, float] = {}
            for _ts, _t, f in entries_used:
                for k, w in f.items():
                    single[k] = max(single.get(k, 0.0), w)
            fam: dict[str, float] = {}
            for j in (" ".join(texts), "".join(texts), " ".join(reversed(texts)), "".join(reversed(texts))):
                for k, w in self._families(j).items():
                    fam[k] = max(fam.get(k, 0.0), w)
            gained = sorted(k for k, w in fam.items() if w > single.get(k, 0.0) + 1e-9)
            score = sum(fam.values())
            if gained and score >= scan.HOLD_AT:
                verdict = scan.Verdict(level=scan.HOLD, score=round(score, 3), families=fam, channel="window",
                                       reasons=[f"{k}@window" for k in gained], chars=sum(map(len, texts)),
                                       notes=["split across messages"])
        if verdict is None:
            # older messages, each paired with the new one: filler messages in between do not
            # separate two halves of one instruction (recheck M1)
            for _ts, old, old_fam in entries[:-2]:
                a, b = old[-PAIR_EDGE_CHARS:], part[:PAIR_EDGE_CHARS]
                c, d = part[-PAIR_EDGE_CHARS:], old[:PAIR_EDGE_CHARS]
                fam = {}
                for j in (a + " " + b, a + b, c + " " + d):
                    for k, w in self._quick(j).items():
                        fam[k] = max(fam.get(k, 0.0), w)
                gained = sorted(k for k, w in fam.items() if w > max(old_fam.get(k, 0.0), own.get(k, 0.0)) + 1e-9)
                score = sum(fam.values())
                if gained and score >= scan.HOLD_AT:
                    verdict = scan.Verdict(level=scan.HOLD, score=round(score, 3), families=fam, channel="window",
                                           reasons=[f"{k}@window" for k in gained], chars=len(old) + len(part),
                                           notes=["split across messages"])
                    break
        if verdict is None:
            dq.append(entries[-1])
        return verdict

    def clear(self, key) -> None:
        self._data.pop(key, None)

    def __len__(self) -> int:
        return len(self._data)
