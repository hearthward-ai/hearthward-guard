"""Session taint for Knock (Rule of Two: untrusted input + a risky action never meet unchecked).

Records are keyed by the opaque ids Hermes passes to hooks (session, conversation, task). Ids
seen together are linked, and a check looks at every linked record:
  tainted   any linked record carries a taint reason
  clean     no taint, and some linked record was seen to START fresh in this process
  unknown   history Knock did not see start: recorded as the reason "history not seen" (review
            K-04), so it is sticky and cannot be borrowed away through a shared id
Taint is never cleared by anything the model or a tool can do; it ends only with the session.

Strength: a reason that starts with LOCAL_PREFIX is LOCAL (output of the owner's own machine);
every other reason is REMOTE. policy.py decides what each allows. Strength is sticky (recheck
R-02): every record keeps "remote" and "stranger" as flags, set when a reason arrives, whatever
the length of the reason list (which is for display only). When the list is full, a REMOTE reason
takes the place of a LOCAL one, so the strongest reasons stay visible.

Memory is bounded. Records of stranger and never-clean sessions are pushed out first (review
K-18). A record pushed out by the limit is remembered as "forgotten" (= tainted); if even that
list overflows, every session counts as tainted until restart (fail closed).
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

MAX_LINKS = 64
MAX_REASONS = 8
EVICT_SCAN = 256
LOCAL_PREFIX = "local: "
UNSEEN = "history not seen"
STRANGER = "message from someone who is not an owner"
CHECK_FAILED = "check failed"
# reasons that make the turn count as a stranger's (a failed turn record may hide one, R-05)
STRANGER_REASONS = frozenset({STRANGER, CHECK_FAILED})


def is_local(reason: str) -> bool:
    return isinstance(reason, str) and reason.startswith(LOCAL_PREFIX)


@dataclass
class Record:
    reasons: list = field(default_factory=list)
    clean_start: bool = False
    platform: str = ""
    owner_turn: bool = False         # the latest turn came from an owner or a local surface
                                     # (a check needs ALL linked turn records to be owner turns)
    links: set = field(default_factory=set)
    touched: float = 0.0
    turns: int = 0                   # user turns Knock saw start on this record
    private_read: bool = False       # a source:private tool ran, or LOCAL output came in (K-01, R-03)
    child_reasons: list | None = None    # state handed to children at the last delegate_task (K-05)
    remote: bool = False             # sticky: a REMOTE reason arrived (recheck R-02)
    stranger: bool = False           # sticky: a stranger's turn (or a failed turn record) arrived


def _h(key: str) -> bytes:
    return hashlib.blake2b(key.encode("utf-8", "surrogatepass"), digest_size=8).digest()


def keys(session_id="", conversation_id="", task_id="") -> list[str]:
    out = []
    for prefix, v in (("s", session_id), ("c", conversation_id), ("t", task_id)):
        if isinstance(v, str) and v:
            out.append(f"{prefix}:{v[:256]}")
    # a conversation id is the first session id of the conversation: the same record
    if conversation_id and isinstance(conversation_id, str):
        out.append(f"s:{conversation_id[:256]}")
    return list(dict.fromkeys(out))


@dataclass
class State:
    tainted: bool
    clean: bool
    reasons: list
    platform: str
    owner_turn: bool
    private_read: bool = False
    remote_flag: bool = False
    stranger_flag: bool = False
    seen_turn: bool = False          # some linked record was seen in a turn (pre_llm_call)

    @property
    def label(self) -> str:
        if self.reasons == [UNSEEN]:
            return "unknown"
        return "tainted" if self.tainted else "clean" if self.clean else "unknown"

    @property
    def remote(self) -> bool:
        """Tainted by something other than the owner's own machine (or not seen from its start)."""
        return (self.remote_flag or (not self.clean and not self.reasons)
                or any(not is_local(r) for r in self.reasons))

    @property
    def stranger(self) -> bool:
        return self.stranger_flag or any(r in STRANGER_REASONS for r in self.reasons)


class TaintStore:
    def __init__(self, max_records: int = 20000, clock=time.monotonic):
        self.max = max_records
        self.clock = clock
        self._r: "OrderedDict[str, Record]" = OrderedDict()
        self._forgotten: set = set()
        self.saturated = False
        self._lock = threading.RLock()

    # ---------------------------------------------------------------- internals (lock held)
    def _get(self, k: str, create: bool) -> Record | None:
        rec = self._r.get(k)
        if rec is None and create:
            rec = Record()
            self._r[k] = rec
            if _h(k) in self._forgotten:
                rec.reasons.append("forgotten")
            self._evict(keep=k)
        if rec is not None:
            rec.touched = self.clock()
            self._r.move_to_end(k)
        return rec

    def _evict(self, keep: str = "") -> None:
        while len(self._r) > self.max:
            victim = None
            for i, (k, rec) in enumerate(self._r.items()):     # oldest first
                if i >= EVICT_SCAN:
                    break
                if k == keep or (rec.clean_start and not rec.stranger):
                    continue
                # a link-only record (conversation, task) of a group with a clean owner session is
                # not pushed out first: the owner's session would read as "forgotten" (R-15)
                if not rec.stranger and any((o := self._r.get(x)) is not None and o.clean_start and not o.stranger
                                            for x in list(rec.links)[:MAX_LINKS]):
                    continue
                victim = k
                break
            if victim is None:
                victim = next(k for k in self._r if k != keep)
            self._r.pop(victim)
            self._forgotten.add(_h(victim))
            if len(self._forgotten) > self.max * 10:
                self.saturated = True
                self._forgotten.clear()

    def _closure(self, ks) -> list[str]:
        seen, todo = [], [k for k in ks]
        while todo and len(seen) < MAX_LINKS:
            k = todo.pop()
            if k in seen:
                continue
            seen.append(k)
            rec = self._r.get(k)
            if rec is not None:
                todo += [x for x in rec.links if x not in seen]
        return seen

    def _link(self, ks) -> None:
        recs = [self._get(k, True) for k in ks]
        for k, rec in zip(ks, recs):
            if len(rec.links) < MAX_LINKS:
                rec.links.update(x for x in ks if x != k)

    # ---------------------------------------------------------------- API
    def start_turn(self, ks, *, fresh: bool, platform: str, owner_turn: bool, reasons=(),
                   parent_keys=(), history_users: int | None = None) -> None:
        """A new turn (pre_llm_call). fresh = a new session with no history. history_users = the
        number of user messages in the history Hermes passed (None = not counted)."""
        if not ks:
            return
        with self._lock:
            # only the session's own record says "seen from its start", not a shared task id (R-08)
            known_clean = any((self._r.get(k) is not None and self._r[k].clean_start) for k in ks
                              if k.startswith("s:"))
            seen_turns = max([self._r[k].turns for k in ks if k in self._r and k.startswith("s:")] or [0])
            self._link(ks)
            parent_reasons = None
            if parent_keys:
                parent_reasons = self._child_view(parent_keys)
            for k in ks:
                rec = self._get(k, True)
                if fresh and not parent_keys and not rec.links - set(ks) and not rec.reasons:
                    rec.clean_start = True
                rec.platform = platform or rec.platform
                rec.owner_turn = owner_turn
                if k.startswith("s:"):
                    rec.turns += 1
            extra = list(reasons)
            if not fresh and not known_clean:
                extra.append(UNSEEN)                                   # review K-04
            if history_users is not None and known_clean and history_users > seen_turns:
                extra.append("history changed outside a turn")         # review K-02 item 2
            if parent_reasons is not None:
                if parent_reasons:
                    self._mark(ks, "parent:tainted")
                elif fresh:                                            # a clean parent cleans only a fresh child
                    for k in ks:
                        self._get(k, True).clean_start = True
            if extra:
                self._mark(ks, *extra)

    def _child_view(self, parent_keys) -> list:
        """Reasons a child inherits: the parent's state at its last allowed delegate_task (taken
        before that call marked the parent), else its current state ([] = clean)."""
        snap = None
        for k in self._closure(parent_keys):
            rec = self._r.get(k)
            if rec is not None and rec.child_reasons is not None:
                snap = (snap or []) + [r for r in rec.child_reasons if r not in (snap or [])]
        if snap is not None:
            return snap
        st = self._state(parent_keys)
        return [] if st.clean else (st.reasons or [UNSEEN])

    def snapshot_for_children(self, ks) -> None:
        """Called just before a delegate_task call marks the parent (review K-05)."""
        if not ks:
            return
        with self._lock:
            st = self._state(ks)
            view = [] if st.clean else (st.reasons or [UNSEEN])
            for k in self._closure(ks):
                rec = self._get(k, True)
                rec.child_reasons = list(view)

    def _mark(self, ks, *reasons) -> None:
        for k in self._closure(ks):
            rec = self._get(k, True)
            for reason in reasons:
                local = is_local(reason)
                if not local:
                    rec.remote = True             # sticky, whatever the list length (R-02)
                if reason in STRANGER_REASONS:
                    rec.stranger = True
                if reason in rec.reasons:
                    continue
                if len(rec.reasons) < MAX_REASONS:
                    rec.reasons.append(reason)
                elif not local:                   # keep the strongest visible: replace a LOCAL one
                    i = next((j for j, r in enumerate(rec.reasons) if is_local(r)), None)
                    if i is not None:
                        rec.reasons.pop(i)
                        rec.reasons.append(reason)

    def mark(self, ks, *reasons) -> None:
        if not ks:
            return
        with self._lock:
            self._link(ks)
            self._mark(ks, *reasons)

    def mark_private_read(self, ks) -> None:
        if not ks:
            return
        with self._lock:
            for k in self._closure(ks):
                self._get(k, True).private_read = True

    def adopt(self, session_key: str, conversation_key: str) -> None:
        """Hermes says this session continues that conversation (compression rotates the session
        id; tool calls carry conversation_id, set by Hermes, not by the model). A session whose
        only reason is "history not seen" takes the conversation's real state instead, if Knock saw
        that conversation start. Any other reason stays."""
        with self._lock:
            conv = self._r.get(conversation_key)
            if conv is None or not conv.clean_start:
                return
            group = self._closure([session_key])
            recs = [self._r.get(k) for k in group]
            if any(r is not None and [x for x in r.reasons if x != UNSEEN] for r in recs):
                return
            for r in recs:
                if r is not None and UNSEEN in r.reasons:
                    r.reasons.remove(UNSEEN)
                    if not any(not is_local(x) for x in r.reasons) and not r.stranger:
                        r.remote = False          # "history not seen" was its only REMOTE reason

    def link(self, ks) -> None:
        """Link the ids of one call; also refreshes them so an active session is not pushed out."""
        if ks:
            with self._lock:
                self._link(ks)

    def _state(self, ks) -> State:
        if self.saturated:
            return State(True, False, ["memory limit"], "", False, False, True, True, False)
        reasons, clean, platform, owner, seen_turn, private = [], False, "", True, False, False
        remote_f = stranger_f = False
        for k in self._closure(ks):
            rec = self._r.get(k)
            if rec is None:
                if _h(k) in self._forgotten:
                    reasons.append("forgotten")
                continue
            reasons += [r for r in rec.reasons if r not in reasons]
            clean = clean or rec.clean_start
            private = private or rec.private_read
            remote_f = remote_f or rec.remote
            stranger_f = stranger_f or rec.stranger
            if rec.platform:            # records seen in a turn: every one must be an owner turn
                seen_turn = True
                owner = owner and rec.owner_turn
        # the platform of THIS call's own session record, not of the group (review K-04)
        for k in ks:
            rec = self._r.get(k)
            if rec is not None and rec.platform:
                platform = rec.platform
                break
        if len(reasons) > MAX_REASONS:              # keep REMOTE reasons visible first
            reasons = [r for r in reasons if not is_local(r)] + [r for r in reasons if is_local(r)]
        tainted = bool(reasons) or remote_f or stranger_f
        return State(tainted, clean and not tainted, reasons[:MAX_REASONS], platform, owner and seen_turn,
                     private, remote_f, stranger_f, seen_turn)

    def state(self, ks) -> State:
        with self._lock:
            if not ks:
                return State(False, False, [], "", False)
            return self._state(ks)

    def __len__(self) -> int:
        return len(self._r)
