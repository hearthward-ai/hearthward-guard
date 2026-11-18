"""The guard: Threshold (inbound), holds, Gatehouse (outbound) wired to documented Hermes hooks.

Fail-closed rules (Hermes itself fails OPEN when a pre_gateway_dispatch, pre_llm_call or
transform_tool_result callback raises, so every callback here catches its own errors):
  pre_gateway_dispatch  error or guard unhealthy -> skip the message (with a fixed reply)
  pre_llm_call          error or guard unhealthy -> block the turn
  transform_tool_result error or guard unhealthy -> replace the result with a fixed notice
  transform_llm_output  error or guard unhealthy -> replace the reply with a fixed notice
A missing hook argument (a renamed keyword after a Hermes update) is a compat problem, never
"empty input". In mode "report" nothing is enforced; decisions are only logged.

Pictures (job 6, the scam shield): a picture never reaches the model. Its text (OCR plus metadata) is
checked like an attachment (rules, the model check when configured) and for scam signs; the message is
skipped and the sender gets a short verdict. Text aimed at the AI, or a picture that cannot be read,
is held for the owner like any other hold.

Holds (owner decisions, job 5): an attachment the guard cannot read is HELD and the owner is told;
holds live in memory and after a restart the owner is told how many were dropped; "follow" releases
the held text (as data) into the owner's own conversation, i.e. the chat where the owner typed it;
a second check that fails or times out holds the message.
"""
from __future__ import annotations

import asyncio
import inspect
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor

from .common import compat, config, events, messages, status
from .gatehouse import output
from .knock import Knock
from .threshold import holds as holds_mod
from .threshold import budget, media, normalize, ocr, recheck, scam, scan, second_check
from .threshold.window import Window

PLUGIN_NAME = "hearthward-guard"
VERSION = "0.9.3"
CONTEXT_CHARS = 20_000       # conversation text kept per session for the reply's link check
CONTEXT_MESSAGES = 40
CONTEXT_SESSIONS = 200
LOCAL_SURFACES = {"cli", "tui", "desktop", "acp", "local"}
SKIP_HELD = {"action": "skip", "reason": "hearthward-guard: held"}
SKIP_ERROR = {"action": "skip", "reason": "hearthward-guard: could not check"}
SKIP_DOWN = {"action": "skip", "reason": "hearthward-guard: guard unhealthy"}
SKIP_MEDIA = {"action": "skip", "reason": "hearthward-guard: attachment not checkable"}
SKIP_COMMAND = {"action": "skip", "reason": "hearthward-guard: hold command"}
SKIP_PICTURE = {"action": "skip", "reason": "hearthward-guard: picture checked, not passed on"}
SEND_TIMEOUT_S = 10.0
RELEASE_TTL_S = 600
LATE_PROBE_EVERY_S = 60.0
# separate bounded worker pools (review MC-4): a flood of pictures or model checks cannot starve the rule
# scan that every message (the owner's too) needs
POOL_SIZES = {"scan": 4, "ocr": 2, "check": 2}
SCAM_TIMEOUT_S = 5.0
REPLY_FIELDS = ("reply_to_text", "channel_context", "channel_prompt")
NAME_FIELDS = ("user_name", "reply_to_author_name")
_MISSING = object()


class Guard:
    def __init__(self, settings, *, prober=None, clock=time.monotonic, wall=time.time, data_dir: str | None = None,
                 heartbeat: bool = False, ocr_runner=None, ocr_which=None):
        """settings: the raw plugins.entries.<id>.settings mapping. prober: () -> (problems, hermes
        version); None = no static probes (unit tests outside Hermes)."""
        self.clock = clock
        self.wall = wall
        self.problems: list[str] = []
        self.late_problems: list[str] = []
        self.hermes_version = ""
        try:
            self.cfg = config.parse(settings)
        except config.ConfigError as e:
            self.problems.append(f"config: {e}"[:300])
            self.cfg = config.Config()
        except Exception as e:  # anything else in parsing: fail closed too
            self.problems.append(f"config: unreadable ({type(e).__name__})")
            self.cfg = config.Config()
        if prober is not None:
            try:
                probs, self.hermes_version = prober(self.cfg.require_no_hook_timeout)
                self.problems += list(probs)
            except Exception as e:
                self.problems.append(compat.bad("probe", f"crashed ({type(e).__name__})"))
        c = self.cfg
        self.data_dir = data_dir if data_dir is not None else status.data_dir()
        log_path = c.log_path or (f"{self.data_dir}/events.jsonl" if self.data_dir else "")
        self.events = events.EventLog(log_path, c.log_raw_text)
        self.holds = holds_mod.HoldStore(c.holds.timeout_min, c.holds.max_pending, c.holds.notices_per_sender_10min,
                                         clock=clock,
                                         state_path=f"{self.data_dir}/pending-holds.json" if self.data_dir else "")
        self._restart_dropped = self.holds.dropped_at_start
        self.window = Window(c.threshold.window_messages, c.threshold.window_minutes, clock=clock)
        self.knock = Knock(settings, self)   # tool policy (knock/); its hook is probed via compat.HOOKS
        self._setup_told = False
        if prober is not None:               # real Hermes: is a person answering approval cards?
            try:
                self.knock.check_setup()
            except Exception as e:
                self.events.write("knock-setup-error", error=type(e).__name__)
        self._lock = threading.Lock()
        self._released: "OrderedDict[str, tuple[float, str]]" = OrderedDict()
        self._down_notice: dict[tuple, float] = {}
        # recent conversation text per session and recent tool results: the reply's link check looks
        # for pieces of it in links (recheck item 7). Memory only, bounded.
        self._convo: "OrderedDict[str, str]" = OrderedDict()
        self._tool_text = ""
        self._probing = prober is not None
        self._next_probe = 0.0
        self.counters = {"held": 0, "skipped": 0, "allowed": 0, "errors": 0, "llm_blocked": 0,
                         "tool_withheld": 0, "replies_changed": 0, "replies_withheld": 0, "notice_failures": 0,
                         "pictures_read": 0, "scam_warnings": 0}
        # model check (design 2026-11-17): None = rules only, with the warning below
        self.checker = None
        self.recheck = None
        self.deliver_late = None      # (platform, chat_id, user_id, text) -> bool | awaitable; set by register()
        self.deliver_scope = "owner"  # "owner": late releases only to the owner's own chat (ctx.inject_message)
        self._late_pass: "OrderedDict[tuple, float]" = OrderedDict()
        self._recheck_task = None
        self._pools = {k: ThreadPoolExecutor(max_workers=n, thread_name_prefix=f"hearthward-{k}")
                       for k, n in POOL_SIZES.items()}
        self.budget = budget.CallBudget(c.second_check.calls_per_sender_10min, c.second_check.calls_all_10min,
                                        clock=clock)
        self._owner_notices: deque = deque()     # global cap on hold notices to the owner (review OC-5)
        self._owner_notices_skipped = 0
        if c.second_check.enabled:
            try:
                self.checker = second_check.Checker(c.second_check, clock=clock)
            except Exception as e:
                self.problems.append(f"second_check: checker prompts unreadable ({type(e).__name__})")
            if self.checker is not None and c.second_check.recheck_unavailable:
                self.recheck = recheck.RecheckQueue(attempts=c.second_check.recheck_attempts,
                                                    window_s=60.0 * c.second_check.recheck_window_min, clock=clock)
        else:
            self.events.write("model-check-off", warning=messages.MODEL_CHECK_OFF)
        # picture shield (job 6): None = pictures follow threshold.unscanned_media (no engine, or switched off)
        self.ocr = None
        self.ocr_off_why = ""
        self._scam_alerts: deque = deque()
        oc = c.ocr
        self.ocr_unbounded = os.name == "nt" and ocr_runner is None   # no engine memory limit on Windows
        if self.ocr_unbounded and oc.enabled == "auto":
            # fix round (OC-3): Windows has no memory limit for the engine process, so the reader is off
            # unless the owner switches it on explicitly (ocr.enabled: true + ocr.engine_path)
            self.ocr_off_why = ("Windows: the picture reader would run without a memory limit; set "
                                "ocr.enabled: true and ocr.engine_path to accept that")
            self.events.write("ocr-off", why=self.ocr_off_why)
        elif oc.enabled is not False:
            kw = {"runner": ocr_runner} if ocr_runner is not None else {}
            if ocr_which is not None:
                kw["which"] = ocr_which
            eng = ocr.Engine(oc, **kw)
            if eng.available or oc.enabled is True:
                self.ocr = eng           # switched on without an engine: every picture is held (fail closed)
            else:
                self.ocr_off_why = eng.missing
                self.events.write("ocr-off", why=eng.missing)
        else:
            self.ocr_off_why = "switched off (ocr.enabled: false)"
        self.heartbeat = None
        if heartbeat:
            hb_dir = c.heartbeat_dir or f"{self.data_dir}/status"
            self.heartbeat = status.Heartbeat(hb_dir, c.heartbeat_interval_s, self.snapshot)

    # ------------------------------------------------------------------ health
    @property
    def healthy(self) -> bool:
        return not self.problems and not self.late_problems

    @property
    def enforce(self) -> bool:
        return self.cfg.enforce

    def all_problems(self) -> list[str]:
        return list(self.problems) + list(self.late_problems)

    def _problem(self, p: str) -> None:
        with self._lock:
            if p not in self.late_problems:
                self.late_problems.append(p)

    def late_probe(self) -> None:
        """Probes that need a finished plugin load; repeated at most every LATE_PROBE_EVERY_S (review
        L8, M11: stream holding and safe-worker mode can change while running)."""
        if not self._probing:
            return
        now = self.clock()
        if now < self._next_probe:
            return
        self._next_probe = now + LATE_PROBE_EVERY_S
        probs: list[str] = []
        for fn in (compat.probe_stream_held, compat.probe_safe_worker):
            try:
                fn(probs)
            except Exception as e:
                probs.append(compat.bad(fn.__name__, f"probe error ({type(e).__name__})"))
        for p in probs:
            self._problem(p)

    def snapshot(self) -> dict:
        return {"plugin": PLUGIN_NAME, "version": VERSION, "hermes": self.hermes_version, "mode": self.cfg.mode,
                "healthy": self.healthy, "problems": self.all_problems()[:20], "pending_holds": len(self.holds),
                "counters": dict(self.counters), "log_failures": self.events.failures,
                "knock": self.knock.status()}                      # review K-15

    def _count(self, k: str) -> None:
        with self._lock:
            self.counters[k] = self.counters.get(k, 0) + 1

    # ------------------------------------------------------------------ helpers
    async def _send(self, adapter, chat_id: str, text: str) -> bool:
        if adapter is None or not chat_id:
            return False
        try:
            r = adapter.send(chat_id, text)
            if inspect.isawaitable(r):
                r = await asyncio.wait_for(r, SEND_TIMEOUT_S)
            ok = getattr(r, "success", True)
            if ok is False:
                self._count("notice_failures")
            return ok is not False
        except Exception:
            self._count("notice_failures")
            return False

    async def _reply(self, gateway, source, text: str) -> bool:
        return await self._send(compat.adapter_for(gateway, source), str(getattr(source, "chat_id", "") or ""), text)

    async def _to_owner(self, gateway, platform: str, text: str) -> bool:
        c = self.cfg
        target = platform if platform in c.owner_chats else next(iter(c.owner_chats), "")
        if not target:
            # no chat to send to: say so in the guard log, never silently (lab re-test 2 bug 9).
            # Knock does not guess a DM from the owner's user id (a user id is not a chat id).
            self._count("notice_failures")
            self.events.write("owner-notice-not-sent", platform=platform,
                              why="owner_chats is not set; add owner_chats: {<platform>: <owner DM chat id>}")
            return False
        return await self._send(compat.adapter_for_platform(gateway, target), c.owner_chats[target], text)

    async def _guard_down_reply(self, gateway, source) -> None:
        key = (compat.platform_name(source), str(getattr(source, "chat_id", "")))
        now = self.clock()
        if now - self._down_notice.get(key, -1e9) < 600:
            return
        self._down_notice[key] = now
        if len(self._down_notice) > 1000:
            self._down_notice.clear()
        await self._reply(gateway, source, messages.GUARD_DOWN)

    def _consume_released(self, text: str) -> str:
        """Remove released blocks (from an owner's follow) that this guard issued; one use each."""
        now = self.clock()
        with self._lock:
            for nonce in list(self._released):
                exp, block = self._released[nonce]
                if now > exp:
                    del self._released[nonce]
                    continue
                if block in text:
                    text = text.replace(block, " ")
                    del self._released[nonce]
        return text

    async def _in_pool(self, pool: str, limit: float, fn, *args):
        """Run a blocking call in one of the guard's own bounded pools, with a time limit (review MC-4).
        Raises asyncio.TimeoutError when the limit passes (the call itself is told to stop where it can)."""
        fut = asyncio.get_running_loop().run_in_executor(self._pools[pool], fn, *args)
        return await asyncio.wait_for(fut, limit)

    async def _scan_parts(self, parts: list) -> scan.Verdict:
        """scan_many off the event loop with a time limit (review H1): a slow scan holds."""
        t = self.cfg.threshold.scan_timeout_s
        try:
            return await self._in_pool("scan", t + 2.0, scan.scan_many, parts, self.cfg.threshold.max_scan_chars, t)
        except asyncio.TimeoutError:
            v = scan.Verdict(channel="mixed")
            v.raise_to(scan.HOLD, "signal:check-timeout")
            v.signals.append("check-timeout")
            v.notes.append("took too long to check")
            return v

    def _weak_holds(self, v: scan.Verdict, content: bool) -> bool:
        th = self.cfg.threshold
        return v.level == scan.WEAK and (th.weak_action_content if content else th.weak_action) == "hold"

    def _event_parts(self, event, with_names: bool = True) -> tuple[list, list]:
        """Untrusted text around the message itself: quoted reply, channel context, sender names,
        metadata and unreviewed fields (review M5). -> (parts, names of fields that cannot be vouched for)."""
        parts: list[tuple[str, object]] = []
        if self.cfg.threshold.scan_reply_context:
            for f in REPLY_FIELDS:
                val = getattr(event, f, None)
                if val is None or val == "":
                    continue
                parts.append(("reply_context", val if isinstance(val, str) else object()))
        if with_names:
            for t in compat.sender_texts(event):
                parts.append(("name", t))          # read last when parts are joined (recheck H3)
        extra_texts, extra_media = compat.extra_content(event)
        parts += [("reply_context", t) for t in extra_texts]
        return parts, extra_media

    # ------------------------------------------------------------------ pre_gateway_dispatch
    async def on_pre_gateway_dispatch(self, event=None, gateway=None, session_store=None, **kwargs):
        try:
            return await self._dispatch(event, gateway)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._count("errors")
            self.events.write("dispatch-error", error=type(e).__name__)
            if not self.enforce:
                return None
            try:
                await self._guard_down_reply(gateway, getattr(event, "source", None))
            except Exception:
                pass
            return SKIP_ERROR

    async def _restart_notice(self, gateway, platform: str) -> None:
        n, self._restart_dropped = self._restart_dropped, 0
        if n and gateway is not None:
            self.events.write("restart-dropped-holds", count=n)
            await self._to_owner(gateway, platform, messages.RESTART_DROPPED.format(n=n))

    async def _dispatch(self, event, gateway):
        self.late_probe()
        if event is not None and getattr(event, "internal", False) is True:
            return None
        for p in compat.event_problems(event, gateway):
            self._problem(p)
        src = getattr(event, "source", None)
        platform = compat.platform_name(src)
        user = str(getattr(src, "user_id", "") or "")
        ev_user = getattr(event, "user_id", None)
        if ev_user not in (None, "") and str(ev_user) != user:
            user = ""      # a merged turn has no single sender: never an owner
        chat = str(getattr(src, "chat_id", "") or "")
        if not self.healthy:
            self.events.write("refused", platform=platform, reason="unhealthy")
            if not self.enforce:
                return None
            self._count("skipped")
            await self._guard_down_reply(gateway, src)
            return SKIP_DOWN
        if self._restart_dropped:
            await self._restart_notice(gateway, platform)
        if self.knock.setup_notice and not self._setup_told:
            self._setup_told = True          # once per start: tell the owner plainly (lab re-test bug 12)
            await self._to_owner(gateway, platform, messages.KNOCK_SETUP.format(notice=self.knock.setup_notice))
        c = self.cfg
        self.holds.expire()
        text = getattr(event, "text", "") or ""
        if not isinstance(text, str):
            raise TypeError("event text is not a string")
        is_owner = c.is_owner(platform, user)
        if is_owner and self._late_passed(event, text, platform, chat, user):   # a late release this guard delivered
            self.events.write("late-release-arrived", platform=platform)
            self._count("allowed")
            return None

        cmd = holds_mod.parse_command(text)
        if cmd and cmd[0] in ("follow", "ignore"):
            if is_owner:
                return await self._hold_command(cmd[0], cmd[1], event, gateway, src, platform, user, chat)
            if self.holds.is_pending(cmd[1]):
                self.events.write("hold-command-refused", platform=platform, user=events.anon(user))
                if self.holds.may_notify(platform, user, "not-owner"):
                    await self._reply(gateway, src, messages.NOT_OWNER)
                return SKIP_COMMAND
            # not an owner and not a pending id: an ordinary message (review L1)

        # ---- collect untrusted parts
        parts: list[tuple[str, object]] = [("chat", text)]
        ctx_parts, extra_media = self._event_parts(event)
        parts += ctx_parts
        parts += [("attachment", t) for t in media.inlined_texts(event)]

        atts = media.describe(event)
        att_texts: list[tuple[str, str]] = []
        media_issue = ""
        unscanned = False
        pics: list[tuple[str, object]] = []
        pic_texts: list[str] = []
        meta_texts: list[str] = []
        if extra_media:
            media_issue = "unknown attachment type"
        if len(atts) > c.threshold.max_attachments:
            media_issue = "too many attachments"
        for a in atts if not media_issue else []:
            name = a["name"] if isinstance(a["name"], str) else ""
            if name:
                parts.append(("name", name))       # read last when parts are joined (recheck H3)
            if c.threshold.scan_attachments and media.is_text_kind(a["mime"], name or str(a["path"])):
                try:
                    body = media.read_local_text(a["path"], c.threshold.max_attachment_bytes)
                except media.Unreadable as e:
                    media_issue = str(e.args[0]) if e.args else "unreadable"
                    break
                att_texts.append((name or "attachment", body))
                parts.append(("attachment", body))
            elif self.ocr is not None and ocr.is_image_kind(a["mime"], name or str(a["path"])):
                pics.append((name or "picture", a["path"]))
            else:
                unscanned = True
        if pics and not media_issue:
            media_issue = await self._read_pictures(pics, parts, att_texts, pic_texts, meta_texts)
        if unscanned and not media_issue:
            pol = c.threshold.unscanned_media
            if pol in ("hold", "skip") or (pol == "owners" and not is_owner):
                media_issue = "attachments of this kind can't be checked yet"

        # ---- scan
        verdict = await self._scan_parts(parts)
        if meta_texts and verdict.level != scan.HOLD:
            # lab 0.9.2 bug 2: text stored inside a picture file (EXIF, XMP, PNG text, JPEG comment) has no
            # ordinary reason to address an AI, so ONE weak sign there holds (content elsewhere needs two)
            mv = await self._scan_parts([("attachment", m) for m in meta_texts])
            if mv.level == scan.HOLD or mv.score >= scan.WEAK_AT - 1e-9:
                verdict.raise_to(scan.HOLD, "picture-metadata")
                # 0.9.3 re-run M1: the content rule's "one weak sign only" note is stale once this holds
                verdict.notes = [n for n in verdict.notes if n != "one weak sign only"]
                verdict.notes.append("text aimed at the AI stored in the picture file")
                for f, w in mv.families.items():
                    verdict.families[f] = max(verdict.families.get(f, 0.0), w)
                verdict.snippets += [s for s in mv.snippets if s not in verdict.snippets][:max(0, 5 - len(verdict.snippets))]
        key = (platform, chat)           # per chat, not per sender (review M1)
        if verdict.level != scan.HOLD:
            joined = "\n".join([text] + [b for _n, b in att_texts])
            wv = self.window.check(key, joined)
            if wv is not None:
                verdict.level = scan.HOLD
                for f, w in wv.families.items():
                    verdict.families[f] = max(verdict.families.get(f, 0.0), w)
                verdict.reasons += wv.reasons
                verdict.notes += wv.notes
        pre_level = verdict.level
        mc = None
        unchecked = ""
        if verdict.level != scan.HOLD and not media_issue:      # never send what the rules already held
            mc, unchecked = await self._model_check_inbound(parts, verdict, is_owner, text, platform, user)
        if self._weak_holds(verdict, verdict.content_level != scan.PASS):
            verdict.raise_to(scan.HOLD, "weak-held")
        sa = None
        if pics and not media_issue:
            try:          # off the event loop, with a time limit (review OC-6)
                sa = await self._in_pool("scan", SCAM_TIMEOUT_S, scam.assess, "\n".join([text] + pic_texts))
            except asyncio.TimeoutError:
                media_issue = "checking the picture took too long"
        if media_issue:
            verdict.raise_to(scan.HOLD, "attachment-unreadable")      # owner decision: hold, tell the owner
            verdict.notes.insert(0, f"attachment not checked: {media_issue}")
        self.events.write("inbound", text=text, platform=platform, user=events.anon(user), chat=events.anon(chat),
                          verdict=verdict.level, score=verdict.score, families=verdict.families,
                          signals=verdict.signals, notes=verdict.notes, chars=verdict.chars, owner=is_owner,
                          media_issue=media_issue, model_check=mc,
                          unreviewed=compat.unreviewed_fields(event) if extra_media else [],
                          pictures=len(pics), scam=sa.level if sa else None, scam_signs=sa.categories if sa else [])
        if pics and self.enforce and verdict.level != scan.HOLD:
            # the picture never reaches the model: skip, and answer with the verdict (API spike, job 6)
            return await self._picture_verdict(sa, pic_texts, gateway, src, platform, user, chat, is_owner)
        if verdict.level != scan.HOLD or not self.enforce:
            self._note_outside(event, platform, user, atts, verdict, text, unchecked)
            self._count("allowed")
            return None

        # ---- hold (the window keeps the earlier messages: a held decoy must not wipe them, review M1)
        h, dropped = self.holds.add(platform=platform, chat_id=chat, user_id=user, text=text,
                                    attachment_texts=att_texts, had_media=unscanned or bool(media_issue),
                                    summary=verdict.summary(), sha=scan.text_sha(text),
                                    snippet=(verdict.snippets or [""])[0])
        for d in dropped:
            self.events.write("hold-dropped", hold=d.hold_id, reason="too many pending")
        self._count("held")
        self.events.write("hold", hold=h.hold_id, platform=platform, user=events.anon(user), reasons=verdict.summary())
        queued = False
        quoted = any(ch == "reply_context" for ch, _t in ctx_parts)
        if (mc or {}).get("outcome") == "unavailable" and not pics and not att_texts and not quoted and \
                self._recheck_ok(verdict, pre_level, media_issue, is_owner, platform, chat):
            # review MC-7: a late release delivers the text only, so a message with an attachment or a
            # quote stays held for the owner's "follow" (which passes them on as data)
            queued = self.recheck.add(recheck.Item(
                hold_id=h.hold_id, platform=platform, chat_id=chat, user_id=user, jobs=mc["jobs"],
                added=self.clock(), deadline=self.clock() + 60.0 * c.second_check.recheck_window_min))
            if queued:
                self.events.write("recheck-queued", hold=h.hold_id)
                self._ensure_recheck_task(gateway)
        sender_text = None
        if pics:
            loc = c.ocr.locale
            if media_issue:
                sender_text = messages.picture_text("held_unreadable", loc, reason=media_issue)
            elif ((mc or {}).get("outcome") in ("unavailable", "tamper", "busy") and pre_level != scan.HOLD
                  and "weak-held" not in verdict.reasons):
                # review OC-4: the checker was down, paused, busy or answered wrongly: say so neutrally,
                # never "your picture tries to give instructions"
                sender_text = messages.picture_text("held_unchecked", loc)
            elif ((mc or {}).get("partial_only") and pre_level != scan.HOLD
                  and "weak-held" not in verdict.reasons):
                # lab 0.9.2 bug 1: held only because it was too long to double-check in full
                sender_text = messages.picture_text("held_partial", loc)
            else:
                sender_text = messages.picture_text("held_injection", loc)
            if sa is not None and sa.level in ("high", "medium"):
                sender_text += "\n" + messages.picture_text("scam_" + sa.level, loc, reasons=sa.categories[:4])
                self._count("scam_warnings")
        await self._notify_hold(h, gateway, src, platform, user, chat, is_owner, queued, sender_text=sender_text)
        return SKIP_HELD

    # ------------------------------------------------------------------ picture shield (job 6)
    async def _read_pictures(self, pics: list, parts: list, att_texts: list, pic_texts: list,
                             meta_texts: list | None = None) -> str:
        """Text of each picture (OCR, plus metadata text) into parts / att_texts / pic_texts.
        -> "" when all were read, else the plain-language reason (the message is then held)."""
        oc = self.cfg.ocr
        if len(pics) > oc.max_pictures:
            return "too many pictures to check"
        limit = 2 * oc.timeout_s + 5.0          # a slot wait plus one engine run, both bounded (review MC-4)
        for name, path in pics:
            try:
                # file read, header checks, metadata and the engine all run in the OCR pool, never on the
                # event loop (review OC-1), and end by one deadline
                meta, raw = await self._in_pool("ocr", limit, self._read_one_picture, path,
                                                time.monotonic() + limit - 1.0)
            except media.Unreadable as e:
                return str(e.args[0]) if e.args else "unreadable"
            except ocr.OcrError as e:
                return str(e.args[0]) if e.args else "unreadable"
            except asyncio.TimeoutError:
                return "reading the picture took too long"
            self._count("pictures_read")
            found = [("picture text", ocr.tidy(raw, oc.max_text_chars))] + [("picture metadata", m) for m in meta]
            for label, t in found:
                if t.strip():
                    parts.append(("attachment", t))
                    att_texts.append((f"{label}: {name}", t))
                    pic_texts.append(t)
                    if label == "picture metadata" and meta_texts is not None:
                        meta_texts.append(t)
        return ""

    def _read_one_picture(self, path, deadline: float) -> tuple[list, str]:
        """Blocking (OCR pool): -> (metadata texts, raw engine text). Raises media.Unreadable / OcrError."""
        oc = self.cfg.ocr
        data = media.read_local_bytes(path, oc.max_bytes)
        fmt, _w, _h = ocr.check_size(data, oc)
        meta = ocr.metadata_texts(data, fmt) if oc.read_metadata else []
        return meta, self.ocr.read(data, deadline=deadline)

    def _scam_alert_ok(self, platform: str, user: str) -> bool:
        """Owner scam alerts: per sender (the hold-notice limit) and for all senders together."""
        now = self.clock()
        with self._lock:
            while self._scam_alerts and now - self._scam_alerts[0] > 600:
                self._scam_alerts.popleft()
            if len(self._scam_alerts) >= self.cfg.ocr.alerts_per_10min:
                return False
        if not self.holds.may_notify(platform, user, "scam-alert"):
            return False
        with self._lock:
            self._scam_alerts.append(now)
        return True

    async def _picture_verdict(self, sa, pic_texts: list, gateway, src, platform: str, user: str, chat: str,
                               is_owner: bool):
        oc = self.cfg.ocr
        if sa.level == "high":
            key = "scam_high"
        elif sa.level == "medium":
            key = "scam_medium"
        else:
            key = "clean" if any(t.strip() for t in pic_texts) else "no_text"
        self._count("skipped")
        if key.startswith("scam"):
            self._count("scam_warnings")
        self.events.write("picture-verdict", platform=platform, user=events.anon(user), chat=events.anon(chat),
                          verdict=key, signs=sa.categories, owner=is_owner)
        reasons = sa.categories[:4]
        if self.holds.may_notify(platform, user, "picture"):
            await self._reply(gateway, src, messages.picture_text(key, oc.locale, reasons=reasons))
        else:
            self.events.write("picture-reply-limited", platform=platform, user=events.anon(user))
        if key == "scam_high" and not is_owner and oc.alert_owner:
            if self._scam_alert_ok(platform, user):
                await self._to_owner(gateway, platform, messages.picture_text(
                    "owner_alert", oc.locale, who=f"{platform} user {events.anon(user)}",
                    where=f"chat {events.anon(chat)}", reasons=reasons))
            else:
                self.events.write("scam-alert-limited", platform=platform, user=events.anon(user))
        return SKIP_PICTURE

    # ------------------------------------------------------------------ model check (design 2026-11-17)
    def _route(self, parts: list, verdict, is_owner: bool, text: str) -> tuple[list, str]:
        """Routing table 1.1. -> ([(variant, text, decoded)], why some outside text was left unchecked)."""
        sc = self.cfg.second_check
        content_on = [ch for ch in ("attachment", "reply_context") if ch in sc.channels]
        real = [(ch, t) for ch, t in parts if isinstance(t, str) and t.strip()]
        body = [(ch, t) for ch, t in real if ch in ("attachment", "reply_context")]
        names = [t for ch, t in real if ch == "name"]        # the owner's own name alone never goes
        if self.checker is None:
            return [], ("not model-checked" if body or not is_owner else "")
        weak_only = sc.scope == "weak" and verdict.level != scan.WEAK
        jobs, skipped = [], False
        if body:
            ctexts = [t for ch, t in body if ch in content_on]
            skipped = weak_only or len(ctexts) < len(body)
            if ctexts and not weak_only:
                jobs.append(("content",) + self._model_text(ctexts + (names if "reply_context" in content_on else [])))
        chat_text = text if text.strip() else ""
        if not is_owner and not body and names:
            chat_text = "\n".join([chat_text] + names).strip()    # a stranger's display name is outside text
        if chat_text:
            if "chat" not in sc.channels:
                go, skipped = False, skipped or not is_owner
            elif is_owner:
                go = (sc.owner_chat == "all" or (sc.owner_chat == "weak" and verdict.level == scan.WEAK)) \
                    and not text.lstrip().startswith("/")          # owner commands are handled by code
            else:
                go, skipped = not weak_only, skipped or weak_only
            if go:
                jobs.append(("chat",) + self._model_text([chat_text]))
        return jobs, ("not model-checked" if skipped else "")

    @staticmethod
    def _model_text(texts: list) -> tuple[str, str]:
        """The guard's revealed text (hidden characters as visible tags) plus the decoded text: hidden
        payloads and the layers the rules decode (base64, hex, rot13, escapes ...; design 2.1, review MC-1).
        Blocking: called in a worker pool."""
        shown, decoded = [], []
        for t in texts:
            rv = normalize.reveal(t)
            shown.append(rv.text)
            decoded += [p for p in rv.hidden_payloads[:5] if isinstance(p, str)]
            for src in [rv.text] + [p for p in rv.hidden_payloads[:5] if isinstance(p, str)]:
                d = second_check.decoded_layers(src, second_check.DECODED_CHARS)
                if d:
                    decoded.append(d)
        return "\n\n".join(shown), "\n".join(decoded)[:second_check.DECODED_CHARS * 2]

    def _scorer(self):
        th = self.cfg.threshold

        def score(chunk: str) -> float:
            return scan.scan_text(chunk, "attachment", th.max_scan_chars, min(1.0, th.scan_timeout_s)).score
        return score

    def _run_jobs(self, jobs: list, timeout: float, cancel: "threading.Event | None" = None,
                  retry_ok=None) -> list:
        """Blocking: one checker call set per job (content / chat). Raises CheckError on any failure.
        cancel: set when the caller gave up; the next call is then not made (review MC-4).
        retry_ok: see second_check.check_text (None = a bad answer is never retried)."""
        out = []
        for variant, txt, decoded in jobs:
            out.append(second_check.check(txt, self.cfg.second_check.endpoint, self.cfg.second_check.model, timeout,
                                          self.cfg.second_check.max_chars, checker=self.checker, variant=variant,
                                          scorer=self._scorer(), decoded=decoded, cancel=cancel, retry_ok=retry_ok))
        return out

    def _retry_gate(self, v: scan.Verdict, budget_key: str | None, jobs: list | tuple = ()):
        """second_check.tamper_retry (off by default, decision review pick 8): a callable for ONE retry
        per message after a bad checker answer, or None. Only when the rules saw nothing at all (no family,
        no signal, score 0), no words aimed at a checker, and, for a non-owner's message, one more call fits
        the budget (owner messages and tool results are counted, never refused)."""
        if not self.cfg.second_check.tamper_retry or v.level != scan.PASS or v.score > 0 or v.signals or v.families:
            return None
        # words aimed at a checker (a hijack attempt on the check itself) close the gate too (leak review
        # suggestion 5): the retry only reaches texts in which the rules and these words find nothing
        if any(second_check.checker_words(t if isinstance(t, str) else "") or
               second_check.checker_words(d if isinstance(d, str) else "") for _v, t, d in jobs):
            return None
        used = []

        def ok() -> bool:
            if used:
                return False
            used.append(1)
            if budget_key is None:
                self.budget.note(1)
                return True
            return self.budget.charge(budget_key, 1, count_refusal=False)   # a tamper hold, not "over budget"
        return ok

    def _job_calls(self, jobs: list) -> int:
        sc = self.cfg.second_check
        return sum(min(sc.max_chunks, len(second_check.token_chunks(t, sc.chunk_tokens, sc.max_chars)))
                   for _v, t, _d in jobs)

    def _job_limit(self, jobs: list, timeout: float, retry: bool = False) -> float:
        calls = self._job_calls(jobs) + (2 if self.checker.health.due() else 0) + (1 if retry else 0)
        return timeout * calls + 2.0

    async def _checked(self, jobs: list, timeout: float, retry_ok=None) -> list:
        """The jobs in the model-check pool with a time limit; on time-out the work is cancelled."""
        cancel = threading.Event()
        try:
            return await self._in_pool("check", self._job_limit(jobs, timeout, retry_ok is not None), self._run_jobs,
                                       jobs, timeout, cancel, retry_ok)
        except BaseException:
            cancel.set()
            raise

    def _apply_results(self, verdict, results: list, is_owner_chat: bool, stranger: bool = True) -> dict:
        """Only ever stricter: inject -> HOLD, suspicious -> one weak sign (second sign holds), checker words
        -> a weak sign. A clean result changes nothing and never clears taint.
        Partly checked (fix round MC-2): held, except the owner's own typed chat (tainted); with
        oversize: taint the owner's forwarded content is tainted too, a stranger's is always held."""
        sc = self.cfg.second_check
        worst = max(results, key=lambda r: second_check._RANK[r.verdict])
        partial = any(r.partial for r in results)
        if worst.verdict == "inject":
            verdict.raise_to(scan.HOLD, "second-check")
            verdict.notes.append("double-check flagged it")
            if worst.line_text.strip():
                verdict.snippets.insert(0, worst.line_text)     # the guard's own copy of the flagged line
        elif worst.verdict == "suspicious":
            if verdict.level == scan.WEAK and not is_owner_chat:
                verdict.raise_to(scan.HOLD, "second-check-suspicious")      # second weak sign (R5)
            else:
                verdict.raise_to(scan.WEAK, "second-check-suspicious")
            verdict.notes.append("double-check unsure")
        if any(r.checker_words for r in results):
            verdict.raise_to(scan.WEAK, "checker-words")
        partial_only = False
        if partial and not is_owner_chat and (sc.oversize == "hold" or stranger):
            # lab 0.9.2 bug 1: remember when the length alone held it (the sender is then told
            # "too long to check", never "tries to give instructions")
            # 0.9.3 re-run M3: only when the checker said "none" and saw no checker words; "suspicious"
            # is a reason of its own, so the sender is never told "too much text" then
            partial_only = (worst.verdict == "none" and not any(r.checker_words for r in results) and (
                verdict.level == scan.PASS or (
                    verdict.level == scan.WEAK and not self._weak_holds(verdict, verdict.content_level != scan.PASS))))
            verdict.raise_to(scan.HOLD, "second-check-partial")
            verdict.notes.append("too long to double-check in full")
        return {"verdict": worst.verdict, "kinds": list(worst.kinds), "partial": partial,
                "partial_only": partial_only, "retried": next((r.retried for r in results if r.retried), ""),
                "ms": round(sum(r.ms for r in results), 1), "prompt_id": worst.prompt_id,
                "score": max((r.score for r in results if r.score is not None), default=None)}

    async def _model_check_inbound(self, parts: list, verdict, is_owner: bool, text: str, platform: str = "",
                                   user: str = "") -> tuple[dict | None, str]:
        sc = self.cfg.second_check
        try:      # routing decodes layers (MC-1): off the event loop too
            jobs, unchecked = await self._in_pool("scan", self.cfg.threshold.scan_timeout_s + 2.0, self._route,
                                                  parts, verdict, is_owner, text)
        except asyncio.TimeoutError:
            verdict.raise_to(scan.HOLD, "second-check-unavailable")
            verdict.notes.append("could not double-check")
            return {"outcome": "busy"}, ""
        if not jobs:
            return None, unchecked
        calls = self._job_calls(jobs)
        if is_owner:
            self.budget.note(calls)
        elif not self.budget.charge(f"{platform}:{user}", calls):
            # review MC-4: a stranger over the checker budget is held without calling the shared model
            verdict.raise_to(scan.HOLD, "second-check-busy")
            verdict.notes.append("too many messages to double-check right now")
            self.events.write("model-check-budget", platform=platform, user=events.anon(user), calls=calls)
            return {"outcome": "busy"}, unchecked
        retry_ok = self._retry_gate(verdict, None if is_owner else f"{platform}:{user}", jobs)
        try:
            results = await self._checked(jobs, sc.timeout_s, retry_ok)
        except second_check.CheckTampered:      # decision review pick 8: a hijack sign (tamper_retry: after 1 retry)
            verdict.raise_to(scan.HOLD, "second-check-tamper")
            verdict.notes.append("double-check answer was not in the agreed shape")
            return {"outcome": "tamper"}, unchecked
        except (second_check.CheckUnavailable, asyncio.TimeoutError):
            verdict.raise_to(scan.HOLD, "second-check-unavailable")        # owner decision: hold
            verdict.notes.append("could not double-check")
            return {"outcome": "unavailable", "jobs": jobs}, unchecked
        owner_chat_only = is_owner and all(v == "chat" for v, _t, _d in jobs)
        mc = self._apply_results(verdict, results, owner_chat_only, stranger=not is_owner)
        mc["outcome"] = "checked"
        if mc["partial"]:
            unchecked = (unchecked + ", " if unchecked else "") + "partly checked"
        return mc, unchecked

    # ------------------------------------------------------------------ recheck queue (3.3.1, hard rules)
    def _recheck_ok(self, verdict, pre_level, media_issue, is_owner: bool, platform: str, chat: str) -> bool:
        """Rule 1: only items held ONLY because the checker was unavailable. Inbound only (rule 5: tool
        results never come here). Needs a delivery path; the ctx.inject_message one reaches the owner's
        own chat only."""
        if self.recheck is None or self.deliver_late is None or media_issue or pre_level == scan.HOLD:
            return False
        if any(r in ("weak-held", "attachment-unreadable") for r in verdict.reasons):
            return False
        th = self.cfg.threshold
        if pre_level == scan.WEAK and (th.weak_action_content if verdict.content_level != scan.PASS
                                       else th.weak_action) == "hold":
            return False                     # the rules alone would have held it: not an outage hold
        if self.deliver_scope == "owner" and not (is_owner and self.cfg.owner_chats.get(platform) == chat):
            return False
        return True

    def _ensure_recheck_task(self, gateway) -> None:
        if self._recheck_task is not None and not self._recheck_task.done():
            return
        try:
            self._recheck_task = asyncio.get_running_loop().create_task(self._recheck_loop(gateway))
        except RuntimeError:
            self._recheck_task = None

    async def _recheck_loop(self, gateway) -> None:
        while len(self.recheck):
            wake = self.recheck.next_wake()
            await asyncio.sleep(min(60.0, max(0.5, (wake if wake is not None else self.clock()) - self.clock())))
            await self.recheck_tick(gateway)

    async def recheck_tick(self, gateway=None) -> list:
        """Process due recheck items. Each check runs off the event loop with a time limit, so a stuck
        checker never blocks replies; items end at the attempt or time limit, held for the owner."""
        out = []
        for item in self.recheck.due():
            if not self.holds.is_pending(item.hold_id):          # the owner answered first, or it expired
                out.append((item.hold_id, self.recheck.finish(item, "gone")))
                continue
            sc = self.cfg.second_check
            try:
                results = await self._checked(item.jobs, sc.timeout_s)
                worst = max(results, key=lambda r: second_check._RANK[r.verdict])
                clean = worst.verdict == "none" and not any(r.checker_words or r.partial for r in results)
                if clean and self.checker.health.degraded:
                    clean = False                                    # rule 4: no release during a fault
                    outcome = self.recheck.retry(item, "degraded")
                elif clean:
                    outcome = "release"
                else:
                    outcome = self.recheck.finish(item, "held")      # rule 3: only "none" is clean
            except second_check.CheckTampered:
                outcome = self.recheck.finish(item, "held")          # rule 2: a hijack sign, never retried
            except (second_check.CheckUnavailable, asyncio.TimeoutError):
                outcome = self.recheck.retry(item, "unavailable")
            except Exception as e:
                self.events.write("recheck-error", error=type(e).__name__)
                outcome = self.recheck.finish(item, "held")
            if outcome == "release":
                outcome = await self._release_late(item, gateway)
            self.events.write("recheck", hold=item.hold_id, outcome=outcome, attempt=item.attempts)
            out.append((item.hold_id, outcome))
        return out

    async def _release_late(self, item, gateway) -> str:
        res = self.holds.resolve("release", item.hold_id)
        if not res.ok:
            return self.recheck.finish(item, "gone")
        h = res.hold
        minutes = max(1, int(round((self.clock() - h.created) / 60.0)))
        nonce = secrets.token_hex(6)
        note = messages.LATE_RELEASE.format(minutes=minutes, nonce=nonce)
        body = note + h.text                                              # rule 6: marked as late
        with self._lock:
            # review MC-6: bound to the owner's chat and user, not the text alone
            key = (item.platform, item.chat_id, item.user_id, scan.text_sha(body))
            self._late_pass[key] = self.clock() + RELEASE_TTL_S
            self._released[nonce] = (self.clock() + RELEASE_TTL_S, note)  # pre_llm_call reads past our note
            while len(self._late_pass) > 50:
                self._late_pass.popitem(last=False)
        try:
            r = self.deliver_late(item.platform, item.chat_id, item.user_id, body)
            if inspect.isawaitable(r):
                r = await asyncio.wait_for(r, SEND_TIMEOUT_S)
            ok = r is not False
        except Exception as e:
            self.events.write("recheck-deliver-error", error=type(e).__name__)
            ok = False
        if not ok:                                   # could not deliver: put it back for the owner
            self.holds.restore(h)
            return self.recheck.finish(item, "held")
        self.recheck.finish(item, "release")
        if gateway is not None:
            await self._to_owner(gateway, item.platform, messages.LATE_RELEASED.format(hid=item.hold_id))
        return "release"

    def _late_passed(self, event, text: str, platform: str = "", chat: str = "", user: str = "") -> bool:
        """A late release this guard just delivered: same platform, chat and user, exact text, one use, no
        media or quoted text."""
        if not self._late_pass:
            return False
        key = (platform, chat, user, scan.text_sha(text))
        with self._lock:
            exp = self._late_pass.get(key)
            if exp is None or self.clock() > exp:
                return False
            if media.describe(event) or media.inlined_texts(event) or any(
                    getattr(event, f, None) not in (None, "") for f in REPLY_FIELDS) or compat.extra_content(event)[0]:
                return False
            del self._late_pass[key]
            return True

    def picture_status(self) -> str:
        if self.ocr is None:
            return "pictures: not read (" + (self.ocr_off_why or "off") + ")"
        if not self.ocr.available:
            return "pictures: reader MISSING, every picture is held"
        if self.ocr_unbounded:
            return "pictures: read and checked, never passed on (Windows: the reader has NO memory limit)"
        return "pictures: read and checked, never passed on"

    def model_check_status(self) -> str:
        if self.checker is None:
            return "model check OFF (rules only)"
        h = self.checker.health
        return f"model check on ({self.checker.prompt_id}, probes {h.state})"

    def _note_outside(self, event, platform: str, user: str, atts, verdict, text: str = "", unchecked: str = "") -> None:
        """Tell Knock that this message carried outside text, so the turn starts tainted (K-02)."""
        try:
            why = []
            if unchecked:
                why.append(unchecked)        # anything left unchecked makes risky tools need approval
            if any(getattr(event, f, None) not in (None, "") for f in REPLY_FIELDS):
                why.append("quote or channel context")
            if atts or media.inlined_texts(event):
                why.append("attachment")
            if compat.extra_content(event)[0]:
                why.append("extra text fields")
            if verdict.level == scan.WEAK:
                why.append("weak warning signs")
            if why:
                self.knock.note_outside(platform, user, ", ".join(why), text=text)    # recheck R-06
        except Exception as e:
            self.events.write("knock-note-error", error=type(e).__name__)

    async def _notify_hold(self, h, gateway, src, platform: str, user: str, chat: str, is_owner: bool,
                           queued: bool = False, sender_text: str | None = None) -> None:
        c = self.cfg
        minutes = c.holds.timeout_min
        if queued:
            h.summary = (h.summary + messages.RECHECK_NOTE)[:300]
        if not self.holds.may_notify(platform, user):
            self.events.write("hold-notice-limited", hold=h.hold_id)
            return
        if is_owner:
            await self._reply(gateway, src, messages.HOLD_OWNER_SELF.format(reasons=h.summary, hid=h.hold_id,
                                                                            minutes=minutes))
            return
        if c.holds.tell_sender:
            await self._reply(gateway, src, sender_text or messages.HOLD_SENDER)
        n = c.holds.notice_excerpt_chars
        start = messages.defuse(h.text, n // 2 if h.snippet else n)
        excerpt = f': "{start}"' if start else ""
        if h.snippet and n:
            excerpt += f', matched "{messages.defuse(h.snippet, n)}"'           # the part that matched (review M10)
        note = messages.HOLD_OWNER.format(
            who=f"{platform} user {events.anon(user)}", where=f"chat {events.anon(chat)}", reasons=h.summary,
            excerpt=excerpt, hid=h.hold_id, minutes=minutes)
        skipped = self._owner_notice_slot()
        if skipped is None:                      # review OC-5: global cap; the next notice carries a digest
            self.events.write("owner-notice-limited", hold=h.hold_id)
            return
        if skipped:
            note += messages.HOLD_DIGEST.format(n=skipped)
        await self._to_owner(gateway, platform, note)

    def _owner_notice_slot(self) -> int | None:
        """-> None when the owner already got holds.owner_notices_10min hold notices in 10 minutes (the
        hold is counted as skipped), else how many were skipped since the last notice that went out."""
        now = self.clock()
        with self._lock:
            while self._owner_notices and now - self._owner_notices[0] > 600:
                self._owner_notices.popleft()
            if len(self._owner_notices) >= self.cfg.holds.owner_notices_10min:
                self._owner_notices_skipped += 1
                return None
            self._owner_notices.append(now)
            n, self._owner_notices_skipped = self._owner_notices_skipped, 0
            return n

    @staticmethod
    def _as_data(text: str) -> str:
        """Visible text plus any decoded hidden text, as plain data (review M10: no invisible characters
        are passed on)."""
        rv = normalize.reveal(text)
        out = rv.text
        for p in rv.hidden_payloads[:5]:
            out += messages.RELEASE_HIDDEN.format(text=messages.defuse(p, 2000))
        return out

    async def _hold_command(self, verb, hold_id, event, gateway, src, platform, user, chat):
        if media.describe(event) or media.inlined_texts(event) or compat.extra_content(event)[1]:
            await self._reply(gateway, src, messages.FOLLOW_BLOCKED_MEDIA)
            return SKIP_COMMAND
        if verb == "follow":
            # a follow sent as a reply carries quoted text the model will also read (review M10)
            ctx_parts, extra_media = self._event_parts(event, with_names=False)
            if extra_media:
                await self._reply(gateway, src, messages.FOLLOW_BLOCKED_MEDIA)
                return SKIP_COMMAND
            if ctx_parts:
                v = await self._scan_parts(ctx_parts)
                if v.level == scan.HOLD or self._weak_holds(v, True):
                    self.events.write("follow-refused", hold=hold_id, reason="reply context")
                    await self._reply(gateway, src, messages.FOLLOW_BLOCKED_REPLY)
                    return SKIP_COMMAND
        res = self.holds.resolve(verb, hold_id)
        if not res.ok:
            await self._reply(gateway, src, messages.HOLD_EXPIRED if res.message == "expired" else messages.HOLD_UNKNOWN)
            return SKIP_COMMAND
        h = res.hold
        self.events.write("hold-" + verb, hold=h.hold_id, platform=platform)
        if verb == "ignore":
            await self._reply(gateway, src, messages.IGNORED)
            return SKIP_COMMAND
        nonce = secrets.token_hex(6)
        body_parts = [self._as_data(h.text)] + [f"[attachment: {messages.defuse(n, 80)}]\n{self._as_data(b)}"
                                                for n, b in h.attachment_texts]
        body = messages.defuse_fences("\n\n".join(p for p in body_parts if p))
        reasons = h.summary + (messages.FOLLOW_MEDIA_NOTE if h.had_media else "") + (messages.FOLLOW_CUT_NOTE if h.cut else "")
        block = (messages.RELEASE_PREFIX.format(reasons=reasons, nonce=nonce) + body
                 + messages.RELEASE_SUFFIX.format(nonce=nonce))
        with self._lock:
            self._released[nonce] = (self.clock() + RELEASE_TTL_S, block)
            while len(self._released) > 50:
                self._released.popitem(last=False)
        # the release is a rewrite of the owner's own follow message: it lands in the owner's own
        # conversation (where the owner typed it), never in the sender's chat (owner decision 3)
        return {"action": "rewrite", "text": block}

    # ------------------------------------------------------------------ conversation context
    def _remember(self, session_id, user_message, conversation_history) -> None:
        """Keep the last CONTEXT_CHARS of a session's conversation (memory only) for the reply's link
        check: a link that carries pieces of it is removed (recheck item 7)."""
        texts = []
        if isinstance(conversation_history, (list, tuple)):
            for m in list(conversation_history)[-CONTEXT_MESSAGES:]:
                c = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
                texts.append(_flatten(c) if isinstance(c, (str, list, tuple)) else "")
        if user_message is not _MISSING:
            texts.append(_flatten(user_message))
        key = str(session_id or "")
        self._convo[key] = "\n".join(t for t in texts if t)[-CONTEXT_CHARS:]
        self._convo.move_to_end(key)
        while len(self._convo) > CONTEXT_SESSIONS:
            self._convo.popitem(last=False)

    # ------------------------------------------------------------------ pre_llm_call
    def on_pre_llm_call(self, session_id="", user_message=_MISSING, conversation_history=None, is_first_turn=False,
                        model="", platform=_MISSING, **kwargs):
        try:          # Knock's turn observer first: one pre_llm_call callback per plugin (review K-17)
            self.knock.on_pre_llm_call(session_id=session_id,
                                       user_message=None if user_message is _MISSING else user_message,
                                       conversation_history=conversation_history, is_first_turn=is_first_turn,
                                       model=model, platform="" if platform is _MISSING else platform, **kwargs)
        except Exception:
            pass      # the observer handles its own errors (marks the session); never skip the turn check
        try:
            self._remember(session_id, user_message, conversation_history)
        except Exception:
            pass
        try:
            self.late_probe()
            if user_message is _MISSING or platform is _MISSING:
                missing = [n for n, v in (("user_message", user_message), ("platform", platform)) if v is _MISSING]
                self._problem(compat.bad("pre_llm_call", "missing argument(s) " + ", ".join(missing)))
            if not self.healthy:
                self.events.write("llm-refused", reason="unhealthy")
                if self.enforce:
                    self._count("llm_blocked")
                    return {"action": "block", "message": messages.LLM_GUARD_DOWN}
                return None
            plat = str(platform or "").lower()
            if plat in LOCAL_SURFACES and not self.cfg.threshold.scan_local_turns:
                return None
            text = self._consume_released(_flatten(user_message))
            # the whole turn, as the model will read it (review M1: no "already cleared" parts removed)
            v = scan.scan_text(text, "chat", self.cfg.threshold.max_scan_chars, self.cfg.threshold.scan_timeout_s)
            if self._weak_holds(v, False):
                v.raise_to(scan.HOLD, "weak-held")
            if v.level == scan.HOLD:
                self.events.write("llm-block", platform=plat, families=v.families, signals=v.signals, notes=v.notes)
                if self.enforce:
                    self._count("llm_blocked")
                    return {"action": "block", "message": messages.LLM_BLOCKED.format(reasons=v.summary())}
            return None
        except Exception as e:
            self._count("errors")
            self.events.write("llm-error", error=type(e).__name__)
            return {"action": "block", "message": messages.LLM_GUARD_DOWN} if self.enforce else None

    # ------------------------------------------------------------------ transform_tool_result
    def on_transform_tool_result(self, tool_name="", args=None, result=_MISSING, task_id="", **kwargs):
        tool = "?"
        try:
            tool = messages.defuse(str(tool_name or "?"), 60)
            self.late_probe()
            if not self.healthy:
                return messages.TOOL_ERROR.format(tool=tool) if self.enforce else None
            if self.knock.args_changed(args, kwargs.get("tool_call_id"),
                                       result=None if result is _MISSING else result):     # lab item 12
                return messages.TOOL_ARGS_CHANGED.format(tool=tool) if self.enforce else None
            c = self.cfg
            if not c.threshold.scan_tool_results:
                return None
            if not isinstance(result, str):
                raise TypeError("tool result is not text")
            text, truncated = result, False
            if len(text) > c.threshold.max_scan_chars:
                text, truncated = text[:c.threshold.max_scan_chars], True
            v = scan.scan_text(text, "tool_result", c.threshold.max_scan_chars, c.threshold.scan_timeout_s)
            sc = c.second_check
            mc = None
            if self.checker is not None and "tool_result" in sc.channels and v.level != scan.HOLD and text.strip():
                try:          # bounded like inbound checks (design 3.3); a held tool result is never rechecked
                    jobs = [("content",) + _bounded(lambda: self._model_text([text]), c.threshold.scan_timeout_s)]
                    self.budget.note(self._job_calls(jobs))
                    cancel = threading.Event()
                    retry_ok = self._retry_gate(v, None, jobs)
                    results = _bounded(lambda: self._run_jobs(jobs, sc.tool_timeout_s, cancel, retry_ok),
                                       self._job_limit(jobs, sc.tool_timeout_s, retry_ok is not None), cancel)
                    mc = self._apply_results(v, results, False, stranger=False)
                except second_check.CheckTampered:
                    v.raise_to(scan.HOLD, "second-check-tamper")           # decision review pick 8
                except second_check.CheckUnavailable:
                    v.raise_to(scan.HOLD, "second-check-unavailable")      # owner decision: hold
            if self._weak_holds(v, True):
                v.raise_to(scan.HOLD, "weak-held")                         # review H8
            self.events.write("tool-result", tool=tool, verdict=v.level, score=v.score, families=v.families,
                              signals=v.signals, chars=len(result), truncated=truncated, model_check=mc)
            if not self.enforce:
                return None
            if v.level == scan.HOLD:
                self._count("tool_withheld")
                return messages.TOOL_WITHHELD.format(tool=tool, reasons=v.summary())
            out = normalize.reveal(text).text
            self._tool_text = (self._tool_text + "\n" + out)[-CONTEXT_CHARS:]
            if c.threshold.fence_tool_results:
                nonce = secrets.token_hex(6)
                out = (messages.TOOL_FENCE_HEAD.format(tool=tool, nonce=nonce)
                       + messages.defuse_fences(out) + messages.TOOL_FENCE_TAIL.format(nonce=nonce))
            if truncated:
                out += messages.TOOL_TRUNCATED.format(n=c.threshold.max_scan_chars)
            if mc and mc.get("partial"):
                out += messages.TOOL_PARTLY_CHECKED
            return None if out == result else out
        except Exception as e:
            self._count("errors")
            self.events.write("tool-error", tool=tool, error=type(e).__name__)
            return messages.TOOL_ERROR.format(tool=tool) if self.enforce else None

    # ------------------------------------------------------------------ transform_llm_output
    def on_transform_llm_output(self, response_text=_MISSING, session_id="", model="", platform="", **kwargs):
        try:
            self.late_probe()
            if response_text is _MISSING:
                self._problem(compat.bad("transform_llm_output", "missing argument response_text"))
            if not self.healthy:
                if self.enforce:
                    self._count("replies_withheld")
                    return messages.REPLY_WITHHELD
                return None
            new, notes = output.filter_reply(response_text, self.cfg.gatehouse,
                                             context=self._convo.get(str(session_id or ""), "") + "\n" + self._tool_text)
            try:                          # Knock's history check compares the next turn's history (R-07)
                self.knock.note_reply(session_id, response_text if isinstance(response_text, str) else "",
                                      new if isinstance(new, str) else "")
            except Exception:
                pass
            if notes:
                self.events.write("reply", notes=notes, chars=len(response_text or ""))
            if not self.enforce or new is None:
                return None
            self._count("replies_withheld" if new == output.WITHHELD else "replies_changed")
            return new
        except Exception as e:
            self._count("errors")
            self.events.write("reply-error", error=type(e).__name__)
            if self.enforce:
                self._count("replies_withheld")
                return messages.REPLY_WITHHELD
            return None

    # ------------------------------------------------------------------ /guard
    def cmd_guard(self, raw_args: str = "", source=None, **kwargs) -> str:
        try:
            head = f"{PLUGIN_NAME} {VERSION} ({self.cfg.mode}): " + ("healthy" if self.healthy else "NOT healthy")
            head += "; " + self.knock.status_line()                   # review K-15
            head += "; " + self.model_check_status()
            head += "; " + self.picture_status()
            if source is None:
                return head      # caller unknown: no problems, hold ids or counters (review L5)
            plat = compat.platform_name(source)
            if not self.cfg.is_owner(plat, getattr(source, "user_id", None)):
                return messages.NOT_OWNER
            lines = [head] + [f"- {p}" for p in self.all_problems()[:10]]
            pend = self.holds.pending()
            lines.append(f"pending holds: {len(pend)}" + (" (" + ", ".join(h.hold_id for h in pend[:10]) + ")" if pend else ""))
            lines.append("counts: " + ", ".join(f"{k} {v}" for k, v in self.counters.items() if v))
            if self.checker is not None:
                b = self.budget.status()
                lines.append(f"model check calls in 10 min: {b['calls_10min']}; strangers held over budget: "
                             f"{b['refused']}")
            if self._owner_notices_skipped:
                lines.append(f"hold notices not sent (10-minute limit): {self._owner_notices_skipped}")
            return "\n".join(lines)
        except Exception as e:
            return f"guard status unavailable ({type(e).__name__})"


def _flatten(user_message) -> str:
    """Text of a turn's user message: a str, or the text parts of a multimodal list."""
    if user_message is None:
        return ""
    if isinstance(user_message, str):
        return user_message
    if isinstance(user_message, (list, tuple)):
        out = []
        for part in user_message:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict):
                t = part.get("text")
                if isinstance(t, str):
                    out.append(t)
                elif part.get("type") not in ("image_url", "input_image", "image", "input_audio", "audio", "file"):
                    out.append(str(part)[:50_000])
        return "\n".join(out)
    return str(user_message)


def _bounded(fn, limit: float, cancel: "threading.Event | None" = None):
    """Run a blocking call with a time limit from synchronous hooks (tool results, design 3.3). On time-out
    the cancel event is set, so a model check stops before its next call (review MC-4)."""
    box: dict = {}

    def run():
        try:
            box["r"] = fn()
        except BaseException as e:      # handed to the caller below
            box["e"] = e
    t = threading.Thread(target=run, name="hearthward-model-check", daemon=True)
    t.start()
    t.join(limit)
    if t.is_alive():
        if cancel is not None:
            cancel.set()
        raise second_check.CheckUnavailable("check took too long")
    if "e" in box:
        raise box["e"]
    return box["r"]
