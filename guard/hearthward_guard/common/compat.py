"""Compatibility probes: the only place the guard touches Hermes beyond the plugin context.

Fail-closed pattern: every assumption is probed; any mismatch becomes a problem line
"compat: <item>: <detail>", and while any problem exists the guard refuses every message, blocks
every model call and withholds every reply. After a Hermes update: run preflight, review each
line, then update the expectations here.

Documented surface used: ctx.register_hook (incl. hold_stream), ctx.register_command,
ctx.get_config, the pre_gateway_dispatch kwargs (event, gateway, session_store) and
gateway.adapters[platform].send(...).

Reach-ins that are public names but not documented on the hooks page (probed, never private):
  1. MessageEvent field names (media_urls, media_types, media_text_inlined, media_filenames,
     reply_to_text, channel_context, channel_prompt): needed to know whether a message carries
     media or extra text the hook cannot rewrite. Unknown new fields that look like media or text
     fail closed.
  2. hermes_cli.plugins_manifest.running_hermes_version(): the version floor.
  3. hermes_cli.config.load_config_readonly(): plugins.hook_callback_timeout and gateway keys.
  4. hermes_cli.plugins.VALID_HOOKS and hermes_cli.plugins_dispatch.stream_held(): that our hooks
     exist and that the reply stream is really held.
  5. Knock's approval gate (fix round 2026-11-17, moved here from knock/policy.py):
     tools.approval.is_current_session_yolo_enabled(), gateway.session_finite.unattended_turn(),
     gateway.hosted_room_execution_policy.current_room_execution_policy(): whether a person
     answers the approval card right now.
  6. agent.safe_worker_policy.safe_worker_enabled(): safe-worker mode skips plugin hooks.
No private (underscore) names are imported anywhere in the guard, and this file is the only one
that imports Hermes modules.

Plugin catalog rule 9 ("private core imports") warns on every import of a Hermes module outside
the plugin context. None of the reach-ins above has a ctx or documented equivalent in v0.23.1:
ctx.get_config reads one plugin key, not the approvals or plugins sections; the running version,
the hook list, the stream-held flag, safe-worker mode and the approval state are not exposed. Each
is probed and fails closed. The warning is therefore expected here, and only here; it goes away
when Hermes adds public calls (track this in the upstream issue list before each upgrade).
"""
from __future__ import annotations

import dataclasses
import inspect
import re

PREFIX = "compat"
MIN_HERMES = (0, 23, 1)
MAX_HERMES = (0, 24, 0)      # exclusive: a newer Hermes needs a review of these probes first (review L8)
HOOKS = ("pre_gateway_dispatch", "pre_llm_call", "transform_tool_result", "transform_llm_output", "pre_tool_call")
# MessageEvent fields reviewed at v0.23.1. The guard reads the text and media ones.
TEXT_FIELDS = ("text", "reply_to_text", "channel_context", "channel_prompt")
MEDIA_FIELDS = ("media_urls", "media_types", "media_text_inlined", "media_filenames")
REVIEWED_EVENT_FIELDS = frozenset({
    "text", "message_type", "user_id", "user_name", "source", "raw_message", "message_id", "ledger_message_id",
    "reply_anchor_override", "platform_update_id", "media_urls", "media_types", "media_text_inlined",
    "reply_to_message_id", "reply_to_text", "reply_to_author_id", "reply_to_author_name", "reply_to_is_own_message",
    "prompt_response", "auto_skill", "channel_prompt", "channel_context", "internal", "metadata", "timestamp",
    "allow_gateway_control", "reply_expected", "inherit_channel_pin", "edit_revision", "media_filenames",
    "_admitted_before_drain", "_gateway_accepted", "_notification_reply_muted"})
# A new field whose name matches this may carry content the guard does not see: fail closed.
CONTENT_WORDS = re.compile(r"media|attach|file|image|photo|picture|video|audio|voice|document|sticker|vision|url|"
                           r"path|blob|upload|asset|text|context|prompt|quote|caption|content|body|message|"
                           r"transcript|forward|embed|poll|location|contact", re.I)
_NOT_CONTENT = {"message_type", "message_id", "ledger_message_id", "reply_to_message_id"}


def bad(item: str, detail: str) -> str:
    return f"{PREFIX}: {item}: {detail}"[:300]


def parse_version(s: str) -> tuple:
    m = re.match(r"\s*v?(\d+)\.(\d+)(?:\.(\d+))?", str(s or ""))
    if not m:
        return ()
    return tuple(int(x or 0) for x in m.groups())


# ---------------------------------------------------------------- static probes (at load)
def probe_version(problems: list) -> str:
    try:
        from hermes_cli.plugins_manifest import running_hermes_version
        ver = str(running_hermes_version())
    except Exception as e:
        problems.append(bad("hermes version", f"unreadable ({type(e).__name__})"))
        return ""
    v = parse_version(ver)
    if not v:
        problems.append(bad("hermes version", "unparseable"))
    elif v < MIN_HERMES:
        problems.append(bad("hermes version", f"{ver} is older than {'.'.join(map(str, MIN_HERMES))}"))
    elif v >= MAX_HERMES:
        problems.append(bad("hermes version", f"{ver} is newer than this guard was reviewed for "
                                              f"(< {'.'.join(map(str, MAX_HERMES))}); update the guard"))
    return ver


def probe_hooks(problems: list) -> None:
    try:
        from hermes_cli.plugins import VALID_HOOKS
    except Exception as e:
        problems.append(bad("hook names", f"unreadable ({type(e).__name__})"))
        return
    missing = [h for h in HOOKS if h not in VALID_HOOKS]
    if missing:
        problems.append(bad("hook names", "missing " + ", ".join(missing)))


def probe_event_fields(problems: list, event_cls=None) -> None:
    try:
        if event_cls is None:
            from gateway.platforms.event import MessageEvent as event_cls  # noqa: N813
        names = {f.name for f in dataclasses.fields(event_cls)}
    except Exception as e:
        problems.append(bad("MessageEvent", f"unreadable ({type(e).__name__})"))
        return
    gone = [f for f in TEXT_FIELDS + MEDIA_FIELDS if f not in names]
    if gone:
        problems.append(bad("MessageEvent", "renamed or removed: " + ", ".join(gone)))
    new = sorted(n for n in names - REVIEWED_EVENT_FIELDS if n not in _NOT_CONTENT)
    if new:      # any unreviewed field, whatever its name (review M5)
        problems.append(bad("MessageEvent", "new field(s) not reviewed yet: " + ", ".join(new)))


def read_hermes_config() -> dict:
    from hermes_cli.config import load_config_readonly
    cfg = load_config_readonly() or {}
    if not isinstance(cfg, dict):
        raise TypeError("config is not a mapping")
    return cfg


# ---------------------------------------------------------------- Knock's approval-gate reach-ins
# Public (non-underscore) names, but not plugin API: Hermes has no ctx call that says whether a
# person answers the approval card right now. They are kept here so compat.py is the only file
# that imports Hermes modules. Any import or call failure is "not a person" (callers fail closed).
def yolo_env_on() -> bool:
    """HERMES_YOLO_MODE: any non-empty value except 0/false/no/off is on (review K-06)."""
    import os
    return os.getenv("HERMES_YOLO_MODE", "").strip().lower() not in ("", "0", "false", "no", "off")


def session_yolo() -> bool:
    from tools.approval import is_current_session_yolo_enabled
    return is_current_session_yolo_enabled() is not False


def unattended_turn() -> bool:
    from gateway.session_finite import unattended_turn as _unattended
    return _unattended() is not False


def room_policy():
    from gateway.hosted_room_execution_policy import current_room_execution_policy
    return current_room_execution_policy()


def probe_hook_timeout(problems: list, cfg: dict | None = None) -> None:
    """plugins.hook_callback_timeout must be 0 (disabled): a timed-out pre_llm_call fails open."""
    try:
        cfg = read_hermes_config() if cfg is None else cfg
        val = ((cfg.get("plugins") or {}).get("hook_callback_timeout", 30))
        val = float(val)
    except Exception as e:
        problems.append(bad("plugins.hook_callback_timeout", f"unreadable ({type(e).__name__})"))
        return
    if val > 0:
        problems.append(bad("plugins.hook_callback_timeout", f"is {val:g}; set it to 0 (a timed-out check would let a turn through)"))


def probe_static(require_no_hook_timeout: bool = True) -> tuple[list, str]:
    """Load-time probes. -> (problems, hermes version)."""
    problems: list[str] = []
    ver = ""
    for fn in (probe_version, probe_hooks, probe_event_fields, probe_safe_worker):
        try:
            r = fn(problems)
            if fn is probe_version:
                ver = r or ""
        except Exception as e:   # a probe that crashes is a mismatch too
            problems.append(bad(fn.__name__, f"probe error ({type(e).__name__})"))
    if require_no_hook_timeout:
        try:
            probe_hook_timeout(problems)
        except Exception as e:
            problems.append(bad("probe_hook_timeout", f"probe error ({type(e).__name__})"))
    return problems, ver


def probe_stream_held(problems: list) -> None:
    """After registration: the reply stream must be held for our output filter."""
    try:
        from hermes_cli.plugins_dispatch import stream_held
        if stream_held() is not True:
            problems.append(bad("hold_stream", "the reply stream is not held (transform_llm_output)"))
    except Exception as e:
        problems.append(bad("hold_stream", f"unverifiable ({type(e).__name__})"))


def probe_safe_worker(problems: list) -> None:
    """Safe-worker mode skips plugin hooks entirely: it must be off (API spike item 5, review M11)."""
    try:
        from agent.safe_worker_policy import safe_worker_enabled
        if safe_worker_enabled() is not False:
            problems.append(bad("safe worker", "safe-worker mode is on: plugin hooks would not run"))
    except Exception as e:
        problems.append(bad("safe worker", f"unverifiable ({type(e).__name__})"))


def probe_register_hook_signature(ctx, problems: list) -> None:
    try:
        params = inspect.signature(ctx.register_hook).parameters
        if "hold_stream" not in params:
            problems.append(bad("register_hook", "no hold_stream parameter"))
    except (TypeError, ValueError):
        pass   # opaque callables (C, mocks): checked by probe_stream_held instead


# ---------------------------------------------------------------- runtime probes (per event)
def event_problems(event, gateway) -> list:
    """Per-event contract checks for pre_gateway_dispatch."""
    problems = []
    if event is None:
        return [bad("pre_gateway_dispatch", "no event")]
    if not isinstance(getattr(event, "text", ""), (str, type(None))):
        problems.append(bad("MessageEvent.text", "not a string"))
    src = getattr(event, "source", None)
    if src is None or getattr(src, "platform", None) is None:
        problems.append(bad("MessageEvent.source", "missing platform"))
    if gateway is not None:
        adapters = getattr(gateway, "adapters", None)
        if not hasattr(adapters, "get"):
            problems.append(bad("gateway.adapters", "missing"))
    return problems


def platform_name(source) -> str:
    p = getattr(source, "platform", None)
    v = getattr(p, "value", p)
    return str(v or "").lower()


_PRIMITIVE = (int, float, bool, type(None))
LEAF_LIMIT = 200
LEAF_CHARS = 20_000


def string_leaves(val, limit: int = LEAF_LIMIT) -> tuple[list, bool]:
    """(strings inside a str/list/tuple/set/dict, found something that is neither a string nor a
    number). Keys of mappings count as strings too. Bounded in count, depth and size."""
    out: list[str] = []
    odd = False
    stack = [(val, 0)]
    while stack and len(out) < limit:
        v, depth = stack.pop()
        if isinstance(v, str):
            if v.strip():
                out.append(v[:LEAF_CHARS])
        elif isinstance(v, _PRIMITIVE):
            continue
        elif depth >= 6:
            odd = True
        elif isinstance(v, dict):
            for k, x in list(v.items())[:limit]:
                stack.append((k, depth + 1))
                stack.append((x, depth + 1))
        elif isinstance(v, (list, tuple, set, frozenset)):
            for x in list(v)[:limit]:
                stack.append((x, depth + 1))
        else:
            odd = True
    if stack:
        odd = True          # more than the limit: not fully checked
    return out, odd


def sender_texts(event) -> list:
    """Sender-controlled text on reviewed fields that the model may see but that carries no message
    content of its own: display names and metadata (review M5)."""
    out: list[str] = []
    for f in ("user_name", "reply_to_author_name"):
        v = getattr(event, f, None)
        if isinstance(v, str) and v.strip():
            out.append(v[:LEAF_CHARS])
    meta = getattr(event, "metadata", None)
    if meta:
        out += string_leaves(meta)[0]
    return out


def extra_content(event) -> tuple[list, list]:
    """(text found in unreviewed fields, names of unreviewed fields whose content cannot be vouched
    for). Strings, and strings inside lists or mappings, get scanned; bytes, other objects, or
    non-text values on a content-like field mean "cannot vouch" (review M5)."""
    texts, media = [], []
    try:
        names = [f.name for f in dataclasses.fields(event)] if dataclasses.is_dataclass(event) else []
    except TypeError:
        names = []
    try:
        names += list(vars(event))
    except TypeError:
        pass
    for n in sorted(set(names)):
        if n in REVIEWED_EVENT_FIELDS or n in _NOT_CONTENT or n.startswith("__"):
            continue
        val = getattr(event, n, None)
        if not val or isinstance(val, _PRIMITIVE):
            continue
        if isinstance(val, str):
            texts.append(val)
            continue
        if isinstance(val, (bytes, bytearray, memoryview)):
            media.append(n)
            continue
        if n.startswith("_") and _inert(val):
            continue                       # Hermes bookkeeping (a time, a state, a lock): no content
        if n == "_busy_arrival" and _busy_arrival_ok(val):
            continue                       # reviewed metrics record, no message text (lab re-test 2 bug 5)
        leaves, odd = string_leaves(val)
        texts += leaves
        if n.startswith("_") and not odd and not leaves:
            continue                       # ids, counts and flags only (lab re-test bug 8)
        if odd or (CONTENT_WORDS.search(n) and not leaves):
            media.append(n)
    return texts, media


_INERT_MODULES = ("datetime", "enum", "uuid", "decimal", "asyncio", "_asyncio", "threading", "_thread",
                  "concurrent.futures")


def _inert(val) -> bool:
    """A value that cannot carry message content: dates and times, enum members, UUIDs, decimals,
    and asyncio / threading objects (events, locks, futures, tasks). Hermes sets such private
    attributes on an event at run time, for example while an approval card is open (lab re-test
    bug 8). Anything else on a private attribute is still read or counted as unreadable."""
    import enum
    if isinstance(val, enum.Enum):
        return True
    mod = getattr(type(val), "__module__", "") or ""
    return any(mod == m or mod.startswith(m + ".") for m in _INERT_MODULES)


# Hermes 0.23.1 tags a message that reaches a busy chat (for example while an approval card is
# open) with `_busy_arrival`, an `_Arrival` from hermes_cli/observability/shared_metrics_busy.py:
# a metrics record (times, a queue state, ids, flags, and the receiving adapter object or its
# platform) with these slots and no message text.
# Only this exact class and slot set, with short plain values, is passed; anything else on the
# attribute is still "cannot vouch" (lab re-test 2 bug 5).
_ARRIVAL_MODULE = "hermes_cli.observability.shared_metrics_busy"
_ARRIVAL_SLOTS = frozenset({"admission_id", "admitting", "arrived", "disposition", "done", "home", "merged",
                            "parked", "platform"})


def _busy_arrival_ok(val, depth: int = 0) -> bool:
    import enum
    t = type(val)
    if (depth > 3 or t.__name__ != "_Arrival" or getattr(t, "__module__", "") != _ARRIVAL_MODULE
            or frozenset(getattr(t, "__slots__", ()) or ()) != _ARRIVAL_SLOTS or hasattr(val, "__dict__")):
        return False
    for slot in _ARRIVAL_SLOTS:
        v = getattr(val, slot, None)
        if slot == "merged":
            if not isinstance(v, list) or len(v) > 64 or not all(_busy_arrival_ok(x, depth + 1) for x in v):
                return False
        elif isinstance(v, str):
            if len(v) > 128:
                return False
        elif slot == "platform" and _is_adapter(v):
            continue      # Hermes stores the receiving adapter itself here (lab re-test 3): not message text
        elif not isinstance(v, (_PRIMITIVE, enum.Enum)):
            return False
    return True


def _is_adapter(v) -> bool:
    try:
        from gateway.platforms.base import BasePlatformAdapter
    except Exception:
        return False
    return isinstance(v, BasePlatformAdapter)


def unreviewed_fields(event) -> list:
    """Names and value types of unreviewed attributes on an event (for the event log only)."""
    try:
        names = list(vars(event))
    except TypeError:
        return []
    out = []
    for n in sorted(names):
        if n in REVIEWED_EVENT_FIELDS or n in _NOT_CONTENT or n.startswith("__"):
            continue
        out.append(f"{n}:{type(getattr(event, n, None)).__name__}"[:60])
    return out[:10]


def adapter_for(gateway, source):
    """The documented side-channel send target: gateway.adapters[source.platform]."""
    adapters = getattr(gateway, "adapters", None)
    if adapters is None:
        return None
    p = getattr(source, "platform", None)
    try:
        a = adapters.get(p)
        if a is None and p is not None:
            name = platform_name(source)
            for k, v in adapters.items():
                if str(getattr(k, "value", k)).lower() == name:
                    return v
        return a
    except Exception:
        return None


def adapter_for_platform(gateway, platform: str):
    adapters = getattr(gateway, "adapters", None)
    if adapters is None:
        return None
    try:
        for k, v in adapters.items():
            if str(getattr(k, "value", k)).lower() == platform:
                return v
    except Exception:
        return None
    return None
