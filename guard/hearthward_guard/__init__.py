"""hearthward-guard: Hermes plugin entry point. register() wires hooks and one command, nothing else.

If anything in setup fails, the hooks are still registered in refuse-all mode (Hermes would
otherwise disable a plugin whose register() raises and carry on without it). That includes a guard
module that cannot even be imported (a damaged file, a half-finished update): then a stdlib-only
refuse-all stand-in below is registered instead (review M11).
"""
from __future__ import annotations

import os
import sys

HOOK_NAMES = ("pre_gateway_dispatch", "pre_llm_call", "transform_tool_result", "transform_llm_output", "pre_tool_call")

_DOWN = "The safety guard could not load, so nothing is read, run or sent until the owner fixes it."


class _RefuseAll:
    """Stand-in when the guard package cannot be imported: every hook refuses. Standard library only."""

    healthy = False

    def __init__(self, reason: str):
        self.problems = [f"setup: guard modules could not be imported ({reason})"]

    async def on_pre_gateway_dispatch(self, event=None, gateway=None, **kwargs):
        return {"action": "skip", "reason": "hearthward-guard: guard could not load"}

    def on_pre_llm_call(self, **kwargs):
        return {"action": "block", "message": _DOWN}

    def on_transform_tool_result(self, **kwargs):
        return "[Guard: the tool output was withheld because the safety guard could not load.]"

    def on_transform_llm_output(self, **kwargs):
        return _DOWN

    def on_pre_tool_call(self, **kwargs):
        return {"action": "block", "message": _DOWN}

    def cmd_guard(self, raw_args: str = "", **kwargs) -> str:
        return "hearthward-guard: NOT healthy (guard modules could not be imported)"


def _read_settings(ctx, plugin_id: str):
    """The whole plugins.entries.<id>.settings mapping, so unknown (mistyped) keys can be refused.
    Falls back to per-key ctx.get_config when the full config cannot be read."""
    from .common import compat, config
    try:
        cfg = compat.read_hermes_config()
        entries = ((cfg.get("plugins") or {}).get("entries") or {})
        entry = entries.get(plugin_id) or {}
        if not isinstance(entry, dict):
            raise TypeError("plugin entry is not a mapping")
        return entry.get("settings") or {}
    except Exception:
        out = {}
        for key in config.SECTIONS:
            v = ctx.get_config(key, default=None)
            if v is not None:
                out[key] = v
        return out


def _want_heartbeat() -> bool:
    v = os.getenv("HEARTHWARD_GUARD_HEARTBEAT", "")
    if v in ("0", "1"):
        return v == "1"
    return "gateway" in sys.argv[1:3]


def _register_refuse_all(ctx, reason: str):
    stub = _RefuseAll(reason)
    for name, cb, kw in (("pre_gateway_dispatch", stub.on_pre_gateway_dispatch, {}),
                         ("pre_llm_call", stub.on_pre_llm_call, {}),
                         ("transform_tool_result", stub.on_transform_tool_result, {}),
                         ("transform_llm_output", stub.on_transform_llm_output, {"hold_stream": True}),
                         ("pre_tool_call", stub.on_pre_tool_call, {})):
        try:
            ctx.register_hook(name, cb, **kw)
        except Exception:
            pass
    try:
        ctx.register_command("guard", stub.cmd_guard, description="Guard status")
    except Exception:
        pass
    return stub


def _wire_model_check(ctx, guard) -> None:
    """Startup warning when no model is set; the late-release path for the recheck queue (owner's own
    chat only, through ctx.inject_message; unverified in the lab, so recheck_unavailable stays off by
    default and without this path nothing is ever queued)."""
    import logging
    from .common import messages
    try:
        if guard.checker is None:
            logging.getLogger("hearthward_guard").warning(messages.MODEL_CHECK_OFF)
            return
        inject = getattr(ctx, "inject_message", None)
        if guard.recheck is None or not callable(inject):
            return
        import inspect
        try:
            takes_origin = "origin" in inspect.signature(inject).parameters
        except (TypeError, ValueError):
            takes_origin = False

        def deliver(platform, chat_id, user_id, text):
            return inject(text, origin="hearthward-guard:late-release") if takes_origin else inject(text)
        guard.deliver_late = deliver
        guard.deliver_scope = "owner"
    except Exception as e:
        guard.events.write("model-check-wiring-error", error=type(e).__name__)


def register(ctx):
    try:
        from .common import compat
        from .hooks import Guard
    except BaseException as e:  # noqa: BLE001  (ImportError, SyntaxError, anything at import time)
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        return _register_refuse_all(ctx, type(e).__name__)

    try:
        plugin_id = str(getattr(ctx, "plugin_id", "") or "hearthward-guard")
        settings = _read_settings(ctx, plugin_id)
        # probes always run: outside a real Hermes they fail, and the guard refuses everything
        guard = Guard(settings, prober=compat.probe_static, heartbeat=_want_heartbeat())
    except Exception as e:  # last resort: refuse everything
        try:
            guard = Guard({"mode": "enforce"}, prober=None)
            guard.problems.append(f"setup: {type(e).__name__}")
        except Exception as e2:
            return _register_refuse_all(ctx, type(e2).__name__)
    try:
        compat.probe_register_hook_signature(ctx, guard.problems)
    except Exception:
        pass
    for name, cb, kw in (("pre_gateway_dispatch", guard.on_pre_gateway_dispatch, {}),
                         ("pre_llm_call", guard.on_pre_llm_call, {}),
                         ("transform_tool_result", guard.on_transform_tool_result, {}),
                         ("transform_llm_output", guard.on_transform_llm_output, {"hold_stream": True}),
                         ("pre_tool_call", guard.knock.on_pre_tool_call, {})):     # Knock: tool policy
        try:
            ctx.register_hook(name, cb, **kw)
        except Exception as e:
            guard.problems.append(compat.bad("register_hook", f"{name} failed ({type(e).__name__})"))
    try:
        ctx.register_command("guard", guard.cmd_guard, description="Guard status (owner only)")
    except Exception:
        pass   # status command only; the guard works without it
    _wire_model_check(ctx, guard)
    if guard.heartbeat is not None:
        try:
            guard.heartbeat.start()
            if hasattr(ctx, "on_unload"):
                ctx.on_unload(guard.heartbeat.stop)
        except Exception:
            pass   # no heartbeat file = the supervisor treats the guard as down
    return guard
