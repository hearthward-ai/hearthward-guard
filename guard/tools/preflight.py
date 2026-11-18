#!/usr/bin/env python3
"""Fail-closed preflight for hearthward-guard. Run it with the Python that runs Hermes, before
starting the gateway (and with --heartbeat after start, from a supervisor).

    python tools/preflight.py [--plugin-dir DIR] [--platform NAME ...] [--allow-toolset NAME ...]
                              [--tools-cli] [--heartbeat] [--max-age SECONDS]

Exit 0 = every check passed. Exit 1 = at least one problem (each printed as "FAIL: ...").
Exit 2 = the preflight itself could not run. It never prints config values, only key names.

Checks:
  - the guard plugin imports, registers its hooks, and its compatibility probes pass
    (Hermes version, hook names, MessageEvent fields, plugins.hook_callback_timeout == 0);
  - the plugin is listed in plugins.enabled and not in plugins.disabled;
  - its settings block parses (unknown or mistyped keys fail);
  - gateway.strict is true and gateway.trust_recent_files is false, and no environment variable
    overrides them (Hermes lets the environment win);
  - every chat platform (from --platform, owners and owner_chats) has an explicit
    platform_toolsets entry that names only allowed toolsets (default: no_mcp only);
  - optional --tools-cli: `hermes tools list --platform P` shows no enabled tool;
  - optional --heartbeat: a fresh, healthy heartbeat file from a running gateway exists.
An "OCR:" line (not a failure) names the picture reader: engine found or not, where it came from
(ocr.engine_path or PATH; the path itself is never printed), its version line and whether the
configured language data is installed. A missing engine or language data fails closed in the guard
(every picture is held, or pictures follow threshold.unscanned_media when the reader is off).
A NOTE line (not a failure) says when Knock cannot show approval cards because approvals.mode is
not manual (Hermes 0.23.1 defaults to smart); set it with: hermes config set approvals.mode manual
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time

PLUGIN_NAME = "hearthward-guard"
DEFAULT_ALLOWED_TOOLSETS = ("no_mcp",)
LOCAL_PLATFORMS = {"cli", "tui", "desktop", "acp", "local"}
ENV_OVERRIDES = {"HERMES_MEDIA_DELIVERY_STRICT": ("1", "true", "yes", "on"),
                 "HERMES_MEDIA_TRUST_RECENT_FILES": ("0", "false", "no", "off")}


def load_plugin(plugin_dir: str):
    """Import the plugin package from its directory (installed plugin dirs may carry a hyphenated
    name, so it is loaded by path under its package name)."""
    init = os.path.join(plugin_dir, "__init__.py")
    if not os.path.isfile(init):
        raise FileNotFoundError("plugin __init__.py not found")
    if "hearthward_guard" in sys.modules:
        return sys.modules["hearthward_guard"]
    spec = importlib.util.spec_from_file_location("hearthward_guard", init, submodule_search_locations=[plugin_dir])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["hearthward_guard"] = mod
    spec.loader.exec_module(mod)
    return mod


class _Ctx:
    """Minimal registration context: records what register() asks for."""

    def __init__(self, cfg: dict):
        self.plugin_id = PLUGIN_NAME
        self.hooks: dict = {}
        self.commands: dict = {}
        self._cfg = cfg

    def register_hook(self, name, callback, *, hold_stream=False):
        self.hooks[name] = hold_stream

    def register_command(self, name, handler, description="", args_hint="", argument_mode="raw"):
        self.commands[name] = handler

    def get_config(self, key, default=None):
        entry = (((self._cfg.get("plugins") or {}).get("entries") or {}).get(PLUGIN_NAME) or {})
        return (entry.get("settings") or {}).get(key, default) if isinstance(entry, dict) else default


def _names(v) -> set:
    if v is None:
        return set()
    if isinstance(v, str):
        return {v}
    if isinstance(v, (list, tuple, set)):
        return {str(x) for x in v}
    return {"<unreadable>"}


def check_config(cfg: dict, env: dict, platforms: list, allowed: tuple) -> list:
    problems = []
    plugins = cfg.get("plugins") if isinstance(cfg.get("plugins"), dict) else {}
    if PLUGIN_NAME not in _names(plugins.get("enabled")):
        problems.append(f"plugins.enabled does not list {PLUGIN_NAME}")
    if PLUGIN_NAME in _names(plugins.get("disabled")):
        problems.append(f"plugins.disabled lists {PLUGIN_NAME}")
    to = plugins.get("hook_callback_timeout", 30)
    try:
        if float(to) != 0:
            problems.append("plugins.hook_callback_timeout must be 0 (a timed-out check lets a turn through)")
    except (TypeError, ValueError):
        problems.append("plugins.hook_callback_timeout is not a number")

    gw = cfg.get("gateway") if isinstance(cfg.get("gateway"), dict) else {}
    if gw.get("strict") is not True:
        problems.append("gateway.strict must be true (media delivery limited to allowed folders)")
    if gw.get("trust_recent_files") is not False:
        problems.append("gateway.trust_recent_files must be false")
    for var, good in ENV_OVERRIDES.items():
        if var in env and str(env[var]).strip().lower() not in good:
            problems.append(f"environment variable {var} overrides the gateway media setting")
    if env.get("HERMES_MEDIA_ALLOW_DIRS"):
        problems.append("environment variable HERMES_MEDIA_ALLOW_DIRS is set (check it is intended; preflight refuses)")

    toolsets = cfg.get("platform_toolsets") if isinstance(cfg.get("platform_toolsets"), dict) else {}
    for p in sorted(set(platforms)):
        if p in LOCAL_PLATFORMS:
            continue
        if p not in toolsets:
            problems.append(f"platform_toolsets.{p} is missing (Hermes would use its default tools)")
    for p, ts in sorted(toolsets.items(), key=lambda kv: str(kv[0])):
        if str(p) in LOCAL_PLATFORMS:
            continue
        extra = sorted(_names(ts) - set(allowed))
        if extra:
            problems.append(f"platform_toolsets.{p} has toolsets that are not allowed: {', '.join(extra)}")
    return problems


def check_plugin(plugin_dir: str, cfg: dict) -> tuple[list, object]:
    problems = []
    try:
        mod = load_plugin(plugin_dir)
    except Exception as e:
        return [f"plugin does not import ({type(e).__name__})"], None
    ctx = _Ctx(cfg)
    try:
        guard = mod.register(ctx)
    except Exception as e:
        return [f"plugin register() failed ({type(e).__name__})"], None
    want = set(getattr(mod, "HOOK_NAMES", ()))
    if not want or set(ctx.hooks) != want:
        problems.append("plugin did not register all of its hooks")
    if ctx.hooks.get("transform_llm_output") is not True:
        problems.append("transform_llm_output is not registered with hold_stream")
    for p in getattr(guard, "problems", ["guard object missing"]):
        problems.append(f"guard: {p}")
    hb = getattr(guard, "heartbeat", None)
    if hb is not None:
        try:
            hb.stop()
        except Exception:
            pass
    return problems, guard


def check_tools_cli(platforms: list, runner=None) -> list:
    """`hermes tools list --platform P` must show no enabled tool. The output format is matched
    loosely; an error or empty output is a problem (cannot verify)."""
    run = runner or (lambda args: subprocess.run(args, capture_output=True, text=True, timeout=60))
    problems = []
    for p in sorted(set(platforms) - LOCAL_PLATFORMS):
        try:
            r = run(["hermes", "tools", "list", "--platform", p])
        except Exception as e:
            problems.append(f"tools list for {p} failed ({type(e).__name__})")
            continue
        out = (getattr(r, "stdout", "") or "")
        if getattr(r, "returncode", 1) != 0 or not out.strip():
            problems.append(f"tools list for {p} could not be read")
            continue
        lines = out.splitlines()
        if not any(("✓" in ln or "✗" in ln) for ln in lines) and "no tools" not in out.lower():
            problems.append(f"tools list for {p} has an unknown format (cannot verify)")
            continue
        enabled = [ln for ln in lines if "✓" in ln]
        if enabled:
            problems.append(f"{p} has {len(enabled)} enabled tool line(s)")
    return problems


def check_ocr(guard) -> str:
    """One "OCR: ..." line: the picture reader the guard will use and whether it was found. Never prints
    the engine path (a config value), only its file name, where it came from, and its version line."""
    if guard is None:
        return ""
    eng = getattr(guard, "ocr", None)
    if eng is None:
        why = getattr(guard, "ocr_off_why", "") or "off"
        return f"OCR: picture reader not used ({why}); pictures follow threshold.unscanned_media"
    if not getattr(eng, "available", False):
        return (f"OCR: engine NOT found ({getattr(eng, 'missing', '') or 'unknown reason'}); "
                "every picture will be held")
    cfg = getattr(getattr(guard, "cfg", None), "ocr", None)
    source = "ocr.engine_path" if getattr(cfg, "engine_path", "") else "PATH"
    name = os.path.basename(str(eng.path))
    version = eng.version() or "version unknown"
    langs = "language data ok" if eng.languages_ok() else "language data MISSING (every picture will be held)"
    unbounded = "; Windows: NO memory limit for the engine" if getattr(guard, "ocr_unbounded", False) else ""
    return f"OCR: engine found ({name}, from {source}, {version}), {langs}{unbounded}"


def check_heartbeat(directory: str, max_age: float, now: float | None = None, pid: int | None = None) -> list:
    """Fresh, healthy heartbeat. With *pid*, only the gateway process's own file counts (review M11):
    a stale or foreign process's file cannot vouch for the running gateway."""
    now = time.time() if now is None else now
    try:
        names = [n for n in os.listdir(directory) if n.endswith(".json")]
    except OSError:
        return ["no heartbeat folder (is the gateway running with the guard?)"]
    if pid is not None:
        names = [n for n in names if n == f"{int(pid)}.json"]
        if not names:
            return [f"no heartbeat file for gateway pid {int(pid)}"]
    fresh = []
    for n in names:
        try:
            with open(os.path.join(directory, n), encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and now - float(data.get("ts", 0)) <= max_age:
            if pid is not None and data.get("pid") != int(pid):
                continue
            fresh.append(data)
    if not fresh:
        return ["no fresh heartbeat (guard not running, or stalled)"]
    if not all(d.get("healthy") is True for d in fresh):
        return ["the guard reports itself unhealthy: " + "; ".join(
            str(p)[:120] for d in fresh for p in (d.get("problems") or [])[:3])]
    return []


def read_hermes_config() -> dict:
    from hermes_cli.config import load_config_readonly
    cfg = load_config_readonly() or {}
    if not isinstance(cfg, dict):
        raise TypeError("config is not a mapping")
    return cfg


def platforms_from(cfg: dict, extra: list) -> list:
    settings = ((((cfg.get("plugins") or {}).get("entries") or {}).get(PLUGIN_NAME) or {}).get("settings") or {})
    out = list(extra)
    for o in settings.get("owners") or []:
        if isinstance(o, str) and ":" in o:
            out.append(o.split(":", 1)[0])
    out += [str(k) for k in (settings.get("owner_chats") or {})]
    return sorted(set(out))


def main(argv=None, cfg=None, env=None) -> int:
    ap = argparse.ArgumentParser(description="hearthward-guard preflight")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--plugin-dir", default=os.path.join(os.path.dirname(here), "hearthward_guard"))
    ap.add_argument("--platform", action="append", default=[])
    ap.add_argument("--allow-toolset", action="append", default=[])
    ap.add_argument("--tools-cli", action="store_true")
    ap.add_argument("--heartbeat", action="store_true")
    ap.add_argument("--heartbeat-dir", default="")
    ap.add_argument("--max-age", type=float, default=60.0)
    ap.add_argument("--pid", type=int, default=None, help="gateway process id: only its heartbeat counts")
    a = ap.parse_args(argv)
    try:
        cfg = read_hermes_config() if cfg is None else cfg
    except Exception as e:
        print(f"ERROR: cannot read the Hermes config ({type(e).__name__}); run with the Hermes Python")
        return 2
    env = dict(os.environ) if env is None else env
    plats = platforms_from(cfg, a.platform)
    if not plats:
        print("FAIL: no chat platform named (use --platform, or set owners in the guard settings)")
        return 1
    problems = check_config(cfg, env, plats, tuple(a.allow_toolset) or DEFAULT_ALLOWED_TOOLSETS)
    plugin_problems, guard = check_plugin(a.plugin_dir, cfg)
    problems += plugin_problems
    if a.tools_cli:
        problems += check_tools_cli(plats)
    if a.heartbeat:
        hb_dir = a.heartbeat_dir
        if not hb_dir and guard is not None:
            hb_dir = getattr(guard.cfg, "heartbeat_dir", "") or os.path.join(getattr(guard, "data_dir", ""), "status")
        problems += check_heartbeat(hb_dir, a.max_age, pid=a.pid)
    for p in problems:
        print(f"FAIL: {p}")
    # Knock needs approvals.mode manual to show approval cards (0.23.1 default: smart). A guard
    # without tools works without it, so this is a note, not a failure (lab re-test bug 12)
    notice = getattr(getattr(guard, "knock", None), "setup_notice", None)
    if isinstance(notice, str) and notice:
        print(f"NOTE: {notice}")
    if guard is not None and not getattr(getattr(guard, "cfg", None), "owner_chats", None):
        # without it, owner notices (setup, restart, hold) are only logged (lab re-test 2 bug 9)
        print("NOTE: owner_chats is not set, so owner notices (setup, restart, holds) go to the guard "
              "log and /guard only; add owner_chats: {<platform>: <owner DM chat id>} to get them as DMs")
    ocr_line = check_ocr(guard)
    if ocr_line:
        print(ocr_line)
    if guard is not None and getattr(guard, "checker", "unset") is None:
        # rules only (design 2026-11-17, section 4): a clear warning, not a failure
        _m = getattr(sys.modules.get(type(guard).__module__), "messages", None)
        print(f"NOTE: {getattr(_m, 'MODEL_CHECK_OFF', 'Model check OFF: rules only.')}")
    if not problems:
        print(f"OK: {PLUGIN_NAME} preflight passed for {', '.join(plats)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
