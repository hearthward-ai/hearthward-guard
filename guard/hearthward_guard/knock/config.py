"""Settings for Knock (plugins.entries.<id>.settings.knock).

Strict like the rest of the guard: an unknown key, a wrong type or a bad value raises
ConfigError, and the guard then refuses everything (and Knock blocks every tool) until fixed.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ..common.config import ConfigError
from . import never, tools

KEYS = ("enabled", "taint", "local_taint", "unknown_tools", "untainted_acts", "untainted_exec", "ask_scope",
        "tools", "job_allowlists", "trusted_cron_jobs", "never_allow", "never_allow_disable", "unsafe_override",
        "max_sessions", "local_skills", "chat_grants_and_partial")
# fullmatch everywhere: "$" would accept a trailing newline (review K-16)
_JOB_RX = re.compile(r"[A-Za-z0-9_-]{1,64}")
_TRUSTED_RX = re.compile(r"([A-Za-z0-9_-]{1,64})(?::([0-9a-f]{16,64}))?")
_SKILL_PIN_RX = re.compile(r"([A-Za-z0-9_.-]{1,128}):([0-9a-f]{16,64})")
_GLOB_RX = re.compile(r"[A-Za-z0-9_.:*?\-]{1,128}")
_LIST_KEY_RX = re.compile(r"(\*|cron:\*|cron:[A-Za-z0-9_-]{1,64}|platform:[a-z][a-z0-9_-]{0,31})")


@dataclass(frozen=True)
class KnockConfig:
    enabled: bool = True
    taint: str = "deny"                 # deny | ask   (risky tool after REMOTE outside content)
    local_taint: str = "ask"            # deny | ask   (risky tool after LOCAL output: terminal, own files)
    unknown_tools: str = "deny"         # deny | ask   (a tool Knock has no class for)
    untainted_acts: str = "allow"       # allow | ask  (risky tool in a clean turn)
    untainted_exec: str = "ask"         # allow | ask  (code-running tool in a clean turn; bench 2026-11-17)
    ask_scope: str = "call"             # call | tool  (what an "always" answer on the card covers;
                                        #  tool = this session, this tool, today only; needs unsafe_override)
    tools: tuple = ()                   # ((glob, class), ...) user classes, checked before built-ins
    job_allowlists: tuple = ()          # ((key, (glob, ...)), ...)
    trusted_cron_jobs: frozenset = frozenset()
    trusted_cron_hashes: tuple = ()     # ((job id, sha256 prefix of its stored prompt), ...) (review K-21)
    never_rules: tuple = ()             # active never.Rule objects (built-ins minus disabled, plus extras)
    disabled_builtins: tuple = ()
    unsafe: tuple = ()                  # every setting that used unsafe_override (shown in /guard)
    max_sessions: int = 20000
    # skills the owner wrote: reading them with skill_view is LOCAL, not outside content (recheck R-04).
    # Empty by default (public version: every skill counts as outside content). An owner lists only
    # skills they wrote themselves, pinned by exact name AND the sha256 of the skill's SKILL.md
    # (decision review pick 4: a changed text, or any sub-file of the skill, is outside content):
    #   knock: {local_skills: ["my-notes:<sha256 of skills/.../my-notes/SKILL.md>"]}
    # (sha256sum <file>; 16 to 64 hex characters of it). A hub or downloaded skill must never be listed.
    local_skills: frozenset = frozenset()          # the names
    local_skill_pins: tuple = ()                   # ((name, sha256 prefix), ...)
    # grants and IN PART cards on chat platforms (decision review picks 1 and 2). Off until the lab
    # shows the 280-character card renders whole on that platform; local surfaces (CLI, TUI) always.
    # Lab re-test 2 (Hermes 0.23.1, Discord): grant cards fit and render whole, but IN PART cards do
    # NOT fit Discord's 280-character card budget, so on Discord a long write is refused (too-long),
    # never shown IN PART, whatever this switch says. Keep it off on Discord; IN PART is CLI/TUI only.
    chat_grants_and_partial: bool = False

    @property
    def asks(self) -> bool:
        return "ask" in (self.taint, self.local_taint, self.unknown_tools, self.untainted_acts, self.untainted_exec)


def _get(sec: Mapping, key: str, typ, default):
    if key not in sec:
        return default
    v = sec[key]
    if typ is int and isinstance(v, bool):
        raise ConfigError(f"knock.{key}: expected int, got bool")
    if not isinstance(v, typ):
        raise ConfigError(f"knock.{key}: expected {getattr(typ, '__name__', typ)}, got {type(v).__name__}")
    return v


def _choice(key: str, v: str, options: tuple) -> str:
    if v not in options:
        raise ConfigError(f"knock.{key}: {v!r} is not one of {', '.join(options)}")
    return v


def _glob(where: str, g) -> str:
    if not isinstance(g, str) or not _GLOB_RX.fullmatch(g):
        raise ConfigError(f"{where}: {g!r} is not a tool name or glob (letters, digits, _ . : - * ?)")
    return g


def parse(raw: Any) -> KnockConfig:
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ConfigError("knock: expected a mapping")
    unknown = sorted(set(map(str, raw)) - set(KEYS))
    if unknown:
        raise ConfigError(f"knock: unknown key(s) {', '.join(unknown)}")
    d = KnockConfig()
    unsafe = _get(raw, "unsafe_override", bool, False)
    needs_override: list[str] = []

    user_tools = []
    t = _get(raw, "tools", Mapping, {})
    if len(t) > 500:
        raise ConfigError("knock.tools: at most 500 entries")
    for name, cls in t.items():
        _glob("knock.tools", name)
        if cls not in tools.CLASSES:
            raise ConfigError(f"knock.tools.{name}: class must be one of {', '.join(tools.CLASSES)}")
        # lowering a built-in tool, a glob over built-in tools, or "read" for a tool Knock does not
        # know switches off checks: that needs unsafe_override, like removing a never rule (K-12)
        hits = [b for b in tools.BUILTIN if b == name or (any(ch in name for ch in "*?")
                                                         and fnmatch.fnmatchcase(b, name))]
        if any(tools.BUILTIN[b] != cls and cls != tools.ACT_SOURCE for b in hits) or \
                (cls == tools.READ and not hits):
            needs_override.append(f"tools.{name}")
        user_tools.append((name, cls))

    lists = []
    jl = _get(raw, "job_allowlists", Mapping, {})
    if len(jl) > 200:
        raise ConfigError("knock.job_allowlists: at most 200 lists")
    for key, names in jl.items():
        if not isinstance(key, str) or not _LIST_KEY_RX.fullmatch(key):
            raise ConfigError(f"knock.job_allowlists: key {key!r} must be *, cron:*, cron:<job id> or "
                              "platform:<name>")
        if not isinstance(names, (list, tuple)) or len(names) > 200:
            raise ConfigError(f"knock.job_allowlists.{key}: expected a list of tool names (max 200)")
        lists.append((key, tuple(_glob(f"knock.job_allowlists.{key}", n) for n in names)))

    jobs, hashes = [], []
    for j in _get(raw, "trusted_cron_jobs", list, []):
        m = _TRUSTED_RX.fullmatch(j) if isinstance(j, str) else None
        if not m:
            raise ConfigError("knock.trusted_cron_jobs: every entry must be a cron job id, or "
                              "'<job id>:<sha256 of its prompt>'")
        jobs.append(m.group(1))
        if m.group(2):
            hashes.append((m.group(1), m.group(2)))

    skills = _get(raw, "local_skills", list, [])
    if len(skills) > 500:
        raise ConfigError("knock.local_skills: at most 500 entries")
    pins = []
    for n in skills:
        m = _SKILL_PIN_RX.fullmatch(n) if isinstance(n, str) else None
        if not m:
            raise ConfigError("knock.local_skills: every entry must be '<skill name>:<sha256 of its SKILL.md>' "
                              "(16-64 lower-case hex characters, no wildcards)")
        pins.append((m.group(1), m.group(2)))

    disabled = _get(raw, "never_allow_disable", list, [])
    for rid in disabled:
        if rid not in never.BUILTIN_IDS:
            raise ConfigError(f"knock.never_allow_disable: {rid!r} is not a built-in rule id")
    if disabled:
        needs_override.append("never_allow_disable")
    enabled = _get(raw, "enabled", bool, d.enabled)
    if not enabled:
        needs_override.append("enabled: false")                       # review K-14
    scope = _choice("ask_scope", _get(raw, "ask_scope", str, d.ask_scope), ("call", "tool"))
    if scope == "tool":
        needs_override.append("ask_scope: tool")                      # review K-08
    if needs_override and not unsafe:
        raise ConfigError("knock: " + ", ".join(needs_override[:5]) + " switch(es) off checks and need(s) "
                          "knock.unsafe_override: true")
    extras = _get(raw, "never_allow", list, [])
    if len(extras) > 100:
        raise ConfigError("knock.never_allow: at most 100 extra rules")
    rules = [r for r in never.BUILTIN if r.rid not in disabled]
    seen = {r.rid for r in never.BUILTIN}
    for i, e in enumerate(extras):
        r = never.user_rule(e, f"knock.never_allow[{i}]")   # raises ConfigError
        if r.rid in seen:
            raise ConfigError(f"knock.never_allow[{i}]: id {r.rid!r} is already used")
        seen.add(r.rid)
        rules.append(r)

    return KnockConfig(
        enabled=enabled,
        taint=_choice("taint", _get(raw, "taint", str, d.taint), ("deny", "ask")),
        local_taint=_choice("local_taint", _get(raw, "local_taint", str, d.local_taint), ("deny", "ask")),
        unknown_tools=_choice("unknown_tools", _get(raw, "unknown_tools", str, d.unknown_tools), ("deny", "ask")),
        untainted_acts=_choice("untainted_acts", _get(raw, "untainted_acts", str, d.untainted_acts),
                               ("allow", "ask")),
        untainted_exec=_choice("untainted_exec", _get(raw, "untainted_exec", str, d.untainted_exec),
                               ("allow", "ask")),
        ask_scope=scope,
        tools=tuple(user_tools),
        job_allowlists=tuple(lists),
        trusted_cron_jobs=frozenset(jobs),
        trusted_cron_hashes=tuple(hashes),
        never_rules=tuple(rules),
        disabled_builtins=tuple(disabled),
        unsafe=tuple(needs_override),
        local_skills=frozenset(n for n, _h in pins),
        local_skill_pins=tuple(pins),
        chat_grants_and_partial=_get(raw, "chat_grants_and_partial", bool, d.chat_grants_and_partial),
        max_sessions=_range_int("max_sessions", _get(raw, "max_sessions", int, d.max_sessions), 100, 1_000_000),
    )


def _range_int(key: str, v: int, lo: int, hi: int) -> int:
    if not lo <= v <= hi:
        raise ConfigError(f"knock.{key}: {v} is outside {lo}..{hi}")
    return v

