"""Settings loader for plugins.entries.hearthward-guard.settings.

Hermes only warns when settings do not match the manifest schema, so this loader is strict and
fails closed: an unknown key, a wrong type or an out-of-range value raises ConfigError, and the
guard then refuses every message until the settings are fixed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping


class ConfigError(ValueError):
    """Invalid guard settings (the guard runs in refuse-all mode until fixed)."""


SECTIONS = ("mode", "owners", "owner_chats", "threshold", "holds", "second_check", "gatehouse", "log",
            "heartbeat", "require_no_hook_timeout", "knock", "ocr")   # knock: parsed by knock/config.py

_PLATFORM_RX = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_ID_RX = re.compile(r"^[A-Za-z0-9@._:+=-]{1,128}$")


@dataclass(frozen=True)
class SecondCheck:
    endpoint: str = ""                 # "" = off
    model: str = "local"
    timeout_s: float = 8.0
    max_chars: int = 6000              # per chunk
    scope: str = "all"                 # all | weak
    channels: tuple = ("chat", "attachment", "reply_context", "tool_result")
    on_error: str = "hold"             # hold only: a failed or timed-out check never lets a message through
    allow_remote: bool = False         # a non-loopback endpoint sends message text off this machine
    # model-check stage (design 2026-11-17)
    owner_chat: str = "weak"           # owner direct chat to the model: off, only when the rules scored it weak, or all
    json_mode: str = "schema"          # schema (llama.cpp, vLLM) | json_object (Ollama, LM Studio) | none
    slot: int = -1                     # llama.cpp id_slot; -1 = any
    api_key_env: str = ""              # the NAME of an environment variable holding a key; never a key
    max_chunks: int = 4                # chunks checked per item: first, highest rule signals, last
    chunk_tokens: int = 1500           # estimated tokens per chunk (CJK x1 + other chars / 4)
    # an item too long to check in full (fix round MC-2): hold = held, except the owner's own typed chat
    # (tainted); taint = strangers are still held, the owner's forwarded content is tainted (risky tools
    # then need approval)
    oversize: str = "hold"
    calls_per_sender_10min: int = 12   # checker calls one non-owner may cause per 10 minutes (review MC-4)
    calls_all_10min: int = 60          # checker calls all non-owners together may cause per 10 minutes
    prompt_variant_dir: str = ""       # advanced: a folder with content.txt / chat.txt / probes.json
    recheck_unavailable: bool = False  # re-check items held only because the checker was down (3.3.1)
    recheck_attempts: int = 3
    recheck_window_min: int = 10
    probes: bool = True                # canary probes before checks: at start, then every probe_every_min
    probe_every_min: int = 30
    pause_flag: str = ""               # a file whose presence means "checker paused" (e.g. a gaming flag)
    tool_timeout_s: float = 8.0
    score_mode: bool = False           # ask for logprobs and record a score (tuning only)
    # one retry after a bad checker answer, only for items with no rule-layer sign (11-18). Off by default:
    # decision review pick 8 says a bad answer is a hijack sign and is never retried
    tamper_retry: bool = False

    @property
    def enabled(self) -> bool:
        return bool(self.endpoint)


@dataclass(frozen=True)
class Threshold:
    scan_attachments: bool = True
    scan_tool_results: bool = True
    scan_reply_context: bool = True
    scan_local_turns: bool = False      # CLI/TUI/desktop turns in pre_llm_call
    window_messages: int = 6
    window_minutes: int = 1440          # the chat history outlives a short window (review M1)
    max_scan_chars: int = 120_000
    max_attachment_bytes: int = 2_000_000
    max_attachments: int = 8
    unscanned_media: str = "hold"       # hold (= skip) | owners | allow
    weak_action: str = "pass"           # pass | hold: weak score in direct chat
    weak_action_content: str = "hold"   # pass | hold: weak score in attachments, quoted text, tool results
    #   (rule signs; a model-check "suspicious" alone on inbound text taints the turn instead, see README)
    fence_tool_results: bool = True
    scan_timeout_s: float = 10.0        # a scan that takes longer holds the message


@dataclass(frozen=True)
class Holds:
    timeout_min: int = 30
    default: str = "ignore"             # the only accepted value: no answer never releases
    max_pending: int = 50
    notices_per_sender_10min: int = 3
    owner_notices_10min: int = 10      # hold notices to the owner for all senders together (review OC-5)
    notice_excerpt_chars: int = 160
    tell_sender: bool = True


@dataclass(frozen=True)
class Gatehouse:
    strip_invisible: bool = True
    withhold_secrets: bool = True
    block_media_directives: bool = True
    block_markdown_images: bool = True
    block_query_links: bool = True      # links shaped like data leaving: encoded pieces, conversation text (recheck item 7)
    safe_link_hosts: tuple = ()         # extra hosts whose links are never removed (logs an outsider cannot read)
    id_patterns: tuple = ()             # compiled regexes; matches become "(id removed)"


@dataclass(frozen=True)
class Ocr:
    """Picture text for the scam shield (job 6). The picture itself never reaches the model."""
    enabled: Any = "auto"              # auto (on when the engine is found) | true | false
    engine_path: str = ""              # "" = find "tesseract" on PATH
    tessdata_dir: str = ""             # "" = the engine's own language data folder
    languages: tuple = ("eng", "chi_sim")
    timeout_s: float = 20.0            # per picture
    memory_mb: int = 1024              # engine address-space limit (Linux/macOS)
    max_bytes: int = 10_000_000        # per picture file
    max_pixels: int = 40_000_000
    max_pictures: int = 4              # per message
    max_text_chars: int = 20_000       # per picture
    read_metadata: bool = True         # EXIF / XMP / PNG text / JPEG comments are checked too
    locale: str = "en"                 # en | zh | both: verdicts and owner alerts
    alert_owner: bool = True           # tell the owner when someone else sends a likely scam picture
    alerts_per_10min: int = 6          # all owner scam alerts together


@dataclass(frozen=True)
class Config:
    mode: str = "enforce"               # enforce | report
    owners: frozenset = frozenset()     # {"platform:user_id"}
    owner_chats: Mapping[str, str] = field(default_factory=dict)  # platform -> chat id for hold notices
    threshold: Threshold = Threshold()
    holds: Holds = Holds()
    second_check: SecondCheck = SecondCheck()
    gatehouse: Gatehouse = Gatehouse()
    ocr: Ocr = Ocr()
    log_raw_text: bool = False
    log_path: str = ""                  # "" = <data dir>/events.jsonl
    heartbeat_dir: str = ""             # "" = <data dir>/status
    heartbeat_interval_s: int = 15
    require_no_hook_timeout: bool = True

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    def is_owner(self, platform: str, user_id: Any) -> bool:
        if user_id is None or not platform:
            return False
        uid = str(user_id)
        return bool(uid) and f"{platform}:{uid}" in self.owners


def _type_name(t) -> str:
    return getattr(t, "__name__", str(t))


def _get(section: Mapping, key: str, typ, default, where: str):
    if key not in section:
        return default
    v = section[key]
    if typ is float and isinstance(v, int) and not isinstance(v, bool):
        v = float(v)
    if typ is int and isinstance(v, bool):
        raise ConfigError(f"{where}.{key}: expected int, got bool")
    if not isinstance(v, typ):
        raise ConfigError(f"{where}.{key}: expected {_type_name(typ)}, got {type(v).__name__}")
    return v


def _range(where: str, v, lo, hi):
    if not (lo <= v <= hi):
        raise ConfigError(f"{where}: the value is outside {lo}..{hi}")      # never echo values (review L3)
    return v


def _choice(where: str, v: str, options: tuple):
    if v not in options:
        raise ConfigError(f"{where}: the value is not one of {', '.join(options)}")
    return v


_LOOPBACK_RX = re.compile(r"^https?://(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[::1\])(?::\d{1,5})?(?:/|$)", re.I)


def _section(raw: Mapping, name: str, allowed: set) -> Mapping:
    sec = raw.get(name, {})
    if sec is None:
        sec = {}
    if not isinstance(sec, Mapping):
        raise ConfigError(f"{name}: expected a mapping")
    unknown = sorted(set(map(str, sec)) - allowed)
    if unknown:
        raise ConfigError(f"{name}: unknown key(s) {', '.join(unknown)}")
    return sec


def _owners(raw) -> frozenset:
    if raw is None:
        return frozenset()
    if not isinstance(raw, (list, tuple)):
        raise ConfigError("owners: expected a list of 'platform:user_id' strings")
    out = set()
    for item in raw:
        if not isinstance(item, (str, int)) or isinstance(item, bool):
            raise ConfigError("owners: every entry must be 'platform:user_id'")
        s = str(item).strip()
        plat, sep, uid = s.partition(":")
        if not sep or not _PLATFORM_RX.match(plat) or not _ID_RX.match(uid):
            raise ConfigError(f"owners: entry {len(out) + 1} is not 'platform:user_id'")
        out.add(f"{plat}:{uid}")
    return frozenset(out)


def _owner_chats(raw) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ConfigError("owner_chats: expected a mapping of platform -> chat id")
    out = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not _PLATFORM_RX.match(k):
            raise ConfigError("owner_chats: bad platform name")
        if not isinstance(v, (str, int)) or isinstance(v, bool) or not _ID_RX.match(str(v)):
            raise ConfigError(f"owner_chats.{k}: bad chat id")
        out[k] = str(v)
    return out


def _endpoint(v: str) -> str:
    if not v:
        return ""
    if not re.match(r"^https?://[A-Za-z0-9.\-\[\]:]+(?::\d{1,5})?(?:/[A-Za-z0-9._~/\-]*)?$", v):
        raise ConfigError("second_check.endpoint: expected an http(s) base URL such as http://host:port/v1")
    return v.rstrip("/")


_ENV_RX = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")


def _env_name(v: str) -> str:
    if v and not _ENV_RX.match(v):
        raise ConfigError("second_check.api_key_env: expected the NAME of an environment variable (A-Z, 0-9, _), "
                          "never the key itself")
    return v


def _short_path(where: str, v: str) -> str:
    if len(v) > 500 or any(ord(ch) < 32 for ch in v):
        raise ConfigError(f"{where}: expected a file or folder path")
    return v


_HOST_RX = re.compile(r"^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


# Hosts where anyone can publish a page, form, script or webhook (decision review pick 7): a link there
# sends its data to whoever made that page, so they can never be listed as safe.
_USER_CONTENT_RX = re.compile(
    r"(^|\.)(docs|forms|script|sites|drive|storage)\.google\.com$|(^|\.)(googleusercontent\.com|forms\.gle|"
    r"github\.io|githubusercontent\.com|gist\.github\.com|pages\.dev|workers\.dev|vercel\.app|netlify\.app|"
    r"herokuapp\.com|glitch\.me|repl\.co|replit\.app|webhook\.site|pipedream\.net|requestbin\.(com|net)|"
    r"beeceptor\.com|hookbin\.com|notion\.site|firebaseapp\.com|web\.app|blogspot\.com|wordpress\.com|"
    r"ngro[k](-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serve[o]\.net|duckdns\.org|"
    r"interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator\.net)$")


def _hosts(raw) -> tuple:
    """Exact host names (never whole domains): google.com does not cover docs.google.com."""
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)) or len(raw) > 64:
        raise ConfigError("gatehouse.safe_link_hosts: expected a list of at most 64 host names")
    out = []
    for i, h in enumerate(raw):
        if not isinstance(h, str) or not _HOST_RX.match(h.strip().lower()):
            raise ConfigError(f"gatehouse.safe_link_hosts[{i}]: expected a host name such as docs.python.org")
        if _USER_CONTENT_RX.search(h.strip().lower()):
            raise ConfigError(f"gatehouse.safe_link_hosts[{i}]: {h.strip().lower()} hosts pages, forms or scripts "
                              "anyone can publish, so links there are never safe")
        out.append(h.strip().lower())
    return tuple(out)


def _patterns(raw) -> tuple:
    if raw is None:
        return ()
    if not isinstance(raw, (list, tuple)) or len(raw) > 32:
        raise ConfigError("gatehouse.id_patterns: expected a list of at most 32 regex strings")
    out = []
    for i, p in enumerate(raw):
        if not isinstance(p, str) or not 2 <= len(p) <= 300:
            raise ConfigError(f"gatehouse.id_patterns[{i}]: expected a regex string (2-300 chars)")
        try:
            out.append(re.compile(p))
        except re.error as e:
            raise ConfigError(f"gatehouse.id_patterns[{i}]: invalid regex ({e.msg})") from None
    return tuple(out)


def parse(raw: Any) -> Config:
    """Build a Config from the plugin's settings mapping (None or {} = all defaults)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, Mapping):
        raise ConfigError("settings: expected a mapping")
    unknown = sorted(set(map(str, raw)) - set(SECTIONS))
    if unknown:
        raise ConfigError(f"settings: unknown key(s) {', '.join(unknown)}")

    mode = _choice("mode", _get(raw, "mode", str, "enforce", "settings"), ("enforce", "report"))

    t = _section(raw, "threshold", set(Threshold.__dataclass_fields__))
    d = Threshold()
    threshold = Threshold(
        scan_attachments=_get(t, "scan_attachments", bool, d.scan_attachments, "threshold"),
        scan_tool_results=_get(t, "scan_tool_results", bool, d.scan_tool_results, "threshold"),
        scan_reply_context=_get(t, "scan_reply_context", bool, d.scan_reply_context, "threshold"),
        scan_local_turns=_get(t, "scan_local_turns", bool, d.scan_local_turns, "threshold"),
        window_messages=_range("threshold.window_messages",
                               _get(t, "window_messages", int, d.window_messages, "threshold"), 1, 50),
        window_minutes=_range("threshold.window_minutes",
                              _get(t, "window_minutes", int, d.window_minutes, "threshold"), 1, 10080),
        max_scan_chars=_range("threshold.max_scan_chars",
                              _get(t, "max_scan_chars", int, d.max_scan_chars, "threshold"), 1000, 2_000_000),
        max_attachment_bytes=_range("threshold.max_attachment_bytes",
                                    _get(t, "max_attachment_bytes", int, d.max_attachment_bytes, "threshold"),
                                    1000, 50_000_000),
        max_attachments=_range("threshold.max_attachments",
                               _get(t, "max_attachments", int, d.max_attachments, "threshold"), 1, 50),
        unscanned_media=_choice("threshold.unscanned_media",
                                _get(t, "unscanned_media", str, d.unscanned_media, "threshold"),
                                ("hold", "skip", "owners", "allow")),
        weak_action=_choice("threshold.weak_action", _get(t, "weak_action", str, d.weak_action, "threshold"),
                            ("pass", "hold")),
        weak_action_content=_choice("threshold.weak_action_content",
                                    _get(t, "weak_action_content", str, d.weak_action_content, "threshold"),
                                    ("pass", "hold")),
        fence_tool_results=_get(t, "fence_tool_results", bool, d.fence_tool_results, "threshold"),
        scan_timeout_s=_range("threshold.scan_timeout_s",
                              _get(t, "scan_timeout_s", float, d.scan_timeout_s, "threshold"), 0.5, 120.0),
    )

    h = _section(raw, "holds", set(Holds.__dataclass_fields__))
    dh = Holds()
    holds = Holds(
        timeout_min=_range("holds.timeout_min", _get(h, "timeout_min", int, dh.timeout_min, "holds"), 1, 10080),
        default=_choice("holds.default", _get(h, "default", str, dh.default, "holds"), ("ignore",)),
        max_pending=_range("holds.max_pending", _get(h, "max_pending", int, dh.max_pending, "holds"), 1, 1000),
        notices_per_sender_10min=_range("holds.notices_per_sender_10min",
                                        _get(h, "notices_per_sender_10min", int, dh.notices_per_sender_10min,
                                             "holds"), 0, 100),
        notice_excerpt_chars=_range("holds.notice_excerpt_chars",
                                    _get(h, "notice_excerpt_chars", int, dh.notice_excerpt_chars, "holds"), 0, 1000),
        tell_sender=_get(h, "tell_sender", bool, dh.tell_sender, "holds"),
        owner_notices_10min=_range("holds.owner_notices_10min",
                                   _get(h, "owner_notices_10min", int, dh.owner_notices_10min, "holds"), 1, 1000),
    )

    s = _section(raw, "second_check", set(SecondCheck.__dataclass_fields__))
    ds = SecondCheck()
    chans = _get(s, "channels", list, list(ds.channels), "second_check")
    for c in chans:
        _choice("second_check.channels", c if isinstance(c, str) else repr(c),
                ("chat", "attachment", "reply_context", "tool_result"))
    second = SecondCheck(
        endpoint=_endpoint(_get(s, "endpoint", str, ds.endpoint, "second_check")),
        model=_get(s, "model", str, ds.model, "second_check")[:200],
        timeout_s=_range("second_check.timeout_s", _get(s, "timeout_s", float, ds.timeout_s, "second_check"),
                         0.5, 600.0),
        max_chars=_range("second_check.max_chars", _get(s, "max_chars", int, ds.max_chars, "second_check"),
                         500, 100_000),
        scope=_choice("second_check.scope", _get(s, "scope", str, ds.scope, "second_check"), ("all", "weak")),
        channels=tuple(chans),
        on_error=_choice("second_check.on_error", _get(s, "on_error", str, ds.on_error, "second_check"),
                         ("hold",)),
        allow_remote=_get(s, "allow_remote", bool, ds.allow_remote, "second_check"),
        owner_chat=_choice("second_check.owner_chat", _get(s, "owner_chat", str, ds.owner_chat, "second_check"),
                           ("off", "weak", "all")),
        json_mode=_choice("second_check.json_mode", _get(s, "json_mode", str, ds.json_mode, "second_check"),
                          ("schema", "json_object", "none")),
        slot=_range("second_check.slot", _get(s, "slot", int, ds.slot, "second_check"), -1, 64),
        api_key_env=_env_name(_get(s, "api_key_env", str, ds.api_key_env, "second_check")),
        max_chunks=_range("second_check.max_chunks", _get(s, "max_chunks", int, ds.max_chunks, "second_check"), 1, 16),
        chunk_tokens=_range("second_check.chunk_tokens", _get(s, "chunk_tokens", int, ds.chunk_tokens, "second_check"),
                            200, 8000),
        oversize=_choice("second_check.oversize", _get(s, "oversize", str, ds.oversize, "second_check"),
                         ("taint", "hold")),
        prompt_variant_dir=_short_path("second_check.prompt_variant_dir",
                                       _get(s, "prompt_variant_dir", str, ds.prompt_variant_dir, "second_check")),
        recheck_unavailable=_get(s, "recheck_unavailable", bool, ds.recheck_unavailable, "second_check"),
        recheck_attempts=_range("second_check.recheck_attempts",
                                _get(s, "recheck_attempts", int, ds.recheck_attempts, "second_check"), 1, 3),
        recheck_window_min=_range("second_check.recheck_window_min",
                                  _get(s, "recheck_window_min", int, ds.recheck_window_min, "second_check"), 1, 10),
        probes=_get(s, "probes", bool, ds.probes, "second_check"),
        probe_every_min=_range("second_check.probe_every_min",
                               _get(s, "probe_every_min", int, ds.probe_every_min, "second_check"), 5, 1440),
        pause_flag=_short_path("second_check.pause_flag", _get(s, "pause_flag", str, ds.pause_flag, "second_check")),
        tool_timeout_s=_range("second_check.tool_timeout_s",
                              _get(s, "tool_timeout_s", float, ds.tool_timeout_s, "second_check"), 0.5, 600.0),
        score_mode=_get(s, "score_mode", bool, ds.score_mode, "second_check"),
        tamper_retry=_get(s, "tamper_retry", bool, ds.tamper_retry, "second_check"),
        calls_per_sender_10min=_range("second_check.calls_per_sender_10min",
                                      _get(s, "calls_per_sender_10min", int, ds.calls_per_sender_10min,
                                           "second_check"), 1, 10_000),
        calls_all_10min=_range("second_check.calls_all_10min",
                               _get(s, "calls_all_10min", int, ds.calls_all_10min, "second_check"), 1, 100_000),
    )
    if second.endpoint and not second.allow_remote and not _LOOPBACK_RX.match(second.endpoint):
        raise ConfigError("second_check.endpoint: not a loopback address; message text would leave this machine "
                          "(set second_check.allow_remote: true to accept that)")

    g = _section(raw, "gatehouse", set(Gatehouse.__dataclass_fields__))
    dg = Gatehouse()
    gate = Gatehouse(
        strip_invisible=_get(g, "strip_invisible", bool, dg.strip_invisible, "gatehouse"),
        withhold_secrets=_get(g, "withhold_secrets", bool, dg.withhold_secrets, "gatehouse"),
        block_media_directives=_get(g, "block_media_directives", bool, dg.block_media_directives, "gatehouse"),
        block_markdown_images=_get(g, "block_markdown_images", bool, dg.block_markdown_images, "gatehouse"),
        block_query_links=_get(g, "block_query_links", bool, dg.block_query_links, "gatehouse"),
        id_patterns=_patterns(g.get("id_patterns")),
        safe_link_hosts=_hosts(g.get("safe_link_hosts")),
    )

    o = _section(raw, "ocr", set(Ocr.__dataclass_fields__))
    do = Ocr()
    enabled = o.get("enabled", do.enabled)
    if enabled != "auto" and not isinstance(enabled, bool):
        raise ConfigError("ocr.enabled: expected auto, true or false")
    langs = _get(o, "languages", list, list(do.languages), "ocr")
    if not 1 <= len(langs) <= 8 or not all(isinstance(x, str) and re.match(r"^[A-Za-z_]{2,24}$", x) for x in langs):
        raise ConfigError("ocr.languages: expected 1-8 engine language codes such as eng or chi_sim")
    engine_path = _short_path("ocr.engine_path", _get(o, "engine_path", str, do.engine_path, "ocr"))
    if engine_path and not (engine_path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", engine_path)):
        raise ConfigError("ocr.engine_path: expected a full path to the engine program")
    ocr = Ocr(
        enabled=enabled,
        engine_path=engine_path,
        tessdata_dir=_short_path("ocr.tessdata_dir", _get(o, "tessdata_dir", str, do.tessdata_dir, "ocr")),
        languages=tuple(langs),
        timeout_s=_range("ocr.timeout_s", _get(o, "timeout_s", float, do.timeout_s, "ocr"), 1.0, 120.0),
        memory_mb=_range("ocr.memory_mb", _get(o, "memory_mb", int, do.memory_mb, "ocr"), 128, 8192),
        max_bytes=_range("ocr.max_bytes", _get(o, "max_bytes", int, do.max_bytes, "ocr"), 10_000, 50_000_000),
        max_pixels=_range("ocr.max_pixels", _get(o, "max_pixels", int, do.max_pixels, "ocr"), 10_000, 200_000_000),
        max_pictures=_range("ocr.max_pictures", _get(o, "max_pictures", int, do.max_pictures, "ocr"), 1, 10),
        max_text_chars=_range("ocr.max_text_chars", _get(o, "max_text_chars", int, do.max_text_chars, "ocr"),
                              500, 200_000),
        read_metadata=_get(o, "read_metadata", bool, do.read_metadata, "ocr"),
        locale=_choice("ocr.locale", _get(o, "locale", str, do.locale, "ocr"), ("en", "zh", "both")),
        alert_owner=_get(o, "alert_owner", bool, do.alert_owner, "ocr"),
        alerts_per_10min=_range("ocr.alerts_per_10min", _get(o, "alerts_per_10min", int, do.alerts_per_10min, "ocr"),
                                0, 100),
    )

    lg = _section(raw, "log", {"raw_text", "path"})
    hb = _section(raw, "heartbeat", {"dir", "interval_s"})
    return Config(
        mode=mode,
        owners=_owners(raw.get("owners")),
        owner_chats=_owner_chats(raw.get("owner_chats")),
        threshold=threshold,
        holds=holds,
        second_check=second,
        gatehouse=gate,
        ocr=ocr,
        log_raw_text=_get(lg, "raw_text", bool, False, "log"),
        log_path=_get(lg, "path", str, "", "log"),
        heartbeat_dir=_get(hb, "dir", str, "", "heartbeat"),
        heartbeat_interval_s=_range("heartbeat.interval_s", _get(hb, "interval_s", int, 15, "heartbeat"), 2, 3600),
        require_no_hook_timeout=_get(raw, "require_no_hook_timeout", bool, True, "settings"),
    )
