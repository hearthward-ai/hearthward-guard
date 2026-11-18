"""guard_adapter.py - the runner's plug-in point for the guard under test.

run.py only talks to an Adapter. Two exist:

* HearthwardAdapter: the real guard core (job 5, `guard/hearthward_guard`), loaded from a path.
  It calls the same functions the plugin's hooks call (threshold.scan.scan_many / scan_text,
  threshold.window.Window, threshold.second_check.check, gatehouse.output.filter_reply) with the
  guard's default config, and mirrors the hook logic (window only when not already held,
  second check only raises, weak_action for chat and weak_action_content for attachments and
  tool results; --weak-action overrides both).
* StubAdapter: a few regexes, for the runner's own tests and plumbing checks. Its results are
  labelled "stub" and can never be recorded as an honest run.

Layers not built yet report `available = False` and the runner marks the affected cases
unscored instead of counting them as misses:
  scam   (scam_level on chat text, scam_text) -> plug in: Adapter.scam(text) -> "none"|"warn"|"high"
  ocr    (image_ocr channel)            -> Adapter.ocr(image bytes) -> [texts] (picture text, then text
         stored in the file) and Adapter.picture_scam(text) -> "none"|"warn"|"high". Built (guard 0.9.x):
         HearthwardAdapter(..., ocr=True) with a real engine; the picture's scam verdict is part of it.
  knock  (tool-call gate, category 7)   -> plug in: Adapter.knock(case) -> "deny"|"allow"
When job 5+ adds them, implement the method and add the name to `available`.
"""
from __future__ import annotations

import hashlib
import importlib
import re
import sys
from pathlib import Path

HOLD, WEAK, PASS = "hold", "weak", "pass"


class CheckUnavailable(Exception):
    """The model-backed second check could not answer (timeout, connection error, HTTP 5xx)."""


class PictureUnreadable(Exception):
    """The guard could not read a picture (engine failure, time limit, too large): it holds the message."""


class CheckTampered(Exception):
    """The checker answered outside the agreed shape (wrong code, bad JSON ...): the guard holds."""


class Adapter:
    name = "abstract"
    version = "0"
    fingerprint = ""
    available: frozenset = frozenset()
    weak_action = "pass"
    weak_action_content = "pass"
    second_check_channels = ("chat", "attachment", "reply_context")

    def weak_holds(self, channel: str) -> bool:
        """Mirror of the guard hooks: weak_action for direct chat, weak_action_content for attachments,
        quoted text and tool results."""
        return (self.weak_action if channel == "chat" else self.weak_action_content) == "hold"

    def scan(self, parts: list[tuple[str, str]]) -> dict:
        """-> {"level": hold|weak|pass, "score": float, "families": [names], "signals": [names]}"""
        raise NotImplementedError

    def new_window(self):
        return None

    def window_check(self, window, key, text: str) -> dict | None:
        return None

    def second_check(self, text: str, endpoint: str, model: str, timeout: float, variant: str = "content",
                     score_mode: bool = False) -> dict:
        """-> {"verdict": none|suspicious|inject, "kinds", "partial", "score", "prompt_id", "calls"}."""
        raise CheckUnavailable("second check not available")

    def gatehouse(self, text: str) -> tuple[str, list[str]]:
        """-> ("withhold"|"strip"|"pass", notes)"""
        raise NotImplementedError

    def scam(self, text: str) -> str:
        raise NotImplementedError

    def ocr(self, image: bytes) -> list[str]:
        """-> the picture's texts as the guard reads them; raises PictureUnreadable."""
        raise NotImplementedError

    def picture_scam(self, text: str) -> str:
        """-> "none"|"warn"|"high" for the joined picture texts (the shield's verdict)."""
        raise NotImplementedError

    def knock(self, case: dict) -> str:
        raise NotImplementedError


def tree_fingerprint(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".yaml", ".yml", ".json", ".txt"):
            h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()[:16]


class HearthwardAdapter(Adapter):
    name = "hearthward-guard"

    def __init__(self, guard_root: Path, weak_action: str | None = None, ocr: bool = False, ocr_engine: str = ""):
        pkg = Path(guard_root) / "hearthward_guard"
        if not (pkg / "__init__.py").is_file():
            raise ImportError(f"no hearthward_guard package under {guard_root}")
        if str(guard_root) not in sys.path:
            sys.path.insert(0, str(guard_root))
        self.scan_mod = importlib.import_module("hearthward_guard.threshold.scan")
        self.window_mod = importlib.import_module("hearthward_guard.threshold.window")
        self.output_mod = importlib.import_module("hearthward_guard.gatehouse.output")
        self.sc_mod = importlib.import_module("hearthward_guard.threshold.second_check")
        config = importlib.import_module("hearthward_guard.common.config")
        cfg = config.parse({})
        self.threshold_cfg, self.gatehouse_cfg, self.sc_cfg = cfg.threshold, cfg.gatehouse, cfg.second_check
        self.weak_action = weak_action or self.threshold_cfg.weak_action
        self.weak_action_content = weak_action or getattr(self.threshold_cfg, "weak_action_content", "pass")
        self.second_check_channels = tuple(self.sc_cfg.channels)
        m = re.search(r"^version:\s*['\"]?([^'\"\s]+)", (pkg / "plugin.yaml").read_text(encoding="utf-8"), re.M) \
            if (pkg / "plugin.yaml").is_file() else None
        self.version = m.group(1) if m else "unknown"
        self.fingerprint = tree_fingerprint(pkg)
        self.available = frozenset({"threshold", "window", "gatehouse", "second_check"})
        self.ocr_engine = ""
        if ocr:     # opt-in, so rules-only runs stay comparable (image cases are skipped without it)
            self._setup_ocr(config, cfg, ocr_engine)

    def _setup_ocr(self, config, cfg, engine_path: str) -> None:
        """The guard's own picture reader (threshold.ocr.Engine, default settings) and scam rules."""
        self.ocr_mod = importlib.import_module("hearthward_guard.threshold.ocr")
        self.scam_mod = importlib.import_module("hearthward_guard.threshold.scam")
        self.ocr_cfg = config.parse({"ocr": {"engine_path": str(engine_path)}}).ocr if engine_path else cfg.ocr
        eng = self.ocr_mod.Engine(self.ocr_cfg)
        if not eng.available:
            raise ImportError(f"--ocr: {eng.missing}")
        if not eng.languages_ok():
            raise ImportError("--ocr: the engine is missing the configured language data")
        self.engine = eng
        self.ocr_engine = f"{Path(eng.path).name} ({eng.version() or 'version unknown'})"
        self.available = self.available | {"ocr"}

    @staticmethod
    def _out(v) -> dict:
        return {"level": v.level, "score": v.score, "families": sorted(v.families), "signals": list(v.signals)}

    def scan(self, parts):
        if len(parts) == 1 and parts[0][0] == "tool_result":
            return self._out(self.scan_mod.scan_text(parts[0][1], "tool_result", self.threshold_cfg.max_scan_chars))
        return self._out(self.scan_mod.scan_many(parts, self.threshold_cfg.max_scan_chars))

    def new_window(self):
        return self.window_mod.Window(self.threshold_cfg.window_messages, self.threshold_cfg.window_minutes)

    def window_check(self, window, key, text):
        v = window.check(key, text)
        return None if v is None else self._out(v)

    def second_check(self, text, endpoint, model, timeout, variant="content", score_mode=False):
        sc = self.sc_cfg
        if not hasattr(self.sc_mod, "Result"):           # guard < 0.8.0: QUOTE/ASKS checker
            try:
                found = bool(self.sc_mod.check(text, endpoint, model, timeout, sc.max_chars))
            except self.sc_mod.CheckError as e:
                raise CheckUnavailable(str(e)) from None
            return {"verdict": "inject" if found else "none", "kinds": [], "partial": False, "score": None,
                    "prompt_id": "legacy"}
        score = (lambda chunk: self.scan_mod.scan_text(chunk, "attachment", self.threshold_cfg.max_scan_chars).score)
        try:
            r = self.sc_mod.check(text, endpoint, model, timeout, sc.max_chars, variant=variant,
                                  max_chunks=sc.max_chunks, chunk_tokens=sc.chunk_tokens, json_mode=sc.json_mode,
                                  score_mode=score_mode, scorer=score)
        except self.sc_mod.CheckTampered as e:
            raise CheckTampered(str(e)) from None
        except self.sc_mod.CheckError as e:
            raise CheckUnavailable(str(e)) from None
        return {"verdict": r.verdict, "kinds": list(r.kinds), "partial": r.partial, "score": r.score,
                "prompt_id": r.prompt_id, "calls": r.chunks}

    def ocr(self, image):
        """Mirror of Guard._read_one_picture + _read_pictures: size and header checks, text stored in
        the file, then the engine; -> non-empty texts (picture text first)."""
        oc, om = self.ocr_cfg, self.ocr_mod
        if len(image) > oc.max_bytes:
            raise PictureUnreadable("the picture is too large to check")
        try:
            fmt, _w, _h = om.check_size(image, oc)
            meta = om.metadata_texts(image, fmt) if oc.read_metadata else []
            raw = self.engine.read(image)
        except om.OcrError as e:
            raise PictureUnreadable(str(e.args[0]) if e.args else "unreadable") from None
        return [t for t in [om.tidy(raw, oc.max_text_chars)] + list(meta) if t.strip()]

    def picture_scam(self, text):
        return {"high": "high", "medium": "warn"}.get(self.scam_mod.assess(text).level, "none")

    def gatehouse(self, text):
        new, notes = self.output_mod.filter_reply(text, self.gatehouse_cfg)
        if new is None:
            return "pass", notes
        return ("withhold" if new == self.output_mod.WITHHELD else "strip"), notes


class StubAdapter(Adapter):
    """Tiny regex stand-in. Only for tests and plumbing; never an honest result."""
    name = "stub"
    version = "stub"
    fingerprint = "stub"
    available = frozenset({"threshold", "window", "gatehouse"})
    _HOLD = re.compile(r"ignore (all |your )?(previous|prior|above)|disregard .{0,20}instructions|"
                       r"<\s*/?\s*(system|information)\s*>|忽略.{0,6}指令", re.I)
    _WEAK = re.compile(r"\b(password|system prompt|secret)\b", re.I)
    _INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿]")
    _SECRET = re.compile(r"\b(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,})\b")

    def scan(self, parts):
        text = "\n".join(t for _c, t in parts)
        if self._HOLD.search(text):
            return {"level": HOLD, "score": 1.0, "families": ["stub-override"], "signals": []}
        if self._WEAK.search(text):
            return {"level": WEAK, "score": 0.5, "families": ["stub-weak"], "signals": []}
        return {"level": PASS, "score": 0.0, "families": [], "signals": []}

    def new_window(self):
        return {}

    def window_check(self, window, key, text):
        joined = window.get(key, "") + " " + text
        window[key] = joined
        if self._HOLD.search(joined):
            return {"level": HOLD, "score": 1.0, "families": ["stub-override"], "signals": []}
        return None

    def gatehouse(self, text):
        if self._SECRET.search(text):
            return "withhold", ["secret"]
        if self._INVISIBLE.search(text):
            return "strip", ["invisible"]
        return "pass", []


def load(kind: str, guard_root: Path, weak_action: str | None = None, ocr: bool = False,
         ocr_engine: str = "") -> Adapter:
    if kind == "stub":
        if ocr:
            raise ValueError("--ocr needs the hearthward guard")
        return StubAdapter()
    if kind == "hearthward":
        return HearthwardAdapter(guard_root, weak_action, ocr=ocr, ocr_engine=ocr_engine)
    raise ValueError(f"unknown guard kind: {kind}")
