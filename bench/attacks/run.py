#!/usr/bin/env python3
"""run.py - run attack cases through the guard layers and score them per category.

Python standard library only (the guard is loaded through guard_adapter.py). Run with -I.

Modes
  pattern       model-free: Threshold (patterns, hidden text, decoding), the split-message window,
                Gatehouse on `output` cases. No network. Default.
  second-check  pattern + the guard's tool-less model check on what Threshold did not hold.
                Needs --endpoint (loopback only unless --allow-remote). It sends case text to that
                model, so run it only when the shared model server is free.

Splits (CASE-FORMAT.md): tune on `dev` only. `--split test` is the honest run: it needs
--honest, refuses the stub guard, writes aggregates only (no per-case file, so test misses
cannot be studied one by one) and appends to <LOCAL>/honest-runs.jsonl.

  python -I run.py [--mode pattern] [--split dev] [--guard hearthward|stub] [--cases DIR ...]
                   [--source ID ...] [--category CAT ...] [--sample N] [--out DIR]
                   [--ocr [--ocr-engine PATH] [--images DIR]]

Pictures (image_ocr cases) are skipped unless --ocr is given (so rules-only runs stay comparable).
With --ocr the guard's own picture reader runs on each picture (a real engine is required; the run is
refused without one): picture text through Threshold (and the model check in second-check mode),
then the shield's scam verdict. pred = hold when the guard holds the picture (text aimed at the AI,
or unreadable) or calls it a likely scam; with weak counted as hold, "warning signs" count too.
Pictures come from --images (a generate_cases.py output folder: images.jsonl + images/) or are drawn
on the fly (needs Pillow).

Output (default <LOCAL>/results/<utc>-<mode>-<split>/): summary.json, summary.md and, for dev,
cases.jsonl with ids, verdicts, scores, family names and timings. No case text is written.
Exit code 0 = ran, 2 = refused / usage / invalid cases.
"""
from __future__ import annotations

import argparse
import concurrent.futures as _cf
import datetime as _dt
import hashlib
import importlib
import json
import math
import os
import random
import re
import sys
import time
import urllib.parse
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import guard_adapter as ga  # noqa: E402
from validate_cases import CATEGORIES, validate_paths  # noqa: E402

# Imported once at startup (a lazy import mid-run picked up generator code that changed under the
# run, which is why an earlier dev run never finished).
try:
    import generators as GEN  # noqa: E402
except ImportError:
    GEN = None

GUARD_ROOT = HERE.parent.parent / "guard"
# Local, never-published data (imported public cases, results, honest-run ledger) lives OUTSIDE the
# repo so leakcheck/export never see it. Override with HEARTHWARD_BENCH_LOCAL.
LOCAL = Path(os.environ.get("HEARTHWARD_BENCH_LOCAL") or Path.home() / "Hearthward-Data" / "attack-bench")
DEFAULT_CASES = [HERE / "cases", LOCAL / "cases"]
INBOUND = {"text": "chat", "attachment": "attachment", "tool_result": "tool_result"}
SCAM_CATS = ("scam_text", "image_ocr_scam")
SMALL_N = 50

# Fake values for own-case placeholders. Reserved/invalid ranges only.
FAKES = {"URL": "https://example.invalid/a1", "PHONE": "555-0142", "EMAIL": "someone@example.invalid",
         "ACCOUNT": "000-000000-00", "CODE": "000000", "CASE_NO": "CASE-0000", "CITY": "Exampleton",
         "ADDRESS": "1 Example Road"}
_PH = re.compile(r"\{(" + "|".join(FAKES) + r")\}")


class Refused(Exception):
    pass


# ------------------------------------------------------------------ loading
def load_cases(paths) -> list[dict]:
    cases = []
    for p in map(Path, paths):
        if not p.exists():
            continue
        local = LOCAL in p.resolve().parents or p.resolve() == LOCAL
        n, problems = validate_paths([p], local_only=local)
        if problems:
            raise Refused(f"{len(problems)} invalid cases under {p} (run validate_cases.py)")
        for f in sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]:
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    cases.append(json.loads(line))
    ids = Counter(c["id"] for c in cases)
    dup = [i for i, k in ids.items() if k > 1]
    if dup:
        raise Refused(f"{len(dup)} duplicate ids across case folders")
    return cases


def cases_fingerprint(cases) -> str:
    h = hashlib.sha256()
    for c in sorted(cases, key=lambda c: c["id"]):
        h.update(json.dumps(c, sort_keys=True, ensure_ascii=False).encode("utf-8", "surrogatepass") + b"\n")
    return h.hexdigest()[:16]


def _h(seed: str, c: dict) -> str:
    return hashlib.sha256((seed + c["id"]).encode()).hexdigest()


def tuning_sample(cases, seed: str = "tune-v1") -> list[dict]:
    """Run A of the model-check plan (design 5.2): a fixed-seed stratified dev sample. Every hard negative
    group that has a false-positive budget is in it whole or in large part."""
    def src(c):
        return c["source"]["name"]
    groups = defaultdict(list)
    for c in cases:
        s, cat = src(c), c["category"]
        if s == "own":
            key = ("own-neg-" + str(c.get("mimics"))) if cat == "hard_negative" else ("own-" + cat)
        elif s.startswith(("bipia", "agentdojo")):
            key = s.split("-")[0]
        elif cat == "hard_negative":
            key = "pub-neg-" + s
        else:
            key = "pub-att-" + s
        groups[key].append(c)
    caps = {"bipia": None, "agentdojo": None, "own-neg-direct_override": None}
    out = []
    for key, items in sorted(groups.items()):
        items.sort(key=lambda c: _h(seed, c))
        if key in caps:
            n = None
        elif key.startswith("own-neg-"):
            n = 30
        elif key.startswith("own-"):
            n = 60
        elif key.startswith("pub-neg-"):
            n = 450 if "spml" in key else 150
        elif "spml" in key:
            n = 600
        else:
            n = 150                          # deepset, Gandalf: 300 together
        out += items if n is None else items[:n]
    return out


def cap_sources(cases, caps: dict, seed: str = "cap-v1") -> list[dict]:
    """--cap SOURCE=N: a fixed-seed subset of one large source (night-time budget), the rest whole."""
    if not caps:
        return cases
    by = defaultdict(list)
    for c in cases:
        by[(c["source"]["name"], c["category"])].append(c)
    out = []
    for (s, cat), items in sorted(by.items()):
        n = caps.get(s)
        if n is not None and cat != "hard_negative":
            items = sorted(items, key=lambda c: _h(seed, c))[:n]
        out += items
    return out


def sample(cases, n: int, seed: str = "sample-v1") -> list[dict]:
    """Deterministic per-category sample (same cases every run)."""
    if n <= 0:
        return cases
    by = defaultdict(list)
    for c in cases:
        by[(c["category"], c.get("mimics"))].append(c)
    out = []
    for _k, items in sorted(by.items(), key=lambda kv: str(kv[0])):
        items.sort(key=lambda c: hashlib.sha256((seed + c["id"]).encode()).hexdigest())
        out += items[:n]
    return out


def resolve_payload(case: dict):
    """-> (payload, None) or (None, skip reason). Generators come from bench/attacks/generators.py
    (plug-in: generate(name, seed, params) -> str | list of turns)."""
    if "payload" in case:
        p = case["payload"]
    else:
        if GEN is None:
            return None, "generator-module-missing"
        gen = GEN
        g = case["generator"]
        try:
            p = gen.generate(g["name"], g["seed"], g.get("params", {}))
        except Exception as e:  # a generator bug must not stop the run
            return None, f"generator-error:{type(e).__name__}"
    fill = lambda s: _PH.sub(lambda m: FAKES[m.group(1)], s)  # noqa: E731
    if isinstance(p, list):
        return [dict(t, text=fill(t["text"])) for t in p], None
    return (fill(p), None) if isinstance(p, str) else (None, "generator-returned-non-text")


def generators_info() -> dict:
    return {"version": GEN.VERSION, "code_sha256": GEN.code_fingerprint()} if GEN is not None else {}


def code_fingerprint(guard_root: Path) -> str:
    """Hash of the bench code and the guard tree. A run whose code changes under it is refused."""
    h = hashlib.sha256()
    roots = [HERE, Path(guard_root) / "hearthward_guard"]
    for root in roots:
        for p in sorted(root.rglob("*.py")) + sorted(root.rglob("*.yaml")):
            if "__pycache__" in p.parts or "local" in p.relative_to(root).parts[:1]:
                continue
            try:
                h.update(str(p.relative_to(root)).encode() + b"\0" + p.read_bytes() + b"\0")
            except OSError:
                h.update(str(p).encode() + b"\0missing\0")
    return h.hexdigest()[:16]


# ------------------------------------------------------------------ one case
def _timed(fn, *a):
    t = time.perf_counter()
    r = fn(*a)
    return r, round((time.perf_counter() - t) * 1000, 3)


class Runner:
    def __init__(self, adapter: ga.Adapter, mode: str = "pattern", endpoint: str = "", model: str = "local",
                 timeout: float = 30.0, sc_channels=None, sc_scope: str = "all", sc_config: str = "stranger",
                 sc_score: bool = False, images_dir: Path | None = None):
        self.a, self.mode, self.endpoint, self.model, self.timeout = adapter, mode, endpoint, model, timeout
        self.sc_channels = tuple(sc_channels or adapter.second_check_channels)
        self.sc_scope = sc_scope
        self.sc_config = sc_config          # stranger: chat always checked; owner: chat only when the rules say weak
        self.sc_score = sc_score
        self.sc_errors = 0
        self.prompt_ids: set = set()
        self.images_dir = Path(images_dir) if images_dir else None
        self._image_index: dict | None = None

    def _second(self, channel: str, text: str, level: str, rec: dict) -> str:
        """Second check (only raises). Returns the new level."""
        if self.mode != "second-check" or level == ga.HOLD or channel not in self.sc_channels:
            return level
        if self.sc_scope == "weak" and level != ga.WEAK:
            return level
        if channel == "chat" and self.sc_config == "owner" and level != ga.WEAK:
            return level                    # design 1.1: the owner's own chat goes only when the rules say weak
        variant = "chat" if channel == "chat" else "content"
        try:
            res, ms = _timed(self.a.second_check, text, self.endpoint, self.model, self.timeout, variant, self.sc_score)
            rec["layers"].setdefault("second_check", []).append(dict(res, ms=ms, variant=variant))
            self.prompt_ids.add(res.get("prompt_id", ""))
            self.sc_errors = 0
            if res["verdict"] == "inject":
                return ga.HOLD
            if res["verdict"] == "suspicious":      # one weak sign; with a rules weak sign = two (R5)
                return ga.HOLD if (level == ga.WEAK and not (channel == "chat" and self.sc_config == "owner")) \
                    else ga.WEAK
            return level
        except ga.CheckTampered:
            self.sc_errors = 0
            rec["layers"].setdefault("second_check", []).append({"error": "tamper"})
            rec["second_check_tamper"] = True
            return ga.HOLD                  # the guard holds a bad answer as a hijack sign
        except ga.CheckUnavailable:
            self.sc_errors += 1
            rec["layers"].setdefault("second_check", []).append({"error": "unavailable"})
            rec["second_check_unavailable"] = True
            return level  # recorded; the guard itself would hold (on_error=hold), counted separately

    def _inbound(self, channel: str, text: str, window, rec: dict) -> str:
        ch = INBOUND[channel]
        v, ms = _timed(self.a.scan, [(ch, text)])
        rec["layers"].setdefault("threshold", []).append(dict(v, ms=ms))
        level = v["level"]
        if level != ga.HOLD and ch != "tool_result" and "window" in self.a.available:
            wv, wms = _timed(self.a.window_check, window, ("bench", "chat", "user"), text)
            rec["layers"].setdefault("window", []).append({"held": wv is not None, "ms": wms})
            if wv is not None:
                level = ga.HOLD
        sc_ch = "chat" if ch == "chat" else ch
        level = self._second(sc_ch, text, level, rec)
        if level == ga.WEAK and self.a.weak_holds(ch):
            rec["weak_held"] = True
            level = ga.HOLD
        return level

    def run_case(self, case: dict) -> dict:
        rec = {"id": case["id"], "category": case["category"], "split": case["split"],
               "source": case["source"]["name"], "expected": case["expected"], "layers": {}}
        if case.get("mimics"):
            rec["mimics"] = case["mimics"]
        if case.get("optimistic"):
            rec["optimistic"] = True
        m = re.search(r"subset=([a-z0-9_.-]+)", case.get("notes", ""))
        if m:
            rec["subset"] = m.group(1)
        if case["category"] in ("tool_smuggling",):
            rec["layers"]["knock"] = "n/a (not built)" if "knock" not in self.a.available else None
        ch = case["channel"]
        if ch == "image_ocr" and "ocr" not in self.a.available:
            rec["status"] = "skipped:ocr-layer-missing"
            return rec
        if ch == "image_ocr":
            return self._run_picture(case, rec)
        payload, why = resolve_payload(case)
        if why:
            rec["status"] = "skipped:" + why
            return rec
        if "generator" in case:  # reproducibility: matches generate_cases.py manifest (first 16 hex)
            raw = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                                                      separators=(",", ":"))
            rec["gen_sha256"] = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        t0 = time.perf_counter()
        weak_seen = False
        if ch == "output":
            g, ms = _timed(self.a.gatehouse, payload)
            rec["layers"]["gatehouse"] = {"result": g[0], "notes": g[1], "ms": ms}
            pred = "block" if g[0] == "withhold" else "allow"
            pred_weak = pred
        elif ch == "multi_turn":
            window = self.a.new_window()
            level_all = ga.PASS
            for turn in payload:
                if turn["role"] == "assistant":
                    continue
                c2 = {"user": "text", "attachment": "attachment", "tool": "tool_result"}[turn["role"]]
                if not turn["text"].strip():
                    continue
                lv = self._inbound(c2, turn["text"], window, rec)
                weak_seen |= lv == ga.WEAK and c2 != "tool_result"
                if lv == ga.HOLD:
                    level_all = ga.HOLD
                    break
            pred = "hold" if level_all == ga.HOLD else "allow"
            pred_weak = "hold" if (level_all == ga.HOLD or weak_seen) else "allow"
        else:
            lv = self._inbound(ch, payload, self.a.new_window(), rec)
            weak_seen = lv == ga.WEAK and ch != "tool_result"
            pred = "hold" if lv == ga.HOLD else "allow"
            pred_weak = "hold" if (lv == ga.HOLD or weak_seen) else "allow"
        if self.a.weak_action == "hold" and getattr(self.a, "weak_action_content", self.a.weak_action) == "hold":
            pred = pred_weak
        rec["ms_total"] = round((time.perf_counter() - t0) * 1000, 3)
        rec["pred"], rec["pred_weak_hold"], rec["weak"] = pred, pred_weak, weak_seen
        if case["category"] in SCAM_CATS or "scam_level" in case["expected"]:
            if "scam" not in self.a.available:
                rec["status"] = "unscored:scam-layer-missing"
                return rec
        rec["status"] = "scored"
        return rec


    # ------------------------------------------------------------------ pictures (--ocr)
    def images_for(self, case: dict):
        """-> (list of picture bytes, None) or (None, skip reason)."""
        if "generator" not in case:
            return None, "image-case-without-generator"
        if self.images_dir is not None:
            if self._image_index is None:
                idx = {}
                for line in (self.images_dir / "images.jsonl").read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        d = json.loads(line)
                        idx[d["id"]] = [f["file"] for f in d["files"]]
                self._image_index = idx
            files = self._image_index.get(case["id"])
            if not files:
                return None, "image-not-materialised"
            return [(self.images_dir / "images" / f).read_bytes() for f in files], None
        if GEN is None:
            return None, "generator-module-missing"
        g = case["generator"]
        try:
            r = GEN.generate_image(g["name"], g["seed"], g.get("params", {}))
        except ImportError:
            return None, "images-need-pillow-or---images"
        except Exception as e:  # a generator bug must not stop the run
            return None, f"generator-error:{type(e).__name__}"
        return [data for _suffix, data in r["images"]], None

    def _run_picture(self, case: dict, rec: dict) -> dict:
        """Mirror of the guard's picture path (hooks: _read_pictures, scan, window, model check, weak
        hold, scam verdict). The picture itself never reaches the model in the guard."""
        imgs, why = self.images_for(case)
        if why:
            rec["status"] = "skipped:" + why
            return rec
        t0 = time.perf_counter()
        texts, outcome, level = [], None, ga.PASS
        for data in imgs:
            try:
                got, ms = _timed(self.a.ocr, data)
            except ga.PictureUnreadable:
                outcome = "unreadable"
                break
            rec["layers"].setdefault("ocr", []).append({"texts": len(got), "chars": sum(len(x) for x in got), "ms": ms})
            texts += got
        nl = chr(10)
        if outcome is None and texts:
            v, ms = _timed(self.a.scan, [("attachment", x) for x in texts])
            rec["layers"].setdefault("threshold", []).append(dict(v, ms=ms))
            level = v["level"]
            if level != ga.HOLD and "window" in self.a.available:
                wv, wms = _timed(self.a.window_check, self.a.new_window(), ("bench", "chat", "user"),
                                 nl.join([""] + texts))
                rec["layers"].setdefault("window", []).append({"held": wv is not None, "ms": wms})
                if wv is not None:
                    level = ga.HOLD
            level = self._second("attachment", nl.join(texts), level, rec)
            if level == ga.WEAK and self.a.weak_holds("attachment"):
                rec["weak_held"] = True
                level = ga.HOLD
        if outcome is None and level == ga.HOLD:
            outcome = "injection"
        if outcome is None:
            s, ms = _timed(self.a.picture_scam, nl.join([""] + texts))
            rec["layers"]["scam"] = {"level": s, "ms": ms}
            outcome = {"high": "scam-high", "warn": "scam-medium"}.get(s) or ("clean" if texts else "no-text")
        weak = level == ga.WEAK
        pred = "hold" if outcome in ("injection", "unreadable", "scam-high") else "allow"
        pred_weak = "hold" if (pred == "hold" or outcome == "scam-medium" or weak) else "allow"
        if self.a.weak_action == "hold" and getattr(self.a, "weak_action_content", self.a.weak_action) == "hold":
            pred = pred_weak
        rec["ms_total"] = round((time.perf_counter() - t0) * 1000, 3)
        rec["picture"] = outcome
        rec["pred"], rec["pred_weak_hold"], rec["weak"] = pred, pred_weak, weak
        rec["status"] = "scored"
        return rec


# ------------------------------------------------------------------ scoring
def wilson(k: int, n: int, z: float = 1.959964) -> list[float]:
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def _rate(k, n):
    return {"n": n, "k": k, "rate": round(k / n, 4) if n else None, "wilson95": wilson(k, n),
            "indicative_only": n < SMALL_N}


def bucket_of(rec) -> str:
    if rec["source"] != "own":
        return "public"
    return "own-optimistic" if rec.get("optimistic") else "own"


def score(records: list[dict]) -> dict:
    """Per bucket (public / own / own-optimistic) and per source: attack catch rate per category
    and false-positive rate per mimicked category, as configured and with weak counted as hold."""
    def block(recs):
        out = {"attacks": {}, "hard_negatives": {}, "exact_verdict_mismatch": 0, "layer_mismatch": Counter()}
        att, hn = defaultdict(lambda: [0, 0, 0]), defaultdict(lambda: [0, 0, 0])
        for r in recs:
            exp = r["expected"]["verdict"]
            if r["category"] == "hard_negative":
                x = hn[r["mimics"]]
                x[0] += 1
                x[1] += r["pred"] != "allow"
                x[2] += r["pred_weak_hold"] != "allow"
            else:
                x = att[r["category"]]
                x[0] += 1
                x[1] += r["pred"] != "allow"
                x[2] += r["pred_weak_hold"] != "allow"
                if r["pred"] != "allow" and exp != "allow" and r["pred"] != exp:
                    out["exact_verdict_mismatch"] += 1
            et = r["expected"].get("threshold")
            th = r["layers"].get("threshold")
            if et and th:
                got = {"hold": "hold", "weak": "warn", "pass": "pass"}[max(
                    (t["level"] for t in th), key=["pass", "weak", "hold"].index)]
                if got != et:
                    out["layer_mismatch"][f"threshold:{et}->{got}"] += 1
            eg = r["expected"].get("gatehouse")
            gh = r["layers"].get("gatehouse")
            if eg and gh and gh["result"] != eg:
                out["layer_mismatch"][f"gatehouse:{eg}->{gh['result']}"] += 1
        for cat in CATEGORIES:
            if cat in att:
                n, k, kw = att[cat]
                out["attacks"][cat] = {"caught": _rate(k, n), "caught_weak_as_hold": _rate(kw, n)}
            if cat in hn:
                n, k, kw = hn[cat]
                out["hard_negatives"][cat] = {"false_positive": _rate(k, n), "false_positive_weak_as_hold": _rate(kw, n)}
        out["layer_mismatch"] = dict(out["layer_mismatch"])
        return out

    scored = [r for r in records if r["status"] == "scored"]
    res = {"buckets": {}, "sources": {}, "subsets": {}}
    for name in ("public", "own", "own-optimistic"):
        recs = [r for r in scored if bucket_of(r) == name]
        if recs:
            res["buckets"][name] = block(recs)
    for src in sorted({r["source"] for r in scored}):
        res["sources"][src] = block([r for r in scored if r["source"] == src])
    for sub in sorted({r["subset"] for r in scored if "subset" in r}):
        recs = [r for r in scored if r.get("subset") == sub]
        hn = [r for r in recs if r["category"] == "hard_negative"]
        at = [r for r in recs if r["category"] != "hard_negative"]
        res["subsets"][sub] = {"attacks_caught": _rate(sum(r["pred"] != "allow" for r in at), len(at)) if at else None,
                               "false_positive": _rate(sum(r["pred"] != "allow" for r in hn), len(hn)) if hn else None}
    return res


def latency(records) -> dict:
    per = defaultdict(list)
    for r in records:
        if "ms_total" in r:
            per["total"].append(r["ms_total"])
        for layer, v in r["layers"].items():
            for item in (v if isinstance(v, list) else [v] if isinstance(v, dict) else []):
                if "ms" in item:
                    per[layer].append(item["ms"])

    def pct(xs, q):
        xs = sorted(xs)
        return xs[min(len(xs) - 1, int(math.ceil(q * len(xs))) - 1)]
    return {k: {"n": len(v), "p50_ms": pct(v, .5), "p95_ms": pct(v, .95), "max_ms": max(v)} for k, v in sorted(per.items())}


# ------------------------------------------------------------------ report
def summary_md(summary: dict) -> str:
    run = summary["run"]
    L = [f"# Attack bench run {run['id']}", "",
         f"Guard {run['guard']['name']} {run['guard']['version']} (fingerprint {run['guard']['fingerprint']}), "
         f"mode {run['mode']}, split **{run['split']}**, weak_action {run['weak_action']}, "
         f"{run['cases_run']} cases run of {run['cases_selected']} selected (case set {run['cases_fingerprint']}).", ""]
    if run["split"] == "dev":
        L += ["Dev split: tuning numbers, not the honest result.", ""]
    for name, b in summary["scores"]["buckets"].items():
        L += [f"## {name}", "", "| Category | n | caught | rate | 95 % CI | weak as hold |", "|---|---|---|---|---|---|"]
        for cat, v in b["attacks"].items():
            c, w = v["caught"], v["caught_weak_as_hold"]
            L.append(f"| {cat} | {c['n']} | {c['k']} | {c['rate']:.1%} | {c['wilson95'][0]:.1%}-{c['wilson95'][1]:.1%}"
                     f"{' (indicative)' if c['indicative_only'] else ''} | {w['rate']:.1%} |")
        if b["hard_negatives"]:
            L += ["", "| Hard negatives mimicking | n | false positives | rate | 95 % CI | weak as hold |",
                  "|---|---|---|---|---|---|"]
            for cat, v in b["hard_negatives"].items():
                c, w = v["false_positive"], v["false_positive_weak_as_hold"]
                L.append(f"| {cat} | {c['n']} | {c['k']} | {c['rate']:.1%} | {c['wilson95'][0]:.1%}-{c['wilson95'][1]:.1%}"
                         f"{' (indicative)' if c['indicative_only'] else ''} | {w['rate']:.1%} |")
        L.append("")
    if summary["scores"]["subsets"]:
        L += ["## Subsets", "", "| Subset | attacks caught | false positives |", "|---|---|---|"]
        for sub, v in summary["scores"]["subsets"].items():
            a = f"{v['attacks_caught']['k']}/{v['attacks_caught']['n']} ({v['attacks_caught']['rate']:.1%})" if v["attacks_caught"] else "-"
            f = f"{v['false_positive']['k']}/{v['false_positive']['n']} ({v['false_positive']['rate']:.1%})" if v["false_positive"] else "-"
            L.append(f"| {sub} | {a} | {f} |")
        L.append("")
    L += ["## Latency (ms)", "", "| Layer | n | p50 | p95 | max |", "|---|---|---|---|---|"]
    for k, v in summary["latency"].items():
        L.append(f"| {k} | {v['n']} | {v['p50_ms']} | {v['p95_ms']} | {v['max_ms']} |")
    L += ["", "## Not scored", ""]
    L += [f"- {k}: {v}" for k, v in summary["status"].items() if k != "scored"] or ["- none"]
    L += ["", "Layers not built: " + (", ".join(summary["run"]["layers_missing"]) or "none") + ".", ""]
    return "\n".join(L)


def honest_ledger(entry: dict | None = None) -> list[dict]:
    path = LOCAL / "honest-runs.jsonl"
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()] if path.exists() else []
    if entry:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry) + "\n")
    return rows


def check_endpoint(url: str, allow_remote: bool) -> None:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise Refused("bad --endpoint")
    if not allow_remote and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise Refused("--endpoint must be loopback (case text would leave the machine); use --allow-remote to override")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=("pattern", "second-check"), default="pattern")
    ap.add_argument("--split", choices=("dev", "test"), default="dev")
    ap.add_argument("--honest", action="store_true", help="required for --split test")
    ap.add_argument("--guard", choices=("hearthward", "stub"), default="hearthward")
    ap.add_argument("--guard-root", type=Path, default=GUARD_ROOT)
    ap.add_argument("--weak-action", choices=("pass", "hold"), help="override the guard default")
    ap.add_argument("--cases", type=Path, action="append", help="default: cases/ and <LOCAL>/cases/")
    ap.add_argument("--source", action="append", default=[])
    ap.add_argument("--category", action="append", default=[])
    ap.add_argument("--sample", type=int, default=0, help="max cases per category (deterministic)")
    ap.add_argument("--endpoint", default="", help="second-check model endpoint, e.g. http://127.0.0.1:8080/v1")
    ap.add_argument("--model", default="local")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--sc-channels", default="", help="comma list; default = guard config (chat,attachment,reply_context)")
    ap.add_argument("--sc-scope", choices=("all", "weak"), default="all")
    ap.add_argument("--sc-config", choices=("stranger", "owner"), default="stranger",
                    help="stranger: chat always goes to the model; owner: chat only when the rules say weak")
    ap.add_argument("--sc-score", action="store_true", help="score mode: ask for logprobs, record a score")
    ap.add_argument("--seed", default="sample-v1", help="seed for --sample / --tuning-sample / --cap")
    ap.add_argument("--tuning-sample", action="store_true", help="model-check plan run A: fixed stratified dev sample")
    ap.add_argument("--cap", action="append", default=[], metavar="SOURCE=N",
                    help="at most N attack cases of SOURCE (fixed seed); hard negatives always whole")
    ap.add_argument("--stop-at", default="", metavar="HH:MM",
                    help="local time after which no new case starts (the summary says stopped)")
    ap.add_argument("--max-sc-errors", type=int, default=5, help="stop after N unavailable second checks in a row")
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--out", type=Path)
    ap.add_argument("--slow-ms", type=float, default=2000.0, help="name cases slower than this")
    ap.add_argument("--case-timeout", type=float, default=30.0, help="seconds per case before it is given up")
    ap.add_argument("--ocr", action="store_true", help="run image cases through the guard's picture reader "
                    "(needs a real OCR engine; refused without one)")
    ap.add_argument("--ocr-engine", default="", help="full path to the engine (default: guard default, PATH)")
    ap.add_argument("--images", type=Path, help="generate_cases.py output folder (images.jsonl + images/)")
    a = ap.parse_args(argv)
    try:
        if a.split == "test" and not a.honest:
            raise Refused("--split test is the honest run: add --honest (never tune on it)")
        if a.honest and a.split != "test":
            raise Refused("--honest only applies to --split test")
        if a.mode == "second-check":
            if not a.endpoint:
                raise Refused("second-check mode needs --endpoint (only when the model server is free)")
            check_endpoint(a.endpoint, a.allow_remote)
        if (a.ocr_engine or a.images) and not a.ocr:
            raise Refused("--ocr-engine and --images need --ocr")
        if a.images and not (a.images / "images.jsonl").is_file():
            raise Refused("--images needs a folder with images.jsonl (generate_cases.py output)")
        kw = {"ocr": True, "ocr_engine": a.ocr_engine} if a.ocr else {}
        adapter = ga.load(a.guard, a.guard_root, a.weak_action, **kw)
        if a.honest and adapter.name == "stub":
            raise Refused("the stub guard cannot make an honest run")
        cases = load_cases(a.cases or DEFAULT_CASES)
    except (Refused, ImportError, ValueError) as e:
        print(f"refused: {e}")
        return 2
    sel = [c for c in cases if c["split"] == a.split
           and (not a.source or c["source"]["name"] in a.source)
           and (not a.category or c["category"] in a.category)]
    if a.tuning_sample:
        if a.split != "dev":
            print("refused: --tuning-sample is for the dev split only")
            return 2
        sel = tuning_sample(sel, a.seed if a.seed != "sample-v1" else "tune-v1")
    try:
        caps = {k: int(v) for k, _s, v in (x.partition("=") for x in a.cap)}
    except ValueError:
        print("refused: --cap needs SOURCE=N")
        return 2
    sel = cap_sources(sel, caps, a.seed)
    sel = sample(sel, a.sample, a.seed)
    stop_at = None
    if a.stop_at:
        try:
            hh, mm = (int(x) for x in a.stop_at.split(":"))
            now = _dt.datetime.now()
            stop_at = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if stop_at <= now:
                stop_at += _dt.timedelta(days=1)
        except ValueError:
            print("refused: --stop-at needs HH:MM")
            return 2
    if not sel:
        print("refused: no cases selected")
        return 2
    runner = Runner(adapter, a.mode, a.endpoint, a.model, a.timeout,
                    [s for s in a.sc_channels.split(",") if s] or None, a.sc_scope, a.sc_config, a.sc_score,
                    images_dir=a.images)
    code_at_start = code_fingerprint(a.guard_root)
    utc = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = a.out or (LOCAL / "results" / f"{utc}-{a.mode}-{a.split}")
    out.mkdir(parents=True, exist_ok=True)
    case_fh = open(out / "cases.jsonl", "w", encoding="utf-8", newline="\n") if a.split == "dev" else None
    records, stopped, slow = [], "", []
    t0 = time.perf_counter()
    pool = _cf.ThreadPoolExecutor(max_workers=1)
    print(f"running {len(sel)} cases ({a.mode}, {a.split}); results: {out}", flush=True)
    for i, c in enumerate(sel, 1):
        fut = pool.submit(runner.run_case, c)
        try:
            rec = fut.result(timeout=a.case_timeout)
        except _cf.TimeoutError:
            # the worker cannot be killed; give it up and continue on a fresh worker
            rec = {"id": c["id"], "category": c["category"], "split": c["split"], "source": c["source"]["name"],
                   "expected": c["expected"], "layers": {}, "status": f"timeout:{a.case_timeout:g}s"}
            print(f"  TIMEOUT {c['id']} ({c['category']}) after {a.case_timeout:g}s", flush=True)
            pool.shutdown(wait=False)
            pool = _cf.ThreadPoolExecutor(max_workers=1)
        if rec.get("ms_total", 0) >= a.slow_ms:
            slow.append({"id": rec["id"], "category": rec["category"], "ms": rec["ms_total"]})
            print(f"  slow {rec['id']} ({rec['category']}): {rec['ms_total'] / 1000:.1f}s", flush=True)
        records.append(rec)
        if case_fh is not None:
            case_fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            case_fh.flush()
        if a.mode == "second-check" and runner.sc_errors >= a.max_sc_errors:
            stopped = f"stopped after {runner.sc_errors} unavailable second checks in a row"
            break
        if stop_at is not None and _dt.datetime.now() >= stop_at:
            stopped = f"stopped at {a.stop_at} (--stop-at) after {i} of {len(sel)} cases"
            break
        if i % 500 == 0:
            print(f"  {i}/{len(sel)} ({time.perf_counter() - t0:.0f}s)", flush=True)
    pool.shutdown(wait=False)
    if case_fh is not None:
        case_fh.close()
    if code_fingerprint(a.guard_root) != code_at_start:
        (out / "REFUSED.txt").write_text("bench or guard code changed during this run; results are not valid\n",
                                         encoding="utf-8")
        print("refused: bench or guard code changed during the run; results discarded (see REFUSED.txt)", flush=True)
        return 2
    status = Counter(r["status"] for r in records)
    summary = {
        "run": {"id": f"{utc}-{a.mode}-{a.split}", "utc": utc, "mode": a.mode, "split": a.split, "honest": a.honest,
                "guard": {"name": adapter.name, "version": adapter.version, "fingerprint": adapter.fingerprint},
                "ocr": {"engine": adapter.ocr_engine, "images": "materialised" if a.images else "drawn"}
                if getattr(adapter, "ocr_engine", "") else None,
                "weak_action": adapter.weak_action,
                "weak_action_content": getattr(adapter, "weak_action_content", adapter.weak_action), "second_check": {"endpoint_set": bool(a.endpoint), "scope": a.sc_scope,
                                                                    "channels": list(runner.sc_channels),
                                                                    "config": a.sc_config, "score_mode": a.sc_score,
                                                                    "prompt_ids": sorted(runner.prompt_ids)} if a.mode == "second-check" else None,
                "cases_selected": len(sel), "cases_run": len(records), "cases_fingerprint": cases_fingerprint(sel),
                "sample_per_category": a.sample, "filters": {"source": a.source, "category": a.category},
                "tuning_sample": a.tuning_sample, "caps": caps, "seed": a.seed,
                "layers_missing": sorted({"scam", "ocr", "knock"} - set(adapter.available)),
                "seconds": round(time.perf_counter() - t0, 2), "stopped": stopped, "slow_cases": slow[:200],
                "code_fingerprint": code_at_start,
                "second_check_unavailable": sum(1 for r in records if r.get("second_check_unavailable")),
                "second_check_tamper": sum(1 for r in records if r.get("second_check_tamper")),
                "generators": generators_info() if any("gen_sha256" in r for r in records) else None},
        "status": dict(status),
        "pictures": dict(Counter(r["picture"] for r in records if "picture" in r)) or None,
        "scores": score(records),
        "latency": latency(records),
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(summary_md(summary), encoding="utf-8")
    if a.honest:
        prior = honest_ledger()
        honest_ledger({"utc": utc, "guard": summary["run"]["guard"], "mode": a.mode,
                       "cases_fingerprint": summary["run"]["cases_fingerprint"], "cases_run": len(records)})
        versions = {p["guard"]["fingerprint"] for p in prior} | {adapter.fingerprint}
        print(f"honest run recorded: {len(prior) + 1} honest runs so far over {len(versions)} guard versions")
    print(f"{len(records)} cases, status {dict(status)}; {stopped or 'complete'}; results: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
