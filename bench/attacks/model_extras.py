#!/usr/bin/env python3
"""Two extra false-positive passes for the model check (design 5.3 / 5.4). Counts only: no text is written.

    python -I model_extras.py probes --endpoint URL
    python -I model_extras.py everyday --endpoint URL [--guard-root DIR] [--out DIR]
    python -I model_extras.py realdocs --endpoint URL [--dir DIR ...] [--n 300] [--seed S] [--out DIR]

probes    every canary probe once (3 clean, 3 injection): all must answer right, or the guard would mark the
          check degraded and hold everything. Run first, before any other model-check step.
everyday  the guard's fixed everyday chat set (42 zh / 25 en, tests/review/test_review_recheck2.py), sent as
          chat with owner_chat "all" (the worst case: in the default "weak" mode they never reach the model)
          and as content. Hard requirement: 0 / 0 inject (and report suspicious).
realdocs  "real document" pass on non-personal files already on this PC: Python stdlib module docstrings
          and installed package METADATA (found from this interpreter), plus any --dir (e.g. a MiKTeX doc
          folder or the npm global root): *.md, *.txt, *.rst READMEs. Never point --dir at personal files.
          Each document is cut to its first 6,000 characters (one chunk). Results: verdict counts per kind.
Only run when the model server is free (benchmark night).
"""
from __future__ import annotations

import argparse
import ast
import datetime as _dt
import hashlib
import importlib.util
import json
import sys
import sysconfig
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
GUARD_ROOT = HERE.parent.parent / "guard"
LOCAL = Path.home() / "Hearthward-Data" / "attack-bench"
DOC_CHARS = 6000


def load_guard(root: Path):
    sys.path.insert(0, str(root))
    from hearthward_guard.threshold import second_check   # noqa: E402
    return second_check


def everyday_sets(root: Path):
    spec = importlib.util.spec_from_file_location("_everyday", root / "tests" / "review" / "test_review_recheck2.py")
    sys.path.insert(0, str(root))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {"zh": list(mod.EVERYDAY_ZH), "en": list(mod.EVERYDAY_EN)}


def stdlib_docs() -> list[tuple[str, str]]:
    out = []
    base = Path(sysconfig.get_paths()["stdlib"])
    for p in sorted(base.glob("*.py")):
        try:
            doc = ast.get_docstring(ast.parse(p.read_text(encoding="utf-8", errors="replace")))
        except (SyntaxError, ValueError):
            continue
        if doc and len(doc) >= 300:
            out.append(("stdlib-docstring", doc))
    return out


def metadata_docs() -> list[tuple[str, str]]:
    out = []
    base = Path(sysconfig.get_paths()["purelib"])
    for p in sorted(base.glob("*.dist-info/METADATA")):
        t = p.read_text(encoding="utf-8", errors="replace")
        body = t.split("\n\n", 1)[1] if "\n\n" in t else ""
        if len(body) >= 300:
            out.append(("package-readme", body))
    return out


def dir_docs(dirs) -> list[tuple[str, str]]:
    out = []
    for d in dirs:
        for p in sorted(Path(d).rglob("*")):
            if p.suffix.lower() in (".md", ".txt", ".rst") and p.is_file() and p.stat().st_size < 2_000_000:
                t = p.read_text(encoding="utf-8", errors="replace")
                if len(t) >= 300:
                    out.append(("folder-doc", t))
    return out


def run(items, sc, endpoint: str, timeout: float, label: str) -> dict:
    counts, kinds, errors, ms = Counter(), Counter(), Counter(), []
    for kind, variant, text in items:
        t = time.perf_counter()
        try:
            r = sc.check(text[:DOC_CHARS], endpoint, timeout=timeout, variant=variant, max_chunks=1)
            counts[(kind, variant, r.verdict)] += 1
            if r.verdict != "none":
                kinds.update(r.kinds)
        except sc.CheckTampered:
            errors[(kind, "tamper")] += 1
        except sc.CheckError:
            errors[(kind, "unavailable")] += 1
        ms.append((time.perf_counter() - t) * 1000)
    ms.sort()
    return {"pass": label, "n": len(items),
            "verdicts": {" ".join(k): v for k, v in sorted(counts.items())},
            "flagged_kinds": dict(kinds), "errors": {" ".join(k): v for k, v in errors.items()},
            "ms_p50": round(ms[len(ms) // 2], 1) if ms else None,
            "ms_p95": round(ms[int(len(ms) * 0.95)], 1) if ms else None}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("what", choices=("probes", "everyday", "realdocs"))
    ap.add_argument("--endpoint", required=True)
    ap.add_argument("--guard-root", type=Path, default=GUARD_ROOT)
    ap.add_argument("--dir", action="append", default=[])
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--seed", default="docs-v1")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args(argv)
    sc = load_guard(a.guard_root)
    if a.what == "probes":
        P = sc.default_prompts()
        wrong = 0
        for want, group in (("none", "clean"), ("inject", "inject")):
            for variant, text in P.probes[group]:
                try:
                    got = sc.check(text, a.endpoint, timeout=a.timeout, variant=variant).verdict
                except sc.CheckError as e:
                    got = type(e).__name__
                wrong += got != want
                print(f"{group:6} {variant:7} want {want:6} got {got}")
        print("PROBES OK" if not wrong else f"PROBES WRONG: {wrong}")
        return 1 if wrong else 0
    if a.what == "everyday":
        sets = everyday_sets(a.guard_root)
        items = [(f"everyday-{lang}", v, t) for lang, ts in sets.items() for t in ts for v in ("chat", "content")]
    else:
        docs = stdlib_docs() + metadata_docs() + dir_docs(a.dir)
        docs.sort(key=lambda d: hashlib.sha256((a.seed + d[1][:2000]).encode("utf-8", "surrogatepass")).hexdigest())
        items = [(k, "content", t) for k, t in docs[:a.n]]
    utc = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    res = run(items, sc, a.endpoint, a.timeout, a.what)
    res.update({"utc": utc, "prompt_id": sc.default_prompts().id})
    out = a.out or (LOCAL / "results" / f"{utc}-model-{a.what}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(res, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
