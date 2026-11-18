#!/usr/bin/env python3
"""build.py - build cases/own/*.jsonl from the d*.py data modules.

Python standard library only. Run from anywhere:
  python -I bench/attacks/own_build/build.py

Rules
  * Ids are numbered per (category, lang) in module order. Add new cases at the
    END of a module (or in a new module at the end of MODULES) so ids stay stable.
  * Splits are computed with validate_cases.split_for() from the group (or id).
  * Generator seeds come from a hash of the id, so they are stable too.
  * Placeholders such as {URL}, {PHONE}, {EMAIL}, {ACCOUNT}, {CODE}, {CASE_NO},
    {CITY}, {ADDRESS} are filled with fake values by the runner (see COVERAGE.md).
"""
from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True  # keep __pycache__ out of the repo (leakcheck refuses it)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
from validate_cases import split_for  # noqa: E402

OUT = HERE.parent / "cases" / "own"
SRC = {"name": "own", "licence": "Apache-2.0", "attribution": "bench authors (synthetic)"}
INJECTION = {"verdict": "hold", "threshold": "hold"}
DEFAULTS = {
    "scam_text": {"verdict": "hold", "scam_level": "high"},
    "image_ocr_scam": {"verdict": "hold", "scam_level": "high"},
    "output_leak": {"verdict": "block", "gatehouse": "withhold"},
    "hard_negative": {"verdict": "allow", "threshold": "pass"},
}
MODULES = ["d01_direct", "d02_markers", "d03_encoding", "d04_hidden", "d05_lookalike",
           "d06_split", "d07_tool", "d08_ocr", "d09_scam", "d10_output",
           "d11_hn_a", "d12_hn_b", "d13_more",
           "d14_attacks2", "d15_hn2"]


class Builder:
    def __init__(self) -> None:
        self.cases: list[dict] = []
        self.counters: dict[tuple[str, str], int] = {}

    def add(self, cat: str, lang: str, ch: str, payload=None, *, g: str | None = None,
            gp: dict | None = None, exp: dict | None = None, grp: str | None = None,
            att: str | None = None, mim: str | None = None, note: str | None = None) -> None:
        key = (cat, lang)
        self.counters[key] = self.counters.get(key, 0) + 1
        cid = f"own:{cat}-{lang}-{self.counters[key]:03d}"
        c: dict = {"id": cid}
        if grp:
            c["group"] = "own:" + grp
        c["category"] = cat
        if mim:
            c["mimics"] = mim
        c["lang"] = lang
        c["channel"] = ch
        if payload is not None:
            c["payload"] = payload
        if g:
            seed = int(hashlib.sha256(cid.encode()).hexdigest()[:6], 16)
            c["generator"] = {"name": g, "seed": seed, "params": gp or {}}
        if att:
            c["attachment_name"] = att
        e = dict(DEFAULTS.get(cat, INJECTION))
        if ch == "output" and "gatehouse" not in e:
            e["gatehouse"] = "pass"
        e.update(exp or {})
        c["expected"] = e
        c["hard_negative"] = cat == "hard_negative"
        c["source"] = SRC
        c["split"] = split_for(c.get("group") or cid)
        if note:
            c["notes"] = note
        self.cases.append(c)


def main() -> int:
    b = Builder()
    for m in MODULES:
        importlib.import_module(m).build(b)
    OUT.mkdir(parents=True, exist_ok=True)
    files: dict[str, list[str]] = {}
    for c in b.cases:
        name = (f"hard_negative-{c['mimics']}" if c["category"] == "hard_negative"
                else c["category"])
        files.setdefault(name, []).append(json.dumps(c, ensure_ascii=False))
    for old in OUT.glob("*.jsonl"):
        if old.stem not in files:
            old.unlink()
    for name, lines in files.items():
        (OUT / f"{name}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(b.cases)} cases in {len(files)} files -> {OUT.name}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
