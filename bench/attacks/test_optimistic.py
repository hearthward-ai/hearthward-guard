#!/usr/bin/env python3
"""An own case whose text the guard's checker prompt (or canary probes) quotes word for word tests a
prompt that was written with it in view, so it must be marked `optimistic` (export leak review
2026-11-18, suggestion 4). Needs the guard next to the bench (../guard); skipped otherwise.

    python -I bench/attacks/test_optimistic.py
"""
from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases" / "own"
CHECKER = HERE.parent.parent / "guard" / "hearthward_guard" / "threshold" / "checker"
_END = ".。!！?？ \t\n"


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.casefold()).strip(_END)


def quoted_texts() -> list[str]:
    """Every quoted example in the checker prompts plus every probe text, normalised."""
    out: list[str] = []
    for p in sorted(CHECKER.glob("*.txt")):
        out += [norm(m) for m in re.findall(r'"([^"\n]{4,300})"', p.read_text(encoding="utf-8"))]
    probes = json.loads((CHECKER / "probes.json").read_text(encoding="utf-8"))
    out += [norm(x["text"]) for k in ("clean", "inject") for x in probes.get(k, [])]
    return [q for q in out if len(q) >= 4]


def quoting_cases(quotes: list[str]) -> list[dict]:
    """Own cases whose whole payload is a quoted prompt example (or the other way round)."""
    hits = []
    for f in sorted(CASES.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            c = json.loads(line)
            p = c.get("payload")
            if not isinstance(p, str) or not p.strip():
                continue
            np_ = norm(p)
            if any(np_ == q or (len(q) >= 0.8 * len(np_) and q in np_) for q in quotes):
                hits.append(c)
    return hits


@unittest.skipUnless(CHECKER.is_dir(), "guard checker prompts not found next to the bench")
class TestOptimisticFlag(unittest.TestCase):
    def test_cases_quoted_by_the_checker_prompt_are_optimistic(self):
        hits = quoting_cases(quoted_texts())
        missing = [c["id"] for c in hits if not c.get("optimistic")]
        self.assertEqual(missing, [], "quoted in the checker prompt but not optimistic")

    def test_the_check_finds_the_known_quoted_cases(self):
        ids = {c["id"] for c in quoting_cases(quoted_texts())}
        self.assertIn("own:hard_negative-en-871", ids)
        self.assertIn("own:hard_negative-zh-755", ids)

    def test_norm(self):
        self.assertEqual(norm("Ignore my last message, that was a typo."), "ignore my last message, that was a typo")
        self.assertEqual(norm("我上一条发错了，请忽略。"), "我上一条发错了，请忽略")


if __name__ == "__main__":
    unittest.main()
