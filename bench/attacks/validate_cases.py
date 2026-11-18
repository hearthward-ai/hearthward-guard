#!/usr/bin/env python3
"""validate_cases.py - check attack test cases (bench/attacks/cases/*.jsonl).

Python standard library only. Enforces case.schema.json plus the cross-field
rules in CASE-FORMAT.md:
  * ids are unique across all files;
  * the split is fixed by a hash of the case's group (or id), so it cannot drift;
  * hard negatives: category hard_negative <=> hard_negative true, need `mimics`,
    and must expect "allow";
  * channel rules (multi_turn = list of turns, image_ocr = generator, output =
    gatehouse expectation);
  * licence policy: public case files may only hold redistributable licences.

Usage:
  python -I validate_cases.py [--local-only] FILE_OR_DIR [...]
  python -I validate_cases.py --split-of KEY     # print the split for a group/id
Exit code 0 = valid, 1 = problems found, 2 = usage error.
Case text is never printed, only ids, line numbers and the rule that failed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

CATEGORIES = ("direct_override", "fake_markers", "encoding", "hidden_chars", "lookalike",
              "split_instruction", "tool_smuggling", "image_ocr_scam", "scam_text",
              "output_leak", "hard_negative")
LANGS = ("en", "zh", "mixed")
CHANNELS = ("text", "attachment", "tool_result", "image_ocr", "multi_turn", "output")
VERDICTS = ("block", "hold", "allow")
THRESHOLD = ("hold", "warn", "pass")
SCAM_LEVELS = ("none", "warn", "high")
GATEHOUSE = ("strip", "withhold", "pass")
ROLES = ("user", "assistant", "tool", "attachment")
SPLITS = ("dev", "test")

# Licences whose cases may be kept in the public repo (with attribution).
PUBLIC_LICENCES = {"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "CC-BY-4.0", "CC0-1.0"}

TOP_KEYS = {"id", "group", "category", "mimics", "lang", "channel", "payload", "generator",
            "attachment_name", "expected", "hard_negative", "source", "optimistic", "split", "notes"}
REQUIRED = ("id", "category", "lang", "channel", "expected", "hard_negative", "source", "split")
SOURCE_KEYS = {"name", "url", "revision", "licence", "attribution", "original_id"}
EXPECTED_KEYS = {"verdict", "threshold", "scam_level", "gatehouse"}
GENERATOR_KEYS = {"name", "seed", "params"}

ID_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{2,120}$")
GEN_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)*$")
MAX_TEXT = 65536

SPLIT_SALT = b"attacks-split-v1\x00"
TEST_PERCENT = 40  # share of groups that go to the honest test split


def split_for(key: str) -> str:
    """Fixed split: sha256(salt + key), first 8 hex digits mod 100 < TEST_PERCENT -> test."""
    h = hashlib.sha256(SPLIT_SALT + key.encode("utf-8")).hexdigest()
    return "test" if int(h[:8], 16) % 100 < TEST_PERCENT else "dev"


def _is_str(v, lo=1, hi=MAX_TEXT):
    return isinstance(v, str) and lo <= len(v) <= hi


def check_case(c, local_only: bool = False) -> list[str]:
    """Return a list of problems for one parsed case (empty = valid)."""
    if not isinstance(c, dict):
        return ["case is not a JSON object"]
    errs: list[str] = []
    for k in sorted(set(c) - TOP_KEYS):
        errs.append(f"unknown key '{k}'")
    for k in REQUIRED:
        if k not in c:
            errs.append(f"missing '{k}'")
    if errs:
        return errs

    if not (isinstance(c["id"], str) and ID_RE.match(c["id"])):
        errs.append("bad id format")
    if "group" in c and not (isinstance(c["group"], str) and ID_RE.match(c["group"])):
        errs.append("bad group format")
    if c["category"] not in CATEGORIES:
        errs.append("unknown category")
    if c["lang"] not in LANGS:
        errs.append("lang must be en/zh/mixed")
    if c["channel"] not in CHANNELS:
        errs.append("unknown channel")

    # payload / generator
    has_p, has_g = "payload" in c, "generator" in c
    if not (has_p or has_g):
        errs.append("needs payload or generator")
    if has_p:
        p = c["payload"]
        if c["channel"] == "multi_turn":
            if not (isinstance(p, list) and 2 <= len(p) <= 50):
                errs.append("multi_turn payload must be a list of 2-50 turns")
            else:
                for i, t in enumerate(p):
                    if not (isinstance(t, dict) and set(t) == {"role", "text"}
                            and t["role"] in ROLES and _is_str(t["text"], 0)):
                        errs.append(f"bad turn {i}")
        elif not _is_str(p):
            errs.append("payload must be a non-empty string (max 64 KiB)")
    if has_g:
        g = c["generator"]
        if not (isinstance(g, dict) and not (set(g) - GENERATOR_KEYS)):
            errs.append("bad generator object")
        else:
            if not (isinstance(g.get("name"), str) and GEN_RE.match(g["name"])):
                errs.append("bad generator name")
            if not (isinstance(g.get("seed"), int) and not isinstance(g.get("seed"), bool)
                    and g["seed"] >= 0):
                errs.append("generator seed must be an int >= 0")
            if "params" in g and not isinstance(g["params"], dict):
                errs.append("generator params must be an object")
    if c["channel"] == "image_ocr" and not has_g:
        errs.append("image_ocr cases need a generator (synthetic images only)")
    if "attachment_name" in c and not _is_str(c["attachment_name"], 1, 200):
        errs.append("bad attachment_name")

    # expected
    e = c["expected"]
    if not (isinstance(e, dict) and not (set(e) - EXPECTED_KEYS)):
        errs.append("bad expected object")
    else:
        for key, allowed in (("verdict", VERDICTS), ("threshold", THRESHOLD),
                             ("scam_level", SCAM_LEVELS), ("gatehouse", GATEHOUSE)):
            if (key in e or key == "verdict") and e.get(key) not in allowed:
                errs.append(f"expected.{key} invalid")
        if e.get("verdict") == "allow" and (e.get("threshold") == "hold"
                                            or e.get("gatehouse") == "withhold"):
            errs.append("verdict allow contradicts a hold/withhold layer")
        if c["channel"] == "output" and "gatehouse" not in e:
            errs.append("output channel needs expected.gatehouse")
        if c["category"] == "output_leak" and c["channel"] != "output":
            errs.append("output_leak cases use the output channel")

    # hard negatives
    hn = c["hard_negative"]
    if not isinstance(hn, bool):
        errs.append("hard_negative must be true/false")
    elif hn != (c["category"] == "hard_negative"):
        errs.append("hard_negative flag must match category hard_negative")
    if c["category"] == "hard_negative":
        if c.get("mimics") not in CATEGORIES[:-1]:
            errs.append("hard negatives need 'mimics' (one of the 10 attack categories)")
        if isinstance(e, dict) and e.get("verdict") != "allow":
            errs.append("hard negatives must expect allow")
    elif "mimics" in c:
        errs.append("'mimics' is only for hard negatives")
    if "optimistic" in c and not isinstance(c["optimistic"], bool):
        errs.append("optimistic must be true/false")

    # source + licence
    s = c["source"]
    if not (isinstance(s, dict) and not (set(s) - SOURCE_KEYS)):
        errs.append("bad source object")
    else:
        for k in ("name", "licence", "attribution"):
            if not _is_str(s.get(k), 1, 500):
                errs.append(f"source.{k} missing")
        if "url" in s and not (isinstance(s["url"], str) and s["url"].startswith("https://")):
            errs.append("source.url must be https")
        if s.get("name") != "own" and not s.get("revision"):
            errs.append("public-source cases need source.revision (pinned)")
        if not local_only and s.get("licence") not in PUBLIC_LICENCES:
            errs.append("licence not allowed in public case files (use --local-only for the cache)")

    # split
    if c["split"] not in SPLITS:
        errs.append("split must be dev/test")
    elif isinstance(c.get("id"), str):
        key = c.get("group") or c["id"]
        if isinstance(key, str) and c["split"] != split_for(key):
            errs.append(f"split must be '{split_for(key)}' (fixed by hash)")
    if "notes" in c and not _is_str(c["notes"], 0, 2000):
        errs.append("notes too long")
    return errs


def iter_files(paths):
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(p.rglob("*.jsonl"))
        else:
            yield p


def validate_paths(paths, local_only=False) -> tuple[int, list[str]]:
    """Validate files; return (case count, problem lines)."""
    seen: dict[str, str] = {}
    problems: list[str] = []
    n = 0
    for f in iter_files(paths):
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"{f}: cannot read ({type(exc).__name__})")
            continue
        for ln, line in enumerate(lines, 1):
            if not line.strip():
                continue
            n += 1
            where = f"{f}:{ln}"
            try:
                c = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"{where}: invalid JSON")
                continue
            cid = c.get("id") if isinstance(c, dict) else None
            for err in check_case(c, local_only):
                problems.append(f"{where}: [{cid}] {err}")
            if isinstance(cid, str):
                if cid in seen:
                    problems.append(f"{where}: [{cid}] duplicate id (first at {seen[cid]})")
                else:
                    seen[cid] = where
    return n, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--local-only", action="store_true",
                    help="allow non-redistributable licences (local fetch cache only)")
    ap.add_argument("--split-of", metavar="KEY", help="print the fixed split for a group or id")
    a = ap.parse_args(argv)
    if a.split_of:
        print(split_for(a.split_of))
        return 0
    if not a.paths:
        ap.print_usage()
        return 2
    n, problems = validate_paths(a.paths, a.local_only)
    for p in problems:
        print(p)
    print(f"{n} cases, {len(problems)} problems")
    return 1 if problems or n == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
