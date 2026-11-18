#!/usr/bin/env python3
"""import_public.py - turn the fetched public datasets into attack cases (CASE-FORMAT.md).

The fetch cache (made by fetch.py) is UNTRUSTED DATA. This script only reads it:
parquet through pyarrow (dev-only dependency, bench venv), CSV/JSON with the standard
library, and the AgentDojo wheel as a zip (its .py files are parsed with `ast`, never
imported or run). Run it with `python -I`.

Output goes to a local folder outside the repo (default: ~/Hearthward-Data/attack-bench/cases,
override with HEARTHWARD_BENCH_LOCAL), never into the repo: the fetch list says "fetch, don't
vendor" for these sources.
Only case ids and results are published.

  python -I import_public.py --cache <fetch cache> [--out <dir>] [--source <id> ...]

Every file is re-checked against the cache's MANIFEST.lock.json and the pinned size/hash in
sources.json before it is read. Rows are language-filtered (en/zh/mixed kept; AgentDojo and
BIPIA are English benchmark text inside YAML/email contexts, so they are tagged en), deduplicated
across all sources (texts that appear with conflicting labels are dropped entirely), split by
the fixed hash rule, and validated with validate_cases.check_case before being written.
Exit code 0 = ok, 1 = a source failed, 2 = usage / integrity refusal.
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import os
import re
import sys
import unicodedata
import zipfile
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fetch  # noqa: E402
from validate_cases import MAX_TEXT, check_case, split_for  # noqa: E402

DEFAULT_OUT = Path(os.environ.get("HEARTHWARD_BENCH_LOCAL") or Path.home() / "Hearthward-Data" / "attack-bench") / "cases"
ORDER = ("deepset-prompt-injections", "lakera-gandalf-ignore-instructions",
         "spml-chatbot-prompt-injection", "agentdojo", "bipia")
INJECTION = {"verdict": "hold", "threshold": "hold"}
BENIGN = {"verdict": "allow", "threshold": "pass"}

ATTRIBUTION = {
    "deepset-prompt-injections": "deepset, prompt-injections dataset (Hugging Face)",
    "lakera-gandalf-ignore-instructions": "Lakera AI, gandalf_ignore_instructions; cite Gandalf the Red, arXiv 2501.07927",
    "spml-chatbot-prompt-injection": "Sharma et al., SPML chatbot prompt injection dataset; cite arXiv 2402.11755",
    "agentdojo": "Debenedetti et al., AgentDojo v0.1.35 (ETH Zurich SPY Lab), MIT licence",
    "bipia": "Copyright (c) Microsoft Corporation, BIPIA benchmark (Yi et al., arXiv 2312.14197), MIT licence",
}


class Integrity(Exception):
    pass


# ------------------------------------------------------------------ helpers
def norm_key(text: str) -> str:
    """Dedupe key: NFKC, casefold, collapsed whitespace."""
    t = unicodedata.normalize("NFKC", text).casefold()
    return hashlib.sha256(" ".join(t.split()).encode("utf-8", "surrogatepass")).hexdigest()


def slug(s: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:n].strip("-") or "x"


_EN = set("the and is to of you what how are in for a i it that with on be do can my your this me "
          "please tell about not have will from all".split())
_OTHER = {
    "de": set("und der die das ist nicht ich sie wie was ein eine mit für auf zu von den dem sind bitte "
              "wir werden oder auch es mir mich kann ihr gibt welche wer warum".split()),
    "es": set("el la los las que es y en por para con una un como del al pero muy qué cómo".split()),
    "fr": set("le la les des est et en pour avec une un du que qui pas sur dans je vous ce".split()),
    "it": set("il lo gli che è e per con una un del della non sono come ciao".split()),
    "pt": set("o os que é e em para com uma um do da não são como você".split()),
    "nl": set("de het een en van is dat niet ik je wat hoe voor met op zijn".split()),
}
_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)


def _script(ch: str) -> str:
    cp = ord(ch)
    if 0x3040 <= cp <= 0x30FF or 0xAC00 <= cp <= 0xD7AF or 0x1100 <= cp <= 0x11FF:
        return "kana-hangul"
    if 0x4E00 <= cp <= 0x9FFF or 0x3400 <= cp <= 0x4DBF or 0x20000 <= cp <= 0x2FFFF or 0xF900 <= cp <= 0xFAFF:
        return "cjk"
    if cp < 0x250 or 0x1E00 <= cp <= 0x1EFF or 0xFF21 <= cp <= 0xFF5A:
        return "latin"
    return "other"


def lang_of(text: str) -> tuple[str | None, str]:
    """-> (en|zh|mixed, "") or (None, reason). Heuristic; only en/zh/mixed are kept."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return "en", ""
    sc = Counter(_script(c) for c in letters)
    if sc["kana-hangul"]:
        return None, "lang:ja-ko"
    if sc["cjk"]:
        return ("zh" if sc["cjk"] / len(letters) > 0.5 else "mixed"), ""
    if sc["other"] / len(letters) > 0.3:
        return None, "lang:other-script"
    words = [w.lower() for w in _WORD.findall(text)]
    en = sum(w in _EN for w in words)
    best, hits = None, 0
    for lang, vocab in _OTHER.items():
        h = sum(w in vocab for w in words)
        if h > hits:
            best, hits = lang, h
    if best == "de" and re.search(r"[äöüßÄÖÜ]", text) and hits >= 1 and hits >= en:
        return None, "lang:de"
    if best and hits >= 2 and hits > en:
        return None, f"lang:{best}"
    return "en", ""


def make_case(source: dict, cid: str, original_id: str, category: str, channel: str, payload: str,
              lang: str, group: str | None = None, mimics: str | None = None,
              attachment_name: str | None = None, notes: str | None = None) -> dict:
    hn = category == "hard_negative"
    c: dict = {"id": cid}
    if group:
        c["group"] = group
    c["category"] = category
    if mimics:
        c["mimics"] = mimics
    c["lang"] = lang
    c["channel"] = channel
    c["payload"] = payload
    if attachment_name:
        c["attachment_name"] = attachment_name
    c["expected"] = dict(BENIGN if hn else INJECTION)
    c["hard_negative"] = hn
    c["source"] = {"name": source["id"], "url": source["page"], "revision": source["revision"],
                   "licence": source["licence"], "attribution": ATTRIBUTION[source["id"]],
                   "original_id": original_id}
    c["split"] = split_for(group or cid)
    if notes:
        c["notes"] = notes
    return c


# ------------------------------------------------------------------ integrity
def checked_bytes(cache: Path, source: dict, rel: str) -> bytes:
    """Read a cache file only if it matches both MANIFEST.lock.json and the sources.json pin."""
    spec = next((f for f in source["files"] if f["dest"] == rel), None)
    if spec is None:
        raise Integrity(f"{rel}: not in sources.json")
    man = json.loads((cache / "MANIFEST.lock.json").read_text(encoding="utf-8"))
    entry = next((m for m in man if m["path"] == rel and m["source"] == source["id"]), None)
    if entry is None:
        raise Integrity(f"{rel}: not in MANIFEST.lock.json")
    data = fetch.safe_dest(cache, rel).read_bytes()
    why = fetch.verify(data, spec)
    if why or hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise Integrity(f"{rel}: {why or 'manifest sha256 mismatch'}")
    return data


def read_parquet(data: bytes) -> list[dict]:
    import pyarrow.parquet as pq  # dev-only dependency (bench venv)
    return pq.read_table(io.BytesIO(data)).to_pylist()


# ------------------------------------------------------------------ sources
def rows_deepset(cache: Path, src: dict):
    for split in ("train", "test"):
        for i, r in enumerate(read_parquet(checked_bytes(cache, src, f"deepset-prompt-injections/{split}.parquet"))):
            label = r.get("label")
            if label not in (0, 1) or not isinstance(r.get("text"), str):
                yield None, "bad-row"
                continue
            cat = "direct_override" if label == 1 else "hard_negative"
            yield dict(cid=f"{src['id']}:{split}:{i}", original_id=f"{split}:{i}", category=cat,
                       channel="text", payload=r["text"],
                       mimics=None if label == 1 else "direct_override"), ""


def rows_lakera(cache: Path, src: dict):
    for split in ("train", "validation", "test"):
        for i, r in enumerate(read_parquet(checked_bytes(cache, src, f"lakera-gandalf/{split}.parquet"))):
            if not isinstance(r.get("text"), str):
                yield None, "bad-row"
                continue
            yield dict(cid=f"lakera-gandalf:{split}:{i}", original_id=f"{split}:{i}", category="direct_override",
                       channel="text", payload=r["text"]), ""


def rows_spml(cache: Path, src: dict):
    data = checked_bytes(cache, src, "spml/spml_prompt_injection.csv").decode("utf-8")
    csv.field_size_limit(1 << 24)
    for i, r in enumerate(csv.DictReader(io.StringIO(data, newline=""))):
        label, text = r.get("Prompt injection"), r.get("User Prompt")
        if label not in ("0", "1") or not isinstance(text, str):
            yield None, "bad-row"
            continue
        deg = r.get("Degree", "")
        origin = "gandalf" if (r.get("Source") or "").strip().lower() == "gandalf" else "spml"
        yield dict(cid=f"spml:csv:{i}", original_id=f"row:{i}",
                   category="direct_override" if label == "1" else "hard_negative",
                   channel="text", payload=text, mimics=None if label == "1" else "direct_override",
                   notes=f"subset=spml-degree-{slug(deg, 3)} origin={origin}"), ""


# --- AgentDojo (wheel read as a zip; python files parsed with ast, never executed)
AD_SUITES = ("banking", "slack", "travel", "workspace")
AD_PREFIX = "agentdojo/"
AD_DEFAULT_USER, AD_DEFAULT_MODEL = "the user", "the AI language model"
AD_NAMED_USER = "Emma Johnson"


def _const_eval(node, env: dict):
    """Evaluate a tiny, safe subset of Python expressions: str/int/float constants, f-strings of
    names from *env*, and string '+'. Anything else returns None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.Name):
        return env.get(node.id)
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                out.append(v.value)
            elif isinstance(v, ast.FormattedValue) and v.conversion == -1 and v.format_spec is None:
                x = _const_eval(v.value, env)
                if x is None:
                    return None
                out.append(str(x))
            else:
                return None
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _const_eval(node.left, env), _const_eval(node.right, env)
        return a + b if isinstance(a, str) and isinstance(b, str) else None
    return None


def _assigns(body) -> list[tuple[str, ast.AST]]:
    out = []
    for st in body:
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name):
            out.append((st.targets[0].id, st.value))
        elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name) and st.value is not None:
            out.append((st.target.id, st.value))
    return out


def ad_goals(source_text: str) -> tuple[list[tuple[str, str]], int]:
    """-> ([(class name, GOAL text)], number of GOALs that could not be evaluated)."""
    tree = ast.parse(source_text)
    module_env: dict = {}
    for name, val in _assigns(tree.body):
        v = _const_eval(val, module_env)
        if v is not None:
            module_env[name] = v
    goals, skipped = [], 0
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        env = dict(module_env)
        goal = None
        for name, val in _assigns(cls.body):
            v = _const_eval(val, env)
            if v is not None:
                env[name] = v
            if name == "GOAL":
                goal = v if isinstance(v, str) else False
        if goal:
            goals.append((cls.name, goal))
        elif goal is False:
            skipped += 1
    return goals, skipped


def ad_templates(attacks_py: dict[str, str]) -> dict[str, str]:
    """Attack name -> template, from the attack modules' source (ast only). Templates that need
    tool ground truth ({tools}) or interactive input are skipped."""
    out: dict[str, str] = {}
    for text in attacks_py.values():
        for cls in (n for n in ast.parse(text).body if isinstance(n, ast.ClassDef)):
            env = {k: _const_eval(v, {}) for k, v in _assigns(cls.body)}
            name = env.get("name")
            tpl = env.get("_JB_STRING") or env.get("_DOS_STRING")
            if tpl is None:
                for node in ast.walk(cls):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "__init__" and node.args
                            and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                        tpl = node.args[0].value
                        break
            if isinstance(name, str) and isinstance(tpl, str) and "{tools}" not in tpl:
                out[name] = tpl
    return out


_VEC_RX = re.compile(r'^([A-Za-z_]\w*):\s*$')
_DEF_RX = re.compile(r'^\s+default:\s*(".*")\s*$')


def ad_vectors(yaml_text: str) -> dict[str, str]:
    """injection_vectors.yaml -> {name: default}. Only the simple layout used by AgentDojo."""
    out, cur = {}, None
    for line in yaml_text.splitlines():
        m = _VEC_RX.match(line)
        if m:
            cur = m.group(1)
            continue
        d = _DEF_RX.match(line)
        if d and cur:
            try:
                out[cur] = json.loads(d.group(1))
            except json.JSONDecodeError:
                out[cur] = d.group(1)[1:-1]
    return out


def ad_window(env_files: dict[str, str], vectors: dict[str, str], target: str, value: str, radius: int = 6) -> str:
    """The environment lines around {target}, with *value* in its place and other vectors at their
    benign defaults: a stand-in for what a tool would return."""
    ph = "{" + target + "}"
    for text in env_files.values():
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if ph in line:
                seg = "\n".join(lines[max(0, i - radius): i + radius + 1])
                seg = seg.replace(ph, value)
                for k, v in vectors.items():
                    seg = seg.replace("{" + k + "}", v)
                return seg
    raise KeyError(target)


def _pick(options: list, key: str):
    return options[int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % len(options)]


def rows_agentdojo(cache: Path, src: dict):
    data = checked_bytes(cache, src, "agentdojo/agentdojo-0.1.35-py3-none-any.whl")
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    rd = lambda n: z.read(n).decode("utf-8")  # noqa: E731
    attacks_py = {n: rd(n) for n in names if n.startswith(AD_PREFIX + "attacks/") and n.endswith("_attacks.py")}
    templates = ad_templates(attacks_py)
    goal_tpls = {k: v for k, v in templates.items() if "{goal}" in v}
    dos_tpls = {k: v for k, v in templates.items() if "{goal}" not in v}
    if "important_instructions" in goal_tpls:
        goal_tpls["important_instructions_no_names"] = goal_tpls["important_instructions"]
    suites = {}
    for s in AD_SUITES:
        base = f"{AD_PREFIX}data/suites/{s}/"
        vec = ad_vectors(rd(base + "injection_vectors.yaml"))
        env = {n: rd(n) for n in names if n.startswith(base) and n.endswith(".yaml") and "injection_vectors" not in n}
        suites[s] = (vec, env)

    def fill(tpl: str, attack: str, goal: str = "") -> str:
        named = not attack.endswith("_no_names")
        return tpl.format(goal=goal, user=AD_NAMED_USER if named else AD_DEFAULT_USER, model=AD_DEFAULT_MODEL)

    for n in sorted(names):
        m = re.match(rf"{AD_PREFIX}default_suites/(v[0-9_]+)/(\w+)/injection_tasks\.py$", n)
        if not m:
            continue
        ver, suite = m.groups()
        goals, skipped = ad_goals(rd(n))
        for _ in range(skipped):
            yield None, "agentdojo:goal-not-static"
        vec, env = suites[suite]
        vnames = sorted(vec)
        for cls, goal in goals:
            group = f"agentdojo:goal:{suite}-{hashlib.sha256(goal.encode()).hexdigest()[:10]}"
            for att in sorted(goal_tpls):
                target = _pick(vnames, f"{suite}\0{goal}\0{att}")
                payload = ad_window(env, vec, target, fill(goal_tpls[att], att, goal))
                yield dict(cid=f"agentdojo:{ver}:{suite}:{slug(cls)}:{slug(att)}",
                           original_id=f"{ver}/{suite}/{cls} x {att} @ {target}", category="tool_smuggling",
                           channel="tool_result", payload=payload, group=group,
                           notes=f"subset=agentdojo-{slug(att)} vector={target}", lang="en"), ""
    for att in sorted(dos_tpls):
        for suite in AD_SUITES:
            vec, env = suites[suite]
            target = _pick(sorted(vec), f"{suite}\0dos\0{att}")
            yield dict(cid=f"agentdojo:dos:{suite}:{slug(att)}", original_id=f"{att} @ {suite}/{target}",
                       category="tool_smuggling", channel="tool_result",
                       payload=ad_window(env, vec, target, fill(dos_tpls[att], att)),
                       group=f"agentdojo:dos:{slug(att)}", notes=f"subset=agentdojo-dos vector={target}", lang="en"), ""
    for suite in AD_SUITES:
        vec, env = suites[suite]
        for target in sorted(vec):
            yield dict(cid=f"agentdojo:benign:{suite}:{slug(target, 60)}", original_id=f"{suite}/{target} (default)",
                       category="hard_negative", mimics="tool_smuggling", channel="tool_result",
                       payload=ad_window(env, vec, target, vec[target]),
                       notes="subset=agentdojo-benign", lang="en"), ""


# --- BIPIA (email task only; attack text inserted at start / middle / end)
def bipia_insert(context: str, attack: str, pos: str) -> str:
    if pos == "start":
        return attack + "\n" + context
    if pos == "end":
        return context + "\n" + attack
    mid = len(context) // 2
    cuts = [m.end() for m in re.finditer(r"\n|(?<=[.!?])\s", context)]
    cut = min(cuts, key=lambda c: abs(c - mid)) if cuts else mid
    return context[:cut] + "\n" + attack + "\n" + context[cut:]


def rows_bipia(cache: Path, src: dict):
    emails = {}
    for split in ("train", "test"):
        raw = checked_bytes(cache, src, f"bipia/email_{split}.jsonl").decode("utf-8")
        emails[split] = [json.loads(line)["context"] for line in raw.splitlines() if line.strip()]
    for kind in ("text", "code"):
        for split in ("train", "test"):
            attacks = json.loads(checked_bytes(cache, src, f"bipia/{kind}_attack_{split}.json").decode("utf-8"))
            for fam, items in attacks.items():
                for i, attack in enumerate(items):
                    if not isinstance(attack, str):
                        yield None, "bad-row"
                        continue
                    group = f"bipia:{kind}-{split}:{slug(fam)}-{i}"
                    ei = int(hashlib.sha256(attack.encode()).hexdigest()[:8], 16) % len(emails[split])
                    for pos in ("start", "middle", "end"):
                        yield dict(cid=f"{group}:{pos}", original_id=f"{kind}_attack_{split}/{fam}/{i} in email_{split}/{ei} ({pos})",
                                   category="tool_smuggling", channel="attachment", attachment_name="email.txt",
                                   payload=bipia_insert(emails[split][ei], attack, pos), group=group,
                                   notes=f"subset=bipia-{kind} family={slug(fam)}", lang="en"), ""
    for split in ("train", "test"):
        for i, ctx in enumerate(emails[split]):
            yield dict(cid=f"bipia:email-{split}:{i}", original_id=f"email_{split}/{i}", category="hard_negative",
                       mimics="tool_smuggling", channel="attachment", attachment_name="email.txt", payload=ctx,
                       notes="subset=bipia-clean-email", lang="en"), ""


READERS = {"deepset-prompt-injections": rows_deepset, "lakera-gandalf-ignore-instructions": rows_lakera,
           "spml-chatbot-prompt-injection": rows_spml, "agentdojo": rows_agentdojo, "bipia": rows_bipia}


# ------------------------------------------------------------------ pipeline
def existing_keys(paths) -> dict[str, str]:
    """Dedupe keys of cases already in the public cases/ folder (own cases win over imports)."""
    out = {}
    for p in paths:
        for f in sorted(Path(p).rglob("*.jsonl")) if Path(p).is_dir() else []:
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    c = json.loads(line)
                    if isinstance(c.get("payload"), str):
                        out[norm_key(c["payload"])] = c["id"]
    return out


def import_all(cache: Path, sources: dict, ids, known: dict | None = None) -> tuple[dict, dict]:
    """-> ({source id: [cases]}, report). Dedupe is global across the selected sources."""
    report: dict = {"sources": {}, "conflicts_dropped": 0}
    candidates: list[tuple[str, dict]] = []
    for sid in ids:
        src = sources[sid]
        r = Counter()
        try:
            for row, why in READERS[sid](cache, src):
                r["rows"] += 1
                if row is None:
                    r["dropped:" + why] += 1
                    continue
                text = row["payload"]
                if not text.strip():
                    r["dropped:empty"] += 1
                    continue
                if len(text) > MAX_TEXT:
                    r["dropped:too-long"] += 1
                    continue
                lang, why = (row.pop("lang"), "") if "lang" in row else lang_of(text)
                if lang is None:
                    r["dropped:" + why] += 1
                    continue
                cid = row.pop("cid")
                case = make_case(src, cid, lang=lang, **row)
                errs = check_case(case, local_only=True)
                if errs:
                    r["dropped:invalid"] += 1
                    continue
                candidates.append((sid, case))
        except (Integrity, OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
            r["error"] = 1
            report["sources"][sid] = dict(r) | {"failed": f"{type(exc).__name__}: {exc}"}
            continue
        report["sources"][sid] = dict(r)

    by_key: dict[str, list[tuple[str, dict]]] = {}
    for sid, c in candidates:
        by_key.setdefault(norm_key(c["payload"]), []).append((sid, c))
    known = known or {}
    out: dict[str, list[dict]] = {sid: [] for sid in ids}
    for key, items in by_key.items():
        benign = {c["category"] == "hard_negative" for _s, c in items}
        if len(benign) > 1:
            report["conflicts_dropped"] += len(items)
            for sid, _c in items:
                report["sources"][sid]["dropped:label-conflict"] = report["sources"][sid].get("dropped:label-conflict", 0) + 1
            continue
        if key in known:
            for sid, _c in items:
                report["sources"][sid]["dropped:dup-of-own"] = report["sources"][sid].get("dropped:dup-of-own", 0) + 1
            continue
        sid, keep = items[0]
        out[sid].append(keep)
        for dsid, _c in items[1:]:
            k = "dropped:dup-same-source" if dsid == sid else "dropped:dup-cross-source"
            report["sources"][dsid][k] = report["sources"][dsid].get(k, 0) + 1
    for sid, cases in out.items():
        s = report["sources"].setdefault(sid, {})
        s["imported"] = len(cases)
        s["by_category_split"] = dict(sorted(Counter(f"{c['category']}/{c['split']}" for c in cases).items()))
        s["by_lang"] = dict(Counter(c["lang"] for c in cases))
    return out, report


def write_out(out_dir: Path, cases: dict, report: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for sid, items in cases.items():
        items = sorted(items, key=lambda c: c["id"])
        with open(out_dir / f"public-{sid}.jsonl", "w", encoding="utf-8", newline="\n") as fh:
            for c in items:
                fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    (out_dir / "import-report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cache", type=Path, required=True, help="folder made by fetch.py")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--source", action="append", default=[], help="default: all approved sources")
    a = ap.parse_args(argv)
    sources = fetch.load_sources()
    ids = a.source or [s for s in ORDER if sources[s].get("approved") is True]
    for sid in ids:
        if sid not in READERS or sources.get(sid, {}).get("approved") is not True:
            print(f"refused: {sid} is unknown or not approved")
            return 2
    try:
        a.out.resolve().relative_to(HERE.parent.parent.resolve())
        print("refused: imported cases must stay outside the repo (fetch, don't vendor)")
        return 2
    except ValueError:
        pass
    if not (a.cache / "MANIFEST.lock.json").is_file():
        print("refused: cache has no MANIFEST.lock.json")
        return 2
    cases, report = import_all(a.cache, sources, ids, existing_keys([HERE / "cases"]))
    write_out(a.out, cases, report)
    failed = 0
    for sid in ids:
        s = report["sources"][sid]
        failed += "failed" in s
        print(f"{sid:38} rows={s.get('rows', 0):6} imported={s['imported']:6} " + (s.get("failed") or ""))
    print(f"label conflicts dropped: {report['conflicts_dropped']}; report: {a.out / 'import-report.json'}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
