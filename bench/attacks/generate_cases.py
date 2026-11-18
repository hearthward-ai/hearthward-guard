#!/usr/bin/env python3
"""generate_cases.py - materialise every generator case into concrete payloads OUTSIDE the repo.

    python -I -B generate_cases.py [--cases DIR ...] [--out DIR] [--no-images]
    python -I -B generate_cases.py --check [--out DIR]      # regenerate, compare with the manifest

Writes (default <LOCAL>/generated/, LOCAL = ~/Hearthward-Data/attack-bench):
  payloads.jsonl   one line per text case: id, category, generator, seed, sha256, payload
  images/<id>.png|.jpg plus images.jsonl (id, files with sha256, ground-truth text)
  manifest.json    code hashes, Pillow + font hashes, per-case sha256, counts, set fingerprint
The run never touches the case files, so ids, groups and the hash split are unchanged.
Exit 0 = ok, 1 = --check found a difference, 2 = usage / invalid cases / generator error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import unicodedata
from collections import Counter
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generators as G  # noqa: E402
from validate_cases import validate_paths  # noqa: E402

LOCAL = Path(os.environ.get("HEARTHWARD_BENCH_LOCAL") or Path.home() / "Hearthward-Data" / "attack-bench")
FORMAT = "hearthward-generated-v1"


def payload_sha(p) -> str:
    """sha256 of the payload as UTF-8 (lists: canonical JSON). surrogatepass keeps odd input hashable."""
    if isinstance(p, list):
        raw = json.dumps(p, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    else:
        raw = p
    return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def safe_name(cid: str) -> str:
    return cid.replace(":", "_")


def load(paths) -> list[dict]:
    cases = []
    for p in paths:
        n, problems = validate_paths([p])
        if problems:
            raise SystemExit(f"refused: {len(problems)} invalid cases under {p}")
        for f in sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]:
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    c = json.loads(line)
                    if "generator" in c:
                        cases.append(c)
    cases.sort(key=lambda c: c["id"])
    return cases


def build(cases, images: bool):
    """-> (text_rows, image_rows, image_files {name: bytes}, errors)."""
    text_rows, image_rows, files, errors = [], [], {}, []
    for c in cases:
        g = c["generator"]
        try:
            if G.is_image(g["name"]):
                if not images:
                    continue
                r = G.generate_image(g["name"], g["seed"], g.get("params", {}))
                flist = []
                for suffix, data in r["images"]:
                    fname = safe_name(c["id"]) + suffix
                    files[fname] = data
                    flist.append({"file": fname, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
                image_rows.append({"id": c["id"], "category": c["category"], "mimics": c.get("mimics"),
                                   "generator": g["name"], "seed": g["seed"], "files": flist,
                                   "text_sha256": payload_sha(r["text"]), "text": r["text"]})
            else:
                p = G.generate(g["name"], g["seed"], g.get("params", {}))
                text_rows.append({"id": c["id"], "category": c["category"], "mimics": c.get("mimics"),
                                  "channel": c["channel"], "generator": g["name"], "seed": g["seed"],
                                  "sha256": payload_sha(p), "payload": p})
        except Exception as e:  # report, never print case text
            errors.append(f"{c['id']}: {type(e).__name__}: {e}"[:300])
    return text_rows, image_rows, files, errors


def manifest(cases, text_rows, image_rows, images: bool) -> dict:
    per = {r["id"]: r["sha256"] for r in text_rows}
    for r in image_rows:
        per[r["id"]] = hashlib.sha256("".join(f["sha256"] for f in r["files"]).encode()).hexdigest()
    counts = Counter()
    for r in text_rows + image_rows:
        counts[r["category"] if r["category"] != "hard_negative" else f"hard_negative:{r['mimics']}"] += 1
    env = {"python": platform.python_version(), "unicodedata": unicodedata.unidata_version}
    if images and image_rows:
        import gen_render
        env.update(gen_render.environment())
    spec = hashlib.sha256()
    for c in cases:
        spec.update(json.dumps(c, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n")
    setfp = hashlib.sha256("".join(f"{k}\t{v}\n" for k, v in sorted(per.items())).encode()).hexdigest()
    return {"format": FORMAT, "generators_version": G.VERSION, "code_sha256": G.code_fingerprint(),
            "environment": env, "images": images, "spec_fingerprint": spec.hexdigest(),
            "set_fingerprint": setfp, "cases": len(per), "text_cases": len(text_rows),
            "image_cases": len(image_rows), "image_files": sum(len(r["files"]) for r in image_rows),
            "counts": dict(sorted(counts.items())), "case_sha256": dict(sorted(per.items()))}


def write_jsonl(path: Path, rows) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", type=Path, action="append", help="default: cases/")
    ap.add_argument("--out", type=Path, default=LOCAL / "generated")
    ap.add_argument("--no-images", action="store_true")
    ap.add_argument("--check", action="store_true", help="regenerate and compare with <out>/manifest.json")
    a = ap.parse_args(argv)
    out = a.out.resolve()
    if HERE.parent.parent in out.parents or out == HERE.parent.parent:
        print("refused: --out must be outside the repo")
        return 2
    cases = load(a.cases or [HERE / "cases"])
    images = not a.no_images
    if images:
        try:
            import gen_render  # noqa: F401
        except ImportError as e:
            print(f"refused: images need Pillow ({e}); use --no-images")
            return 2
    text_rows, image_rows, files, errors = build(cases, images)
    if errors:
        print(f"{len(errors)} generator errors:")
        print("\n".join(errors[:20]))
        return 2
    m = manifest(cases, text_rows, image_rows, images)
    if a.check:
        old = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        diff = [k for k in set(old["case_sha256"]) | set(m["case_sha256"])
                if old["case_sha256"].get(k) != m["case_sha256"].get(k)]
        env_diff = old.get("environment") != m["environment"] or old.get("code_sha256") != m["code_sha256"]
        print(f"check: {len(m['case_sha256'])} cases, {len(diff)} differ; set {m['set_fingerprint'][:16]} "
              f"vs {old['set_fingerprint'][:16]}{'; code/environment changed' if env_diff else ''}")
        for k in sorted(diff)[:20]:
            print("  differs:", k)
        return 1 if diff else 0
    (out / "images").mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "payloads.jsonl", text_rows)
    write_jsonl(out / "images.jsonl", image_rows)
    for old in (out / "images").iterdir():
        if old.name not in files:
            old.unlink()
    for name, data in files.items():
        (out / "images" / name).write_bytes(data)
    (out / "manifest.json").write_text(json.dumps(m, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{m['cases']} cases ({m['text_cases']} text, {m['image_cases']} image cases / {m['image_files']} files); "
          f"set {m['set_fingerprint'][:16]}; out {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
