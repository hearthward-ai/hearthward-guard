#!/usr/bin/env python3
"""fetch.py - download approved public attack datasets at pinned revisions.

Python standard library only. Safety rules:
  * Only sources with "approved": true and status "candidate" in sources.json.
  * Downloads go into a NEW or EMPTY folder you name (never the repo itself).
  * HTTPS only, to an allowlist of hosts (redirects are checked too).
  * Every file is checked for exact size and hash (sha256, or git blob sha1 at
    the pinned commit) before it is kept; mismatches are deleted.
  * Nothing downloaded is extracted, imported or executed. A MANIFEST.lock.json
    with sha256 of every kept file is written next to the data.

Usage:
  python -I fetch.py --list
  python -I fetch.py --dest D:\\attack-cache --source bipia [--source agentdojo ...]
Exit code 0 = ok, 1 = a file failed, 2 = refused (usage, approval, folder).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCES = HERE / "sources.json"
ALLOWED_HOSTS = ("huggingface.co", "raw.githubusercontent.com", "files.pythonhosted.org")
ALLOWED_SUFFIXES = (".hf.co", ".huggingface.co")  # HF LFS / Xet CDN redirects
CHUNK = 1 << 16
TIMEOUT = 60


class Refused(Exception):
    pass


def host_ok(url: str) -> bool:
    u = urllib.parse.urlsplit(url)
    h = (u.hostname or "").lower()
    return u.scheme == "https" and (h in ALLOWED_HOSTS or h.endswith(ALLOWED_SUFFIXES))


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def verify(data: bytes, spec: dict) -> str | None:
    """Return None if data matches the pinned size and hash, else the reason."""
    if len(data) != spec["size"]:
        return f"size {len(data)} != {spec['size']}"
    if "sha256" in spec and hashlib.sha256(data).hexdigest() != spec["sha256"]:
        return "sha256 mismatch"
    if "git_blob_sha1" in spec and git_blob_sha1(data) != spec["git_blob_sha1"]:
        return "git blob sha1 mismatch"
    if "sha256" not in spec and "git_blob_sha1" not in spec:
        return "no pinned hash"
    return None


class _CheckedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not host_ok(newurl):
            raise Refused(f"redirect to a host that is not allowed: {urllib.parse.urlsplit(newurl).hostname}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def http_get(url: str, max_bytes: int) -> bytes:
    if not host_ok(url):
        raise Refused(f"host not allowed: {urllib.parse.urlsplit(url).hostname}")
    opener = urllib.request.build_opener(_CheckedRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "attack-bench-fetch/1"})
    buf = bytearray()
    with opener.open(req, timeout=TIMEOUT) as r:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes:
                raise Refused("file larger than pinned size")
    return bytes(buf)


def load_sources(path: Path = SOURCES) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {s["id"]: s for s in data["sources"]}


def check_dest(dest: Path) -> None:
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise Refused("destination must be a new or empty folder")
    try:
        dest.resolve().relative_to(HERE.parent.parent)
        raise Refused("destination must be outside the repo")
    except ValueError:
        pass


def safe_dest(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    p.relative_to(root.resolve())  # raises ValueError on ../ escapes
    return p


def select(sources: dict, ids: list[str]) -> list[dict]:
    out = []
    for i in ids:
        s = sources.get(i)
        if s is None:
            raise Refused(f"unknown source: {i}")
        if s.get("status") != "candidate":
            raise Refused(f"source {i} is {s.get('status')}: not fetchable")
        if s.get("approved") is not True:
            raise Refused(f"source {i} is not approved yet (see DATASETS.md)")
        out.append(s)
    return out


def fetch(dest: Path, chosen: list[dict], get=http_get) -> int:
    check_dest(dest)
    dest.mkdir(parents=True, exist_ok=True)
    manifest, failed = [], 0
    for s in chosen:
        for f in s["files"]:
            target = safe_dest(dest, f["dest"])
            try:
                data = get(f["url"], f["size"])
                why = verify(data, f)
            except (Refused, OSError) as exc:
                why = f"{type(exc).__name__}: {exc}"
            if why:
                failed += 1
                print(f"FAIL {s['id']} {f['dest']}: {why}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            manifest.append({"source": s["id"], "revision": s["revision"], "licence": s["licence"],
                             "url": f["url"], "path": f["dest"], "size": len(data),
                             "sha256": hashlib.sha256(data).hexdigest()})
            print(f"ok   {s['id']} {f['dest']}")
    (dest / "MANIFEST.lock.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return 1 if failed else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--list", action="store_true", help="show sources and their approval state")
    ap.add_argument("--dest", type=Path)
    ap.add_argument("--source", action="append", default=[])
    a = ap.parse_args(argv)
    sources = load_sources()
    if a.list:
        for s in sources.values():
            print(f"{s['id']:38} {s['status']:9} approved={s['approved']!s:5} {s['licence']}")
        return 0
    if not a.dest or not a.source:
        ap.print_usage()
        return 2
    try:
        return fetch(a.dest, select(sources, a.source))
    except Refused as exc:
        print(f"refused: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
