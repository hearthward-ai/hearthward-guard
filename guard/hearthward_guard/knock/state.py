"""Knock's small on-disk memory (decision review 2026-11-17, picks 3 and 5).

<data dir>/knock-state.json, owner-only (folder 0700, file 0600, written atomically). It keeps, across
conversations and gateway restarts:
  armed         files whose content matched a never rule when they were written, or that a card showed
                only in part, or that were edited under a grant: path -> [rule id, label]
  remote_paths  paths written by network fetches (clone, download, pip/npm output): reading them is REMOTE

A missing file is a fresh start. A file that is unreadable or has the wrong shape is a guard problem:
Knock refuses every tool until the owner fixes or moves the file (fail closed; nothing is guessed).
To forget everything Knock remembers, stop the gateway and move the file away.
"""
from __future__ import annotations

import json
import os

from ..common import status

FILE_NAME = "knock-state.json"
MAX_ARMED = 1000
MAX_REMOTE = 2000
_KEY_MAX = 512


class StateError(ValueError):
    pass


def path_for(data_dir: str) -> str:
    return os.path.join(data_dir, FILE_NAME) if data_dir else ""


def load(path: str) -> tuple[list, list]:
    """-> (armed [(path, (rid, label))], remote_paths [path]). Raises StateError on a bad file."""
    if not path or not os.path.exists(path):
        return [], []
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read(4_000_001)
        if len(raw) > 4_000_000:
            raise StateError("too large")
        data = json.loads(raw)
    except StateError:
        raise
    except Exception as e:
        raise StateError(f"unreadable ({type(e).__name__})") from None
    if not isinstance(data, dict) or data.get("version") != 1:
        raise StateError("unknown format")
    armed, remote = data.get("armed", []), data.get("remote_paths", [])
    if not isinstance(armed, list) or not isinstance(remote, list):
        raise StateError("wrong shape")
    out_a = []
    for e in armed[-MAX_ARMED:]:
        if not (isinstance(e, list) and len(e) == 3 and all(isinstance(x, str) for x in e)
                and 0 < len(e[0]) <= _KEY_MAX and len(e[1]) <= 64 and len(e[2]) <= 200):
            raise StateError("bad armed entry")
        out_a.append((e[0], (e[1], e[2])))
    out_r = []
    for p in remote[-MAX_REMOTE:]:
        if not (isinstance(p, str) and 0 < len(p) <= _KEY_MAX):
            raise StateError("bad remote path entry")
        out_r.append(p)
    if os.name == "posix":
        try:
            if os.stat(path).st_mode & 0o077:
                os.chmod(path, 0o600)                     # owner-only, whatever made it wider
        except OSError:
            pass
    return out_a, out_r


def save(path: str, armed, remote_paths) -> None:
    if not path:
        return
    status.write_atomic(path, {"version": 1,
                               "armed": [[p, h[0], h[1]] for p, h in list(armed)[-MAX_ARMED:]],
                               "remote_paths": list(remote_paths)[-MAX_REMOTE:]})
