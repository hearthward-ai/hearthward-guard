"""Heartbeat: <data dir>/status/<pid>.json, rewritten every interval by a daemon thread.

A supervisor (see the examples) refuses to start or keeps the gateway stopped when the file for
the gateway's pid is missing, stale, or says healthy=false. Stale files of dead processes are
removed on start.
"""
from __future__ import annotations

import json
import os
import threading
import time


def data_dir() -> str:
    """$HERMES_HOME/hearthward-guard (HERMES_HOME from Hermes when available, else env, else ~/.hermes)."""
    home = ""
    try:
        from hermes_constants import get_hermes_home
        home = str(get_hermes_home())
    except Exception:
        home = os.getenv("HERMES_HOME", "") or os.path.join(os.path.expanduser("~"), ".hermes")
    return os.path.join(home, "hearthward-guard")


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return _alive_windows(pid)   # os.kill(pid, 0) terminates the process on Windows: never call it there
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _alive_windows(pid: int) -> bool:
    """OpenProcess + GetExitCodeProcess (review L10). Unknown = alive (never delete a live file)."""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)          # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return k32.GetLastError() == 5               # access denied: it exists
        try:
            code = ctypes.c_ulong()
            if not k32.GetExitCodeProcess(h, ctypes.byref(code)):
                return True
            return code.value == 259                     # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except Exception:
        return True


def write_atomic(path: str, data: dict) -> None:
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


class Heartbeat:
    def __init__(self, directory: str, interval_s: int, snapshot):
        self.directory = directory
        self.interval = interval_s
        self.snapshot = snapshot          # () -> dict
        self.path = os.path.join(directory, f"{os.getpid()}.json")
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.errors = 0

    def beat(self) -> bool:
        try:
            data = dict(self.snapshot())
            data.update(pid=os.getpid(), ts=round(time.time(), 3))
            write_atomic(self.path, data)
            return True
        except Exception:
            self.errors += 1
            return False

    def cleanup_stale(self) -> int:
        n = 0
        try:
            for name in os.listdir(self.directory):
                if not name.endswith(".json"):
                    continue
                try:
                    pid = int(name[:-5])
                except ValueError:
                    continue
                if pid != os.getpid() and not _alive(pid):
                    try:
                        os.remove(os.path.join(self.directory, name))
                        n += 1
                    except OSError:
                        pass
        except OSError:
            pass
        return n

    def start(self) -> None:
        if self._thread is not None:
            return
        self.cleanup_stale()
        self.beat()

        def run():
            while not self._stop.wait(self.interval):
                self.beat()

        self._thread = threading.Thread(target=run, name="hearthward-guard-heartbeat", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            os.remove(self.path)
        except OSError:
            pass
