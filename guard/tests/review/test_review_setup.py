"""Review 2026-11-17: load, probe and preflight paths that fail open or say less than they should
(__init__.py, common/compat.py, common/config.py, tools/preflight.py)."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import time
import unittest

from tests.review._review import known_open
from tests.unit import fakes
import hearthward_guard
from hearthward_guard.common import compat

import preflight  # noqa: E402  (guard/tools, put on sys.path by _review)


class TestRegister(unittest.TestCase):
    def test_control_setup_error_gives_a_refuse_all_guard(self):
        g = hearthward_guard.register(fakes.Ctx())          # outside Hermes: probes fail, hooks still registered
        self.assertFalse(g.healthy)

    def test_M11_import_failure_leaves_hermes_without_any_hook(self):
        """`from .hooks import Guard` sits outside register()'s try block. If any guard module fails
        to import (damaged file, half-finished update), register() raises, Hermes disables the
        plugin and keeps running with no guard at all."""
        ctx = fakes.Ctx()
        saved = sys.modules.pop("hearthward_guard.hooks")
        sys.modules["hearthward_guard.hooks"] = None         # makes the import raise
        try:
            try:
                hearthward_guard.register(ctx)
            except Exception as e:  # noqa: BLE001
                self.fail(f"register() raised {type(e).__name__}; no refuse-all hooks were registered")
        finally:
            sys.modules["hearthward_guard.hooks"] = saved
        self.assertEqual(set(ctx.hooks), set(hearthward_guard.HOOK_NAMES))


class TestPreflight(unittest.TestCase):
    CFG = {"plugins": {"enabled": ["hearthward-guard"], "hook_callback_timeout": 0,
                       "entries": {"hearthward-guard": {"settings": {"owners": ["chatapp:1"]}}}},
           "gateway": {"strict": True, "trust_recent_files": False}, "platform_toolsets": {"chatapp": ["no_mcp"]}}

    def _run(self, settings):
        cfg = json.loads(json.dumps(self.CFG))
        cfg["plugins"]["entries"]["hearthward-guard"]["settings"].update(settings)
        buf = io.StringIO()
        orig = compat.read_hermes_config
        compat.read_hermes_config = lambda: cfg
        try:
            with contextlib.redirect_stdout(buf):
                rc = preflight.main([], cfg=cfg, env={})
        finally:
            compat.read_hermes_config = orig
        return rc, buf.getvalue()

    def test_L3_preflight_prints_a_setting_value(self):
        """preflight's docstring: 'It never prints config values, only key names.'"""
        typo = "pasted-into-the-wrong-box-" + "1234"
        rc, out = self._run({"mode": typo})
        self.assertEqual(rc, 1)
        self.assertNotIn(typo, out)

    def test_L3_preflight_prints_an_out_of_range_number(self):
        rc, out = self._run({"holds": {"timeout_min": 987654321}})
        self.assertEqual(rc, 1)
        self.assertNotIn("987654321", out)

    def test_M11_heartbeat_of_another_process_satisfies_the_check(self):
        """status.py says a supervisor checks 'the file for the gateway's pid'; check_heartbeat
        accepts any fresh healthy file in the folder."""
        td = fakes.TmpDir()
        try:
            now = time.time()
            td.file("11111.json", json.dumps({"pid": 11111, "ts": now, "healthy": True, "problems": []}).encode())
            sig = preflight.check_heartbeat.__code__.co_varnames[:preflight.check_heartbeat.__code__.co_argcount]
            self.assertIn("pid", sig, "check_heartbeat cannot be told which gateway process to look for")
        finally:
            td.cleanup()


class TestProbes(unittest.TestCase):
    def test_M5_new_event_field_with_a_neutral_name_is_not_flagged(self):
        import dataclasses

        @dataclasses.dataclass
        class FutureEvent(fakes.Event):
            entities: list = dataclasses.field(default_factory=list)        # e.g. hidden link text
            thread_history: list = dataclasses.field(default_factory=list)

        problems: list = []
        compat.probe_event_fields(problems, FutureEvent)
        self.assertTrue(any("entities" in p or "thread_history" in p for p in problems),
                        "an unreviewed field passes the probe unless its NAME contains a content word")

    def test_M11_safe_worker_mode_is_not_probed(self):
        """API-SPIKE probe list item 5: 'safe_worker_enabled() is False at load and on every
        heartbeat' (safe workers skip plugin hooks). compat.py has no such probe."""
        self.assertTrue(any("safe_worker" in name for name in dir(compat)))


if __name__ == "__main__":
    unittest.main()
