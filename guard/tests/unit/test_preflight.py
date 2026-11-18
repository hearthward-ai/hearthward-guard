"""tools/preflight.py: every check fails closed; a good config passes."""
import contextlib
import importlib.util
import io
import json
import os
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from tests.unit import fakes
from hearthward_guard.common import compat

_spec = importlib.util.spec_from_file_location("preflight", os.path.join(fakes.ROOT, "tools", "preflight.py"))
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)


def good_cfg():
    return {
        "plugins": {"enabled": ["hearthward-guard"], "hook_callback_timeout": 0,
                    "entries": {"hearthward-guard": {"settings": dict(fakes.OWNER_SETTINGS)}}},
        "gateway": {"strict": True, "trust_recent_files": False},
        "platform_toolsets": {"chatapp": ["no_mcp"], "cli": ["hermes-cli"]},
    }


class TestCheckConfig(unittest.TestCase):
    def test_good(self):
        self.assertEqual(preflight.check_config(good_cfg(), {}, ["chatapp"], ("no_mcp",)), [])

    def test_each_bad_setting(self):
        mutations = {
            "not-enabled": lambda c: c["plugins"].update(enabled=[]),
            "disabled": lambda c: c["plugins"].update(disabled=["hearthward-guard"]),
            "timeout-default": lambda c: c["plugins"].pop("hook_callback_timeout"),
            "timeout-5": lambda c: c["plugins"].update(hook_callback_timeout=5),
            "timeout-junk": lambda c: c["plugins"].update(hook_callback_timeout="x"),
            "strict-missing": lambda c: c["gateway"].pop("strict"),
            "strict-string": lambda c: c["gateway"].update(strict="true"),
            "trust-default": lambda c: c["gateway"].pop("trust_recent_files"),
            "no-gateway": lambda c: c.pop("gateway"),
            "toolset-missing": lambda c: c["platform_toolsets"].pop("chatapp"),
            "toolset-extra": lambda c: c["platform_toolsets"].update(chatapp=["no_mcp", "terminal"]),
            "toolset-string": lambda c: c["platform_toolsets"].update(chatapp="hermes-chatapp"),
            "toolset-other-platform": lambda c: c["platform_toolsets"].update(otherapp=["web"]),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                c = good_cfg()
                mutate(c)
                self.assertTrue(preflight.check_config(c, {}, ["chatapp"], ("no_mcp",)), name)

    def test_env_overrides(self):
        for env in ({"HERMES_MEDIA_DELIVERY_STRICT": "0"}, {"HERMES_MEDIA_TRUST_RECENT_FILES": "1"},
                    {"HERMES_MEDIA_ALLOW_DIRS": "/tmp"}):
            with self.subTest(env=env):
                self.assertTrue(preflight.check_config(good_cfg(), env, ["chatapp"], ("no_mcp",)))
        self.assertEqual(preflight.check_config(good_cfg(), {"HERMES_MEDIA_DELIVERY_STRICT": "1"}, ["chatapp"],
                                                ("no_mcp",)), [])

    def test_platforms_from_settings(self):
        self.assertEqual(preflight.platforms_from(good_cfg(), ["otherapp"]), ["chatapp", "otherapp"])


class TestCheckPlugin(unittest.TestCase):
    def setUp(self):
        self.td = fakes.TmpDir()
        self.env = mock.patch.dict(os.environ, {"HERMES_HOME": self.td.path, "HEARTHWARD_GUARD_HEARTBEAT": "0"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.td.cleanup()

    def test_plugin_ok_with_hermes_probes_passing(self):
        cfg = good_cfg()
        with mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                mock.patch.object(compat, "read_hermes_config", return_value=cfg):
            probs, guard = preflight.check_plugin(os.path.join(fakes.ROOT, "hearthward_guard"), cfg)
        self.assertEqual(probs, [])
        self.assertTrue(guard.healthy)

    def test_plugin_outside_hermes_fails(self):
        with mock.patch.object(compat, "read_hermes_config", side_effect=ImportError()):
            probs, _g = preflight.check_plugin(os.path.join(fakes.ROOT, "hearthward_guard"), good_cfg())
        self.assertTrue(any(p.startswith("guard: compat") for p in probs))

    def test_bad_settings_fail(self):
        cfg = good_cfg()
        cfg["plugins"]["entries"]["hearthward-guard"]["settings"]["threshold"] = {"nope": 1}
        with mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                mock.patch.object(compat, "read_hermes_config", return_value=cfg):
            probs, _g = preflight.check_plugin(os.path.join(fakes.ROOT, "hearthward_guard"), cfg)
        self.assertTrue(any("config" in p for p in probs))

    def test_missing_plugin_dir(self):
        with mock.patch.dict("sys.modules"):
            import sys
            sys.modules.pop("hearthward_guard", None)
            probs, g = preflight.check_plugin(os.path.join(self.td.path, "nope"), good_cfg())
        self.assertIsNone(g)
        self.assertTrue(probs)


class TestToolsCli(unittest.TestCase):
    def runner(self, out, code=0):
        return lambda args: SimpleNamespace(stdout=out, returncode=code)

    def test_outputs(self):
        self.assertEqual(preflight.check_tools_cli(["chatapp"], self.runner("web ✗ disabled\nterminal ✗ disabled")), [])
        self.assertTrue(preflight.check_tools_cli(["chatapp"], self.runner("web ✓ enabled")))
        self.assertTrue(preflight.check_tools_cli(["chatapp"], self.runner("", 0)))
        self.assertTrue(preflight.check_tools_cli(["chatapp"], self.runner("whatever", 1)))
        self.assertTrue(preflight.check_tools_cli(["chatapp"], self.runner("Web: on\nShell: on")))   # unknown format

        def boom(args):
            raise FileNotFoundError()
        self.assertTrue(preflight.check_tools_cli(["chatapp"], boom))
        self.assertEqual(preflight.check_tools_cli(["cli"], boom), [])


class TestOcrLine(unittest.TestCase):
    """Preflight names the picture reader and whether it was found (OCR build open item)."""
    ENGINE = "/" + "opt/ocr-test/tesseract"

    def test_found(self):
        from tests.unit import picfakes as P
        stub = P.StubEngine(["tesseract 5.3.4\n leptonica-1.82.0"])
        g = fakes.make_guard({"ocr": {"enabled": True, "engine_path": self.ENGINE}}, ocr_runner=stub)
        line = preflight.check_ocr(g)
        self.assertEqual(line, "OCR: engine found (tesseract, from ocr.engine_path, tesseract 5.3.4), language data ok")
        self.assertNotIn("/opt", line)                         # the configured path is never printed
        self.assertIn(["--version"], [c["argv"][1:] for c in stub.calls])

    def test_language_data_missing(self):
        from tests.unit import picfakes as P
        g = fakes.make_guard({"ocr": {"enabled": True, "engine_path": self.ENGINE}},
                             ocr_runner=P.StubEngine(["tesseract 5.3.4"], langs=("eng",)))
        self.assertIn("language data MISSING", preflight.check_ocr(g))

    def test_version_unreadable(self):
        from tests.unit import picfakes as P
        g = fakes.make_guard({"ocr": {"enabled": True, "engine_path": self.ENGINE}},
                             ocr_runner=P.StubEngine([""], rc=1))
        self.assertIn("version unknown", preflight.check_ocr(g))

    def test_not_found_and_off(self):
        g = fakes.make_guard({"ocr": {"enabled": True}})          # switched on, no engine: every picture held
        line = preflight.check_ocr(g)
        self.assertTrue(line.startswith("OCR: engine NOT found ("), line)
        self.assertIn("every picture will be held", line)
        g = fakes.make_guard({"ocr": {"enabled": False}})
        self.assertIn("not used (switched off", preflight.check_ocr(g))
        self.assertEqual(preflight.check_ocr(None), "")

    def test_main_prints_the_line(self):
        td = fakes.TmpDir()
        try:
            with mock.patch.dict(os.environ, {"HERMES_HOME": td.path, "HEARTHWARD_GUARD_HEARTBEAT": "0"}), \
                    mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                    mock.patch.object(compat, "read_hermes_config", return_value=good_cfg()):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = preflight.main([], cfg=good_cfg(), env={})
        finally:
            td.cleanup()
        self.assertEqual(code, 0, buf.getvalue())
        self.assertIn("OCR: ", buf.getvalue())


class TestHeartbeat(unittest.TestCase):
    def setUp(self):
        self.td = fakes.TmpDir()

    def tearDown(self):
        self.td.cleanup()

    def write(self, name, data):
        with open(os.path.join(self.td.path, name), "w", encoding="utf-8") as f:
            f.write(data if isinstance(data, str) else json.dumps(data))

    def test_states(self):
        now = time.time()
        self.assertTrue(preflight.check_heartbeat(os.path.join(self.td.path, "missing"), 60, now))
        self.assertTrue(preflight.check_heartbeat(self.td.path, 60, now))
        self.write("1.json", {"ts": now - 600, "healthy": True})
        self.assertTrue(preflight.check_heartbeat(self.td.path, 60, now))
        self.write("2.json", "{broken")
        self.assertTrue(preflight.check_heartbeat(self.td.path, 60, now))
        self.write("3.json", {"ts": now - 5, "healthy": True})
        self.assertEqual(preflight.check_heartbeat(self.td.path, 60, now), [])
        self.write("4.json", {"ts": now - 5, "healthy": False, "problems": ["compat: x"]})
        self.assertTrue(preflight.check_heartbeat(self.td.path, 60, now))


class TestMain(unittest.TestCase):
    def run_main(self, argv, cfg, env=None):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = preflight.main(argv, cfg=cfg, env=env or {})
        return code, buf.getvalue()

    def test_main_codes(self):
        td = fakes.TmpDir()
        try:
            with mock.patch.dict(os.environ, {"HERMES_HOME": td.path, "HEARTHWARD_GUARD_HEARTBEAT": "0"}), \
                    mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                    mock.patch.object(compat, "read_hermes_config", return_value=good_cfg()):
                code, out = self.run_main([], good_cfg())
                self.assertEqual(code, 0, out)
                bad = good_cfg()
                bad["gateway"]["strict"] = False
                code, out = self.run_main([], bad)
                self.assertEqual(code, 1)
                self.assertIn("FAIL: gateway.strict", out)
                nop = good_cfg()
                nop["plugins"]["entries"]["hearthward-guard"]["settings"] = {}
                self.assertEqual(self.run_main([], nop)[0], 1)
                code, out = self.run_main(["--heartbeat", "--heartbeat-dir", os.path.join(td.path, "none")], good_cfg())
                self.assertEqual(code, 1)
        finally:
            td.cleanup()
        with mock.patch.object(preflight, "read_hermes_config", side_effect=ImportError()):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(preflight.main([], env={}), 2)

    def test_output_never_prints_values(self):
        cfg = good_cfg()
        secretish = "VALUE" + "1234567890"
        cfg["gateway"]["strict"] = secretish
        cfg["platform_toolsets"]["chatapp"] = ["no_mcp"]
        td = fakes.TmpDir()
        try:
            with mock.patch.dict(os.environ, {"HERMES_HOME": td.path, "HEARTHWARD_GUARD_HEARTBEAT": "0"}):
                code, out = self.run_main([], cfg, env={"HERMES_MEDIA_ALLOW_DIRS": secretish})
        finally:
            td.cleanup()
        self.assertEqual(code, 1)
        self.assertNotIn(secretish, out)


if __name__ == "__main__":
    unittest.main()
