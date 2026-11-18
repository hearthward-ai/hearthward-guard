"""Fix round 2026-11-17: owner decisions for job 5 and fixes that the review tests do not cover directly."""
import os
import time
import unittest
from unittest import mock

from tests.unit import fakes
from tests.unit.fakes import ATTACK, OWNER, Gateway, dispatch, ev, make_guard
import hearthward_guard
from hearthward_guard import hooks
from hearthward_guard.common import messages
from hearthward_guard.threshold import holds, scan, second_check

NL = chr(10)


class TestRestartNotice(unittest.TestCase):
    """Owner decision 2: holds stay in memory; after a restart the owner hears how many were dropped."""

    def test_dropped_holds_reported_once_after_restart(self):
        td = fakes.TmpDir()
        try:
            g1 = hooks.Guard(fakes.OWNER_SETTINGS, data_dir=td.path)
            gw = Gateway()
            dispatch(g1, ev(ATTACK), gw)
            dispatch(g1, ev(ATTACK + " again"), gw)
            self.assertEqual(len(g1.holds), 2)
            g2 = hooks.Guard(fakes.OWNER_SETTINGS, data_dir=td.path)      # "restart"
            gw2 = Gateway()
            self.assertIsNone(dispatch(g2, ev("hello"), gw2))
            notes = [t for c, t in gw2.sent() if c == "owner-dm"]
            self.assertEqual(notes, [messages.RESTART_DROPPED.format(n=2)])
            dispatch(g2, ev("hello again"), gw2)
            self.assertEqual(len([t for c, t in gw2.sent() if c == "owner-dm"]), 1)
            with open(os.path.join(td.path, "pending-holds.json"), encoding="utf-8") as f:
                self.assertNotIn("ignore", f.read())                       # numbers only, never content
        finally:
            td.cleanup()


class TestDecisions(unittest.TestCase):
    def setUp(self):
        self.gw = Gateway()
        self.g = make_guard()

    def test_follow_release_goes_to_the_owner_conversation(self):
        """Decision 3: the release is a rewrite of the owner's own follow message."""
        dispatch(self.g, ev(ATTACK, chat="group-1"), self.gw)
        hid = self.g.holds.pending()[0].hold_id
        r = dispatch(self.g, ev(f"follow {hid}", user=OWNER, chat="owner-dm"), self.gw)
        self.assertEqual(r["action"], "rewrite")
        self.assertNotIn("group-1", [c for c, _t in self.gw.sent() if "released" in _t])

    def test_second_check_timeout_holds_tool_results(self):
        """Decision 4 on the tool path: a failed check withholds."""
        g = make_guard({"second_check": {"endpoint": "http://127.0.0.1:9/v1", "channels": ["tool_result"]}})
        with mock.patch.object(second_check, "_post", side_effect=TimeoutError("slow")):
            self.assertIn("was withheld", g.on_transform_tool_result(tool_name="web", result="plain page text"))

    def test_hold_ids_always_contain_a_digit(self):
        store = holds.HoldStore()
        for _ in range(200):
            hid = store._new_id()
            self.assertTrue(any(c.isdigit() for c in hid) and holds.ID_RX.match(hid), hid)

    def test_stranger_with_unknown_id_is_an_ordinary_message(self):
        self.assertIsNone(dispatch(self.g, ev("follow abc234"), self.gw))
        self.assertEqual(self.gw.sent(), [])

    def test_unreadable_attachment_of_owner_is_held_with_self_notice(self):
        td = fakes.TmpDir()
        try:
            p = td.file("x.txt", b"caf\xe9 menu")                        # Latin-1, not UTF-8 (review M8)
            r = dispatch(self.g, ev("menu", user=OWNER, chat="owner-dm", media_urls=[p], media_types=["text/plain"]),
                         self.gw)
            self.assertEqual(r, hooks.SKIP_HELD)
            self.assertTrue(any("attachment not checked" in t for _c, t in self.gw.sent()))
        finally:
            td.cleanup()


class TestLinearTime(unittest.TestCase):
    """Review H1 inputs at the full size limit (linear now; was minutes)."""

    def test_pathological_whitespace_and_comments(self):
        n = 119_000
        for name, text in (("newlines", "x" + NL * n), ("space-newline", (" " + NL) * (n // 2)),
                           ("comment-openers", "<!--" * (n // 4)), ("role-then-spaces", "system" + " " * (n - 10) + "x")):
            with self.subTest(name=name):
                t0 = time.perf_counter()
                v = scan.scan_text(text, "attachment", 120_000, None)
                self.assertLess(time.perf_counter() - t0, 3.0)
                self.assertNotIn("check-timeout", v.signals)

    def test_time_limit_holds(self):
        v = scan.scan_text("word " * 20_000, "attachment", 120_000, 0.000001)
        self.assertEqual(v.level, scan.HOLD)
        self.assertIn("check-timeout", v.signals)


class TestRefuseAllFallback(unittest.TestCase):
    def test_refuse_all_stub_refuses(self):
        stub = hearthward_guard._RefuseAll("ImportError")
        self.assertEqual(stub.on_pre_llm_call(user_message="hi")["action"], "block")
        self.assertEqual(stub.on_pre_tool_call(tool_name="x")["action"], "block")
        self.assertIn("withheld", stub.on_transform_tool_result(result="x"))
        self.assertNotEqual(stub.on_transform_llm_output(response_text="hi"), "hi")
        self.assertEqual(fakes.run(stub.on_pre_gateway_dispatch(event=None))["action"], "skip")


if __name__ == "__main__":
    unittest.main()
