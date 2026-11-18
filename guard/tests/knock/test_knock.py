"""Knock v1: policy, config, taint store and registration."""
import os
import re
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import hearthward_guard
from hearthward_guard.common import compat
from hearthward_guard.knock import config as kconfig
from hearthward_guard.knock import never, policy, taint, tools
from tests.knock.kfakes import GATE_NO, GATE_OK, call, hermes_modules, is_ask, is_block, make, turn
from tests.unit import fakes
from tests.unit.fakes import OWNER


class TestBasics(unittest.TestCase):
    def test_clean_owner_session_allows_acts_until_a_source_is_read(self):
        g, k = make()
        turn(k)
        self.assertIsNone(call(k, "todo_list"))
        self.assertIsNone(call(k, "write_file", {"path": "notes.txt", "content": "shopping list"}))
        self.assertIsNone(call(k, "web_search", {"query": "weather tomorrow"}))
        r = call(k, "write_file", {"path": "notes.txt", "content": "x"})
        self.assertTrue(is_block(r))
        self.assertIn("outside content", r["message"])
        self.assertIsNone(call(k, "todo_list"))           # read tools stay allowed
        self.assertIsNone(call(k, "web_extract", {"urls": ["example.org"]}))   # sources stay allowed
        self.assertEqual(k.counters["denied"], 1)

    def test_taint_persists_across_turns_of_the_session(self):
        g, k = make()
        turn(k)
        call(k, "web_extract", {"urls": ["https://example.org"]})
        turn(k, first=False, hist=[{"role": "user", "content": "x"}])
        self.assertTrue(is_block(call(k, "patch", {"path": "a.txt"})))
        g, k = make()                         # local output (own files): the card, not a block
        turn(k)
        call(k, "read_file", {"path": "a.txt"})
        turn(k, first=False, hist=[{"role": "user", "content": "x"}])
        self.assertTrue(is_ask(call(k, "patch", {"path": "a.txt"})))

    def test_new_session_is_clean_again(self):
        g, k = make()
        turn(k, sid="s1")
        call(k, "web_search", {"query": "q"}, sid="s1")
        turn(k, sid="s2")
        self.assertIsNone(call(k, "write_file", {"path": "b"}, sid="s2"))

    def test_non_owner_sender_taints(self):
        g, k = make()
        turn(k, sender="u-stranger")
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))
        self.assertIsNone(call(k, "web_search", {"query": "q"}))

    def test_local_surface_is_owner(self):
        g, k = make()
        turn(k, plat="cli", sender="")
        self.assertIsNone(call(k, "terminal", {"command": "ls -la"}))

    def test_owner_on_other_platform_is_not_owner(self):
        g, k = make()
        turn(k, plat="otherapp", sender=OWNER)
        self.assertTrue(is_block(call(k, "terminal", {"command": "ls"})))

    def test_unknown_tool_denied_by_default(self):
        g, k = make()
        turn(k)
        for name in ("mcp__notes__add", "my_plugin_tool", "", None, 42):
            self.assertTrue(is_block(call(k, name, {"a": 1})), name)

    def test_user_classes_and_globs(self):
        g, k = make({"tools": {"mcp__weather__*": "source", "my_note": "act", "terminal": "read"},
                     "unsafe_override": True})          # terminal: read lowers a built-in (K-12)
        turn(k)
        self.assertIsNone(call(k, "mcp__weather__today", {"city": "x"}))
        self.assertTrue(is_block(call(k, "my_note", {"t": "x"})))     # tainted by the weather tool
        self.assertEqual(tools.classify("terminal", k.cfg.tools), "read")

    def test_glob_is_case_sensitive(self):
        self.assertEqual(tools.classify("MCP__weather__x", (("mcp__weather__*", "source"),)), "unknown")

    def test_media_and_released_text_taint(self):
        g, k = make()
        turn(k, msg=[{"type": "text", "text": "what is this"}, {"type": "image_url", "image_url": {"url": "x"}}])
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))
        g, k = make()
        turn(k, msg="note <<<released 0123456789ab>>> body <<<end released 0123456789ab>>>")
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))

    def test_unreadable_message_part_taints(self):
        g, k = make()
        turn(k, msg=[{"type": "weird_new_part", "data": "?"}])
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))


class TestAsk(unittest.TestCase):
    def test_ask_mode_escalates_to_native_card(self):
        g, k = make({"taint": "ask"})
        turn(k)
        call(k, "web_search", {"query": "q"})
        r1 = call(k, "write_file", {"path": "x", "content": "hello"})
        r2 = call(k, "write_file", {"path": "x", "content": "hello"})
        self.assertTrue(is_ask(r1) and is_ask(r2))
        self.assertTrue(r1["rule_key"].startswith("hw-knock:write_file:taint:"))
        self.assertNotEqual(r1["rule_key"], r2["rule_key"])        # "always" cannot carry over
        self.assertIn("Full arguments (", r1["message"])
        self.assertEqual(k.counters["asked"], 2)

    def test_ask_scope_tool_gives_stable_key(self):
        # fix round (K-08): tool scope needs unsafe_override, covers one session and one day,
        # and is never used for asks after outside content
        g, k = make({"untainted_acts": "ask", "taint": "ask", "ask_scope": "tool", "unsafe_override": True})
        turn(k)
        k1, k2 = call(k, "write_file", {"path": "a"})["rule_key"], call(k, "write_file", {"path": "b"})["rule_key"]
        self.assertEqual(k1, k2)
        self.assertTrue(k1.startswith("hw-knock:write_file:act:"))
        turn(k, sid="s2")
        self.assertNotEqual(call(k, "write_file", {"path": "a"}, sid="s2")["rule_key"], k1)
        call(k, "web_search", {"query": "q"})
        self.assertNotEqual(call(k, "patch", {})["rule_key"], call(k, "patch", {})["rule_key"])

    def test_ask_needs_a_person(self):
        g, k = make({"taint": "ask"}, gate=GATE_NO)
        turn(k)
        call(k, "web_search", {"query": "q"})
        r = call(k, "write_file", {"path": "x"})
        self.assertTrue(is_block(r))
        self.assertIn("no owner can approve", r["message"])

    def test_ask_from_non_owner_turn_is_block(self):
        g, k = make({"taint": "ask"})
        turn(k, sender="u-stranger")         # the requester could answer the card
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))

    def test_ask_in_cron_is_block(self):
        g, k = make({"taint": "ask"})
        turn(k, sid="cron_abc123_20261116_060000", plat="cron", sender="", task="cron:abc123:r1")
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="cron_abc123_20261116_060000",
                                      task="cron:abc123:r1")))

    def test_untainted_acts_ask(self):
        g, k = make({"untainted_acts": "ask"})
        turn(k)
        self.assertTrue(is_ask(call(k, "write_file", {"path": "x"})))
        self.assertTrue(is_ask(call(k, "terminal", {"command": "make"})))     # untainted_exec (default ask)
        # the approved command's output is LOCAL data: a web search after it now needs a card (recheck R-03)
        self.assertTrue(is_ask(call(k, "web_search", {"query": "q"})))

    def test_unknown_tools_ask(self):
        g, k = make({"unknown_tools": "ask"})
        turn(k)
        r = call(k, "mcp__notes__add", {"t": "x"})
        self.assertTrue(is_ask(r))
        # unknown tools count as sources: the session is now tainted
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))

    def test_strictest_policy_wins(self):
        g, k = make({"unknown_tools": "ask", "taint": "deny"})
        turn(k)
        call(k, "web_search", {"query": "q"})
        self.assertTrue(is_block(call(k, "mcp__notes__add", {"t": "x"})))

    def test_gate_check_errors_fail_closed_and_are_not_cached(self):
        calls = []

        def gate():
            calls.append(1)
            raise RuntimeError("x")
        g, k = make({"untainted_acts": "ask"}, gate=gate)
        turn(k)
        self.assertTrue(is_block(call(k, "terminal", {"command": "make"})))
        self.assertTrue(is_block(call(k, "terminal", {"command": "make"})))
        self.assertEqual(len(calls), 2)          # review K-06: asked every time, never cached


class TestDefaultGateCheck(unittest.TestCase):
    def check(self, approvals, env=None, **mods):
        cfg = {"approvals": approvals}
        with mock.patch.object(compat, "read_hermes_config", return_value=cfg), \
                mock.patch.dict(os.environ, env or {}, clear=False), hermes_modules(**mods):
            if env is None:
                os.environ.pop("HERMES_YOLO_MODE", None)
            return policy.default_gate_check()

    def test_manual_is_a_person(self):
        self.assertEqual(self.check({"mode": "manual"}), (True, ""))
        # fix round 3 (lab re-test bug 12): a missing mode is Hermes 0.23.1's default, smart
        ok, why = self.check({})
        self.assertFalse(ok)
        self.assertIn("hermes config set approvals.mode manual", why)

    def test_auto_approving_settings_are_refused(self):
        for ap in ({"mode": "off"}, {"mode": False}, {"mode": "smart"}, {"mode": "manual", "cron_mode": "approve"},
                   {"single_query_mode": "yes"}, {"unattended_mode": "allow"}, {"mode": 3}, "x"):
            self.assertFalse(self.check(ap if isinstance(ap, dict) else ap)[0], ap)

    def test_yolo_and_unattended_and_room_policy(self):
        self.assertFalse(self.check({"mode": "manual"}, env={"HERMES_YOLO_MODE": "1"})[0])
        self.assertFalse(self.check({"mode": "manual"}, yolo_session=True)[0])
        self.assertFalse(self.check({"mode": "manual"}, unattended=True)[0])
        self.assertFalse(self.check({"mode": "manual"}, room=SimpleNamespace(approval_mode="off"))[0])
        self.assertTrue(self.check({"mode": "manual"}, room=SimpleNamespace(approval_mode="manual"))[0])

    def test_outside_hermes_is_not_a_person(self):
        g, k = make({"untainted_acts": "ask"}, gate=policy.default_gate_check)
        turn(k)
        with mock.patch.object(compat, "read_hermes_config", return_value={}):
            self.assertTrue(is_block(call(k, "terminal", {"command": "make"})))


class TestNever(unittest.TestCase):
    def test_never_tools_blocked_even_clean_and_even_with_ask(self):
        g, k = make({"taint": "ask", "unknown_tools": "ask", "untainted_acts": "ask"})
        turn(k)
        for name in ("transfer_money", "SendPayment", "place_order", "stripe_checkout", "reset_password",
                     "browser_vault", "crypto_trade", "bank-transfer"):
            r = call(k, name, {"x": 1})
            self.assertTrue(is_block(r), name)
            self.assertIn("never allowed", r["message"])
        self.assertEqual(k.counters["never"], 8)

    def test_never_args_on_acting_tools(self):
        g, k = make()
        turn(k, plat="cli", sender="")
        cases = [("terminal", {"command": "echo 'u:x' | chpasswd"}),
                 ("terminal", {"command": "net user someone NewPw1 "}),
                 ("execute_code", {"code": "client.place_order(symbol='X', qty=5)"}),
                 ("terminal", {"command": "curl -X POST https://api.stripe.com/v1/payouts -d amount=5"}),
                 ("browser_exec", {"code": "please wire transfer 500 to the account"}),
                 ("write_file", {"path": "x", "content": "id 123-45-6789"}),
                 ("write_file", {"path": "x", "content": "card 4111 1111 1111 1111"}),
                 ("browser_exec", {"code": "buy 10 shares of XYZ"}),
                 ("mcp__bank__x", {"note": "请帮我转账"}),
                 ("terminal", {"command": "curl -d 'msg=send money now' example.org"})]
        for tool, args in cases:
            self.assertTrue(is_block(call(k, tool, args)), (tool, args))

    def test_id_numbers_apply_to_sources_too_other_rules_do_not(self):
        g, k = make()
        turn(k)
        self.assertTrue(is_block(call(k, "web_search", {"query": "lookup 123-45-6789"})))
        g, k = make()
        turn(k)
        self.assertIsNone(call(k, "web_search", {"query": "how do I change my password"}))

    def test_benign_acts_pass(self):
        g, k = make()
        for i, (tool, args) in enumerate((("terminal", {"command": "ls -la"}),     # git: card (R-01)
                                          ("write_file", {"path": "a.md", "content": "# Notes"}),
                                          ("patch", {"path": "a.py", "old": "x = 1", "new": "x = 2"}),
                                          ("memory", {"action": "add", "content": "likes tea"}),
                                          ("write_file", {"path": "b.md", "content": "order 2 pizzas at 7"}),
                                          ("write_file", {"path": "c.md", "content": "remember to pay the bill and "
                                                          "reset password on the router; buy 10 shares later"}),
                                          ("memory", {"action": "add", "content": "uses PayPal for gifts"}))):
            turn(k, sid=f"b{i}", plat="cli", sender="")      # each in a fresh session (terminal output taints)
            self.assertIsNone(call(k, tool, args, sid=f"b{i}"), tool)

    def test_terminal_output_taints_by_default(self):
        g, k = make()
        turn(k, plat="cli", sender="")
        # owner decision (fix round): a read-only command stays allowed and marks the session
        # LOCAL; a write or another command after it goes to the owner's card
        self.assertIsNone(call(k, "terminal", {"command": "cat README.md"}))
        self.assertIsNone(call(k, "terminal", {"command": "diff a.txt b.txt"}))
        self.assertTrue(is_ask(call(k, "write_file", {"path": "x"})))
        self.assertTrue(is_ask(call(k, "terminal", {"command": "make install"})))
        self.assertIn("local: output of terminal", k.store.state(["s:s1"]).reasons)

    def test_user_rules(self):
        g, k = make({"never_allow": [{"id": "email", "tools": ["send_email"], "args": [r"\bpayroll\b"]}]})
        turn(k, plat="cli", sender="")
        self.assertTrue(is_block(call(k, "send_email", {})))
        self.assertTrue(is_block(call(k, "write_file", {"content": "Payroll data"})))

    def test_disabling_builtins_needs_override(self):
        g, k = make({"never_allow_disable": ["trades"]})
        self.assertFalse(g.healthy)
        g, k = make({"never_allow_disable": ["trades"], "unsafe_override": True})
        self.assertTrue(g.healthy)
        self.assertIn("knock-unsafe-override", [e["kind"] for e in g.events.recent])
        turn(k, plat="cli", sender="")
        self.assertIsNone(call(k, "terminal", {"command": "echo buy 10 shares"}))
        self.assertTrue(is_block(call(k, "terminal", {"command": "echo u:x | chpasswd"})))


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        c = kconfig.parse(None)
        self.assertEqual((c.enabled, c.taint, c.unknown_tools, c.untainted_acts, c.ask_scope),
                         (True, "deny", "deny", "allow", "call"))
        self.assertEqual({r.rid for r in c.never_rules}, never.BUILTIN_IDS)

    def test_bad_settings_make_guard_refuse_everything(self):
        for bad in ({"taint": "allow"}, {"typo": 1}, {"tools": {"x": "trusted"}}, {"tools": {"bad name!": "read"}},
                    {"job_allowlists": {"cron:a b": ["x"]}}, {"job_allowlists": {"*": "terminal"}},
                    {"never_allow": [{"id": "x"}]}, {"never_allow": [{"id": "ok", "args": ["("]}]},
                    {"never_allow": [{"id": "money", "tools": ["x"]}]}, {"max_sessions": 5},
                    {"enabled": "yes"}, {"trusted_cron_jobs": ["a b"]}, {"never_allow_disable": ["nope"]}, "deny"):
            g, k = make(bad)
            self.assertFalse(g.healthy, bad)
            self.assertTrue(is_block(call(k, "todo_list")), bad)

    def test_disabled_knock_lets_tools_through(self):
        g, k = make({"enabled": False, "unsafe_override": True})      # K-14: needs the override
        self.assertIsNone(call(k, "terminal", {"command": "ls"}))
        self.assertIn("knock-off", [e["kind"] for e in g.events.recent])
        g, k = make({"enabled": False})
        self.assertFalse(g.healthy)


class TestAllowlists(unittest.TestCase):
    def test_global_list(self):
        g, k = make({"job_allowlists": {"*": ["web_search", "read_*"]}})
        turn(k)
        self.assertIsNone(call(k, "web_search", {"query": "q"}))
        self.assertIsNone(call(k, "read_file", {"path": "a"}))
        r = call(k, "terminal", {"command": "ls"})
        self.assertTrue(is_block(r))
        self.assertIn("not on the list", r["message"])

    def test_cron_job_lists(self):
        ks = {"job_allowlists": {"cron:*": ["web_search", "write_file"], "cron:job1": ["web_search"]},
              "trusted_cron_jobs": ["job1", "job2"]}
        g, k = make(ks)
        sid1, t1 = "cron_job1_20261116_060000", "cron:job1:r1"
        turn(k, sid=sid1, plat="cron", sender="", task=t1)
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid=sid1, task=t1)))
        sid2, t2 = "cron_job2_20261116_060000", "cron:job2:r1"
        turn(k, sid=sid2, plat="cron", sender="", task=t2)
        self.assertIsNone(call(k, "write_file", {"path": "x"}, sid=sid2, task=t2))   # trusted job, clean
        self.assertTrue(is_block(call(k, "terminal", {"command": "ls"}, sid=sid2, task=t2)))

    def test_unparseable_cron_id_gets_every_job_list(self):
        g, k = make({"job_allowlists": {"cron:job1": ["web_search"], "cron:job2": ["read_file"]}})
        self.assertTrue(is_block(call(k, "web_search", {"query": "q"}, sid="x", task="cron:a:b:c")))

    def test_platform_lists(self):
        g, k = make({"job_allowlists": {"platform:chatapp": ["web_search"]}})
        turn(k)
        self.assertTrue(is_block(call(k, "read_file", {"path": "a"})))
        turn(k, sid="s2", plat="cli", sender="")
        self.assertIsNone(call(k, "read_file", {"path": "a"}, sid="s2"))
        # a session Knock never saw: its platform is unknown, so every platform list applies
        self.assertTrue(is_block(call(k, "read_file", {"path": "a"}, sid="never-seen")))


class TestCronAndSessions(unittest.TestCase):
    def test_cron_prompt_untrusted_by_default(self):
        g, k = make()
        sid, t = "cron_job9_20261116_060000", "cron:job9:r1"
        turn(k, sid=sid, plat="cron", sender="", task=t)
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid=sid, task=t)))
        self.assertIsNone(call(k, "web_search", {"query": "news"}, sid=sid, task=t))

    def test_cron_job_id_parsing(self):
        self.assertEqual(policy.cron_job_id("cron:abc_1:run", ""), "abc_1")
        self.assertIsNone(policy.cron_job_id("cron:a:b:c", ""))
        self.assertEqual(policy.cron_job_id("", "cron_abc_20261116_060000"), "abc")
        self.assertIsNone(policy.cron_job_id("", "cron_abc"))

    def test_unseen_session_or_history_is_tainted(self):
        g, k = make()
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="never-seen")))
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="")))
        turn(k, sid="resumed", first=False, hist=[{"role": "user", "content": "old"}])
        r = call(k, "write_file", {"path": "x"}, sid="resumed")
        self.assertTrue(is_block(r))
        self.assertIn("history not seen", r["message"])
        turn(k, sid="first-but-history", first=True, hist=[{"role": "user", "content": "old"}])
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="first-but-history")))

    def test_compression_rotation_keeps_state(self):
        g, k = make()
        turn(k, sid="S1")
        turn(k, sid="S2", first=False, hist=[{"role": "assistant", "content": "summary"}])
        self.assertIsNone(call(k, "write_file", {"path": "x"}, sid="S2", conv="S1"))
        call(k, "web_search", {"query": "q"}, sid="S2", conv="S1")
        turn(k, sid="S3", first=False, hist=[{"role": "assistant", "content": "summary"}])
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="S3", conv="S1")))

    def test_subagents_inherit(self):
        g, k = make()
        turn(k, sid="P")
        turn(k, sid="C1", parent="P", plat="cli", sender="")
        self.assertIsNone(call(k, "write_file", {"path": "x"}, sid="C1"))
        call(k, "web_search", {"query": "q"}, sid="P")
        turn(k, sid="C2", parent="P", plat="cli", sender="")
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="C2")))
        turn(k, sid="C3", parent="unknown-parent", plat="cli", sender="")
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"}, sid="C3")))


class TestFailClosed(unittest.TestCase):
    def test_unhealthy_guard_blocks_every_tool(self):
        g, k = make()
        g.problems.append("compat: test")
        for t in ("todo_list", "web_search", "write_file"):
            r = call(k, t, {})
            self.assertTrue(is_block(r))
            self.assertIn("not running correctly", r["message"])

    def test_internal_error_blocks(self):
        g, k = make()
        turn(k)
        with mock.patch.object(never, "check_rule", side_effect=RuntimeError("boom")):   # check() wraps it
            r = call(k, "todo_list")
        self.assertTrue(is_block(r))
        self.assertEqual(k.counters["errors"], 1)

    def test_observer_error_taints_and_returns_none(self):
        g, k = make()
        with mock.patch.object(k.store, "start_turn", side_effect=RuntimeError("boom")):
            self.assertIsNone(turn(k))
        self.assertTrue(is_block(call(k, "write_file", {"path": "x"})))

    def test_report_mode_logs_only(self):
        g, k = make(mode="report")
        turn(k, sender="u-stranger")
        self.assertIsNone(call(k, "write_file", {"path": "x"}))
        self.assertIsNone(call(k, "transfer_money", {}))
        kinds = [(e["kind"], e.get("decision")) for e in g.events.recent]
        self.assertIn(("knock", "block"), kinds)

    def test_every_block_has_a_message(self):
        # Hermes ignores a block without a message: that would be fail-open
        for m in (policy.BLOCK_NEVER, policy.BLOCK_LIST, policy.BLOCK_TAINT, policy.BLOCK_UNSURE,
                  policy.BLOCK_NO_HUMAN, policy.BLOCK_ERROR, policy.BLOCK_DOWN, policy.BLOCK_NO_APPROVER,
                  policy.BLOCK_LONG):
            self.assertTrue(m.format(tool="t", label="l", why="w", gate="g").strip())


class TestTaintStore(unittest.TestCase):
    def test_states(self):
        s = taint.TaintStore(1000)
        self.assertEqual(s.state([]).label, "unknown")
        ks = taint.keys("a")
        s.start_turn(ks, fresh=True, platform="cli", owner_turn=True)
        self.assertEqual(s.state(ks).label, "clean")
        s.mark(ks, "r")
        self.assertEqual(s.state(ks).label, "tainted")
        s.start_turn(ks, fresh=True, platform="cli", owner_turn=True)     # a "fresh" claim never clears taint
        self.assertEqual(s.state(ks).label, "tainted")

    def test_eviction_forgets_as_tainted_and_saturates(self):
        s = taint.TaintStore(100)
        first = taint.keys("s0")
        s.start_turn(first, fresh=True, platform="cli", owner_turn=True)
        for i in range(1, 150):
            s.start_turn(taint.keys(f"s{i}"), fresh=True, platform="cli", owner_turn=True)
        self.assertTrue(s.state(first).tainted)
        self.assertIn("forgotten", s.state(first).reasons)
        s.start_turn(first, fresh=True, platform="cli", owner_turn=True)
        self.assertTrue(s.state(first).tainted)
        for i in range(150, 1300):
            s.mark(taint.keys(f"s{i}"), "x")
        self.assertTrue(s.saturated)
        self.assertTrue(s.state(taint.keys("new")).tainted)

    def test_owner_turn_needs_all_linked_turns(self):
        s = taint.TaintStore(1000)
        s.start_turn(taint.keys("a", "", "t1"), fresh=True, platform="chatapp", owner_turn=True)
        s.start_turn(taint.keys("b"), fresh=True, platform="chatapp", owner_turn=False)
        s.link(taint.keys("a", "b"))
        self.assertFalse(s.state(taint.keys("a")).owner_turn)


class TestRegistration(unittest.TestCase):
    def test_hooks_registered_and_declared(self):
        ctx = fakes.Ctx(settings=fakes.OWNER_SETTINGS)
        with mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                mock.patch.object(compat, "read_hermes_config", side_effect=ImportError("no hermes")):
            g = hearthward_guard.register(ctx)
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(ctx.hooks["pre_tool_call"][0], g.knock.on_pre_tool_call)
        self.assertIn("pre_tool_call", compat.HOOKS)
        yml = open(os.path.join(os.path.dirname(hearthward_guard.__file__), "plugin.yaml"), encoding="utf-8").read()
        declared = set(re.findall(r"^  - (\w+)$", yml.split("provides_hooks:")[1].split("config_schema:")[0], re.M))
        self.assertEqual(declared, set(hearthward_guard.HOOK_NAMES))
        self.assertIn("knock:", yml)

    def test_register_failure_of_pre_tool_call_is_a_problem(self):
        ctx = fakes.Ctx(fail_hooks={"pre_tool_call"}, settings=fakes.OWNER_SETTINGS)
        with mock.patch.object(compat, "probe_static", lambda req=True: ([], "0.23.1")), \
                mock.patch.object(compat, "read_hermes_config", side_effect=ImportError("no hermes")):
            g = hearthward_guard.register(ctx)
        self.assertFalse(g.healthy)


class TestConcurrency(unittest.TestCase):
    def test_parallel_sessions(self):
        g, k = make()
        errors = []

        def worker(i):
            try:
                sid = f"p{i}"
                turn(k, sid=sid)
                for _ in range(20):
                    if call(k, "web_search", {"query": "q"}, sid=sid) is not None:
                        errors.append("search blocked")
                    if not is_block(call(k, "terminal", {"command": "make"}, sid=sid)):
                        errors.append("act after read allowed")
            except Exception as e:  # pragma: no cover
                errors.append(repr(e))
        ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
