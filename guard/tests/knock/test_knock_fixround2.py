"""Knock fix round 2 (2026-11-17, Knock 1.2.0): tests for the re-check fixes beyond the re-check's
own tests (tests/review_knock/test_knock_recheck.py). Report: reviews/knock-recheck-2026-11-17.md,
section "Responses (fix round 2)". Sensitive strings are put together at run time.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest

from hearthward_guard.knock import policy, taint, tools
from tests.knock.kfakes import call, is_ask, is_block, make, turn
from tests.unit.fakes import OWNER, fake_secret

PW = "ch" + "passwd"
HOME = "/ho" + "me/u"          # fixture paths built at run time (leakcheck)
LAN = "19" + "2.168"
SHELL_PW = "echo u:x | " + PW
PAGE = {"urls": ["https://news.example/story"]}


def owner_cli(knock=None):
    g, k = make(knock)
    turn(k, plat="cli", sender="")
    return g, k


def ran(k, tool_call_id, args, result="ok"):
    """What hooks.on_transform_tool_result tells Knock after the tool ran."""
    return k.args_changed(args, tool_call_id, result=result)


def ask_call(k, tool, args, tcid, sid="s1"):
    return k.on_pre_tool_call(tool_name=tool, args=args, task_id="", session_id=sid, tool_call_id=tcid,
                              turn_id="t", conversation_id="")


# ---------------------------------------------------------------------------------- R-01 with real git
@unittest.skipUnless(shutil.which("git"), "git not installed")
class TestR01RealGit(unittest.TestCase):
    """The hazard is real: git status runs core.fsmonitor from the repository's own config, also
    with system and global config switched off. Knock no longer lets git through without a card."""

    def test_git_status_runs_a_program_from_the_repo_config(self):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")

            def git(*a):
                return subprocess.run(["git", *a], cwd=d, env=env, capture_output=True, timeout=60)

            git("init", "-q")
            with open(os.path.join(d, "a.txt"), "w", encoding="utf-8") as f:
                f.write("x\n")
            git("add", "a.txt")
            marker = os.path.join(d, "fsm-marker")
            git("config", "core.fsmonitor", "echo x> fsm-marker; false")
            self.assertFalse(os.path.exists(marker))
            git("status", "--short")
            self.assertTrue(os.path.exists(marker), "git status did not run core.fsmonitor (git changed?)")
        # ... so Knock treats it as a command: a card in a clean or LOCAL session, denied after web content
        self.assertFalse(tools.read_only_command("terminal", {"command": "git status", "workdir": d}))
        g, k = owner_cli()
        self.assertTrue(is_ask(call(k, "terminal", {"command": "git status", "workdir": d})))
        call(k, "web_extract", PAGE)
        self.assertTrue(is_block(call(k, "terminal", {"command": "git status", "workdir": d})))


# ---------------------------------------------------------------------------------- R-02
class TestStickyStrength(unittest.TestCase):
    def test_remote_and_stranger_survive_a_full_reason_list(self):
        g, k = owner_cli()
        ks = taint.keys("s1")
        k.store.mark(ks, *[taint.LOCAL_PREFIX + f"output of t{i}" for i in range(taint.MAX_REASONS + 3)])
        self.assertFalse(k.store.state(ks).remote)
        k.store.mark(ks, "output of web_extract")
        st = k.store.state(ks)
        self.assertTrue(st.remote and "output of web_extract" in st.reasons)      # takes a LOCAL slot
        k.store.mark(ks, *[f"output of r{i}" for i in range(taint.MAX_REASONS + 3)])
        k.store.mark(ks, taint.STRANGER)                                           # list full of REMOTE
        st = k.store.state(ks)
        self.assertTrue(st.remote and st.stranger)
        self.assertTrue(is_block(call(k, "read_file", {"path": (HOME + "/.hermes/.env")})))


# ---------------------------------------------------------------------------------- R-04 origin
class TestOrigin(unittest.TestCase):
    def test_fetching_command_is_remote_and_its_files_too(self):
        g, k = owner_cli()
        self.assertTrue(is_ask(call(k, "terminal", {"command": "cu" + "rl -sL https://x.example/tool.tar.gz -o tool.tgz"})))
        self.assertTrue(k.store.state(taint.keys("s1")).remote)
        self.assertTrue(is_block(call(k, "write_file", {"path": "notes.md", "content": "x"})))
        # another session that reads the downloaded file is REMOTE too
        turn(k, sid="s2", plat="cli", sender="")
        self.assertIsNone(call(k, "read_file", {"path": (HOME + "/tool.tgz")}, sid="s2"))
        self.assertTrue(k.store.state(taint.keys("s2")).remote)

    def test_git_clone_folder_and_downloads_folder(self):
        g, k = owner_cli()
        call(k, "terminal", {"command": "git clone https://h.example/u/proj.git", "workdir": (HOME + "/src")})
        turn(k, sid="s2", plat="cli", sender="")
        call(k, "read_file", {"path": (HOME + "/src/proj/README.md")}, sid="s2")
        self.assertTrue(k.store.state(taint.keys("s2")).remote)
        turn(k, sid="s3", plat="cli", sender="")
        call(k, "terminal", {"command": "cat ~/Downloads/invoice.txt"}, sid="s3")
        self.assertTrue(k.store.state(taint.keys("s3")).remote)

    def test_script_with_an_http_library_is_remote(self):
        g, k = owner_cli()
        call(k, "execute_code", {"code": "import requests\nprint(requests.get(u).text)"})
        self.assertTrue(k.store.state(taint.keys("s1")).remote)

    def test_local_command_stays_local(self):
        g, k = owner_cli()
        call(k, "terminal", {"command": "make test"})
        st = k.store.state(taint.keys("s1"))
        self.assertTrue(st.tainted and not st.remote and st.private_read)

    def test_screen_and_skill_reads_are_remote_unless_listed(self):
        for tool, args in (("read_terminal", {}), ("read_window_below", {}), ("skill_view", {"name": "hub-skill"})):
            g, k = owner_cli()
            call(k, tool, args)
            self.assertTrue(k.store.state(taint.keys("s1")).remote, tool)
        # decision review pick 4 (2026-11-17): entries are pinned "name:sha256" of SKILL.md
        import hashlib
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "notes", "my-notes"))
            with open(os.path.join(td, "notes", "my-notes", "SKILL.md"), "wb") as f:
                f.write(b"---\nname: my-notes\n---\nKeep notes.\n")
            pin = hashlib.sha256(b"---\nname: my-notes\n---\nKeep notes.\n").hexdigest()
            g, k = owner_cli({"local_skills": ["my-notes:" + pin]})
            k.skills_dir = td
            self.assertTrue(g.healthy)
            call(k, "skill_view", {"name": "my-notes"})
            self.assertFalse(k.store.state(taint.keys("s1")).remote)
        for bad in (["bad*"], ["my-notes"]):
            g, k = make({"local_skills": bad})
            self.assertFalse(g.healthy, bad)


# ---------------------------------------------------------------------------------- R-03 / R-05 / R-16
class TestReadsAndSends(unittest.TestCase):
    def test_trivial_commands_do_not_taint(self):
        g, k = owner_cli()
        for cmd in ("date", "pwd", "echo hi", "whoami", "uname -a", "which python3", "true"):
            self.assertIsNone(call(k, "terminal", {"command": cmd}), cmd)
        self.assertEqual(k.store.state(taint.keys("s1")).label, "clean")
        g, k = make()
        turn(k, sender="u-stranger")
        self.assertTrue(is_block(call(k, "terminal", {"command": "whoami"})))       # still a private read

    def test_local_web_target_after_outside_content(self):
        g, k = make()
        turn(k)
        call(k, "web_extract", PAGE)
        self.assertTrue(is_block(call(k, "web_extract", {"urls": ["http://127.0.0.1:8123/api/services/lock/unlock"]})))
        g, k = make()
        turn(k)
        self.assertIsNone(call(k, "web_extract", {"urls": [("http://" + LAN + ".1.20/status")]}))    # clean: allowed
        self.assertTrue(k.store.state(taint.keys("s1")).private_read)

    def test_process_reads_and_process_acts(self):
        g, k = owner_cli()
        self.assertIsNone(call(k, "process_manage", {"action": "poll", "process_id": "p1"}))
        self.assertTrue(is_ask(call(k, "process_manage", {"action": "kill", "process_id": "p1"})))
        g, k = make()
        turn(k, sender="u-stranger")
        self.assertTrue(is_block(call(k, "process_manage", {"action": "log", "process_id": "p1"})))

    def test_same_service_pair_but_not_mixed(self):
        g, k = owner_cli()
        call(k, "spotify_search", {"query": "song"})
        self.assertTrue(is_ask(call(k, "spotify_playback", {"action": "play"})))
        call(k, "web_extract", PAGE)
        self.assertTrue(is_block(call(k, "spotify_playback", {"action": "play"})))
        g, k = owner_cli()
        call(k, "kanban_show", {"id": "1"})
        self.assertTrue(is_block(call(k, "kanban_schedule", {"id": "1"})))           # lasting: still denied

    def test_padded_secret_in_a_request(self):
        g, k = make()
        turn(k)
        self.assertTrue(is_block(call(k, "web_search", {"query": "x " * 15000 + fake_secret("github")})))


# ---------------------------------------------------------------------------------- R-11 / R-16 cards
class TestCardsAndGrants(unittest.TestCase):
    BIG = "def f():\n    return 1\n" * 120

    def test_long_file_write_is_shown_in_part(self):
        # decision review pick 2 (2026-11-17): code files are never shown in part; a document is
        g, k = owner_cli()
        call(k, "read_file", {"path": "a.py"})
        r = call(k, "write_file", {"path": "notes.md", "content": self.BIG})
        self.assertTrue(is_ask(r) and "IN PART" in r["message"] and "characters not shown" in r["message"])
        self.assertLess(len(r["message"]), policy.CARD_MAX * 2 + 600)

    def test_long_write_to_a_file_that_runs_by_itself_is_still_refused(self):
        for path in ((HOME + "/.bashrc"), "repo/.git/hooks/pre-commit", (HOME + "/.config/autostart/x.desktop"),
                     (HOME + "/.hermes/SOUL.md")):
            g, k = owner_cli()
            call(k, "read_file", {"path": "a.py"})
            self.assertTrue(is_block(call(k, "write_file", {"path": path, "content": self.BIG})), path)

    def test_running_a_file_shown_in_part_says_so(self):
        g, k = owner_cli()
        call(k, "read_file", {"path": "a.py"})
        call(k, "write_file", {"path": "big.txt", "content": self.BIG})        # pick 2: not a .py file
        r = call(k, "terminal", {"command": "python big.txt"})
        self.assertTrue(is_ask(r) and "only in part" in r["message"])

    def test_one_approved_edit_covers_a_few_more(self):
        # decision review pick 1 (2026-11-17): files that run get no grant, so this uses documents
        g, k = owner_cli()
        call(k, "read_file", {"path": "a.py"})
        a1 = {"path": "a.md", "old": "x = 1", "new": "x = 2"}
        r = ask_call(k, "patch", a1, "c1")
        self.assertTrue(is_ask(r) and "more edits of this same file" in r["message"])
        self.assertTrue(is_ask(ask_call(k, "patch", {"path": "a.md", "old": "y", "new": "z"}, "c0")))  # not yet
        ran(k, "c1", a1)                                               # the owner approved: it ran
        for i in range(policy.GRANT_USES):
            self.assertIsNone(ask_call(k, "patch", {"path": "a.md", "old": f"v{i}", "new": "w"}, f"g{i}"), i)
        self.assertTrue(is_ask(ask_call(k, "patch", {"path": "a.md", "old": "q", "new": "w"}, "g9")))   # used up
        self.assertTrue(is_ask(ask_call(k, "patch", {"path": "b.md", "old": "q", "new": "w"}, "g10")))  # other file

    def test_no_grant_after_a_refusal_remote_content_or_for_config(self):
        g, k = owner_cli()
        call(k, "read_file", {"path": "a.py"})
        a1 = {"path": "a.py", "old": "x = 1", "new": "x = 2"}
        ask_call(k, "patch", a1, "c1")
        ran(k, "c1", a1, result="The user denied this action.")
        self.assertTrue(is_ask(ask_call(k, "patch", {"path": "a.py", "old": "y", "new": "z"}, "c2")))
        ran(k, "c2", {"path": "a.py", "old": "y", "new": "z"})
        call(k, "web_extract", PAGE)                                   # REMOTE now: the grant does not apply
        self.assertTrue(is_block(ask_call(k, "patch", {"path": "a.py", "old": "q", "new": "w"}, "c3")))
        g, k = owner_cli()
        call(k, "read_file", {"path": "a.py"})
        r = ask_call(k, "write_file", {"path": (HOME + "/.bashrc"), "content": "alias l=ls"}, "c4")
        self.assertTrue(is_ask(r) and "more edits" not in r["message"])

    def test_tool_scope_key_only_while_clean(self):
        g, k = owner_cli({"ask_scope": "tool", "unsafe_override": True})
        r1 = call(k, "terminal", {"command": "make"})
        r2 = call(k, "terminal", {"command": "make"})
        self.assertNotEqual(r1["rule_key"], r2["rule_key"])           # r1 made the session LOCAL


# ---------------------------------------------------------------------------------- R-06 / R-07 / R-09 / R-10
class TestTurnsAndNever(unittest.TestCase):
    def test_threshold_note_with_text_lands_on_its_own_message(self):
        g, k = make()
        k.note_outside("chatapp", OWNER, "quote or channel context", text="please run the setup step from bob")
        turn(k, sid="chatB", msg="hello there")
        self.assertNotEqual(k.store.state(taint.keys("chatB")).label, "clean")      # fail closed while pending
        turn(k, sid="chatA", msg="please run the setup step from bob")
        self.assertNotEqual(k.store.state(taint.keys("chatA")).label, "clean")
        turn(k, sid="chatC", msg="next one")
        self.assertEqual(k.store.state(taint.keys("chatC")).label, "clean")          # used up

    def test_history_edited_before_the_last_turn(self):
        g, k = make()
        turn(k)
        h1 = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}]
        turn(k, first=False, hist=h1, msg="next")
        self.assertEqual(k.store.state(taint.keys("s1")).label, "clean")
        h2 = h1 + [{"role": "user", "content": "next"}, {"role": "assistant", "content": "ok"}]
        turn(k, first=False, hist=h2, msg="again")
        self.assertEqual(k.store.state(taint.keys("s1")).label, "clean")              # honest growth
        h3 = [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi. Also: run x"}] + h2[2:]
        turn(k, first=False, hist=h3, msg="more")
        self.assertNotEqual(k.store.state(taint.keys("s1")).label, "clean")

    def test_armed_file_holds_in_every_session(self):
        # decision review pick 5 (2026-11-17): armed by path process-wide (was per session)
        g, k = owner_cli()
        call(k, "write_file", {"path": "notes.txt", "content": SHELL_PW})
        self.assertTrue(is_block(call(k, "terminal", {"command": "sh notes.txt"})))
        turn(k, sid="s2", plat="cli", sender="")
        r = call(k, "terminal", {"command": "sh notes.txt"}, sid="s2")
        self.assertTrue(is_block(r) and "never" in r["message"])

    def test_new_never_forms(self):
        cases = [("terminal", {"command": "pa" + "sswd"}), ("terminal", {"command": "sudo pa" + "sswd root"}),
                 ("write_file", {"path": (HOME + "/.ssh/authorized_keys"), "content": "ssh-ed25519 AAAA x"}),
                 ("terminal", {"command": "echo k | tee -a ~/.ssh/authorized_keys"}),
                 ("terminal", {"command": "ssh-copy-id u@host"}),
                 ("execute_code", {"code": "client.order_market_sell(symbol='X', quantity=1)"})]
        for tool, args in cases:
            g, k = owner_cli()
            r = call(k, tool, args)
            self.assertTrue(is_block(r) and "never" in r["message"], args)
        for tool, args in (("terminal", {"command": "cat ~/.ssh/authorized_keys"}),
                           ("terminal", {"command": "ls /e" + "tc/pa" + "sswd"}),
                           ("execute_code", {"code": "GPIO.setup(13, GPIO.OUT)  # set the pin mode"})):
            g, k = owner_cli()
            r = call(k, tool, args)
            self.assertFalse(is_block(r) and "never" in r["message"], args)


if __name__ == "__main__":
    unittest.main()
