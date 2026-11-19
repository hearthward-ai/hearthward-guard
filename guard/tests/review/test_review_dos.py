"""Review 2026-11-17: time and memory a stranger can make the guard spend.

The guard requires plugins.hook_callback_timeout = 0 and runs its scan synchronously inside the
gateway's event loop (hooks._dispatch), so a slow scan freezes the whole gateway while the
heartbeat thread keeps reporting "healthy".

Sizes here are small on purpose (the whole file runs in about 10 seconds). The cost was quadratic:
20,000 newlines took 13 s on the review machine and the 120,000-character limit extrapolates to
about 8 minutes for ONE message part.

Time limits are machine-relative (tests/unit/lineartime.py; fixed 0.25 s limits went red on slower
CI runners, 2026-11-18): each hostile shape may cost at most MAX_RATIO x scanning ordinary prose of
the same length, and doubling it may at most triple the time. Both are measured in the same test.
"""
from __future__ import annotations

import unittest

from tests.review._review import known_open
from tests.unit import fakes
from tests.unit.fakes import dispatch, ev, make_guard
from tests.unit.lineartime import Linear
from hearthward_guard.threshold import scan

MAX_RATIO = 3.0     # worst measured 2026-11-18: 0.55x ('<!--'); the original H1 bugs were 20x and more
NL = chr(10)


def scanner(channel: str = "attachment") -> Linear:
    return Linear(lambda text: scan.scan_text(text, channel))


class TestControls(unittest.TestCase):
    def test_ordinary_text_of_the_same_size_is_fast(self):
        """The baseline every ratio below uses must itself scale linearly."""
        self.assertEqual(scanner().baseline_problems(10_000), [])
        self.assertEqual(scanner().problems(("line of text" + NL) * 800, "short lines", MAX_RATIO), [])


class TestQuadraticRegex(unittest.TestCase):
    def assertLinear(self, text: str, label: str, channel: str = "attachment"):
        self.assertEqual(scanner(channel).problems(text, label, MAX_RATIO), [])

    def test_H1_blank_lines(self):
        """patterns.py:150 marker rule (line start, optional whitespace, role word) with re.M:
        every line start re-reads all the whitespace after it."""
        self.assertLinear("Notes" + NL * 6000 + "end", "6,000 blank lines")

    def test_H1_blank_lines_grow_quadratically(self):
        self.assertLinear("x" + NL * 4000 + "y", "4,000 blank lines")

    def test_H1_spaces_then_newlines(self):
        self.assertLinear("x" + (" " + NL) * 4000 + "y", "8,000 characters of space+newline", "tool_result")

    def test_H1_unclosed_html_comments(self):
        """normalize.py:52 comment pattern rescans to the end of the text for every opener."""
        self.assertLinear("<!--" * 7000, "28,000 characters of '<!--'")

    def test_H1_role_word_then_spaces(self):
        self.assertLinear("system" + " " * 40_000 + "x", "'system' + 40,000 spaces")


class TestMemory(unittest.TestCase):
    def test_M12_one_hold_keeps_megabytes_of_attachment_text(self):
        """An oversized text attachment is held ('too long to check') and its full text is stored in
        the hold for 30 minutes: 8 files x 2 MB per message, 50 pending holds by default."""
        td = fakes.TmpDir()
        try:
            g = make_guard()
            paths = [td.file(f"f{i}.txt", b"A" * 500_000) for i in range(8)]
            dispatch(g, ev("files", media_urls=paths, media_types=["text/plain"] * 8,
                           media_filenames=[f"f{i}.txt" for i in range(8)]))
            kept = sum(len(b) for h in g.holds.pending() for _n, b in h.attachment_texts)
            worst = kept * g.cfg.holds.max_pending
            self.assertLess(worst, 20_000_000, f"one message pinned {kept:,} characters; {g.cfg.holds.max_pending} "
                                               f"such holds pin {worst:,} (with the 2 MB default limit: ~760 MB)")
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
