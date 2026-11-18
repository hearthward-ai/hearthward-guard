"""Review 2026-11-17: time and memory a stranger can make the guard spend.

The guard requires plugins.hook_callback_timeout = 0 and runs its scan synchronously inside the
gateway's event loop (hooks._dispatch), so a slow scan freezes the whole gateway while the
heartbeat thread keeps reporting "healthy".

Sizes here are small on purpose (the whole file runs in about 10 seconds). The cost is quadratic:
20,000 newlines took 13 s on the review machine and the 120,000-character limit extrapolates to
about 8 minutes for ONE message part.
"""
from __future__ import annotations

import time
import unittest

from tests.review._review import known_open
from tests.unit import fakes
from tests.unit.fakes import dispatch, ev, make_guard
from hearthward_guard.threshold import scan

BUDGET_S = 0.25     # a linear scan of 10,000 characters takes a few milliseconds
NL = chr(10)


def seconds(text: str, channel: str = "attachment", runs: int = 1) -> float:
    best = 1e9
    for _ in range(runs):
        t = time.perf_counter()
        scan.scan_text(text, channel)
        best = min(best, time.perf_counter() - t)
    return best


class TestControls(unittest.TestCase):
    def test_ordinary_text_of_the_same_size_is_fast(self):
        self.assertLess(seconds("word " * 2000), BUDGET_S)
        self.assertLess(seconds(("line of text" + NL) * 800), BUDGET_S)


class TestQuadraticRegex(unittest.TestCase):
    def test_H1_blank_lines(self):
        """patterns.py:150 marker rule (line start, optional whitespace, role word) with re.M:
        every line start re-reads all the whitespace after it."""
        t = seconds("Notes" + NL * 6000 + "end")
        self.assertLess(t, BUDGET_S, f"6,000 blank lines took {t:.1f}s")

    def test_H1_blank_lines_grow_quadratically(self):
        a = seconds("x" + NL * 2000 + "y", runs=2)
        b = seconds("x" + NL * 4000 + "y", runs=2)
        self.assertLess(b, 3.0 * max(a, 0.005), f"doubling the input multiplied the time by {b / max(a, 1e-6):.1f}")

    def test_H1_spaces_then_newlines(self):
        t = seconds("x" + (" " + NL) * 4000 + "y", "tool_result")
        self.assertLess(t, BUDGET_S, f"8,000 characters of space+newline took {t:.1f}s")

    def test_H1_unclosed_html_comments(self):
        """normalize.py:52 comment pattern rescans to the end of the text for every opener."""
        t = seconds("<!--" * 7000)
        self.assertLess(t, BUDGET_S, f"28,000 characters of '<!--' took {t:.1f}s")

    def test_H1_role_word_then_spaces(self):
        t = seconds("system" + " " * 40_000 + "x")
        self.assertLess(t, BUDGET_S, f"'system' + 40,000 spaces took {t:.1f}s")


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
