"""ReDoS / worst-case timing: every scanner path must stay bounded on hostile input at the size limit.

Guards against catastrophic backtracking or rescanning (quadratic or worse) on a stranger's input,
which would freeze the gateway's event loop. The limits are machine-relative (tests/unit/lineartime.py;
a fixed 8 s / 24 s went red on CI runners 2-3x slower than the dev PC, 2026-11-18): every hostile shape
at the size limit may cost at most MAX_RATIO x the same call on ordinary prose of the same length,
measured in the same test. At 119,000 characters any quadratic term is far beyond that. The growth
(doubling) check of the same helper runs in the smaller review tests (test_review_dos, _recheck2).
"""

import unittest

from tests.unit import fakes
from tests.unit.lineartime import Linear, best
from hearthward_guard.common import config
from hearthward_guard.gatehouse import output
from hearthward_guard.threshold import scan
from hearthward_guard.threshold.window import Window

N = 119_000
MAX_RATIO = 4.0         # worst measured 2026-11-18: scan 2.1x ('dot-runs'), output filter 2.0x ('dash-runs')
WINDOW_RATIO = 3.0      # worst measured 2026-11-18: 1.2x (late window checks vs one scan of the message)

CASES = {
    "spaces": "a " * (N // 2), "repeat-verb": "ignore " * (N // 7), "one-char": "a" * N, "percent": "%41" * (N // 3),
    "entities": "&#65;" * (N // 5), "zeros": "0" * N, "bits": "01" * (N // 2), "zw": "​" * N,
    "tags": "\U000E0041" * (N // 2), "dash-runs": "ab-" * (N // 3), "dot-runs": "x." * (N // 2), "markers": "<|" * (N // 2),
    "md-image": "![" * (N // 2), "b64-chunks": "QUJD " * (N // 5), "hex-spaced": "4a " * (N // 3), "vs": "︁" * N,
    "camel": "aB" * (N // 2), "role-lines": "system: " * (N // 8), "markdown": "*_~" * (N // 3), "html": "<a " * (N // 3),
    "lt": "<" * N, "decimals": "65 " * (N // 3), "uescape": "\\u0041" * (N // 6), "qp": "=41" * (N // 3),
    "gaps": ("ignore " + "x " * 50) * (N // 107), "letter-spaced": "a b c d e " * (N // 10), "cjk": "忽略" * (N // 2),
    "json": '"name": "x", ' * (N // 14), "paths": "/a/b " * (N // 5), "media": "MEDIA: " * (N // 7),
    "attack-flood": (fakes.ATTACK + " ") * (N // 70),
}


class TestWorstCase(unittest.TestCase):
    def test_scan_bounded(self):
        lin = Linear(lambda text: scan.scan_text(text, "attachment", 120_000))
        for name, text in CASES.items():
            with self.subTest(name=name):
                self.assertEqual(lin.problems(text, name, MAX_RATIO, growth=False), [])

    def test_output_filter_bounded(self):
        cfg = config.parse({"gatehouse": {"id_patterns": [r"\bID-\d{4,8}\b"]}}).gatehouse
        lin = Linear(lambda text: output.filter_reply(text, cfg))
        for name, text in CASES.items():
            with self.subTest(name=name):
                self.assertEqual(lin.problems(text, name, MAX_RATIO, growth=False), [])

    def test_window_bounded(self):
        """50 hostile 20,000-character messages in one window. Each check joins recent messages, but
        the join is capped (PART_CHARS edges, JOIN_MAX_CHARS, keep), so a check costs about as much as
        scanning the message once, however long the history. Guards against an uncapped join, which
        rescans the whole history on every message (quadratic in the conversation). This test is heavy,
        not slow code: about 0.35 s per check on the dev PC (~17 s total), 2x that on CI runners."""
        text = CASES["gaps"][:20_000]
        w = Window(50, 60)

        def check(_t: str) -> None:
            w.check(("p", "c", "u"), text)

        per = [best(check, text) for _ in range(50)]
        late = sum(per[-10:]) / 10                      # the window is full here: the most work per check
        base = best(lambda t: scan.scan_text(t, "attachment"), text, 2)
        if late > WINDOW_RATIO * base:                  # measure again before it counts (busy machine)
            late = min(late, sum(best(check, text) for _ in range(5)) / 5)
            base = min(base, best(lambda t: scan.scan_text(t, "attachment"), text, 3))
        self.assertLess(late, WINDOW_RATIO * base,
                        f"a window check took {late:.2f}s = {late / base:.1f}x one scan of the message ({base:.2f}s)")


if __name__ == "__main__":
    unittest.main()
