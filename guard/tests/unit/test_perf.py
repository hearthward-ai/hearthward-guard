"""ReDoS / worst-case timing: every scanner path must stay bounded on hostile input at the size limit."""
import time
import unittest

from tests.unit import fakes
from hearthward_guard.common import config
from hearthward_guard.gatehouse import output
from hearthward_guard.threshold import scan
from hearthward_guard.threshold.window import Window

N = 119_000
LIMIT_S = 8.0     # generous ceiling for slow machines; typical worst case is about 1 s

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
        for name, text in CASES.items():
            with self.subTest(name=name):
                t0 = time.perf_counter()
                scan.scan_text(text, "attachment", 120_000)
                self.assertLess(time.perf_counter() - t0, LIMIT_S, name)

    def test_output_filter_bounded(self):
        cfg = config.parse({"gatehouse": {"id_patterns": [r"\bID-\d{4,8}\b"]}}).gatehouse
        for name, text in CASES.items():
            with self.subTest(name=name):
                t0 = time.perf_counter()
                output.filter_reply(text, cfg)
                self.assertLess(time.perf_counter() - t0, LIMIT_S, name)

    def test_window_bounded(self):
        w = Window(50, 60)
        t0 = time.perf_counter()
        for i in range(50):
            w.check(("p", "c", "u"), CASES["gaps"][:20_000])
        self.assertLess(time.perf_counter() - t0, LIMIT_S * 3)


if __name__ == "__main__":
    unittest.main()
