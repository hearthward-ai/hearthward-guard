"""Picture shield with the REAL engine (job 6). Skips unless Tesseract (eng + chi_sim) is installed and
the bench's generated pictures are on this machine.

    HEARTHWARD_OCR_IMAGES=<dir with the generated pictures>   (default <bench local>/generated/images)
    python3 -I -B -m unittest discover -s tests/integration -t .

Checks the whole path a picture takes: header check, metadata, the engine in its own process with
limits, scam signs, rules, and the reply. Run on Linux it also proves the resource limits are applied
(a 128 MB address-space limit makes the engine fail, and the guard holds the picture).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.unit import fakes
from tests.unit.fakes import Gateway, dispatch, ev, make_guard
from hearthward_guard import hooks
from hearthward_guard.common import messages
from hearthward_guard.threshold import ocr

LOCAL = Path(os.environ.get("HEARTHWARD_BENCH_LOCAL") or Path.home() / "Hearthward-Data" / "attack-bench")
IMAGES = Path(os.environ.get("HEARTHWARD_OCR_IMAGES") or LOCAL / "generated" / "images")
ENGINE = shutil.which("tesseract")


def _langs_ok() -> bool:
    if not ENGINE:
        return False
    try:
        out = subprocess.run([ENGINE, "--list-langs"], capture_output=True, timeout=20, shell=False).stdout.decode()
    except (OSError, subprocess.SubprocessError):
        return False
    return {"eng", "chi_sim"} <= {ln.strip() for ln in out.splitlines()}


READY = _langs_ok() and IMAGES.is_dir()


@unittest.skipUnless(READY, "needs Tesseract with eng + chi_sim and the bench's generated pictures")
class TestRealEngine(unittest.TestCase):
    def run_pic(self, name, settings=None):
        path = IMAGES / name
        if not path.is_file():
            self.skipTest(f"{name} not generated here")
        s = {"ocr": {"enabled": True}}
        s.update(settings or {})
        g = make_guard(s, clock=fakes.Clock(), ocr_which=shutil.which)
        gw = Gateway()
        mime = "image/png" if name.endswith(".png") else "image/jpeg"
        r = dispatch(g, ev("", media_urls=[str(path)], media_types=[mime], media_filenames=[name]), gw)
        return r, gw.sent(), g

    def test_english_scam(self):
        r, sent, g = self.run_pic("own_image_ocr_scam-en-001.jpg")
        self.assertEqual(r, hooks.SKIP_PICTURE)
        self.assertIn("looks like a scam", sent[0][1])
        self.assertEqual([c for c, _t in sent], ["c1", "owner-dm"])
        self.assertEqual(g.counters["pictures_read"], 1)

    def test_chinese_scam_spaced_ocr(self):
        r, sent, _g = self.run_pic("own_image_ocr_scam-zh-002.jpg", {"ocr": {"enabled": True, "locale": "zh"}})
        self.assertEqual(r, hooks.SKIP_PICTURE)
        self.assertTrue(sent[0][1].startswith("我检查了您图片里的文字：这很可能是诈骗"), sent[0][1])

    def test_injection_text_is_held(self):
        r, sent, _g = self.run_pic("own_direct_override-en-007.png")
        self.assertEqual(r, hooks.SKIP_HELD)
        self.assertEqual(sent[0][1], messages.picture_text("held_injection", "en"))

    def test_metadata_injection_is_held(self):
        r, _sent, _g = self.run_pic("own_tool_smuggling-en-027.jpg")
        self.assertEqual(r, hooks.SKIP_HELD)

    def test_honest_notice_is_clean(self):
        r, sent, _g = self.run_pic("own_hard_negative-zh-580.png")
        self.assertEqual(r, hooks.SKIP_PICTURE)
        self.assertEqual(sent[0][1], messages.picture_text("clean", "en"))

    @unittest.skipUnless(os.name == "posix", "memory limits are POSIX only")
    def test_memory_limit_fails_closed(self):
        r, sent, _g = self.run_pic("own_image_ocr_scam-en-001.jpg", {"ocr": {"enabled": True, "memory_mb": 128}})
        self.assertEqual(r, hooks.SKIP_HELD)
        self.assertIn("couldn't read your picture", sent[0][1])

    def test_engine_reads_from_stdin_only(self):
        e = ocr.Engine(make_guard({}).cfg.ocr)
        data = (IMAGES / "own_image_ocr_scam-en-001.jpg").read_bytes()
        self.assertIn("Lakeshore", e.read(data))


if __name__ == "__main__":
    unittest.main()
