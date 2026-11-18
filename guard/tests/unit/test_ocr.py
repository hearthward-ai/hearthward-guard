"""Picture shield (job 6): OCR engine wrapper, metadata text, scam signs, config, and the dispatch flow.

A stub engine stands in for Tesseract (no engine needed). Synthetic pictures are built at run time.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from tests.unit import fakes, picfakes as P
from tests.unit.fakes import OWNER, Gateway, TmpDir, dispatch, ev, make_guard
from hearthward_guard import hooks
from hearthward_guard.common import config, messages
from hearthward_guard.threshold import ocr, scam

PLUGIN = Path(hooks.__file__).resolve().parent
ENGINE = "/usr/bin/tesseract"
SCAM_EN = "SwiftParcel: your package cannot be delivered. Pay the $2.50 redelivery fee within 24 hours at https://example.invalid/a1"
SCAM_ZH = "北辰银行：您的账户已冻结，请立即点击链接 https://example.invalid/a1 验证身份"
CLEAN = "Rosa's Diner menu\nPancakes 6.50\nCoffee 2.00"


def cfg(**kw):
    return config.parse({"ocr": kw}).ocr


class TestHeaders(unittest.TestCase):
    def test_sniff_formats(self):
        self.assertEqual(ocr.sniff(P.png(64, 32)), ("png", 64, 32))
        self.assertEqual(ocr.sniff(P.jpeg(80, 40)), ("jpeg", 80, 40))
        self.assertEqual(ocr.sniff(P.gif(10, 12)), ("gif", 10, 12))
        self.assertEqual(ocr.sniff(P.webp_vp8x(300, 200)), ("webp", 300, 200))
        self.assertEqual(ocr.sniff(P.bmp(5, -7)), ("bmp", 5, 7))

    def test_unknown_and_unsupported_fail(self):
        for data in (b"II*\x00" + b"\x00" * 20, b"\x00\x00\x00\x18ftypheic" + b"\x00" * 20, b"hello world",
                     b"", P.png()[:20]):
            with self.assertRaises(ocr.OcrError, msg=data[:12]):
                ocr.check_size(data, cfg())

    def test_pixel_cap(self):
        with self.assertRaises(ocr.OcrError) as cm:
            ocr.check_size(P.png(5000, 5000), cfg(max_pixels=1_000_000))
        self.assertIn("too large", cm.exception.args[0])
        self.assertEqual(ocr.check_size(P.png(500, 500), cfg(max_pixels=1_000_000))[0], "png")

    def test_image_kind(self):
        self.assertTrue(ocr.is_image_kind("image/png", ""))
        self.assertTrue(ocr.is_image_kind("", "shot.JPG"))
        self.assertTrue(ocr.is_image_kind("image/x-new", "x"))
        self.assertFalse(ocr.is_image_kind("image/svg+xml", "a.svg"))
        self.assertFalse(ocr.is_image_kind("text/plain", "a.txt"))


class TestMetadata(unittest.TestCase):
    def test_png_chunks(self):
        data = P.png(texts={"Comment": "plain note"}, ztexts={"z": "packed note"}, itexts={"i": "intl 注释"},
                     exif=P.exif_block("Some Artist", "user comment"))
        self.assertEqual(ocr.metadata_texts(data, "png"), ["plain note", "packed note", "intl 注释", "Some Artist",
                                                            "user comment"])

    def test_jpeg_exif_xmp_comment_both_byte_orders(self):
        for little in (True, False):
            data = P.jpeg(exif=P.exif_block("Some Artist", "给AI的话", little=little),
                          xmp='<x:xmpmeta><rdf:li xml:lang="x-default">hidden desc</rdf:li></x:xmpmeta>',
                          comment="a comment")
            got = ocr.metadata_texts(data, "jpeg")
            self.assertIn("给AI的话", got)
            self.assertIn("Some Artist", got)
            self.assertIn("a comment", got)
            self.assertTrue(any("hidden desc" in t for t in got), got)

    def test_short_artist_inline(self):
        self.assertIn("ab", ocr.metadata_texts(P.jpeg(exif=P.exif_block("ab", "")), "jpeg"))

    def test_malformed_never_raises(self):
        good = P.jpeg(exif=P.exif_block("Some Artist", "x" * 50))
        for cut in range(4, len(good), 7):
            ocr.metadata_texts(good[:cut], "jpeg")
        bomb = P.png(ztexts={"z": "A" * 5_000_000})
        got = ocr.metadata_texts(bomb, "png")
        self.assertLessEqual(sum(map(len, got)), 4000)

    def test_tidy(self):
        self.assertEqual(ocr.tidy("点 击 链 接 abc  def\x07\n\n x", 100), "点击链接 abc def\nx")
        self.assertEqual(len(ocr.tidy("a" * 50, 10)), 10)


class TestEngine(unittest.TestCase):
    def test_fixed_argv_bytes_on_stdin(self):
        stub = P.StubEngine(["hello"])
        e = ocr.Engine(cfg(engine_path=ENGINE), runner=stub)
        self.assertEqual(e.read(b"PICTURE"), "hello")
        self.assertEqual(stub.calls[0]["argv"], [ENGINE, "--list-langs"])
        self.assertEqual(stub.calls[1]["argv"], [ENGINE, "stdin", "stdout", "-l", "eng+chi_sim", "--psm", "3"])
        self.assertEqual(stub.calls[1]["data"], b"PICTURE")
        self.assertEqual(stub.calls[1]["timeout"], 20.0)
        self.assertEqual(stub.calls[1]["mem"], 1024 * 1024 * 1024)
        self.assertEqual(stub.calls[1]["env"]["OMP_THREAD_LIMIT"], "1")
        e.read(b"again")
        self.assertEqual(sum(1 for c in stub.calls if c["argv"][1:] == ["--list-langs"]), 1)

    def test_missing_language_fails_closed(self):
        e = ocr.Engine(cfg(engine_path=ENGINE), runner=P.StubEngine(["x"], langs=("eng",)))
        for _ in range(2):
            with self.assertRaises(ocr.OcrError) as cm:
                e.read(b"P")
            self.assertIn("language", cm.exception.args[0])

    def test_failures(self):
        for stub, words in ((P.StubEngine(["x"], rc=1), "failed"),
                            (P.StubEngine(exc=subprocess.TimeoutExpired("t", 1)), "too long"),
                            (P.StubEngine(exc=OSError("nope")), "could not start")):
            with self.assertRaises(ocr.OcrError) as cm:
                ocr.Engine(cfg(engine_path=ENGINE), runner=stub).read(b"P")
            self.assertIn(words, cm.exception.args[0])

    def test_no_engine(self):
        e = ocr.Engine(cfg(), which=lambda _n: None)
        self.assertFalse(e.available)
        self.assertIn("no OCR engine", e.missing)
        with self.assertRaises(ocr.OcrError):
            e.read(b"P")
        e2 = ocr.Engine(cfg(engine_path=os.path.abspath(os.path.join(os.sep, "no-such-dir", "tesseract"))))
        self.assertFalse(e2.available)
        # Windows accepts only an .exe engine (fix round OC-7)
        self.assertIn(".exe" if os.name == "nt" else "not an executable", e2.missing)

    def test_run_uses_list_argv_no_shell_and_limits(self):
        seen = {}

        def fake_run(argv, **kw):
            seen.update(kw, argv=argv)
            return subprocess.CompletedProcess(argv, 0, b"ok", b"")
        with mock.patch.object(ocr.subprocess, "run", fake_run):
            rc, out, _ = ocr._run(["/x/tesseract", "stdin", "stdout"], b"DATA", 5.0, 256 << 20, {"A": "1"})
        self.assertEqual((rc, out), (0, b"ok"))
        self.assertIsInstance(seen["argv"], list)
        self.assertIs(seen["shell"], False)
        self.assertEqual(seen["input"], b"DATA")
        self.assertEqual(seen["timeout"], 5.0)
        self.assertEqual(seen["env"], {"A": "1"})
        if os.name == "posix":
            self.assertTrue(callable(seen["preexec_fn"]))

    @unittest.skipUnless(os.name == "posix", "resource limits are POSIX only")
    def test_posix_limits_apply_in_the_child(self):
        r = subprocess.run([sys.executable, "-I", "-c", "import resource as r;print(r.getrlimit(r.RLIMIT_FSIZE),"
                            "r.getrlimit(r.RLIMIT_AS)[0])"], capture_output=True, timeout=30,
                           preexec_fn=ocr._posix_limits(2 << 30, 5))
        self.assertEqual(r.stdout.decode().split(), ["(0,", "0)", str(2 << 30)])

    def test_no_ocr_package_and_no_shell_in_plugin(self):
        self.assertNotIn("pytesseract", sys.modules)
        for f in PLUGIN.rglob("*.py"):
            src = f.read_text(encoding="utf-8")
            self.assertNotRegex(src, r"import\s+pytesseract|os\.system\(|shell\s*=\s*True|os\.popen\(", f.name)


class TestScamSigns(unittest.TestCase):
    def lv(self, t):
        return scam.assess(t).level

    def test_scams_high(self):
        for t in (SCAM_EN, SCAM_ZH, "Buy three Google Play gift cards and send me the numbers",
                  "This is Microsoft support, your computer is infected. Install AnyDesk now.",
                  "爷爷我出车祸了，先转两万五，别告诉我爸妈", "帮我买 10 张 500 元购物卡，拍卡号发我",
                  "点 击 链 接 https://example.invalid/a1 解 除 冻 结",          # OCR spacing
                  "ＵＲＧＥＮＴ: verify your account at https://paypa1-secure.invalid/login"):
            self.assertEqual(self.lv(t), "high", t)

    def test_honest_notices_not_flagged(self):
        for t in ("Police will never ask you to pay by gift card or transfer money to a safe account.",
                  "您的月度账单已生成，可在手机银行查看。我行不会索要密码。", "扫码看菜单，请到柜台付款。",
                  "感谢光临，购物卡请到前台办理。", "Your refund of $18.20 was returned to your original payment method.",
                  "Part-time library assistant wanted. Apply in person. No fees.", "公检法不会电话办案，没有安全账户。",
                  CLEAN, ""):
            self.assertIn(self.lv(t), ("none", "low"), t)

    def test_labels_cover_all_categories(self):
        for c in scam.ORDER:
            self.assertIn(c, messages.SCAM_LABELS)


class TestConfig(unittest.TestCase):
    def test_defaults_and_errors(self):
        c = config.parse({}).ocr
        self.assertEqual((c.enabled, c.languages, c.locale), ("auto", ("eng", "chi_sim"), "en"))
        for bad in ({"enabled": "yes"}, {"languages": ["e n"]}, {"languages": []}, {"engine_path": "tesseract"},
                    {"locale": "fr"}, {"timeout_s": 0}, {"max_pictures": 0}, {"unknown": 1}):
            with self.assertRaises(config.ConfigError, msg=bad):
                config.parse({"ocr": bad})


class PicBase(unittest.TestCase):
    def setUp(self):
        self.td = TmpDir()
        self.clock = fakes.Clock()
        self.gw = Gateway()

    def tearDown(self):
        self.td.cleanup()

    def guard(self, texts=("",), ocr_cfg=None, settings=None, **stub):
        self.stub = P.StubEngine(texts, **stub)
        s = {"ocr": dict({"engine_path": ENGINE}, **(ocr_cfg or {}))}
        s.update(settings or {})
        return make_guard(s, clock=self.clock, ocr_runner=self.stub)

    def pic(self, text="hello", user="u-stranger", data=None, name="shot.png", mime="image/png", chat="c1", n=1):
        paths = [self.td.file(f"{i}-{name}", data if data is not None else P.png()) for i in range(n)]
        return ev(text, user=user, chat=chat, media_urls=paths, media_types=[mime] * n, media_filenames=[name] * n)

    def d(self, g, e):
        return dispatch(g, e, self.gw)

    def sent(self):
        return self.gw.sent()


class TestDispatch(PicBase):
    def test_clean_picture_skipped_with_verdict(self):
        g = self.guard([CLEAN])
        self.assertEqual(self.d(g, self.pic("what is this?")), hooks.SKIP_PICTURE)
        self.assertEqual(self.sent(), [("c1", messages.picture_text("clean", "en"))])
        self.assertEqual(g.counters["pictures_read"], 1)

    def test_scam_from_stranger_warns_sender_and_alerts_owner(self):
        g = self.guard([SCAM_EN])
        self.assertEqual(self.d(g, self.pic("is this real?")), hooks.SKIP_PICTURE)
        chats = [c for c, _t in self.sent()]
        self.assertEqual(chats, ["c1", "owner-dm"])
        self.assertIn("looks like a scam", self.sent()[0][1])
        self.assertIn("asks you to pay or transfer money", self.sent()[0][1])
        self.assertIn("Scam warning", self.sent()[1][1])
        self.assertNotIn("example", self.sent()[1][1])          # no picture text in the alert

    def test_scam_from_owner_no_alert(self):
        g = self.guard([SCAM_ZH])
        self.assertEqual(self.d(g, self.pic("?", user=OWNER, chat="owner-dm")), hooks.SKIP_PICTURE)
        self.assertEqual(len(self.sent()), 1)

    def test_medium_no_alert(self):
        # a lone "call us back" is no longer a warning sign (fix round OC-2); a pay request with a link is
        g = self.guard(["Pay your toll balance at https://example.invalid/a1"])
        self.d(g, self.pic())
        self.assertEqual(len(self.sent()), 1)
        self.assertIn("warning signs", self.sent()[0][1])

    def test_alert_rate_limits(self):
        g = self.guard([SCAM_EN], ocr_cfg={"alerts_per_10min": 2})
        for i in range(3):
            self.d(g, self.pic(user=f"u-{i}", chat=f"c{i}"))
        self.assertEqual(sum(1 for c, _t in self.sent() if c == "owner-dm"), 2)
        self.clock.advance(601)
        self.d(g, self.pic(user="u-9", chat="c9"))
        self.assertEqual(sum(1 for c, _t in self.sent() if c == "owner-dm"), 3)
        g2 = self.guard([SCAM_EN])                       # per sender: the hold-notice limit (3 per 10 min)
        self.gw = Gateway()
        for _ in range(5):
            self.d(g2, self.pic())
        self.assertEqual(sum(1 for c, _t in self.sent() if c == "owner-dm"), 3)
        self.assertEqual(sum(1 for c, _t in self.sent() if c == "c1"), 3)

    def test_no_text(self):
        g = self.guard(["  \n "])
        self.assertEqual(self.d(g, self.pic()), hooks.SKIP_PICTURE)
        self.assertEqual(self.sent()[0][1], messages.picture_text("no_text", "en"))

    def test_injection_in_picture_is_held(self):
        g = self.guard([fakes.ATTACK])
        self.assertEqual(self.d(g, self.pic("look")), hooks.SKIP_HELD)
        self.assertEqual(len(g.holds), 1)
        self.assertEqual(self.sent()[0], ("c1", messages.picture_text("held_injection", "en")))
        self.assertIn("Held a message", self.sent()[1][1])
        hid = g.holds.pending()[0].hold_id
        r = self.d(g, ev(f"follow {hid}", user=OWNER, chat="owner-dm"))
        self.assertEqual(r["action"], "rewrite")
        self.assertIn("[attachment: picture text: ", r["text"])
        self.assertIn("released", r["text"])

    def test_injection_in_metadata_is_held(self):
        data = P.png(texts={"Comment": fakes.ATTACK})
        g = self.guard([CLEAN])
        self.assertEqual(self.d(g, self.pic(data=data)), hooks.SKIP_HELD)

    def test_unreadable_is_held(self):
        cases = {"engine-fails": (dict(rc=1), P.png(), "image/png", "failed"),
                 "not-a-picture": ({}, b"plain words, not a picture", "image/png", "not a picture"),
                 "tiff": ({}, b"II*\x00" + b"\x00" * 64, "image/tiff", "can't be checked yet"),
                 "too-big": ({}, P.png(9000, 9000), "image/png", "too large")}
        for label, (stub, data, mime, words) in cases.items():
            self.gw = Gateway()
            g = self.guard([CLEAN], **stub)
            self.assertEqual(self.d(g, self.pic(data=data, mime=mime)), hooks.SKIP_HELD, label)
            self.assertIn(words, self.sent()[0][1], label)
            self.assertIn("couldn't read your picture", self.sent()[0][1], label)
            self.assertIn("attachment not checked", self.sent()[1][1], label)

    def test_too_many_pictures_and_size(self):
        g = self.guard([CLEAN], ocr_cfg={"max_pictures": 2})
        self.assertEqual(self.d(g, self.pic(n=3)), hooks.SKIP_HELD)
        self.assertIn("too many pictures", self.sent()[0][1])
        self.gw = Gateway()
        g = self.guard([CLEAN], ocr_cfg={"max_bytes": 10_000})
        self.assertEqual(self.d(g, self.pic(data=P.png(texts={"c": "x" * 20_000}))), hooks.SKIP_HELD)

    def test_switched_on_without_engine_holds(self):
        g = make_guard({"ocr": {"enabled": True}}, clock=self.clock)
        self.assertEqual(self.d(g, self.pic()), hooks.SKIP_HELD)
        self.assertIn("no picture reader", self.sent()[0][1])
        self.assertIn("reader MISSING", g.cmd_guard("", source=fakes.Source(user_id=OWNER)))

    def test_auto_without_engine_and_off_fall_back_to_policy(self):
        for s in ({}, {"ocr": {"enabled": False, "engine_path": ENGINE}}):
            g = make_guard(s, clock=self.clock, ocr_runner=P.StubEngine([CLEAN]))
            self.assertIsNone(g.ocr)
            self.assertEqual(self.d(g, self.pic()), hooks.SKIP_HELD)          # unscanned_media: hold
            self.assertIn("pictures: not read", g.cmd_guard("", source=fakes.Source(user_id=OWNER)))
        g = make_guard({"threshold": {"unscanned_media": "allow"}}, clock=self.clock)
        self.assertIsNone(self.d(g, self.pic()))

    def test_report_mode_passes(self):
        g = self.guard([SCAM_EN], settings={"mode": "report"})
        self.assertIsNone(self.d(g, self.pic()))
        self.assertEqual(self.sent(), [])

    def test_locales(self):
        g = self.guard([SCAM_ZH], ocr_cfg={"locale": "zh"})
        self.d(g, self.pic())
        self.assertTrue(self.sent()[0][1].startswith("我检查了您图片里的文字：这很可能是诈骗"))
        self.assertIn("防骗提醒", self.sent()[1][1])
        self.gw = Gateway()
        g = self.guard([CLEAN], ocr_cfg={"locale": "both"})
        self.d(g, self.pic())
        zh, en = self.sent()[0][1].split("\n")
        self.assertIn("没有发现明显的诈骗迹象", zh)
        self.assertIn("no clear scam signs", en)

    def test_caption_counts_for_scam_and_injection(self):
        g = self.guard([CLEAN])
        self.assertEqual(self.d(g, self.pic(fakes.ATTACK)), hooks.SKIP_HELD)
        self.gw = Gateway()
        g = self.guard(["Lakeshore Savings"])
        self.d(g, self.pic("they say: verify your account at https://example.invalid/a1 now"))
        self.assertIn("looks like a scam", self.sent()[0][1])

    def test_picture_text_never_in_replies(self):
        g = self.guard(["SECRETWORD " + SCAM_EN])
        self.d(g, self.pic())
        self.assertTrue(all("SECRETWORD" not in t for _c, t in self.sent()))

    def test_status_line(self):
        g = self.guard([CLEAN])
        self.assertIn("pictures: read and checked", g.cmd_guard())


if __name__ == "__main__":
    unittest.main()
