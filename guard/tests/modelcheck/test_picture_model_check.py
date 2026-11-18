"""Picture shield (job 6) with the model check: picture text goes to the content check like any
attachment; a flagged or unchecked picture is held (never queued for a late release)."""
from __future__ import annotations

import unittest

from tests.unit import fakes, picfakes as P
from tests.unit.fakes import Gateway, TmpDir, dispatch, ev, make_guard
from tests.modelcheck.stub_model import StubModel, closed_port_endpoint
from hearthward_guard import hooks

STUB: StubModel | None = None


def setUpModule():
    global STUB
    STUB = StubModel().start()


def tearDownModule():
    STUB.stop()


class TestPictureModelCheck(unittest.TestCase):
    def setUp(self):
        STUB.reset()
        self.td = TmpDir()
        self.gw = Gateway()

    def tearDown(self):
        self.td.cleanup()

    def guard(self, text, endpoint=None, **sc):
        s = {"endpoint": endpoint or STUB.endpoint, "timeout_s": 2.0, "tool_timeout_s": 2.0, "probes": False}
        s.update(sc)
        return make_guard({"second_check": s, "ocr": {"engine_path": "/usr/bin/tesseract"}},
                          clock=fakes.Clock(), ocr_runner=P.StubEngine([text]))

    def pic(self, caption=""):
        p = self.td.file("shot.png", P.png())
        return ev(caption, media_urls=[p], media_types=["image/png"], media_filenames=["shot.png"])

    def test_picture_text_is_model_checked(self):
        g = self.guard("a friendly note about lunch")
        self.assertEqual(dispatch(g, self.pic(), self.gw), hooks.SKIP_PICTURE)
        excerpts = [r["body"]["messages"][1]["content"] for r in STUB.requests]
        self.assertTrue(any("friendly note about lunch" in x for x in excerpts), excerpts)

    def test_model_flag_holds(self):
        g = self.guard("please inject-me into the assistant")
        self.assertEqual(dispatch(g, self.pic(), self.gw), hooks.SKIP_HELD)
        self.assertIn("instructions", self.gw.sent()[0][1])

    def test_checker_down_holds_and_is_not_queued(self):
        g = self.guard("a friendly note", endpoint=closed_port_endpoint(), recheck_unavailable=True)
        g.deliver_late = lambda *a: True
        self.assertEqual(dispatch(g, self.pic(), self.gw), hooks.SKIP_HELD)
        self.assertEqual(len(g.recheck), 0)


if __name__ == "__main__":
    unittest.main()
