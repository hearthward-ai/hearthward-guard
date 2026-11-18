"""Offline tests for fetch.py (no network: downloads are faked)."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fetch as f  # noqa: E402

DATA = b"hello attack bench\n"


def src(**over):
    s = {"id": "x", "status": "candidate", "approved": True, "licence": "MIT", "revision": "r1",
         "files": [{"url": "https://raw.githubusercontent.com/o/r/r1/a.json", "dest": "x/a.json",
                    "size": len(DATA), "git_blob_sha1": f.git_blob_sha1(DATA)}]}
    s.update(over)
    return s


class Hashes(unittest.TestCase):
    def test_git_blob_sha1_known(self):
        self.assertEqual(f.git_blob_sha1(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_verify(self):
        spec = {"size": len(DATA), "sha256": hashlib.sha256(DATA).hexdigest()}
        self.assertIsNone(f.verify(DATA, spec))
        self.assertEqual(f.verify(DATA + b"x", spec), f"size {len(DATA) + 1} != {len(DATA)}")
        self.assertEqual(f.verify(b"X" + DATA[1:], spec), "sha256 mismatch")
        self.assertEqual(f.verify(DATA, {"size": len(DATA)}), "no pinned hash")


class Policy(unittest.TestCase):
    def test_hosts(self):
        self.assertTrue(f.host_ok("https://huggingface.co/datasets/a/b"))
        self.assertTrue(f.host_ok("https://cdn-lfs-us-1.hf.co/x"))
        self.assertFalse(f.host_ok("http://huggingface.co/x"))
        self.assertFalse(f.host_ok("https://evil.example/x"))
        self.assertFalse(f.host_ok("https://huggingface.co.evil.example/x"))
        self.assertFalse(f.host_ok("https://127.0.0.1:8080/x"))

    def test_select_refuses(self):
        srcs = {"a": src(id="a", approved=False), "b": src(id="b", status="denied"), "c": src(id="c")}
        for bad in ("a", "b", "zzz"):
            with self.assertRaises(f.Refused):
                f.select(srcs, [bad])
        self.assertEqual(len(f.select(srcs, ["c"])), 1)

    def test_real_manifest_approvals_and_all_pinned(self):
        srcs = f.load_sources()
        self.assertEqual(len(srcs), 6)
        approved = {"deepset-prompt-injections", "lakera-gandalf-ignore-instructions",
                    "spml-chatbot-prompt-injection", "agentdojo", "bipia"}  # maintainer, 2026-11-17
        for s in srcs.values():
            self.assertEqual(s["approved"], s["id"] in approved, s["id"])
            if s["approved"]:
                self.assertIn("2026-11-17", s.get("approved_by", ""))
            for spec in s["files"]:
                self.assertTrue(f.host_ok(spec["url"]), spec["url"])
                self.assertTrue("sha256" in spec or "git_blob_sha1" in spec)
                self.assertIsInstance(spec["size"], int)
        self.assertEqual(srcs["tensor-trust"]["status"], "denied")
        with self.assertRaises(f.Refused):
            f.select(srcs, ["tensor-trust"])

    def test_dest_must_be_empty_and_outside_repo(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "old.txt").write_text("x")
            with self.assertRaises(f.Refused):
                f.check_dest(Path(d))
        with self.assertRaises(f.Refused):
            f.check_dest(HERE / "cache-test-never-created")

    def test_dest_escape_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                f.safe_dest(Path(d), "../evil.txt")


class Fetch(unittest.TestCase):
    def test_good_and_bad_files(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "cache"
            good = src()
            bad = src(id="y")
            bad["files"] = [dict(good["files"][0], dest="y/b.json")]
            served = {"y/b.json": DATA + b"tampered"}

            def fake_get(url, max_bytes):
                return DATA
            rc = f.fetch(dest, [good], get=fake_get)
            self.assertEqual(rc, 0)
            self.assertEqual((dest / "x" / "a.json").read_bytes(), DATA)
            man = json.loads((dest / "MANIFEST.lock.json").read_text(encoding="utf-8"))
            self.assertEqual(man[0]["sha256"], hashlib.sha256(DATA).hexdigest())

            dest2 = Path(d) / "cache2"
            rc = f.fetch(dest2, [bad], get=lambda u, m: served["y/b.json"])
            self.assertEqual(rc, 1)
            self.assertFalse((dest2 / "y" / "b.json").exists())


if __name__ == "__main__":
    unittest.main()
