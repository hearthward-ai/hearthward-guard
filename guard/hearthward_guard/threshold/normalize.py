"""Text normalisation for scanning: hidden characters, look-alike letters and spacing tricks.

reveal() removes invisible characters, decodes text hidden in Unicode TAG characters, variation
selectors and zero-width bit strings, and reports what it found. variants() then produces the forms
the pattern families are matched against (NFKC, confusable-folded, de-spaced, leet-folded, accents
removed). Matching is done on every variant; a hit on any of them counts.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Bidirectional controls (embeddings, overrides, isolates, marks).
BIDI = frozenset([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
# Only LRO/RLO reorder text against its own direction; embeddings, isolates and marks are ordinary in
# right-to-left writing (recheck R5).
BIDI_OVERRIDES = frozenset([0x202D, 0x202E])
# Zero-width and other invisible format characters (ZWJ/ZWNJ handled separately).
INVISIBLE = frozenset([0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D, 0x180E,
                       0x180F, 0x200B, *range(0x2060, 0x2065), 0x3164, 0xFEFF, 0xFFA0, 0xFFF9, 0xFFFA,
                       0xFFFB, 0x1BCA0, 0x1BCA1, 0x1BCA2, 0x1BCA3, *range(0x1D173, 0x1D17B)])
ZWNJ, ZWJ = 0x200C, 0x200D
TAG_START, TAG_END = 0xE0000, 0xE007F
VS_BMP = range(0xFE00, 0xFE10)        # VS1-VS16
VS_SUPP = range(0xE0100, 0xE01F0)     # VS17-VS256

# Regex that strips every character reveal() treats as hidden (used by Gatehouse too).
HIDDEN_RX = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u2064"
    "\u2066-\u2069\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]")

# Look-alike letters (Cyrillic, Greek, Armenian, Latin extensions) folded to ASCII.
_CONFUSABLES = {
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c",
    "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "һ": "h", "ӏ": "l", "ɡ": "g", "ɑ": "a", "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "γ": "y", "ω": "w", "η": "n", "μ": "u", "ѵ": "v", "ү": "y",
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "Ѕ": "s", "І": "i", "Ј": "j", "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i",
    "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x", "օ": "o", "ս": "u",
    "ց": "g", "ո": "n", "ı": "i", "ȷ": "j", "ℓ": "l", "ⅰ": "i", "ⅼ": "l", "ꓲ": "i", "Ꭵ": "i", "ᴀ": "a",
    "ʀ": "r", "ɪ": "i", "ᴏ": "o", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ɴ": "n", "ᴇ": "e", "ɢ": "g",
}
_CONFUSABLES.update({
    # Cyrillic / Greek extras, Coptic, Cherokee (review M2)
    "г": "r", "п": "n", "ь": "b", "ԍ": "g", "ɩ": "i", "β": "b", "ϲ": "c", "Ϲ": "c", "ϳ": "j", "ϵ": "e",
    "ø": "o", "Ø": "o", "ð": "d", "đ": "d", "ħ": "h", "ł": "l", "Ł": "l", "ŧ": "t", "ƀ": "b",
    "ⲁ": "a", "ⲃ": "b", "ⲅ": "r", "ⲇ": "d", "ⲉ": "e", "ⲏ": "h", "ⲓ": "i", "ⲕ": "k", "ⲙ": "m", "ⲛ": "n",
    "ⲟ": "o", "ⲣ": "p", "ⲥ": "c", "ⲧ": "t", "ⲩ": "y", "ⲭ": "x", "ⲱ": "w",
    "Ⲁ": "a", "Ⲃ": "b", "Ⲅ": "r", "Ⲇ": "d", "Ⲉ": "e", "Ⲏ": "h", "Ⲓ": "i", "Ⲕ": "k", "Ⲙ": "m", "Ⲛ": "n",
    "Ⲟ": "o", "Ⲣ": "p", "Ⲥ": "c", "Ⲧ": "t", "Ⲩ": "y", "Ⲭ": "x", "Ⲱ": "w",
    "Ꭺ": "a", "Ᏼ": "b", "Ꮯ": "c", "Ꭰ": "d", "Ꭼ": "e", "Ꮐ": "g", "Ꮋ": "h", "Ꭻ": "j", "Ꮶ": "k",
    "Ꮮ": "l", "Ꮇ": "m", "Ꮲ": "p", "Ꮢ": "r", "Ꮪ": "s", "Ꭲ": "t", "Ꮩ": "v", "Ꮃ": "w", "Ꮓ": "z",
})
_CONFUSABLES.update({
    # more Cherokee capitals and the regional-indicator letters (recheck M2)
    "Ꭱ": "r", "Ꭹ": "y", "Ꮍ": "y", "Ꮒ": "h", "Ꮟ": "b", "Ꮤ": "w", "Ꮥ": "s", "Ꮷ": "d", "Ᏻ": "g",
    **{chr(cp): chr(cp - 0x1F1E6 + 97) for cp in range(0x1F1E6, 0x1F200)},
})
# Cherokee small letters fold to the capitals above.
for _c in list(_CONFUSABLES):
    if 0x13A0 <= ord(_c) <= 0x13EF:
        _CONFUSABLES[chr(ord(_c) - 0x13A0 + 0xAB70)] = _CONFUSABLES[_c]


def _generated_latin() -> dict:
    """Latin letter variants (small capitals, letters with stroke or hook, circled/negative/squared
    letters) whose NFKD form is not plain ASCII, folded to the base letter by Unicode name."""
    import itertools
    rx = re.compile(r"^(?:NEGATIVE |CIRCLED |SQUARED |PARENTHESIZED )*LATIN (?:CAPITAL |SMALL )?LETTER "
                    r"(?:SMALL CAPITAL )?([A-Z])(?: WITH .*)?$")
    out = {}
    for cp in itertools.chain(range(0xC0, 0x2B0), range(0x1D00, 0x1D80), range(0x2C60, 0x2C80),
                              range(0xA720, 0xA800), range(0xAB30, 0xAB70), range(0x1F110, 0x1F18A)):
        c = chr(cp)
        m = rx.match(unicodedata.name(c, ""))
        if not m:
            continue
        base = "".join(x for x in unicodedata.normalize("NFKD", c) if not unicodedata.combining(x))
        if not base.isascii():
            out[c] = m.group(1).lower()
    return out


for _c, _v in _generated_latin().items():
    _CONFUSABLES.setdefault(_c, _v)
_CONF_TABLE = str.maketrans(_CONFUSABLES)
_LEET_L_TABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                               "$": "s", "!": "i", "|": "l", "+": "t", "8": "b", "9": "g"})
_LEET_TABLE = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                             "$": "s", "!": "i", "|": "l", "+": "t", "8": "b", "9": "g"})
_WS_RX = re.compile(r"\s+")
# Letter-spaced words: "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e", "i_g_n" (4+ single letters).
_SPACED_RX = re.compile(r"(?<!\w)(?:\w[ .\-_*~|/\\·•]{1,3}){3,}\w(?!\w)")
_INWORD_PUNCT_RX = re.compile(r"(?<=\w)[.\-_*~`|'’·•]+(?=\w)")
_MD_RX = re.compile(r"[*_~`#>]+")
_HTML_COMMENT_RX = re.compile(r"<!--(.*?)-->", re.S)
_HTML_TAG_RX = re.compile(r"</?[A-Za-z][^<>]{0,400}>")


@dataclass
class Revealed:
    text: str                               # visible text, hidden characters removed
    hidden_payloads: list = field(default_factory=list)   # decoded hidden text (tags, VS, zero-width bits)
    counts: dict = field(default_factory=dict)            # kind -> count
    flags: list = field(default_factory=list)             # e.g. "tag-text", "bidi-override", "vs-smuggling"
    spaced: str = ""                        # the text with every removed character turned into a space ("" = same)
    alt: str = ""                           # the text with only ESC bytes removed, revealed ("" = no ESC, recheck R1)


# Real (RGI) subdivision flags: black flag + one of these tag codes + cancel tag. Any other tag run is text.
RGI_TAG_FLAGS = frozenset({"gbeng", "gbsct", "gbwls"})
# Terminal escape sequences (colour codes, cursor moves, window titles) are removed whole.
_ANSI_RX = re.compile(r"\x1b\[[0-?]{0,40}[ -/]{0,5}[@-~]|\x1b\][^\x07\x1b]{0,400}(?:\x07|\x1b\\)|\x1b[@-_]")
# Zero-width characters that carry bits; LRM/RLM runs are decoded the same way.
ZW_RUN = frozenset([0x200B, ZWNJ, ZWJ, 0x2060, 0x2062, 0x2063, 0x2064])
DIR_MARKS = frozenset([0x200E, 0x200F])
# Selectors and joiners are dropped from every copy that patterns are matched on (review H5).
_SELECTOR_RX = re.compile("[\u200c\u200d\ufe00-\ufe0f\U000e0100-\U000e01ef]")
# Modifier letters (U+02BC apostrophe, U+0640 tatweel, U+02D0 length mark ...) and digits inside a
# Latin word: a reader skips them, the word still reads (recheck H4).
_LM_CHARS = "".join(chr(c) for c in range(0x80, 0x10000) if unicodedata.category(chr(c)) == "Lm")
_INLETTER_RX = re.compile("(?<=[A-Za-z])[" + re.escape(_LM_CHARS) + "0-9'\u2019`\u00b4]+(?=[A-Za-z])")
_LM_DEL = {ord(c): None for c in _LM_CHARS}


def _is_emoji_context(ch: str) -> bool:
    if not ch:
        return False
    cp = ord(ch)
    return (unicodedata.category(ch) == "So" or 0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF
            or cp in (0xFE0F, 0x200D, 0x00A9, 0x00AE, 0x2122, 0x3030, 0x303D, 0x203C, 0x2049)
            or 0x1F3FB <= cp <= 0x1F3FF or 0x2190 <= cp <= 0x21FF or 0x2300 <= cp <= 0x23FF
            or 0x2B00 <= cp <= 0x2BFF or 0x30 <= cp <= 0x39 or cp in (0x23, 0x2A))   # keycaps 0-9 # *


def _joining_script(ch: str) -> bool:
    """Scripts where ZWJ/ZWNJ are legitimate (Arabic, Persian, Indic, Sinhala ...)."""
    if not ch:
        return False
    cp = ord(ch)
    return (0x0600 <= cp <= 0x08FF or 0x0900 <= cp <= 0x0DFF or 0xFB50 <= cp <= 0xFEFC
            or 0x0E00 <= cp <= 0x0FFF or 0x1780 <= cp <= 0x17FF)


def _is_cjk(ch: str) -> bool:
    cp = ord(ch) if ch else 0
    return 0x3400 <= cp <= 0x9FFF or 0x20000 <= cp <= 0x3FFFF or 0xF900 <= cp <= 0xFAFF


def _vs_byte(cp: int) -> int:
    return cp - 0xFE00 if 0xFE00 <= cp <= 0xFE0F else cp - 0xE0100 + 16


def _bytes_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _bits_payload(symbols: list) -> str | None:
    """A run of two distinct invisible characters read as bits (both polarities, strict UTF-8)."""
    kinds = sorted(set(symbols), key=symbols.count, reverse=True)
    if len(kinds) != 2 or len(symbols) < 8:
        return None
    for zero in kinds:
        b = "".join("0" if c == zero else "1" for c in symbols)
        data = bytes(int(b[k:k + 8], 2) for k in range(0, len(b) - len(b) % 8, 8))
        try:
            dec = data.decode("utf-8")      # strict: the wrong polarity is not valid text
        except UnicodeDecodeError:
            continue
        if dec.strip() and sum(c.isprintable() for c in dec) >= 0.8 * len(dec):
            return dec
    return None


_PLAIN_RUN_RX = re.compile("[\t\n\r -~]+")


def reveal(text: str) -> Revealed:
    """Strip hidden characters and decode anything smuggled in them."""
    n_ansi = 0
    alt = ""
    if "\x1b" in text:
        # A terminal hides an escape sequence and what it carries (a window title, the letter that
        # ends a CSI sequence); a model reads all of it. Both readings are returned (recheck R1).
        alt = reveal(text.replace("\x1b", " ")).text
        n_ansi = len(_ANSI_RX.findall(text))
        text = _ANSI_RX.sub("", text)
    out: list[str] = []
    sp: list[str] = []          # parallel copy where removed characters become spaces
    payloads: list[str] = []
    counts: dict[str, int] = {}
    flags: list[str] = []
    tag_runs: list[str] = []
    lone_vs: list[int] = []     # single selectors after letters/digits: one smuggled byte each
    n = len(text)
    i = 0

    def bump(k, v=1):
        counts[k] = counts.get(k, 0) + v

    def keep(s):
        out.append(s)
        sp.append(s)

    def drop():
        if not sp or sp[-1][-1:] != " ":
            sp.append(" ")

    if n_ansi:
        bump("ansi", n_ansi)
    while i < n:
        ch = text[i]
        cp = ord(ch)
        if cp < 0x80 and (ch.isprintable() or ch in "\t\n\r"):     # fast path for plain ASCII
            j = _PLAIN_RUN_RX.match(text, i).end()
            keep(text[i:j])
            i = j
            continue
        # TAG block: ASCII hidden as U+E0020..E007E. Only a real subdivision flag is benign.
        if TAG_START <= cp <= TAG_END:
            j = i
            buf = []
            while j < n and TAG_START <= ord(text[j]) <= TAG_END:
                c = ord(text[j])
                if 0xE0020 <= c <= 0xE007E:
                    buf.append(chr(c - 0xE0000))
                j += 1
            run = "".join(buf)
            prev = out[-1][-1:] if out else ""
            if prev == "\U0001F3F4" and run in RGI_TAG_FLAGS and ord(text[j - 1]) == 0xE007F:
                bump("tag-flag")
                keep(text[i:j])
            else:
                bump("tag", j - i)
                drop()
                if run.strip():
                    payloads.append(run)
                    tag_runs.append(run)
                    flags.append("tag-text")
            i = j
            continue
        # Variation selectors: one after an emoji or CJK ideograph is normal; a run, or one after
        # anything else, is byte smuggling (VS1-256 map to bytes 0-255).
        if cp in VS_BMP or cp in VS_SUPP:
            j = i
            while j < n and (ord(text[j]) in VS_BMP or ord(text[j]) in VS_SUPP):
                j += 1
            prev = out[-1][-1:] if out else ""
            run_len = j - i
            if run_len == 1 and (_is_emoji_context(prev) or _is_cjk(prev)):
                keep(ch)
                bump("vs-normal")
            else:
                bump("vs", run_len)
                drop()
                if run_len >= 2:
                    decoded = _bytes_text(bytes(_vs_byte(ord(c)) for c in text[i:j]))
                    if decoded.strip():
                        payloads.append(decoded)
                    flags.append("vs-smuggling")
                else:
                    lone_vs.append(_vs_byte(cp))
            i = j
            continue
        # Zero-width bit strings (two symbols, optionally a third as separator) and LRM/RLM bit strings.
        if cp in ZW_RUN or cp in DIR_MARKS:
            group = ZW_RUN if cp in ZW_RUN else DIR_MARKS
            j = i
            while j < n and ord(text[j]) in group:
                j += 1
            run = text[i:j]
            prev = out[-1][-1:] if out else ""
            nxt = text[j] if j < n else ""
            if len(run) == 1 and cp == ZWJ and (_is_emoji_context(prev) or _is_emoji_context(nxt)):
                keep(ch)
                bump("zwj-emoji")
            elif len(run) == 1 and cp in (ZWNJ, ZWJ) and (_joining_script(prev) or _joining_script(nxt)):
                keep(ch)
                bump("zw-script")
            else:
                bump("zero-width" if group is ZW_RUN else "bidi", len(run))
                drop()
                if len(run) >= 8:
                    syms = list(run)
                    if len(set(syms)) == 3:
                        rare = min(set(syms), key=syms.count)      # separator character
                        syms = [c for c in syms if c != rare]
                    dec = _bits_payload(syms)
                    if dec:
                        payloads.append(dec)
                        flags.append("zero-width-bits")
            i = j
            continue
        if cp in BIDI:
            bump("bidi")
            if cp in BIDI_OVERRIDES:
                bump("bidi-override")
            drop()
            i += 1
            continue
        if cp in INVISIBLE:
            bump("soft-hyphen" if cp == 0xAD else "invisible")      # hyphenation hints: ordinary (R5)
            drop()
            i += 1
            continue
        cat = unicodedata.category(ch)
        if cat == "Cc" and ch not in "\t\n\r":
            bump("control")
            drop()
            i += 1
            continue
        if cat == "Cf" or cp == 0xFFFD or 0xFFF0 <= cp <= 0xFFF8:
            bump("replacement" if cp == 0xFFFD else "invisible")
            drop()
            i += 1
            continue
        keep(ch)
        i += 1
    if len(tag_runs) > 1:
        payloads.append("".join(tag_runs))
    if len(lone_vs) >= 4:
        dec = _bytes_text(bytes(lone_vs))
        if dec.strip():
            payloads.append(dec)
        flags.append("vs-smuggling")
    if counts.get("bidi-override"):
        flags.append("bidi-override")
    bidi = counts.get("bidi", 0)
    hidden_total = (counts.get("zero-width", 0) + counts.get("invisible", 0) + counts.get("vs", 0)
                    + counts.get("tag", 0) + (bidi if bidi >= 16 else 0))
    if hidden_total >= 4:
        flags.append("many-invisible")
    visible = "".join(out)
    spaced = "".join(sp)
    return Revealed(visible, payloads, counts, sorted(set(flags), key=flags.index),
                    spaced if spaced != visible else "", alt if alt and alt != visible else "")


def strip_marks(s: str) -> str:
    """Remove combining marks (accents, 'zalgo' stacks) after NFKD."""
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


def fold_confusables(s: str) -> str:
    return s.translate(_CONF_TABLE)


def drop_selectors(s: str) -> str:
    return _SELECTOR_RX.sub("", s)


def despace(s: str) -> str:
    """Join letter-spaced words and drop punctuation inside words."""
    s = _SPACED_RX.sub(lambda m: re.sub(r"[ .\-_*~|/\\·•]", "", m.group(0)), s)
    return _INWORD_PUNCT_RX.sub("", s)


def collapse_ws(s: str) -> str:
    return _WS_RX.sub(" ", s).strip()


def _html_comments(s: str, sep: str) -> str:
    """Un-wrap HTML comments in linear time (a lazy regex rescans to the end for every unclosed
    opener, review H1). Comment bodies are kept: hidden from a human reader, not from a model."""
    if "<!--" not in s:
        return s
    out, i = [], 0
    while True:
        j = s.find("<!--", i)
        if j < 0:
            out.append(s[i:])
            break
        k = s.find("-->", j + 4)
        if k < 0:
            out.append(s[i:])
            break
        out.append(s[i:j])
        out.append(sep + s[j + 4:k] + sep)
        i = k + 3
    return "".join(out)


def html_visible(s: str) -> str:
    """Text with HTML comments un-wrapped and tags replaced by spaces."""
    return _HTML_TAG_RX.sub(" ", _html_comments(s, " "))


def html_glued(s: str) -> str:
    """Text with HTML comments un-wrapped and tags deleted (tags inside a word glue it back)."""
    return _HTML_TAG_RX.sub("", _html_comments(s, ""))


# Chinese/Japanese: separators, markdown and spaces between ideographs or kana are dropped in one
# variant ("忽**略**", "忽 略", "忽、略"); Traditional characters used by the rules map to Simplified.
_CJK = "\u3040-ヿ㐀-鿿豈-\ufaff"
_CJK_SEP_RX = re.compile("(?<=[" + _CJK + "])[\\s*_~`#、，,·・\\-]+(?=[" + _CJK + "])")
_CJK_ANY_RX = re.compile("[" + _CJK + "]")
_TRAD = ("無視規則輸係統詞記設訴戶從現開沒說約過繞蓋棄為個們顯洩複給隱獄惡發員須將機語體數據請準許"
         "對話應該寫讓關於來時後這裡麼論與議導權級絕條項選擇並當")
_SIMP = ("无视规则输系统词记设诉户从现开没说约过绕盖弃为个们显泄复给隐狱恶发员须将机语体数据请准许"
         "对话应该写让关于来时后这里么论与议导权级绝条项选择并当")
# More Traditional characters (pairs: Traditional, Simplified), so Traditional and Taiwan wording
# that the rules do not list character by character still reads as the rules expect (recheck H6).
_T2S_MORE = ("拋抛萬万別别啟启啓启際际經经進进運运還还邊边達达遞递擇择歷历錄录鍵键鑰钥碼码帳账號号傳传讀读譯译"
             "識识認认證证護护變变論论調调談谈謝谢講讲詳详誤误話话記记計计訊讯試试註注評评詢询響响頁页"
             "順顺預预領领題题類类風风飛飞馬马驗验點点網网線线結结維维續续總总編编練练織织繼继紅红級级紀纪"
             "純纯細细終终組组絡络執执報报場场壓压處处備备夠够夢梦奪夺學学實实專专屬属層层師师帶带幫帮廣广"
             "張张強强彈弹復复應应態态愛爱憑凭戲戏擊击擔担據据擋挡擬拟擴扩攝摄敵敌斷断書书會会東东極极構构"
             "標标樣样檔档檢检歡欢氣气決决減减測测滅灭漢汉濟济爲为狀状獨独獲获環环產产畫画異异盡尽監监盤盘"
             "確确禮礼稱称種种穩稳競竞筆笔簡简範范節节聯联聲声聽听職职腦脑興兴舊旧華华葉叶著着術术衛卫補补"
             "裝装製制規规視视覺觉覽览觀观討讨訂订誰谁課课謀谋豐丰負负財财責责貨货買买費费資资賬账質质購购"
             "趕赶車车軟软載载較较輕轻輯辑轉转辦办農农連连週周遠远適适遲迟遺遗邏逻郵邮醫医釋释針针錢钱錯错"
             "鏈链長长門门閉闭問问間间閱阅隊队陽阳階阶隨随險险隻只雖虽雙双雜杂離离難难雲云電电靜静頭头願愿"
             "飯饭養养館馆魚鱼鳥鸟黃黄業业兩两亂乱亞亚價价優优兒儿內内參参單单嚴严圖图團团國国圍围媽妈"
             "嗎吗衝冲彙汇匯汇區区協协卻却壞坏鐘钟鐵铁臺台裏里")
_T2S = str.maketrans({**dict(zip(_TRAD, _SIMP)),
                      **{_T2S_MORE[i]: _T2S_MORE[i + 1] for i in range(0, len(_T2S_MORE) - 1, 2)}})


def cjk_forms(nfkc: str) -> list[str]:
    """Extra forms for text with Chinese or Japanese characters ([] for other text)."""
    if not _CJK_ANY_RX.search(nfkc):
        return []
    glued = _CJK_SEP_RX.sub("", collapse_ws(_MD_RX.sub(" ", html_glued(nfkc))))
    out = [glued]
    simp = glued.translate(_T2S)
    if simp != glued:
        out.append(simp)
    return out


def variants(text: str) -> list[str]:
    """Distinct forms of already-revealed text to match patterns against (bounded count)."""
    text = drop_selectors(text)
    base = collapse_ws(text)
    nfkc = collapse_ws(unicodedata.normalize("NFKC", text))
    folded = fold_confusables(strip_marks(nfkc))
    plain = collapse_ws(_MD_RX.sub(" ", html_visible(folded)))
    spaced = collapse_ws(despace(plain))
    leet = collapse_ws(spaced.translate(_LEET_TABLE))
    words = words_only(folded)
    inword = collapse_ws(despace(html_glued(folded)))           # markdown/tags inside a word deleted
    md_nofold = collapse_ws(_MD_RX.sub(" ", html_visible(nfkc)))  # Cyrillic etc. kept as written
    inletter = collapse_ws(_INLETTER_RX.sub("", plain))
    out: list[str] = []
    for v in (base, nfkc, folded, plain, spaced, leet, words, inword, md_nofold, *cjk_forms(nfkc), inletter):
        if v and v not in out:
            out.append(v)
    return out


_CAMEL_RX = re.compile(r"(?<=[a-z])(?=[A-Z])")
_NONWORD_RX = re.compile(r"[^\w\s']+|_+")


def words_only(s: str) -> str:
    """Words split on camelCase and on any punctuation, symbol or emoji between them:
    "ignoreAll-previous_instructions" and "ignore. all. previous." both become plain words."""
    return collapse_ws(_NONWORD_RX.sub(" ", _CAMEL_RX.sub(" ", html_visible(s)))).lower()


def squashed(text: str) -> list[str]:
    """The whole text as letters and digits only, lower case, look-alikes folded, in two leetspeak
    readings (1 as i, 1 as l). Catches words run together, invisible or punctuation separators,
    in-word markup and odd chunking ("ign ore prev ious"). Matched only against SQUASHED_WHOLE."""
    t = fold_confusables(strip_marks(unicodedata.normalize("NFKC", html_glued(drop_selectors(text))))).translate(_LM_DEL)
    out = []
    for table in (_LEET_TABLE, _LEET_L_TABLE):
        s = "".join(c for c in t.translate(table) if c.isalnum()).lower()
        if s and s not in out:
            out.append(s)
    return out


def mixed_script_words(text: str, limit: int = 20) -> int:
    """Count words that mix Latin with Cyrillic/Greek letters that pass for Latin ones (a look-alike
    signal): 4+ letters, no digits, and every foreign letter folds to ASCII. Symbols such as
    "λmax", "σyy" or "ωt0" are not look-alike words (recheck R5)."""
    n = 0
    for w in re.findall(r"\w{4,}", text):
        scripts = set()
        for c in w:
            cp = ord(c)
            if c.isascii() and c.isalpha():
                scripts.add("L")
            elif 0x0400 <= cp <= 0x052F:
                scripts.add("C")
            elif 0x0370 <= cp <= 0x03FF:
                scripts.add("G")
        if "L" in scripts and len(scripts) > 1:
            f = fold_confusables(w)
            if not (f.isascii() and f.isalpha()):
                continue
            n += 1
            if n >= limit:
                break
    return n


_LETTER_RUN_RX = re.compile(r"(?<!\w)(?:\w[^\w\n]{1,3}){4,}\w(?!\w)")


def spaced_runs(text: str, limit: int = 50) -> list[str]:
    """Runs of 5+ single characters separated by spaces/punctuation, squashed to lowercase letters
    (look-alikes and leetspeak folded). "I g n o r e  a l l" -> "ignoreall"."""
    out = []
    folded = fold_confusables(strip_marks(unicodedata.normalize("NFKC", text)))
    for m in _LETTER_RUN_RX.finditer(folded):
        s = re.sub(r"[^\w]", "", m.group(0)).translate(_LEET_TABLE).lower()
        if len(s) >= 5:
            out.append(s)
            if len(out) >= limit:
                break
    return out


def strip_stray_selectors(text: str) -> str:
    """Remove variation selectors that do not follow an emoji or a CJK ideograph (for replies)."""
    if not _SELECTOR_RX.search(text):
        return text
    out = []
    for ch in text:
        cp = ord(ch)
        if (cp in VS_BMP or cp in VS_SUPP) and not (out and (_is_emoji_context(out[-1]) or _is_cjk(out[-1]))):
            continue
        out.append(ch)
    return "".join(out)
