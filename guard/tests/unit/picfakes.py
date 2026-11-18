"""Synthetic picture files for the picture-shield tests (stdlib only, built at run time).

The bytes are valid enough for the guard's header checks and metadata reader; the stub OCR engine
never decodes pixels, it answers with the text the test gives it.
"""
from __future__ import annotations

import struct
import zlib


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)


def png(w: int = 64, h: int = 32, texts: dict | None = None, ztexts: dict | None = None, itexts: dict | None = None,
        exif: bytes | None = None) -> bytes:
    out = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
    for k, v in (texts or {}).items():
        out += _chunk(b"tEXt", k.encode("latin-1") + b"\x00" + v.encode("latin-1"))
    for k, v in (ztexts or {}).items():
        out += _chunk(b"zTXt", k.encode("latin-1") + b"\x00\x00" + zlib.compress(v.encode("latin-1")))
    for k, v in (itexts or {}).items():
        out += _chunk(b"iTXt", k.encode("latin-1") + b"\x00\x01\x00\x00\x00" + zlib.compress(v.encode("utf-8")))
    if exif is not None:
        out += _chunk(b"eXIf", exif)
    raw = b"".join(b"\x00" + b"\xff" * (3 * w) for _ in range(h))
    out += _chunk(b"IDAT", zlib.compress(raw)) + _chunk(b"IEND", b"")
    return out


def exif_block(artist: str = "", comment: str = "", little: bool = True) -> bytes:
    """A TIFF/EXIF block with Artist (IFD0) and UserComment (Exif sub-IFD, UNICODE)."""
    e = "<" if little else ">"
    head = (b"II*\x00" if little else b"MM\x00*") + struct.pack(e + "I", 8)
    art = artist.encode("utf-8") + b"\x00"
    com = b"UNICODE\x00" + comment.encode("utf-16-le")
    # IFD0 at 8: 2 entries (Artist, ExifIFD pointer) -> 2 + 24 + 4 = 30 bytes
    ifd0_end = 8 + 2 + 2 * 12 + 4
    art_off = ifd0_end
    sub_off = art_off + len(art)
    sub_end = sub_off + 2 + 12 + 4
    com_off = sub_end
    ifd0 = struct.pack(e + "H", 2)
    if len(art) <= 4:                       # TIFF: values of 4 bytes or less sit in the entry itself
        ifd0 += struct.pack(e + "HHI", 0x013B, 2, len(art)) + art.ljust(4, b"\x00")
        art = b""
        sub_off = art_off
        sub_end = sub_off + 2 + 12 + 4
        com_off = sub_end
    else:
        ifd0 += struct.pack(e + "HHII", 0x013B, 2, len(art), art_off)
    ifd0 += struct.pack(e + "HHII", 0x8769, 4, 1, sub_off)
    ifd0 += struct.pack(e + "I", 0)
    sub = struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x9286, 7, len(com), com_off) + struct.pack(e + "I", 0)
    return head + ifd0 + art + sub + com


def jpeg(w: int = 80, h: int = 40, exif: bytes | None = None, xmp: str = "", comment: str = "") -> bytes:
    def seg(marker: int, body: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(body) + 2) + body
    out = b"\xff\xd8"
    if exif is not None:
        out += seg(0xE1, b"Exif\x00\x00" + exif)
    if xmp:
        out += seg(0xE1, b"http://ns.adobe.com/xap/1.0/\x00" + xmp.encode("utf-8"))
    if comment:
        out += seg(0xFE, comment.encode("utf-8"))
    out += seg(0xC0, bytes([8]) + struct.pack(">HH", h, w) + bytes([1, 1, 0x11, 0]))
    out += seg(0xDA, bytes([1, 1, 0, 0, 63, 0])) + b"\x00" * 16 + b"\xff\xd9"
    return out


def gif(w: int = 10, h: int = 12) -> bytes:
    return b"GIF89a" + struct.pack("<HH", w, h) + b"\x00\x00\x00" + b";"


def webp_vp8x(w: int = 300, h: int = 200) -> bytes:
    body = b"\x00\x00\x00\x00" + (w - 1).to_bytes(3, "little") + (h - 1).to_bytes(3, "little")
    return b"RIFF" + struct.pack("<I", 4 + 8 + len(body)) + b"WEBP" + b"VP8X" + struct.pack("<I", len(body)) + body


def bmp(w: int = 5, h: int = -7) -> bytes:
    return b"BM" + b"\x00" * 16 + struct.pack("<ii", w, h) + b"\x00" * 28


class StubEngine:
    """runner for ocr.Engine: answers --list-langs and returns the text set for the next pictures."""

    def __init__(self, texts=("",), langs=("eng", "chi_sim", "osd"), rc=0, exc=None):
        self.texts = list(texts)
        self.langs = langs
        self.rc = rc
        self.exc = exc
        self.calls: list = []

    def __call__(self, argv, data, timeout, mem_bytes, env):
        self.calls.append({"argv": list(argv), "data": data, "timeout": timeout, "mem": mem_bytes, "env": dict(env)})
        if argv[1:] == ["--list-langs"]:
            return 0, ("List of available languages (3):\n" + "\n".join(self.langs) + "\n").encode(), b""
        if self.exc is not None:
            raise self.exc
        t = self.texts.pop(0) if len(self.texts) > 1 else self.texts[0]
        return self.rc, t.encode("utf-8"), b""
