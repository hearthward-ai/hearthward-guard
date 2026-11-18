"""Picture text for the scam shield (job 6): read the words in an inbound picture so the guard can check them.

The picture itself never reaches the model. The guard reads its text with an external OCR engine
(Tesseract), checks that text (rules, the model check when configured, the scam signs), and answers the
sender with a short verdict. Text hidden in the file's metadata (EXIF, XMP, PNG text chunks, JPEG
comments) is read too, with the standard library.

How the engine runs (fail closed: any problem means "could not read", which holds the message):
  * a separate process started with subprocess.run([...], shell=False): a fixed argument list, the
    picture bytes on stdin (the engine never opens a path the sender chose), no inherited
    environment beyond what the engine needs, a time limit;
  * on Linux and macOS the child gets resource limits before the engine starts (resource.setrlimit in
    preexec_fn: address space, CPU seconds, no file writes); on Windows only the time and size limits
    apply;
  * the file type and the pixel count are checked from the file header before the engine sees it.
No Python OCR package is used or imported: the engine is a program found on PATH or at ocr.engine_path.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import threading
import time
import unicodedata
import zlib

IMAGE_MIMES = {"image/png", "image/jpeg", "image/jpg", "image/pjpeg", "image/gif", "image/webp", "image/bmp",
               "image/x-ms-bmp", "image/tiff", "image/heic", "image/heif", "image/avif"}
IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".jpe", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".avif")
SUPPORTED = ("png", "jpeg", "gif", "webp", "bmp")
_LANG_RX = re.compile(r"^[A-Za-z_]{2,24}$")
_MAX_META_CHARS = 4000
_LIST_LANGS_TIMEOUT_S = 10.0


class OcrError(Exception):
    """The picture could not be read (plain-language reason in args[0])."""


def is_image_kind(mime: str, name: str) -> bool:
    m = (mime or "").split(";")[0].strip().lower()
    if m in IMAGE_MIMES or (m.startswith("image/") and m != "image/svg+xml"):
        return True
    return (name or "").lower().endswith(IMAGE_EXTS)


# ------------------------------------------------------------------ header checks
def sniff(data: bytes) -> tuple[str, int, int]:
    """-> (format, width, height) from the file header. Raises OcrError for anything else."""
    try:
        if data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR":
            w, h = struct.unpack(">II", data[16:24])
            return "png", w, h
        if data[:3] == b"\xff\xd8\xff":
            return ("jpeg",) + _jpeg_size(data)
        if data[:6] in (b"GIF87a", b"GIF89a"):
            w, h = struct.unpack("<HH", data[6:10])
            return "gif", w, h
        if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
            return ("webp",) + _webp_size(data)
        if data[:2] == b"BM" and len(data) >= 26:
            w, h = struct.unpack("<ii", data[18:26])
            return "bmp", abs(w), abs(h)
    except (struct.error, IndexError):
        raise OcrError("damaged picture file") from None
    if data[:4] in (b"II*\x00", b"MM\x00*") or data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftypavif"):
        raise OcrError("this picture type can't be checked yet")
    raise OcrError("not a picture file the guard can check")


def _jpeg_size(data: bytes) -> tuple[int, int]:
    i, n = 2, len(data)
    for _ in range(2000):
        while i < n and data[i] != 0xFF:
            i += 1
        while i < n and data[i] == 0xFF:
            i += 1
        if i >= n:
            break
        marker = data[i]
        i += 1
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xD9:
            break
        seg_len = struct.unpack(">H", data[i:i + 2])[0]
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 3:i + 7])
            return w, h
        i += seg_len
    raise OcrError("damaged picture file")


def _webp_size(data: bytes) -> tuple[int, int]:
    kind = data[12:16]
    if kind == b"VP8X":
        w = int.from_bytes(data[24:27], "little") + 1
        h = int.from_bytes(data[27:30], "little") + 1
        return w, h
    if kind == b"VP8L":
        b = int.from_bytes(data[21:25], "little")
        return (b & 0x3FFF) + 1, ((b >> 14) & 0x3FFF) + 1
    if kind == b"VP8 ":
        w, h = struct.unpack("<HH", data[26:30])
        return w & 0x3FFF, h & 0x3FFF
    raise OcrError("damaged picture file")


# ------------------------------------------------------------------ metadata text
_EXIF_TEXT_TAGS = {0x010E, 0x013B, 0x8298, 0x9286, 0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F, 0x010F, 0x0110, 0x0131}
_UCS2_TAGS = {0x9C9B, 0x9C9C, 0x9C9D, 0x9C9E, 0x9C9F}
_XMP_TAG_RX = re.compile(r"<[^<>]{0,2000}>")          # [^<>]: a run of "<" is read once, not 2,000 times each
_XMP_PI_RX = re.compile(r"<\?[^<>]{0,2000}\?>")       # processing instructions (xpacket framing)
_XMP_ATTR_RX = re.compile(r"\b[\w:.-]{1,60}=\"([^\"]{1,2000})\"")


class _Budget:
    """Running limits for one file's metadata (fix round OC-1): stop reading as soon as enough text was
    found, and never inflate or clean more than a fixed number of bytes, however the file is built."""

    def __init__(self):
        self.chars = _MAX_META_CHARS            # text kept
        self.work = _MAX_META_WORK              # bytes inflated or cleaned (all items together)
        self.items = 0                          # text items (chunks, segments, EXIF values) looked at

    @property
    def done(self) -> bool:
        return self.chars <= 0 or self.work <= 0 or self.items >= _MAX_META_ITEMS

    def take(self, raw_len: int) -> int:
        """-> how many raw bytes of the next item may be processed (0 = stop)."""
        if self.done:
            return 0
        self.items += 1
        n = min(raw_len, _MAX_ITEM_BYTES, self.work, 4 * self.chars + 64)
        self.work -= n
        return n

    def keep(self, text: str) -> str:
        t = text[:max(0, self.chars)]
        self.chars -= len(t)
        return t


_MAX_META_WORK = 256_000      # bytes inflated or cleaned per file
_MAX_ITEM_BYTES = 32_000      # per chunk / segment / value
_MAX_META_ITEMS = 24          # text items per file (PNG text chunks, JPEG segments, EXIF values)
_MAX_EXIF_TEXT_PER_IFD = 20


def _clean_meta(s: str) -> str:
    """Control characters become spaces. Format characters (Unicode Cf: zero-width, bidi, tag characters)
    are KEPT, so the scan sees hidden text and counts invisible characters (0.9.3 lab re-run L1: they were
    blanked, which silently wiped tag-character payloads). A leading byte-order mark is dropped."""
    s = s[1:] if s.startswith("\ufeff") else s
    s = "".join(ch if (ch.isprintable() or ch in "\n\t" or unicodedata.category(ch) == "Cf") else " " for ch in s)
    return re.sub(r"[ \t]+", " ", s).strip()


def _exif_texts(tiff: bytes, budget: "_Budget | None" = None) -> list[str]:
    """Text values in a TIFF/EXIF block: description, artist, copyright, user comment, Windows XP fields.
    Each value offset is read once (fix round OC-1: 300 entries pointing at one 60 KB value were 18 MB)."""
    budget = budget or _Budget()
    if len(tiff) < 8 or tiff[:2] not in (b"II", b"MM"):
        return []
    e = "<" if tiff[:2] == b"II" else ">"
    out: list[str] = []
    seen: set = set()
    values: set = set()
    todo = [struct.unpack(e + "I", tiff[4:8])[0]]
    while todo and len(seen) < 6 and not budget.done:
        off = todo.pop()
        if off in seen or off + 2 > len(tiff):
            continue
        seen.add(off)
        count = min(struct.unpack(e + "H", tiff[off:off + 2])[0], 300)
        texts_here = 0
        for k in range(count):
            p = off + 2 + 12 * k
            if p + 12 > len(tiff) or budget.done or texts_here >= _MAX_EXIF_TEXT_PER_IFD:
                break
            tag, typ, n = struct.unpack(e + "HHI", tiff[p:p + 8])
            if tag in (0x8769, 0xA005) and typ in (4, 13):          # Exif / interop sub-IFD
                todo.append(struct.unpack(e + "I", tiff[p + 8:p + 12])[0])
                continue
            if tag not in _EXIF_TEXT_TAGS or typ not in (1, 2, 7) or n == 0 or n > 65535:
                continue
            voff = p + 8 if n <= 4 else struct.unpack(e + "I", tiff[p + 8:p + 12])[0]
            if (voff, n) in values:
                continue                                              # the same value again: read once
            values.add((voff, n))
            texts_here += 1
            take = budget.take(n)
            if not take:
                break
            raw = tiff[voff:voff + take]
            if tag == 0x9286:                                         # UserComment: 8-byte charset header
                head, body = raw[:8], raw[8:]
                if head.startswith(b"UNICODE"):
                    # writers disagree on the byte order: take the reading with fewer U+xx00 characters
                    # (the wrong order turns ASCII into them)
                    views = [body.decode(enc, errors="replace") for enc in ("utf-16-le", "utf-16-be")]
                    txt = min(views, key=lambda v: sum(1 for ch in v if ord(ch) > 0xFF and ord(ch) & 0xFF == 0))
                else:
                    txt = body.decode("utf-8", errors="replace")
            elif tag in _UCS2_TAGS:
                txt = raw.decode("utf-16-le", errors="replace")
            else:
                txt = raw.decode("utf-8", errors="replace")
            txt = budget.keep(_clean_meta(txt.replace("\x00", " ")))
            if txt:
                out.append(txt)
    return out


def _xmp_text(xml: bytes) -> str:
    s = xml.decode("utf-8", errors="replace")[:_MAX_ITEM_BYTES]
    s = _XMP_PI_RX.sub(" ", s)               # <?xpacket begin=... id=...?> is packet framing, not text (L2)
    attrs = [m.group(1) for m in _XMP_ATTR_RX.finditer(s) if not m.group(1).startswith(("http://", "https://",
                                                                                         "adobe:ns", "uuid:", "xmp."))]
    body = _XMP_TAG_RX.sub(" ", s)
    return _clean_meta(" ".join(attrs + [body]))


def _png_chunks(data: bytes):
    i = 8
    for _ in range(10_000):
        if i + 8 > len(data):
            return
        ln = struct.unpack(">I", data[i:i + 4])[0]
        kind = data[i + 4:i + 8]
        yield kind, data[i + 8:i + 8 + ln]
        if kind == b"IEND":
            return
        i += 12 + ln


def _inflate(blob: bytes, limit: int) -> bytes:
    """At most `limit` bytes out, whatever the compressed data says (fix round OC-1: the limit is the
    running budget, not a fixed 1 MB per chunk). Only the first 64 KB of compressed input is fed."""
    if limit <= 0:
        return b""
    d = zlib.decompressobj()
    return d.decompress(blob[:65_536], limit)


def metadata_texts(data: bytes, fmt: str) -> list[str]:
    """Text stored in the file besides the pixels, read within a running budget (fix round OC-1):
    at most _MAX_META_CHARS characters kept, _MAX_META_WORK bytes inflated or cleaned, and
    _MAX_META_ITEMS text items looked at, whatever the file holds. A damaged structure adds a note.
    Raises OcrError when reading fails in any other way (the picture is then held)."""
    out: list[str] = []
    b = _Budget()

    def add(text: str) -> None:
        t = b.keep(text)
        if t:
            out.append(t)
    try:
        if fmt == "png":
            for kind, body in _png_chunks(data):
                if b.done:
                    break
                if kind == b"tEXt":
                    _k, _, v = body.partition(b"\x00")
                    add(_clean_meta(v[:b.take(len(v))].decode("latin-1")))
                elif kind == b"zTXt":
                    _k, _, v = body.partition(b"\x00")
                    add(_clean_meta(_inflate(v[1:], b.take(_MAX_ITEM_BYTES)).decode("latin-1")))
                elif kind == b"iTXt":
                    k, _, rest = body.partition(b"\x00")
                    comp, rest = rest[:1], rest[2:]
                    _lang, _, rest = rest.partition(b"\x00")
                    _tk, _, txt = rest.partition(b"\x00")
                    n = b.take(_MAX_ITEM_BYTES if comp == b"\x01" else len(txt))
                    raw = _inflate(txt, n) if comp == b"\x01" else txt[:n]
                    add(_xmp_text(raw) if k == b"XML:com.adobe.xmp" else
                        _clean_meta(raw.decode("utf-8", errors="replace")))
                elif kind == b"eXIf":
                    out.extend(_exif_texts(body, b))
        elif fmt == "jpeg":
            i, n = 2, len(data)
            for _ in range(2000):
                if i + 4 > n or data[i] != 0xFF or b.done:
                    break
                marker = data[i + 1]
                if marker in (0xDA, 0xD9):          # start of scan: no more metadata segments
                    break
                ln = struct.unpack(">H", data[i + 2:i + 4])[0]
                if marker == 0xE1 and data.startswith(b"Exif\x00\x00", i + 4):
                    out.extend(_exif_texts(data[i + 10:i + 2 + ln], b))
                elif marker == 0xE1 and data.startswith(b"http://ns.adobe.com/xap/1.0/\x00", i + 4):
                    add(_xmp_text(data[i + 33:min(i + 2 + ln, i + 33 + b.take(ln))]))
                elif marker == 0xFE:
                    add(_clean_meta(data[i + 4:min(i + 2 + ln, i + 4 + b.take(ln))].decode("utf-8", errors="replace")))
                i += 2 + ln
        elif fmt == "webp":
            i = 12
            for _ in range(1000):
                if i + 8 > len(data) or b.done:
                    break
                kind = data[i:i + 4]
                ln = struct.unpack("<I", data[i + 4:i + 8])[0]
                if kind == b"EXIF":
                    body = data[i + 8:i + 8 + ln]
                    out.extend(_exif_texts(body[6:] if body.startswith(b"Exif\x00\x00") else body, b))
                elif kind == b"XMP ":
                    add(_xmp_text(data[i + 8:i + 8 + b.take(ln)]))
                i += 8 + ln + (ln & 1)
    except (struct.error, zlib.error, IndexError, ValueError, UnicodeError):
        out.append("[metadata could not be read completely]")
    except MemoryError:
        raise OcrError("the picture's hidden text could not be read") from None
    except Exception:
        raise OcrError("the picture's hidden text could not be read") from None
    return [t for t in out if t]


# ------------------------------------------------------------------ OCR text clean-up
_CJK = "\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef"
_CJK_GAP = re.compile(f"(?<=[{_CJK}]) +(?=[{_CJK}])")


def tidy(text: str, limit: int) -> str:
    """Engine output -> checkable text: NFC, no control characters, no spaces the engine put between
    Chinese characters, no empty lines; capped."""
    t = unicodedata.normalize("NFC", text)
    t = "".join(ch if (ch.isprintable() or ch == "\n") else " " for ch in t)
    t = _CJK_GAP.sub("", t)
    lines = [re.sub(r"[ \t]+", " ", ln).strip() for ln in t.splitlines()]
    return "\n".join(ln for ln in lines if ln)[:limit]


# ------------------------------------------------------------------ the engine
def _posix_limits(mem_bytes: int, cpu_s: int):
    """preexec_fn for the engine child (POSIX only). Confirmed in the lab (Ubuntu 24.04, Python 3.12):
    a too-small address-space limit makes Tesseract fail at start instead of running."""
    import resource      # POSIX only; imported here so Windows can load this module

    def apply():
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))          # the engine writes nothing to disk
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _run(argv: list, data: bytes | None, timeout: float, mem_bytes: int, env: dict) -> tuple[int, bytes, bytes]:
    """The one place a process starts: list argv, shell=False, bytes on stdin, time limit."""
    kw: dict = {"input": data if data is not None else b"", "capture_output": True, "timeout": timeout,
                "shell": False, "env": env, "close_fds": True}
    if os.name == "posix":
        kw["preexec_fn"] = _posix_limits(mem_bytes, max(1, int(timeout) + 1))
    elif os.name == "nt":
        kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    p = subprocess.run(argv, **kw)
    return p.returncode, p.stdout, p.stderr


def _child_env(tessdata: str) -> dict:
    env = {"OMP_THREAD_LIMIT": "1", "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
    for k in ("PATH", "SYSTEMROOT", "SystemRoot", "TEMP", "TMP", "TESSDATA_PREFIX"):
        v = os.environ.get(k)
        if v:
            env[k] = v
    if tessdata:
        env["TESSDATA_PREFIX"] = tessdata
    return env


def _find_engine(which) -> str:
    """The engine by absolute path only (fix round OC-7). Windows: never searched (shutil.which looks in
    the working folder first and accepts .bat/.cmd), ocr.engine_path is required. Elsewhere: PATH
    folders that are absolute paths only, so "" or "." in PATH never makes the working folder count."""
    if os.name == "nt":
        return ""
    dirs = os.pathsep.join(d for d in os.environ.get("PATH", "").split(os.pathsep) if d and os.path.isabs(d))
    try:
        found = which("tesseract", path=dirs) if which is shutil.which else which("tesseract")
    except Exception:
        return ""
    return found if found and os.path.isabs(found) else ""


class Engine:
    """Tesseract behind fixed arguments. runner: (argv, data, timeout, mem_bytes, env) -> (rc, out, err);
    tests pass a stub, so no engine is needed to test the guard."""

    def __init__(self, cfg, runner=None, which=shutil.which):
        self.cfg = cfg
        self._runner = runner or _run
        self.path = ""
        self.missing = ""
        self._langs_ok: bool | None = None
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(2)      # at most two engine processes at a time
        path = cfg.engine_path or _find_engine(which)
        if not path:
            self.missing = ("no OCR engine path set (on Windows the guard never searches for one: set "
                            "ocr.engine_path to the full path of tesseract.exe)" if os.name == "nt"
                            else "no OCR engine found (install Tesseract, or set ocr.engine_path)")
        elif runner is None and not os.path.isabs(path):
            self.missing = "the OCR engine path is not a full path"
        elif runner is None and os.name == "nt" and not path.lower().endswith(".exe"):
            self.missing = "the OCR engine must be an .exe file on Windows"     # never a .bat/.cmd (review OC-7)
        elif runner is None and not (os.path.isfile(path) and os.access(path, os.X_OK)):
            self.missing = "the OCR engine at ocr.engine_path is not an executable file"
        else:
            self.path = path

    @property
    def available(self) -> bool:
        return bool(self.path)

    def _languages(self) -> None:
        """Once per start: the configured language data must be installed (else every read fails closed)."""
        with self._lock:
            if self._langs_ok is not None:
                if not self._langs_ok:
                    raise OcrError("the picture reader is missing language data")
                return
            try:
                rc, out, _err = self._runner([self.path, "--list-langs"], None, _LIST_LANGS_TIMEOUT_S,
                                             self.cfg.memory_mb * 1024 * 1024, _child_env(self.cfg.tessdata_dir))
            except (OSError, subprocess.SubprocessError, ValueError):
                self._langs_ok = None
                raise OcrError("the picture reader could not start") from None
            have = {ln.strip() for ln in out.decode("utf-8", errors="replace").splitlines()[1:]}
            self._langs_ok = rc == 0 and all(lang in have for lang in self.cfg.languages)
            if not self._langs_ok:
                raise OcrError("the picture reader is missing language data")

    def version(self) -> str:
        """First line of `<engine> --version`, for preflight; "" when it cannot be read."""
        if not self.path:
            return ""
        try:
            rc, out, err = self._runner([self.path, "--version"], None, _LIST_LANGS_TIMEOUT_S,
                                        self.cfg.memory_mb * 1024 * 1024, _child_env(self.cfg.tessdata_dir))
        except (OSError, subprocess.SubprocessError, ValueError):
            return ""
        lines = ((out or b"") + b"\n" + (err or b"")).decode("utf-8", errors="replace").strip().splitlines()
        return "".join(c for c in lines[0].strip() if c.isprintable())[:60] if rc == 0 and lines else ""

    def languages_ok(self) -> bool:
        """The configured language data is installed (preflight). Never raises."""
        try:
            self._languages()
            return True
        except OcrError:
            return False

    def read(self, data: bytes, deadline: float | None = None) -> str:
        """Picture bytes -> raw engine text. Raises OcrError on any failure. deadline (time.monotonic):
        the wait for a free slot and the engine's own time limit both end by then (review MC-4), so a
        picture's work never outlives its message."""
        if not self.path:
            raise OcrError("no picture reader (OCR) is installed")
        self._languages()
        argv = [self.path, "stdin", "stdout", "-l", "+".join(self.cfg.languages), "--psm", "3"]

        def left() -> float:
            return self.cfg.timeout_s if deadline is None else min(self.cfg.timeout_s, deadline - time.monotonic())
        if left() <= 0 or not self._slots.acquire(timeout=max(0.0, left())):
            raise OcrError("the picture reader is busy")
        try:
            limit = left()
            if limit <= 0.5:
                raise OcrError("the picture reader is busy")
            rc, out, _err = self._runner(argv, data, limit, self.cfg.memory_mb * 1024 * 1024,
                                         _child_env(self.cfg.tessdata_dir))
        except subprocess.TimeoutExpired:
            raise OcrError("reading the picture took too long") from None
        except (OSError, subprocess.SubprocessError, ValueError):
            raise OcrError("the picture reader could not start") from None
        finally:
            self._slots.release()
        if rc != 0:
            raise OcrError("the picture reader failed on this picture")
        return out[:4 * self.cfg.max_text_chars].decode("utf-8", errors="replace")


_MAX_GIF_FRAMES = 1000


def gif_frames(data: bytes) -> tuple[int, int]:
    """Walk a GIF's blocks (fix round OC-3). -> (frames, total frame pixels). The decoder (giflib's
    DGifSlurp, used by Leptonica) allocates every frame at its image-descriptor size, which may be far
    larger than the logical screen in the header. Raises OcrError for a damaged or oversized file."""
    n = len(data)
    if n < 13:
        raise OcrError("damaged picture file")
    i = 13
    flags = data[10]
    if flags & 0x80:
        i += 3 * (2 << (flags & 7))                  # global colour table
    frames, pixels = 0, 0
    while i < n:
        block = data[i]
        if block == 0x3B:                            # trailer
            break
        if block == 0x21:                            # extension: label, then data sub-blocks
            i += 2
        elif block == 0x2C:                          # image descriptor
            if i + 10 > n:
                raise OcrError("damaged picture file")
            _x, _y, w, h = struct.unpack("<HHHH", data[i + 1:i + 9])
            fl = data[i + 9]
            frames += 1
            pixels += w * h
            if frames > _MAX_GIF_FRAMES:
                raise OcrError("the picture is too large to check")
            i += 10
            if fl & 0x80:
                i += 3 * (2 << (fl & 7))             # local colour table
            i += 1                                   # LZW minimum code size
        else:
            raise OcrError("damaged picture file")
        while i < n and data[i] != 0:                # data sub-blocks
            i += data[i] + 1
        i += 1
    if frames == 0:
        raise OcrError("damaged picture file")
    return frames, pixels


def check_size(data: bytes, cfg) -> tuple[str, int, int]:
    fmt, w, h = sniff(data)
    if fmt not in SUPPORTED:
        raise OcrError("this picture type can't be checked yet")
    if w <= 0 or h <= 0:
        raise OcrError("damaged picture file")
    if w * h > cfg.max_pixels:
        raise OcrError("the picture is too large to check")
    if fmt == "gif" and gif_frames(data)[1] > cfg.max_pixels:
        raise OcrError("the picture is too large to check")   # all frames together, at their own sizes
    return fmt, w, h


def valid_language(code: str) -> bool:
    return bool(_LANG_RX.match(code or ""))
