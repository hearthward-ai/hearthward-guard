"""Attachments on an inbound message: which are text we can read and scan, and which we cannot vouch for.

Only local cached files are read (never URLs, never network), with a size cap, no symlinks and
strict decoding checks. Anything that cannot be read cleanly is reported as unreadable, so the
caller fails closed.
"""
from __future__ import annotations

import os
import stat

TEXT_MIME_PREFIXES = ("text/",)
TEXT_MIMES = {"application/json", "application/xml", "application/x-yaml", "application/yaml", "application/csv",
              "application/x-sh", "application/javascript", "application/x-python", "application/toml",
              "application/x-ndjson", "application/ld+json", "application/rtf", "message/rfc822",
              "application/x-subrip", "image/svg+xml"}
TEXT_EXTS = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml",
             ".toml", ".ini", ".cfg", ".conf", ".log", ".html", ".htm", ".css", ".js", ".ts", ".py", ".sh", ".bat",
             ".ps1", ".c", ".h", ".cpp", ".java", ".go", ".rs", ".rb", ".php", ".sql", ".tex", ".rst", ".srt",
             ".vtt", ".eml", ".svg", ".rtf", ".org", ".adoc", ".env.example"}


class Unreadable(Exception):
    """The attachment could not be checked (reason in args[0])."""


def is_text_kind(mime: str, name: str) -> bool:
    mime = (mime or "").split(";")[0].strip().lower()
    if mime.startswith(TEXT_MIME_PREFIXES) or mime in TEXT_MIMES:
        return True
    low = (name or "").lower()
    return any(low.endswith(e) for e in TEXT_EXTS)


def decode_text(data: bytes) -> str:
    """Strict decode: UTF-8 (with or without BOM) or UTF-16/32 with BOM. Raises Unreadable for
    binary content (NUL bytes outside UTF-16/32) and for any byte that is not valid UTF-8."""
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    for bom, enc in ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
                     (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if data.startswith(bom):
            try:
                return data[len(bom):].decode(enc)
            except UnicodeDecodeError:
                raise Unreadable("bad text encoding") from None
    if b"\x00" in data:
        # BOM-less UTF-16 is a known trick to hide text from byte-level checks. Whichever way a
        # reader decodes it (either byte order, or UTF-8 with the NULs dropped), the guard scans
        # every view: a shifted byte order must not turn the payload into harmless-looking CJK.
        views = []
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                s = data.decode(enc)
            except UnicodeDecodeError:
                continue
            if s and sum(c.isprintable() or c in "\r\n\t" for c in s) >= 0.95 * len(s):
                views.append(s)
        if not views:
            raise Unreadable("binary content")
        views.append(data.replace(b"\x00", b"").decode("utf-8", errors="replace"))
        return "\n".join(views)
    try:
        # strict: any undecodable byte means another reader may see different text (review M8)
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable("not valid UTF-8 text") from None


def read_local_text(path: str, max_bytes: int) -> str:
    """Read one cached attachment. Raises Unreadable on anything unexpected."""
    return decode_text(read_local_bytes(path, max_bytes))


def read_local_bytes(path: str, max_bytes: int) -> bytes:
    """The bytes of one cached attachment: local regular files only (no URLs, no symlinks), size-capped.
    Raises Unreadable on anything unexpected."""
    if not isinstance(path, str) or not path or "\x00" in path:
        raise Unreadable("no local file")
    if "://" in path and not path.startswith("file://"):
        raise Unreadable("remote file")
    if path.startswith("file://"):
        path = path[7:]
    try:
        st = os.lstat(path)
    except OSError:
        raise Unreadable("missing file") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise Unreadable("not a regular file")
    if st.st_size > max_bytes:
        raise Unreadable("too large to check")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise Unreadable("cannot open") from None
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError:
        raise Unreadable("cannot read") from None
    if len(data) > max_bytes:
        raise Unreadable("too large to check")
    return data


def inlined_texts(event) -> list[str]:
    """Attachment text Hermes already inlined (string entries of media_text_inlined): scanned as
    attachments even without a local path (review M5)."""
    vals = getattr(event, "media_text_inlined", None) or []
    if isinstance(vals, str):
        return [vals]
    try:
        return [v for v in list(vals) if isinstance(v, str) and v.strip()]
    except TypeError:
        return []


def describe(event) -> list[dict]:
    """Attachments on *event* as [{"path", "mime", "name", "inlined"}]. Unequal list lengths are
    tolerated (missing entries are empty)."""
    urls = list(getattr(event, "media_urls", None) or [])
    types = list(getattr(event, "media_types", None) or [])
    names = list(getattr(event, "media_filenames", None) or [])
    inl = list(getattr(event, "media_text_inlined", None) or [])
    out = []
    for i, u in enumerate(urls):
        out.append({"path": u, "mime": types[i] if i < len(types) else "",
                    "name": names[i] if i < len(names) else "", "inlined": inl[i] if i < len(inl) else None})
    return out
