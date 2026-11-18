#!/usr/bin/env python3
"""leakcheck.py - scan a folder for private data before anything is published.

Python standard library only. Run it on a folder before you publish it.

What it checks
  1. Generic patterns (safe to run in CI): Discord IDs and tokens, API token
     shapes, SimpleX/Telegram links and IDs, emails, phone numbers, private
     IPs, user-profile and WSL paths, crypto addresses, high-entropy strings.
  2. An optional private term list kept OUTSIDE the repo (names, IDs, hostnames ...),
     read only from the LEAKCHECK_TERMS environment variable (a file path).
     Hits are printed masked (first letter + length), never in full.
  3. Structure: refused files (.env, auth.json, state.db*, sessions/,
     memories/, logs/, *.pyc, archives, binaries, keys), an optional path
     allowlist, and images that still carry EXIF/text metadata.

With LEAKCHECK_TERMS unset, only the generic patterns and structure rules run.
Term file format: one term per line; "re:<regex>" for a regex; "[category]" starts
a group; "#" comments.

Output: one line per hit, "path:line:col: category [hint]". The matched text
itself is never printed. Exit code 0 = clean, 1 = hits, 2 = usage/config error.
"""
from __future__ import annotations

import argparse
import fnmatch
import math
import os
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TERMS_ENV = "LEAKCHECK_TERMS"
ALLOWLIST_NAME = "export-allowlist.txt"

# ---------------------------------------------------------------- structure
REFUSE_NAMES = {"auth.json", ".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
                "known_hosts", "authorized_keys", ".netrc", ".pypirc", ".npmrc"}
REFUSE_NAME_GLOBS = ["state.db*", ".env.*", "*.pyc", "*.pyo", "*.pem", "*.key",
                     "*.p12", "*.pfx", "*.kdbx", "*.sqlite", "*.sqlite3", "*.db",
                     "*.db-wal", "*.db-shm", "*.log", "*.sqlite*", "*.db-journal", "*.bak-*"]
REFUSE_DIRS = {"sessions", "memories", "logs", "__pycache__", "downloads", "private"}
REFUSE_PATH_GLOBS: list[str] = []
SQLITE_MAGIC = b"SQLite format 3\x00"   # any SQLite database, whatever its name
ARCHIVE_EXT = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
               ".zst", ".whl", ".egg", ".jar", ".apk", ".iso", ".cab", ".msi"}
BINARY_EXT = {".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".obj",
              ".class", ".onnx", ".pt", ".pth", ".safetensors", ".gguf", ".ckpt",
              ".npy", ".npz", ".pkl", ".pickle", ".dat", ".pdf", ".docx", ".xlsx",
              ".pptx", ".doc", ".xls", ".ppt", ".mp3", ".mp4", ".wav", ".ogg",
              ".m4a", ".mov", ".avi", ".mkv", ".webm", ".ttf", ".otf", ".woff",
              ".woff2"}
IMAGE_EXT = {".png", ".jpg", ".jpeg"}               # checked for metadata
IMAGE_UNSUPPORTED_EXT = {".gif", ".webp", ".tif", ".tiff", ".heic", ".heif",
                         ".bmp", ".ico", ".avif", ".jxl", ".psd", ".raw", ".dng"}
SKIP_DIRS = {".git"}

# ------------------------------------------------------------------ patterns
_EMAIL_OK_DOMAINS = ("example.com", "example.org", "example.net", "example",
                     "invalid", "test", "localhost")
_HOME_OK = {"user", "username", "you", "example", "runner", "<user>"}

PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("discord-token", re.compile(
        r"\b[MNO][A-Za-z\d_-]{23,27}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,40}\b")),
    ("api-token", re.compile(
        r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{16,}"
        r"|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"
        r"|xox[abposr]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,}"
        r"|glpat-[A-Za-z0-9_-]{20,})")),
    ("telegram-token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    ("simplex-link", re.compile(
        r"simplex:[/]|smp:[/][/]|xftp:[/][/]|simplex\.chat/(?:contact|invitation)", re.I)),
    ("telegram-link", re.compile(r"\bt\.me/(?:joinchat/|\+)[A-Za-z0-9_-]+", re.I)),
    ("telegram-id", re.compile(
        r"(?:\b-100\d{10}\b)|(?:(?:chat|user|telegram)_?id\W{0,4}-?\d{6,14}\b)", re.I)),
    ("discord-snowflake", re.compile(r"(?<![\w.])\d{17,20}(?![\w.])")),
    ("discord-webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")),
    ("phone", re.compile(
        r"(?<![\w.+-])(?:\+\d{1,3}[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w.-])"
        r"|(?<![\w.+-])\+\d{1,3}[ .-]\d{2,4}[ .-]\d{3,4}[ .-]\d{3,4}(?![\w.-])"
        r"|(?<![\w.+-])1[3-9]\d{9}(?![\w.-])")),
    ("private-ip", re.compile(
        r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01])|169\.254"
        r"|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7]))\.\d{1,3}(?:\.\d{1,3})?(?![\d.])")),
    ("private-ip", re.compile(
        r"(?<![0-9A-Fa-f:])(?:f[cd][0-9a-f]{2}|fe80):[0-9a-f:]{2,}", re.I)),
    ("machine-path", re.compile(r"\b[A-Za-z]:[\\/]+Users[\\/]", re.I)),
    ("machine-path", re.compile(r"\\\\wsl(?:\$|\.localhost)\\", re.I)),
    ("machine-path", re.compile(r"/mnt/[a-z](?:/|\b)")),
    ("machine-path", re.compile(r"(?<![\w.:])/(?:home|Users)/([A-Za-z_][\w.-]*)")),
    ("crypto-address", re.compile(r"\b0x[a-fA-F0-9]{40}\b|\bbc1[a-z0-9]{39,59}\b")),
]
_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")


@dataclass
class Hit:
    path: str
    line: int
    col: int
    category: str
    hint: str = ""

    def __str__(self) -> str:
        hint = f" [{self.hint}]" if self.hint else ""
        return f"{self.path}:{self.line}:{self.col}: {self.category}{hint}"


def mask(text: str) -> str:
    """First letter + length; never the full text."""
    text = text.strip()
    return f"{text[:1]}...({len(text)})" if text else "(0)"


def entropy(s: str) -> float:
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_high_entropy(tok: str) -> bool:
    tok = tok.strip("=")
    if len(tok) < 32 or re.fullmatch(r"[0-9a-fA-F]+", tok):
        return False                        # hex = git SHAs / hash pins: public
    if not (re.search(r"[a-z]", tok) and re.search(r"[A-Z]", tok)
            and re.search(r"\d", tok)):
        return False
    if any(len(p) >= 4 and p.isalpha() and p.islower() for p in re.split(r"[/_-]", tok)) \
            and tok.count("/") + tok.count("-") + tok.count("_") >= 3:
        return False                        # looks like a path/slug
    return entropy(tok) >= 4.2


# -------------------------------------------------------------- private terms
@dataclass
class Term:
    category: str
    regex: re.Pattern


def load_terms(path: Path) -> list[Term]:
    terms: list[Term] = []
    category = "private"
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            category = line[1:-1].strip() or "private"
            continue
        if line.startswith("re:"):
            rx = re.compile(line[3:].strip(), re.I)
        else:
            esc = re.escape(line)
            pre = r"(?<![A-Za-z0-9])" if line[0].isalnum() else ""
            post = r"(?![A-Za-z0-9])" if line[-1].isalnum() else ""
            rx = re.compile(pre + esc + post, re.I)
        terms.append(Term(category, rx))
    return terms


# ------------------------------------------------------------------- allowlist
def load_allowlist(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.replace("\\", "/"))
    return out


def allowed(rel: str, patterns: list[str]) -> bool:
    ok = False
    for p in patterns:
        neg = p.startswith("!")
        pat = p[1:] if neg else p
        if pat.endswith("/"):
            m = rel.startswith(pat)
        else:
            m = fnmatch.fnmatchcase(rel, pat) or fnmatch.fnmatchcase(rel, pat + "/*")
        if m:
            ok = not neg
    return ok


FONT_EXT = {".woff", ".woff2", ".ttf", ".otf"}


def is_site_font(rel: str) -> bool:
    """Font file under a fonts/ directory: scanned via its name table, not refused."""
    parts = rel.lower().split("/")
    return Path(parts[-1]).suffix in FONT_EXT and "fonts" in parts[:-1]


def font_strings(path: Path) -> list[tuple[str, str]]:
    """(label, text) for every name-table record and any meta-table text."""
    from fontTools.ttLib import TTFont          # ImportError -> caller reports a hit
    out = []
    f = TTFont(str(path), lazy=False)
    try:
        for r in f["name"].names:
            try:
                txt = r.toUnicode()
            except Exception:
                txt = r.string.decode("latin-1", errors="replace")
            out.append((f"name{r.nameID}", txt))
        if "meta" in f:
            for tag, v in f["meta"].data.items():
                if isinstance(v, bytes):
                    v = v.decode("utf-8", errors="replace")
                out.append((f"meta-{tag.strip()}", str(v)))
    finally:
        f.close()
    return out


def refused_reason(rel: str) -> str | None:
    parts = rel.split("/")
    name = parts[-1]
    low = name.lower()
    for d in parts[:-1]:
        if d.lower() in REFUSE_DIRS:
            return f"refused-dir:{d}"
    if low in REFUSE_NAMES:
        return "refused-file"
    if any(fnmatch.fnmatch(rel.lower(), g) for g in REFUSE_PATH_GLOBS):
        return "refused-file"
    if any(fnmatch.fnmatch(low, g) for g in REFUSE_NAME_GLOBS):
        return "refused-file"
    suf = Path(low).suffix
    if suf in ARCHIVE_EXT:
        return "refused-archive"
    if suf in BINARY_EXT and not is_site_font(rel):
        return "refused-binary"
    if suf in IMAGE_UNSUPPORTED_EXT:
        return "refused-image-format (convert to PNG/JPEG)"
    return None


# ------------------------------------------------------------- image metadata
PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_KEEP = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM",
            b"sRGB", b"pHYs", b"sBIT", b"bKGD"}


def png_chunks(data: bytes):
    if not data.startswith(PNG_SIG):
        raise ValueError("not a PNG")
    i = 8
    while i + 8 <= len(data):
        length, ctype = struct.unpack(">I4s", data[i:i + 8])
        end = i + 12 + length
        if end > len(data):
            raise ValueError("truncated PNG")
        yield ctype, data[i:end]
        i = end
        if ctype == b"IEND":
            break


def jpeg_segments(data: bytes):
    """Yield (marker, segment_bytes) up to and including SOS; then ('rest', ...)."""
    if not data.startswith(b"\xff\xd8"):
        raise ValueError("not a JPEG")
    yield 0xD8, data[:2]
    i = 2
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            raise ValueError("bad JPEG marker")
        marker = data[i + 1]
        if marker == 0xFF:
            i += 1
            continue
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        seg = data[i:i + 2 + length]
        yield marker, seg
        i += 2 + length
        if marker == 0xDA:          # start of scan: rest is image data
            yield None, data[i:]
            return
    raise ValueError("truncated JPEG")


def _jpeg_keep(marker, seg) -> bool:
    if marker is None or marker == 0xD8:
        return True
    if marker == 0xE0:
        return seg[4:9] == b"JFIF\x00"
    if marker == 0xEE:              # APP14 Adobe colour transform: no personal data
        return True
    return not (0xE1 <= marker <= 0xEF or marker == 0xFE)


def image_metadata(path: Path) -> list[str]:
    """Return metadata block names still present (empty list = clean)."""
    data = path.read_bytes()
    suf = path.suffix.lower()
    if suf == ".png":
        return sorted({c.decode("latin-1") for c, _ in png_chunks(data) if c not in PNG_KEEP})
    found = []
    for marker, seg in jpeg_segments(data):
        if not _jpeg_keep(marker, seg):
            found.append("COM" if marker == 0xFE else f"APP{marker - 0xE0}")
    return sorted(set(found))


def strip_image(src: Path, dst: Path) -> None:
    """Rewrite a PNG/JPEG keeping only pixel and colour data. Raises on failure."""
    data = src.read_bytes()
    suf = src.suffix.lower()
    if suf == ".png":
        out = PNG_SIG + b"".join(chunk for c, chunk in png_chunks(data) if c in PNG_KEEP)
    elif suf in (".jpg", ".jpeg"):
        out = b"".join(seg for m, seg in jpeg_segments(data) if _jpeg_keep(m, seg))
    else:
        raise ValueError(f"unsupported image format {suf}")
    dst.write_bytes(out)


SVG_META = re.compile(r"<metadata\b|sodipodi:docname|inkscape:export-filename|"
                      r"<rdf:RDF\b|xmlns:dc=", re.I)


# ------------------------------------------------------------------- scanning
def scan_text(rel: str, text: str, terms: list[Term], hits: list[Hit]) -> None:
    is_svg = rel.lower().endswith(".svg")
    for ln, line in enumerate(text.splitlines(), 1):
        for cat, rx in PATTERNS:
            for m in rx.finditer(line):
                if cat == "email":
                    dom = m.group(1).lower()
                    if any(dom == d or dom.endswith("." + d) for d in _EMAIL_OK_DOMAINS):
                        continue
                if cat == "machine-path" and rx.groups and m.group(1) in _HOME_OK:
                    continue
                hits.append(Hit(rel, ln, m.start() + 1, cat, mask(m.group(0))))
        for m in _ENTROPY_RE.finditer(line):
            if _is_high_entropy(m.group(0)):
                hits.append(Hit(rel, ln, m.start() + 1, "high-entropy", mask(m.group(0))))
        for t in terms:
            for m in t.regex.finditer(line):
                hits.append(Hit(rel, ln, m.start() + 1, f"private-term:{t.category}",
                                mask(m.group(0))))
        if is_svg and SVG_META.search(line):
            hits.append(Hit(rel, ln, 1, "image-metadata", "svg metadata"))


def scan_file(root: Path, path: Path, terms, allow, hits: list[Hit]) -> None:
    rel = path.relative_to(root).as_posix()
    for t in terms:                                  # file names can leak too
        for m in t.regex.finditer(rel):
            hits.append(Hit(rel, 0, m.start() + 1, f"private-term:{t.category}(path)",
                            mask(m.group(0))))
    if allow is not None and not allowed(rel, allow):
        hits.append(Hit(rel, 0, 0, "not-allowlisted"))
        return
    reason = refused_reason(rel)
    if reason:
        hits.append(Hit(rel, 0, 0, reason))
        return
    try:
        with open(path, "rb") as f:
            head = f.read(len(SQLITE_MAGIC))
    except OSError as e:
        hits.append(Hit(rel, 0, 0, "unreadable", type(e).__name__))
        return
    if head == SQLITE_MAGIC:                         # a renamed database (e.g. saved as .txt)
        hits.append(Hit(rel, 0, 0, "refused-sqlite"))
        return
    suf = path.suffix.lower()
    if is_site_font(rel):
        try:
            strings = font_strings(path)
        except Exception as e:                       # incl. missing fontTools/brotli
            hits.append(Hit(rel, 0, 0, "font-unreadable", type(e).__name__))
            return
        for label, txt in strings:
            scan_text(f"{rel}#{label}", txt, terms, hits)
        return
    if suf in IMAGE_EXT:
        try:
            meta = image_metadata(path)
        except ValueError as e:
            hits.append(Hit(rel, 0, 0, "image-unreadable", str(e)))
            return
        if meta:
            hits.append(Hit(rel, 0, 0, "image-metadata", ",".join(meta)))
        return
    data = path.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = data.decode("utf-16", errors="replace")
    elif b"\x00" in data[:8192]:
        hits.append(Hit(rel, 0, 0, "refused-binary"))
        return
    else:
        text = data.decode("utf-8", errors="replace")
    scan_text(rel, text, terms, hits)


def iter_files(root: Path, git_tracked: bool):
    if git_tracked:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                             capture_output=True, check=True).stdout
        for name in out.decode("utf-8").split("\0"):
            if name:
                yield root / name
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for f in sorted(filenames):
            yield Path(dirpath) / f


def resolve_terms_path() -> Path | None:
    v = os.environ.get(TERMS_ENV)
    return Path(v) if v else None


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def run(root: Path, terms_path: Path | None, allowlist: Path | None,
        git_tracked: bool = False) -> list[Hit]:
    """Scan root. terms_path None = generic patterns only. Raises ConfigError."""
    terms: list[Term] = []
    if terms_path is not None:
        if not terms_path.is_file():
            raise ConfigError(f"private term list not found: {terms_path} "
                              f"(check the {TERMS_ENV} environment variable)")
        if _inside(terms_path, root):
            raise ConfigError("the private term list must live outside the scanned folder")
        terms = load_terms(terms_path)
    allow = None
    if allowlist is not None:
        if not allowlist.is_file():
            raise ConfigError(f"allowlist not found: {allowlist}")
        allow = load_allowlist(allowlist)
    hits: list[Hit] = []
    for p in iter_files(root, git_tracked):
        if p.is_file():
            scan_file(root, p, terms, allow, hits)
    return hits


class ConfigError(Exception):
    pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Scan a folder for private data before publishing.")
    ap.add_argument("root", nargs="?", default=".", help="folder to scan (default .)")
    ap.add_argument("--allowlist", help=f"path allowlist (default <root>/{ALLOWLIST_NAME} if present)")
    ap.add_argument("--no-allowlist", action="store_true", help="ignore any allowlist file")
    ap.add_argument("--git-tracked", action="store_true", help="scan only files tracked by git")
    ap.add_argument("--summary", action="store_true", help="print hit counts per category only")
    a = ap.parse_args(argv)

    root = Path(a.root)
    if not root.is_dir():
        print(f"leakcheck: not a folder: {root}", file=sys.stderr)
        return 2
    terms_path = resolve_terms_path()
    allowlist = None
    if not a.no_allowlist:
        if a.allowlist:
            allowlist = Path(a.allowlist)
        elif (root / ALLOWLIST_NAME).is_file():
            allowlist = root / ALLOWLIST_NAME
    try:
        hits = run(root, terms_path, allowlist, a.git_tracked)
    except ConfigError as e:
        print(f"leakcheck: {e}", file=sys.stderr)
        return 2
    if a.summary:
        counts: dict[str, int] = {}
        for h in hits:
            counts[h.category] = counts.get(h.category, 0) + 1
        for cat in sorted(counts):
            print(f"{counts[cat]:5d}  {cat}")
    else:
        for h in hits:
            print(h)
    mode = "generic only" if terms_path is None else "generic + terms from LEAKCHECK_TERMS"
    print(f"leakcheck: {len(hits)} hit(s) ({mode})", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
