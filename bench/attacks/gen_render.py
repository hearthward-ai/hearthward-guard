#!/usr/bin/env python3
"""gen_render.py - draw synthetic scam / injection images for image_ocr cases (needs Pillow).

Everything drawn comes from generators.render_spec() (fictional brands, reserved fake values), so
the ground-truth text is known without OCR. Chrome (status bars, windows, charts, scenery) is
shapes only: no text appears in an image that is not in the ground truth.

Deterministic for one Pillow version + font files: the drawing randomness is the generators.Rng
stream, the text layout engine is fixed to BASIC, and no timestamps are written. The font files and
the Pillow version are recorded in the materialised manifest (generate_cases.py).

Fonts: HEARTHWARD_BENCH_FONT_DIR, else C:/Windows/Fonts (Microsoft YaHei, Segoe Print, Consolas).
A public build should point this at OFL fonts (for example Noto Sans CJK) instead.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont, PngImagePlugin
import PIL

import generators as G
from gen_qr import qr_matrix

FONT_DIR = Path(os.environ.get("HEARTHWARD_BENCH_FONT_DIR") or "C:/Windows/Fonts")
FONT_FILES = {"sans": "msyh.ttc", "bold": "msyhbd.ttc", "light": "msyhl.ttc", "hand": "segoepr.ttf",
              "mono": "consola.ttf"}
_FONTS: dict = {}


def font(kind: str, size: int) -> ImageFont.FreeTypeFont:
    key = (kind, size)
    if key not in _FONTS:
        _FONTS[key] = ImageFont.truetype(str(FONT_DIR / FONT_FILES[kind]), size, index=0,
                                         layout_engine=ImageFont.Layout.BASIC)
    return _FONTS[key]


def environment() -> dict:
    """What the image bytes depend on besides the code: Pillow version and font file hashes."""
    fonts = {}
    for k, f in sorted(FONT_FILES.items()):
        p = FONT_DIR / f
        fonts[f] = hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
    return {"pillow": PIL.__version__, "fonts": fonts}


# ------------------------------------------------------------------ text helpers
_TOK = re.compile(r"[A-Za-z0-9$%.,:;!?'\"/@&+\-_#()=~*<>\[\]{}]+|\s+|.")


def wrap(text: str, f, maxw: int) -> list[str]:
    out = []
    for para in text.split("\n"):
        line = ""
        for tok in _TOK.findall(para):
            cand = line + tok
            if f.getlength(cand) <= maxw or not line.strip():
                line = cand
            else:
                out.append(line.rstrip())
                line = tok.lstrip()
        out.append(line.rstrip())
    return out


def draw_lines(d: ImageDraw.ImageDraw, x: int, y: int, text: str, f, maxw: int, fill, gap: int = 6) -> int:
    for line in wrap(text, f, maxw):
        d.text((x, y), line, font=f, fill=fill)
        y += int(f.size * 1.25) + gap
    return y


def hand_text(img: Image.Image, x: int, y: int, text: str, size: int, maxw: int, fill, rng: G.Rng) -> int:
    """Handwriting look: Segoe Print for Latin, light CJK font for the rest, per-glyph jitter."""
    lat, cjk = font("hand", size), font("light", size)
    for line in wrap(text, cjk, maxw):
        cx = x
        for ch in line:
            f = lat if ch.isascii() else cjk
            w = int(f.getlength(ch)) or size // 3
            layer = Image.new("RGBA", (w + 12, size * 2), (0, 0, 0, 0))
            ImageDraw.Draw(layer).text((6, size // 4), ch, font=f, fill=fill)
            layer = layer.rotate(rng.below(13) - 6, resample=Image.BICUBIC)
            img.alpha_composite(layer, (cx - 6, y + rng.below(5) - 2))
            cx += w
        y += int(size * 1.6)
    return y


# ------------------------------------------------------------------ backgrounds
def gradient(w: int, h: int, top, bottom) -> Image.Image:
    img = Image.new("RGBA", (w, h))
    d = ImageDraw.Draw(img)
    for yy in range(h):
        t = yy / max(1, h - 1)
        d.line([(0, yy), (w, yy)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    return img


def scene(w: int, h: int, rng: G.Rng) -> Image.Image:
    sky = (120 + rng.below(80), 160 + rng.below(60), 200 + rng.below(55))
    img = gradient(w, h, sky, (235, 240, 245))
    d = ImageDraw.Draw(img)
    horizon = h * (55 + rng.below(15)) // 100
    ground = (60 + rng.below(80), 110 + rng.below(80), 50 + rng.below(60), 255)
    d.rectangle([0, horizon, w, h], fill=ground)
    for _ in range(4 + rng.below(5)):
        cx, cy, r = rng.below(w), horizon - rng.below(h // 3), 20 + rng.below(90)
        col = (rng.below(256), rng.below(256), rng.below(256), 255)
        if rng.below(2):
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=col)
        else:
            d.rectangle([cx - r, cy - r // 2, cx + r, horizon], fill=col)
    return img


def paper(w: int, h: int, rng: G.Rng, tint=(250, 248, 240)) -> Image.Image:
    base = tuple(max(0, c - rng.below(8)) for c in tint)
    return gradient(w, h, base, tuple(max(0, c - 10) for c in base))


def on_table(sheet: Image.Image, rng: G.Rng) -> Image.Image:
    w, h = sheet.size
    table = gradient(w + 160, h + 160, (110 + rng.below(40), 80 + rng.below(30), 60), (70, 50, 40))
    s = sheet.rotate(rng.below(7) - 3, resample=Image.BICUBIC, expand=True, fillcolor=(0, 0, 0, 0))
    table.alpha_composite(s, (80 - (s.size[0] - w) // 2, 80 - (s.size[1] - h) // 2))
    return table


def draw_qr(img: Image.Image, target: str, x: int, y: int, px: int = 6) -> int:
    m = qr_matrix(target)
    n = len(m)
    d = ImageDraw.Draw(img)
    q = 4 * px
    d.rectangle([x, y, x + n * px + 2 * q, y + n * px + 2 * q], fill=(255, 255, 255, 255))
    for r, row in enumerate(m):
        for c, dark in enumerate(row):
            if dark:
                d.rectangle([x + q + c * px, y + q + r * px, x + q + (c + 1) * px - 1, y + q + (r + 1) * px - 1],
                            fill=(0, 0, 0, 255))
    return y + n * px + 2 * q


# ------------------------------------------------------------------ layouts
PHOTO_STYLES = {"photo_of_paper", "flyer_photo", "door_tag_photo", "delivery_photo", "whiteboard_photo",
                "photo_of_screen", "sticky_note", "handwriting"}


def layout_phone(im: dict, rng: G.Rng) -> Image.Image:
    w, h = 540, 960
    img = Image.new("RGBA", (w, h), (246, 246, 248, 255))
    d = ImageDraw.Draw(img)
    accent = (30 + rng.below(60), 100 + rng.below(80), 160 + rng.below(80), 255)
    d.rectangle([0, 0, w, 36], fill=(20, 20, 24, 255))
    d.rectangle([w - 60, 12, w - 20, 26], outline=(220, 220, 220, 255), width=2)
    d.rectangle([0, 36, w, 116], fill=accent)
    y, style = 140, im["style"]
    for text, role in im["lines"]:
        if role == "title":
            draw_lines(d, 24, 56, text, font("bold", 28), w - 48, (255, 255, 255, 255))
        elif role == "meta":
            y = draw_lines(d, 24, y, text, font("sans", 18), w - 48, (120, 120, 130, 255)) + 8
        else:
            f = font("sans", 26)
            lines = wrap(text, f, w - 120)
            bh = len(lines) * (int(f.size * 1.25) + 6) + 28
            left = style not in ("app_screen", "qr_card")
            col = (226, 226, 232, 255) if left else (255, 255, 255, 255)
            d.rounded_rectangle([24, y, w - 60 if left else w - 24, y + bh], radius=22, fill=col)
            y = draw_lines(d, 44, y + 14, text, f, w - 120, (20, 20, 20, 255)) + 30
    if im.get("qr"):
        draw_qr(img, im["qr"], (w - 37 * 6) // 2 - 24, min(y + 10, h - 330))
    return img


def layout_screen(im: dict, rng: G.Rng) -> Image.Image:
    w, h = 960, 640
    img = Image.new("RGBA", (w, h), (60 + rng.below(40), 90 + rng.below(40), 130 + rng.below(40), 255))
    d = ImageDraw.Draw(img)
    style = im["style"]
    box = [40, 40, w - 40, h - 40] if style != "browser_popup" else [180, 140, w - 180, h - 120]
    d.rectangle(box, fill=(255, 255, 255, 255))
    bar = (200, 40, 40, 255) if style in ("browser_popup", "full_screen_lock") else (225, 228, 235, 255)
    d.rectangle([box[0], box[1], box[2], box[1] + 36], fill=bar)
    for i in range(3):
        d.ellipse([box[2] - 30 - i * 26, box[1] + 10, box[2] - 14 - i * 26, box[1] + 26], fill=(150, 150, 150, 255))
    x, y, maxw = box[0] + 24, box[1] + 56, box[2] - box[0] - 48
    for text, role in im["lines"]:
        f = font("bold", 30) if role == "title" else font("sans", 20 if role == "meta" else 26)
        col = (110, 110, 120, 255) if role == "meta" else (25, 25, 30, 255)
        y = draw_lines(d, x, y, text, f, maxw, col) + 10
    if im.get("qr"):
        draw_qr(img, im["qr"], box[2] - 300, box[3] - 300, px=5)
    return img


def layout_paper(im: dict, rng: G.Rng, lang: str) -> Image.Image:
    style = im["style"]
    if style == "paper_receipt":
        w, h = 460, 820
    elif style in ("sticky_note", "handwriting", "note"):
        w, h = 560, 560
    elif style in ("sticker", "table_tent"):
        w, h = 620, 760
    else:
        w, h = 800, 1000
    tint = (255, 236, 120) if style == "sticky_note" else (245, 247, 250) if style == "whiteboard_photo" else (250, 248, 240)
    img = paper(w, h, rng, tint)
    d = ImageDraw.Draw(img)
    if style == "certificate":
        d.rectangle([20, 20, w - 20, h - 20], outline=(150, 120, 40, 255), width=8)
    if style == "profit_chart_poster":
        pts = [(80 + i * 64, h - 120 - (i * i * 5 + rng.below(30))) for i in range(10)]
        d.line([(80, h - 100), (w - 60, h - 100)], fill=(60, 60, 60, 255), width=3)
        d.line(pts, fill=(200, 30, 30, 255), width=6)
    hand = style in ("handwriting", "whiteboard_photo", "sticky_note", "note")
    x, y, maxw = 50, 60, w - 100
    for text, role in im["lines"]:
        if hand:
            y = hand_text(img, x, y, text, 34, maxw, (25, 35, 120, 255), rng) + 6
            d = ImageDraw.Draw(img)
            continue
        f = font("bold", 40) if role == "title" else font("mono" if style == "paper_receipt" and lang == "en" else "sans", 28)
        y = draw_lines(d, x, y, text, f, maxw, (20, 20, 20, 255)) + 14
    if im.get("qr"):
        draw_qr(img, im["qr"], (w - 37 * 7) // 2, min(y + 10, h - 37 * 7 - 20), px=7)
    if style in PHOTO_STYLES or style.endswith("_photo"):
        img = on_table(img, rng)
    return img


def layout_scene(im: dict, rng: G.Rng, lang: str) -> Image.Image:
    """Hard modes and photos: scene or simple base + the special text line."""
    style = im["style"]
    if style == "photo":
        img = scene(900, 640, rng)
    elif style == "screen":
        img = Image.new("RGBA", (900, 640), (255, 255, 255, 255))
        ImageDraw.Draw(img).rectangle([0, 0, 900, 60], fill=(180, 30, 30, 255))
    elif style == "tiles":
        return layout_tiles(im, rng)
    else:
        img = layout_paper(dict(im, lines=[l for l in im["lines"] if l[1] in ("body", "title")]), rng, lang)
    d = ImageDraw.Draw(img)
    w, h = img.size
    y = 80 if style == "screen" else 40
    plain = [t for t, r in im["lines"] if r in ("body", "title") and not (r == "title" and im.get("qr"))]
    if style == "photo" and plain:
        f = font("sans", 28)
        rows = [r for t in plain for r in wrap(t, f, w - 120)]
        top = h - 30 - len(rows) * 44 - 20
        d.rounded_rectangle([30, top, w - 30, h - 30], radius=10, fill=(255, 255, 255, 230))
        for i, r in enumerate(rows):
            d.text((50, top + 12 + i * 44), r, font=f, fill=(20, 20, 20, 255))
    elif style == "screen":
        for text in plain:
            y = draw_lines(d, 40, y, text, font("sans", 28), w - 80, (20, 20, 20, 255)) + 10
    for text, role in im["lines"]:
        if role == "low_contrast":
            region = img.crop((40, h // 6, w - 40, h // 6 + 80)).convert("RGB").resize((1, 1), Image.BILINEAR)
            r, g, b = region.getpixel((0, 0))
            k = int(255 * im.get("contrast", 0.05))
            col = tuple(max(0, c - k) if (r + g + b) > 384 else min(255, c + k) for c in (r, g, b)) + (255,)
            draw_lines(d, 40, h // 6, text, font("sans", 30), w - 80, col)
        elif role == "tiny_footer":
            d.rectangle([0, h - 30, w, h], fill=(250, 250, 250, 255))
            d.text((10, h - 22), text, font=font("sans", max(4, im.get("font_px", 6))), fill=(90, 90, 90, 255))
        elif role == "rotated_text":
            f = font("sans", 30)
            tw = int(f.getlength(text)) + 20
            layer = Image.new("RGBA", (tw, 50), (0, 0, 0, 0))
            ImageDraw.Draw(layer).text((10, 6), text, font=f, fill=(20, 20, 20, 255))
            layer = layer.rotate(im.get("text_rotation", 90), resample=Image.BICUBIC, expand=True)
            if layer.size[0] > w or layer.size[1] > h:
                big = Image.new("RGBA", (max(w, layer.size[0] + 40), max(h, layer.size[1] + 40)), (240, 240, 240, 255))
                big.alpha_composite(img, (0, 0))
                img = big
                w, h = img.size
            img.alpha_composite(layer, (w - layer.size[0] - 20, 20))
            d = ImageDraw.Draw(img)
        elif role == "handwritten":
            if style != "note":
                img = layout_paper(dict(im, style="note", lines=[]), rng, lang)
            hand_text(img, 40, 60, text, 34, img.size[0] - 120, (25, 35, 120, 255), rng)
            d = ImageDraw.Draw(img)
        elif role == "watermark":
            f = font("bold", 46)
            tw = int(f.getlength(text)) + 40
            layer = Image.new("RGBA", (tw, 80), (0, 0, 0, 0))
            ImageDraw.Draw(layer).text((20, 10), text, font=f, fill=(0, 0, 0, int(255 * im.get("opacity", 0.15))))
            layer = layer.rotate(25, resample=Image.BICUBIC, expand=True)
            if layer.size[0] > w:
                layer = layer.resize((w - 20, int(layer.size[1] * (w - 20) / layer.size[0])), Image.BICUBIC)
            img.alpha_composite(layer, ((w - layer.size[0]) // 2, max(0, (h - layer.size[1]) // 2)))
        elif role == "title" and im.get("qr"):
            pass
    if im.get("qr"):
        y2 = draw_qr(img, im["qr"], (w - 37 * 7) // 2, h // 3, px=7)
        cap = [t for t, r in im["lines"] if r == "title"]
        if cap:
            ImageDraw.Draw(img).text((40, min(h - 50, y2 + 10)), cap[0], font=font("bold", 30), fill=(20, 20, 20, 255))
    return img


def layout_tiles(im: dict, rng: G.Rng) -> Image.Image:
    n = max(1, im.get("tiles", len(im["lines"])))
    cols = 2 if n > 1 else 1
    rows = (n + cols - 1) // cols
    t = 400
    img = Image.new("RGBA", (cols * t + (cols - 1) * 8, rows * t + (rows - 1) * 8), (255, 255, 255, 255))
    for i, (text, _role) in enumerate(im["lines"][:n]):
        tile = scene(t, t, rng)
        d = ImageDraw.Draw(tile)
        size = 40
        while size > 14 and len(wrap(text, font("bold", size), t - 40)) > 2:
            size -= 2
        f = font("bold", size)
        rows = wrap(text, f, t - 40)
        lh = int(size * 1.3)
        top = t - 30 - lh * len(rows)
        tw = max(int(f.getlength(r)) for r in rows)
        d.rectangle([(t - tw) // 2 - 10, top - 6, (t + tw) // 2 + 10, t - 24], fill=(0, 0, 0, 160))
        for k, r in enumerate(rows):
            d.text(((t - int(f.getlength(r))) // 2, top + k * lh), r, font=f, fill=(255, 255, 255, 255))
        img.alpha_composite(tile, ((i % cols) * (t + 8), (i // cols) * (t + 8)))
    return img


def draw_image(im: dict, rng: G.Rng, lang: str) -> Image.Image:
    style = im["style"]
    special = any(r in ("low_contrast", "tiny_footer", "rotated_text", "handwritten", "watermark", "tile")
                  for _, r in im["lines"])
    if special or style in ("photo", "screen", "tiles", "sticker", "paper", "note"):
        return layout_scene(im, rng, lang)
    if style in G.PHONE_STYLES:
        return layout_phone(im, rng)
    if style in G.SCREEN_STYLES:
        img = layout_screen(im, rng)
        return on_table(img, rng) if style == "photo_of_screen" else img
    if style == "photo":
        return layout_scene(im, rng, lang)
    return layout_paper(im, rng, lang)


def post_process(img: Image.Image, post: dict) -> Image.Image:
    if post.get("crop") == "partial":
        w, h = img.size
        img = img.crop((0, 0, int(w * 0.94), int(h * 0.94)))
    if post.get("rotation_deg"):
        img = img.rotate(-float(post["rotation_deg"]), resample=Image.BICUBIC, expand=True, fillcolor=(128, 128, 128, 255))
    if post.get("blur"):
        img = img.filter(ImageFilter.GaussianBlur(radius=float(post["blur"]) * 1.5))
    return img


def encode(img: Image.Image, post: dict, meta: dict) -> tuple[str, bytes]:
    rgb = img.convert("RGB")
    buf = io.BytesIO()
    exif = None
    if meta.get("exif_comment") or meta.get("exif_artist"):
        exif = Image.Exif()
        if meta.get("exif_artist"):
            exif[0x013B] = meta["exif_artist"]
        if meta.get("exif_comment"):
            exif.get_ifd(0x8769)[0x9286] = b"UNICODE\0" + meta["exif_comment"].encode("utf-16-le")
    if meta.get("png_text_chunk"):
        info = PngImagePlugin.PngInfo()
        info.add_itxt("Comment", meta["png_text_chunk"])
        kw = {"pnginfo": info}
        if exif is not None:
            kw["exif"] = exif
        rgb.save(buf, "PNG", optimize=False, **kw)
        return ".png", buf.getvalue()
    if exif is not None or meta.get("xmp_description") or post.get("jpeg_quality"):
        kw = {"quality": int(post.get("jpeg_quality", 90))}
        if exif is not None:
            kw["exif"] = exif
        if meta.get("xmp_description"):
            kw["xmp"] = xmp_packet(meta["xmp_description"])
        rgb.save(buf, "JPEG", **kw)
        return ".jpg", buf.getvalue()
    rgb.save(buf, "PNG", optimize=False)
    return ".png", buf.getvalue()


def xmp_packet(desc: str) -> bytes:
    from xml.sax.saxutils import escape
    return ('<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            '<rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:description><rdf:Alt>'
            f'<rdf:li xml:lang="x-default">{escape(desc)}</rdf:li></rdf:Alt></dc:description></rdf:Description>'
            '</rdf:RDF></x:xmpmeta>').encode("utf-8")


def render(name: str, seed: int, params: dict) -> dict:
    kind = name.partition(".")[2]
    spec = G.render_spec(kind, params, G.Rng(name, seed, "render"))
    rng = G.Rng(name, seed, "draw")
    out = []
    for i, im in enumerate(spec["images"]):
        img = draw_image(im, rng, spec.get("lang", "en"))
        img = post_process(img, im.get("post", {}))
        suffix, data = encode(img, im.get("post", {}), im.get("meta", {}))
        out.append((("" if len(spec["images"]) == 1 else f"-{i}") + suffix, data))
    return {"images": out, "text": G.spec_text(spec)}
