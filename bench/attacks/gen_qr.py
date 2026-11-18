#!/usr/bin/env python3
"""gen_qr.py - minimal QR Code encoder for synthetic test images (Python standard library only).

Byte mode, error-correction level M, versions 1-10 (up to 213 bytes). Enough for the short
fake URLs the attack bench puts into scam images. Deterministic: same text -> same matrix.
Follows ISO/IEC 18004 (structure after the public-domain-style reference by Project Nayuki).

    qr_matrix("https://example.invalid/a1") -> list[list[bool]]   (True = dark module)
"""
from __future__ import annotations

# Level M tables, index = version (0 unused).
_ECC_PER_BLOCK = [None, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26]
_NUM_BLOCKS = [None, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5]
_ECL_FORMAT_BITS = 0  # M
MAX_VERSION = 10


def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def rs_divisor(degree: int) -> list[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(len(result)):
            result[j] = _gf_mul(result[j], root)
            if j + 1 < len(result):
                result[j] ^= result[j + 1]
        root = _gf_mul(root, 0x02)
    return result


def rs_remainder(data: list[int], divisor: list[int]) -> list[int]:
    result = [0] * len(divisor)
    for b in data:
        factor = b ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_mul(coef, factor)
    return result


def raw_modules(ver: int) -> int:
    result = (16 * ver + 128) * ver + 64
    if ver >= 2:
        na = ver // 7 + 2
        result -= (25 * na - 10) * na - 55
        if ver >= 7:
            result -= 36
    return result


def data_codewords(ver: int) -> int:
    return raw_modules(ver) // 8 - _ECC_PER_BLOCK[ver] * _NUM_BLOCKS[ver]


def alignment_positions(ver: int) -> list[int]:
    if ver == 1:
        return []
    na = ver // 7 + 2
    size = ver * 4 + 17
    step = (ver * 4 + na * 2 + 1) // (na * 2 - 2) * 2
    pos = [size - 7 - i * step for i in range(na - 1)]
    return [6] + sorted(pos)


def format_bits(mask: int) -> int:
    data = _ECL_FORMAT_BITS << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return (data << 10 | rem) ^ 0x5412


def version_bits(ver: int) -> int:
    rem = ver
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return ver << 12 | rem


def _encode_data(data: bytes) -> tuple[int, list[int]]:
    for ver in range(1, MAX_VERSION + 1):
        cc_bits = 8 if ver <= 9 else 16
        cap = data_codewords(ver) * 8
        if 4 + cc_bits + 8 * len(data) <= cap:
            break
    else:
        raise ValueError("text too long for this QR encoder")
    bits: list[int] = []

    def put(val: int, n: int) -> None:
        bits.extend((val >> i) & 1 for i in reversed(range(n)))
    put(0b0100, 4)
    put(len(data), cc_bits)
    for b in data:
        put(b, 8)
    put(0, min(4, cap - len(bits)))
    put(0, (-len(bits)) % 8)
    pad = 0xEC
    while len(bits) < cap:
        put(pad, 8)
        pad ^= 0xEC ^ 0x11
    words = [int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8)]
    return ver, words


def _add_ecc(ver: int, data: list[int]) -> list[int]:
    nb, ecl = _NUM_BLOCKS[ver], _ECC_PER_BLOCK[ver]
    raw = raw_modules(ver) // 8
    n_short = nb - raw % nb
    short_len = raw // nb
    div = rs_divisor(ecl)
    blocks, k = [], 0
    for i in range(nb):
        dat = data[k:k + short_len - ecl + (0 if i < n_short else 1)]
        k += len(dat)
        ecc = rs_remainder(dat, div)
        if i < n_short:
            dat = dat + [0]
        blocks.append(dat + ecc)
    out = []
    for i in range(len(blocks[0])):
        for j, blk in enumerate(blocks):
            if i != short_len - ecl or j >= n_short:
                out.append(blk[i])
    return out


_MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: x * y % 2 + x * y % 3 == 0,
    lambda x, y: (x * y % 2 + x * y % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + x * y % 3) % 2 == 0,
]


class _Grid:
    def __init__(self, ver: int):
        self.ver = ver
        self.size = ver * 4 + 17
        self.m = [[False] * self.size for _ in range(self.size)]
        self.f = [[False] * self.size for _ in range(self.size)]

    def setf(self, x: int, y: int, dark: bool) -> None:
        self.m[y][x] = dark
        self.f[y][x] = True

    def function_patterns(self) -> None:
        s = self.size
        for i in range(s):
            self.setf(6, i, i % 2 == 0)
            self.setf(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (s - 4, 3), (3, s - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < s and 0 <= y < s:
                        self.setf(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        pos = alignment_positions(self.ver)
        last = len(pos) - 1
        for i, px in enumerate(pos):
            for j, py in enumerate(pos):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.setf(px + dx, py + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format(0)
        if self.ver >= 7:
            bits = version_bits(self.ver)
            for i in range(18):
                bit = (bits >> i) & 1 == 1
                a, b = s - 11 + i % 3, i // 3
                self.setf(a, b, bit)
                self.setf(b, a, bit)

    def draw_format(self, mask: int) -> None:
        bits = format_bits(mask)
        g = lambda i: (bits >> i) & 1 == 1  # noqa: E731
        s = self.size
        for i in range(6):
            self.setf(8, i, g(i))
        self.setf(8, 7, g(6))
        self.setf(8, 8, g(7))
        self.setf(7, 8, g(8))
        for i in range(9, 15):
            self.setf(14 - i, 8, g(i))
        for i in range(8):
            self.setf(s - 1 - i, 8, g(i))
        for i in range(8, 15):
            self.setf(8, s - 15 + i, g(i))
        self.setf(8, s - 8, True)

    def draw_codewords(self, words: list[int]) -> None:
        s, i, right = self.size, 0, self.size - 1
        total = len(words) * 8
        while right >= 1:
            if right == 6:
                right = 5
            for vert in range(s):
                for j in range(2):
                    x = right - j
                    upward = ((right + 1) & 2) == 0
                    y = s - 1 - vert if upward else vert
                    if not self.f[y][x] and i < total:
                        self.m[y][x] = (words[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        fn = _MASKS[mask]
        for y in range(self.size):
            for x in range(self.size):
                if not self.f[y][x] and fn(x, y):
                    self.m[y][x] = not self.m[y][x]

    def penalty(self) -> int:
        """Simplified penalty (runs, 2x2 blocks, dark balance); any mask decodes."""
        s, m, p = self.size, self.m, 0
        for line in [m[y] for y in range(s)] + [[m[y][x] for y in range(s)] for x in range(s)]:
            run, prev = 0, None
            for v in line + [None]:
                if v == prev:
                    run += 1
                else:
                    if run >= 5:
                        p += run - 2
                    run, prev = 1, v
        for y in range(s - 1):
            for x in range(s - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    p += 3
        dark = sum(v for row in m for v in row)
        p += abs(dark * 20 - s * s * 10) // (s * s) * 10
        return p


def qr_matrix(text: str) -> list[list[bool]]:
    ver, words = _encode_data(text.encode("utf-8"))
    words = _add_ecc(ver, words)
    best, best_p = None, None
    for mask in range(8):
        g = _Grid(ver)
        g.function_patterns()
        g.draw_codewords(words)
        g.apply_mask(mask)
        g.draw_format(mask)
        p = g.penalty()
        if best_p is None or p < best_p:
            best, best_p = g, p
    return best.m
