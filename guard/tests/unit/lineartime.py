"""Machine-relative time limits for the DoS / ReDoS tests (CI fix, 2026-11-18).

What the timing tests guard: the guard's scans run synchronously on the gateway's event loop, so
a pattern that backtracks catastrophically or rescans the text (quadratic or worse) lets one
stranger's message freeze the whole gateway. Such a regression grows with the input size. A slow
machine only multiplies every time by about the same constant.

Fixed seconds limits (tuned on the dev PC) went red on GitHub runners that are 2-3x slower. The
limits here are measured in the same test, on the same machine, at about the same moment:

1. ratio:  the hostile input may cost at most R times the same call on ordinary prose of the same
           length (the linear baseline). Each test states its R and the worst ratio measured.
2. growth: doubling the input may multiply the time by at most MAX_GROWTH. Linear code gives
           about 2, quadratic about 4, cubic about 8.

Each check first uses one run (the baseline is a best of 3). A failing check is measured again,
best of RETRY_RUNS with hostile and baseline runs interleaved, before it counts, so a busy runner
has to be slow on every try. Nothing here reads an environment variable: CI cannot loosen it.

Checked 2026-11-18 by injecting regressions (monkeypatch, dev PC + Linux lab, also on one shared
core): the original H1 comment regex fails (ratio 8.8x, growth 3.8x), and so does an added quadratic
rescan in Gatehouse that costs only half of the prose time at 200,000 characters. Limit of the
method: a super-linear term much smaller than the linear cost at the test size passes; that is why
the tests use sizes close to the real input limits.
"""
from __future__ import annotations

import time
from typing import Callable

MAX_GROWTH = 3.0
RETRY_RUNS = 3
BASE_RUNS = 3
NOISE_FRAC = 0.2    # a half-size time below this share of the baseline's half-size time is timer noise
PROSE = "The quick brown fox jumps over the lazy dog. "


def best(fn: Callable[[str], object], arg: str, runs: int = 1) -> float:
    """Shortest wall time of fn(arg) over *runs* calls."""
    b = float("inf")
    for _ in range(max(1, runs)):
        t0 = time.perf_counter()
        fn(arg)
        b = min(b, time.perf_counter() - t0)
    return b


def ordinary(n: int) -> str:
    """Plain English prose of exactly n characters: the linear baseline input."""
    return (PROSE * (n // len(PROSE) + 1))[:n]


class Linear:
    """Times fn(hostile) against fn(ordinary prose of the same length) on this machine."""

    def __init__(self, fn: Callable[[str], object]):
        self.fn = fn
        self._base: dict[int, float] = {}

    def baseline(self, n: int) -> float:
        for m, b in self._base.items():       # lengths within 10% share one measurement, scaled
            if abs(m - n) <= 0.1 * max(m, n):
                return b * n / m
        self._base[n] = best(self.fn, ordinary(n), BASE_RUNS)
        return self._base[n]

    def problems(self, hostile: str, label: str, max_ratio: float, growth: bool = True) -> list[str]:
        """[] when fn(hostile) is within max_ratio x the baseline (and, with growth, scales linearly)."""
        out = self._check(hostile, label, max_ratio, growth, 1, self.baseline(len(hostile)))
        if out:
            out = self._check(hostile, label, max_ratio, growth, RETRY_RUNS, None)
        return out

    def baseline_problems(self, n: int, label: str = "ordinary prose") -> list[str]:
        """The baseline itself must be linear, or every ratio above would hide a slowdown."""
        return self.problems(ordinary(n), label, max_ratio=1.5, growth=True)

    def _check(self, hostile: str, label: str, max_ratio: float, growth: bool, runs: int,
               base: float | None) -> list[str]:
        n = len(hostile)
        half, plain = hostile[: n // 2], ordinary(n)
        t = th = b = float("inf")
        for _ in range(runs):                 # interleaved, so a load spike hits both sides
            t = min(t, best(self.fn, hostile))
            if base is None:
                b = min(b, best(self.fn, plain))
            if growth:
                th = min(th, best(self.fn, half))
        if base is not None:
            b = base
        out = []
        if t > max_ratio * b:
            out.append(f"{label}: {t:.3f}s for {n:,} chars = {t / b:.1f}x ordinary prose of the same length "
                       f"({b:.3f}s); limit {max_ratio}x")
        if growth:
            g = t / max(th, NOISE_FRAC * b / 2)
            if g > MAX_GROWTH:
                out.append(f"{label}: {n // 2:,} -> {n:,} chars multiplied the time by {g:.1f} "
                           f"({th:.3f}s -> {t:.3f}s); limit {MAX_GROWTH} (linear ~2, quadratic ~4)")
        return out
