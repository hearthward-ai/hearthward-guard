"""Model check (design 2026-11-17): a tool-less call to an OpenAI-compatible endpoint (loopback by default).

It can only make a verdict stricter, never lower one and never clear Knock's taint. The untrusted text is
quoted between markers that carry a one-time nonce (look-alike markers in the text are defused), every line
is numbered, and the reply must be ONE small JSON object with fixed choices that copies back a one-time
check code. Two failure kinds (decision review 2026-11-17, pick 8; recheck rules 3.3.1):
  CheckUnavailable  timeout, refused or reset connection, HTTP 5xx, pause flag up, or the canary probes
                    say the checker is degraded. Only this kind may be checked again later (recheck queue).
  CheckTampered     an answer that is not in the agreed shape: wrong code, non-JSON, two objects, a
                    duplicate or extra key, a verdict outside none|suspicious|inject, finish_reason other
                    than "stop", a reply over 200 bytes, or HTTP 4xx. Treated as a hijacked checker: it
                    stays held and is never retried (each retry has a fresh nonce, so retrying would give
                    a hijack several tries at one clean answer). Opt-in exception (second_check.tamper_retry,
                    default off, 11-18): ONE retry per message with a fresh nonce and code, only when the caller
                    allows it (no rule-layer sign at all, budget left) and never after a tool-call reply; a
                    second bad answer is tamper as before.
The prompts and canary probes are data files next to this module (attack wording stays out of plugin
string literals) and are hashed into prompt_id. Nothing the model writes is ever shown or passed on: only
the enum verdict, the kinds, the line number and the timing are kept.
This is our own urllib call on purpose: it does not depend on Hermes provider routing.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import string
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

VERDICTS = ("none", "suspicious", "inject")
KINDS = ("override", "role_spoof", "exfiltrate", "hidden_task", "conceal", "tool_call", "checker_tamper", "other")
VARIANTS = ("content", "chat")
MAX_REPLY_BYTES = 200
MAX_LINES = 999
OVERLAP_CHARS = 300
DECODED_CHARS = 1000
PROMPT_REVISION = 3               # 1 (11-17): "Write the JSON on one line." in both prompts; 2 (11-18): a person
                                  # taking back their own earlier message is none (night bench X1/A1 false holds);
                                  # 3 (11-18, lab re-run M2): only explicit first-person retractions with no other
                                  # request; content rule 8 (summary steering); inject rules win
                                  # prompt_id = r<revision>-<hash of both prompts>
TOOL_CALL_REPLY = "checker reply asked for a tool"
MAX_OUTPUT_TOKENS = 96            # measured 11-17: the grammar output is pretty-printed, 40-61 tokens
DECODED_HEAD = "--- decoded by the guard ---"
SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "kinds", "line", "code"],
    "properties": {
        "verdict": {"enum": list(VERDICTS)},
        "kinds": {"type": "array", "maxItems": 3, "items": {"enum": list(KINDS)}},
        "line": {"type": "integer", "minimum": 0, "maximum": MAX_LINES},
        "code": {"type": "string", "pattern": "^[a-z0-9]{6}$"},
    },
}
_RANK = {v: i for i, v in enumerate(VERDICTS)}
_CODE_ALPHABET = string.ascii_lowercase + string.digits
_PROMPT_DIR = Path(__file__).with_name("checker")

_FENCE_LOOKALIKE = re.compile(r"[<«‹＜〈⟨《〔【][<«‹＜〈⟨《〔【]+|[>»›＞〉⟩》〕】][>»›＞〉⟩》〕】]+")
_MARKER_LINE = re.compile(r"(?im)^([ \t]*)(untrusted|end)(?=[ \t]*[0-9a-f]{4,}\b)")
_CODE_LINE = re.compile(r"(?i)\bcheck[ \t]+code\b")
# Words that talk to a checker (design 2.3 item 4). Only used when the model check runs, so rules-only
# results are unchanged; a checker talked into "none" still leaves this weak sign standing.
_CHECKER_WORDS = re.compile(
    r"(?i)[{,]\s*[\"']?(verdict|kinds|code)[\"']?\s*:|\b(classify|classified|label)\b.{0,40}\b(this|it|as)\b"
    r".{0,40}\b(safe|benign|none|clean|harmless)\b|\b(this|the)\s+(safety\s+)?(check|filter|classifier|checker)\b"
    r".{0,60}\b(answer|reply|output|say|report|return)\b|(判定|分类|判断).{0,12}(安全|无害|正常|none)"
    # fix round (MC-3, best effort): plain paraphrases that talk to a reviewer or ask for the code
    r"|\b(review(?:er|s|ing)?|screen(?:er|ing)|moderat(?:or|ion|ing)|checker|classifier|filter|scanner|grader"
    r"|evaluator|judge|model)\b[^.!?\n]{0,60}\b(mark|rate|grade|label|classify|score|flag|treat|judge)\b"
    r"[^.!?\n]{0,40}\b(fine|safe|benign|harmless|clean|ok|okay|none|normal|acceptable|innocent)\b"
    r"|\b(six|6)[- ]?(character|char|letter|digit)s?\b[^.!?\n]{0,20}\b(token|code|string)\b"
    r"|(?m:^)\s*[\"']?verdict[\"']?\s*[:=]\s*[\"']?(none|safe|clean|benign|harmless|suspicious|inject)\b"
    r"|(模型|AI|系统|程序|审核员|审核者|过滤器|检测器)[^。！？\n]{0,20}(标记|判定|评为|打分|视为|归为|归类)"
    r"[^。！？\n]{0,8}(安全|无害|正常|合格|通过|none)")


class CheckError(RuntimeError):
    pass


class CheckUnavailable(CheckError):
    """The checker could not be reached in time (timeout, connection error, HTTP 5xx, paused, degraded)."""


class CheckDegraded(CheckUnavailable):
    """The canary probes answered wrongly: hold, and the recheck queue releases nothing."""


class CheckTampered(CheckError):
    """The checker answered, but not in the agreed shape: count it as a hijack, never retry."""


class CheckToolCall(CheckTampered):
    """The checker reply asked for a tool: tamper, and never retried even with tamper_retry on."""


@dataclass
class Result:
    verdict: str = "none"
    kinds: tuple = ()
    line: int = 0
    line_text: str = ""            # the guard's own copy of the flagged line (never model words)
    chunks: int = 0                # chunks checked
    chunks_total: int = 0
    partial: bool = False          # more chunks than max_chunks: part of the text was not checked
    ms: float = 0.0
    prompt_id: str = ""
    score: float | None = None     # score mode: P(inject) + 0.5 P(suspicious), None when unavailable
    checker_words: bool = False
    retried: str = ""              # tamper_retry: the first bad answer's reason when one retry was made

    @property
    def found(self) -> bool:
        return self.verdict == "inject"

    def summary(self) -> dict:
        return {"verdict": self.verdict, "kinds": list(self.kinds), "line": self.line, "chunks": self.chunks,
                "chunks_total": self.chunks_total, "partial": self.partial, "ms": round(self.ms, 1),
                "prompt_id": self.prompt_id, "score": self.score, "checker_words": self.checker_words,
                "retried": self.retried}


# ------------------------------------------------------------------ prompts
class Prompts:
    """The two fixed system prompts (content, chat) and the canary probes, loaded once and hashed."""

    def __init__(self, directory: str | os.PathLike | None = None):
        d = Path(directory) if directory else _PROMPT_DIR
        self.text, h = {}, hashlib.sha256()
        for v in VARIANTS:
            t = (d / f"{v}.txt").read_text(encoding="utf-8").strip()
            if not 200 <= len(t) <= 8000:
                raise ValueError(f"checker prompt {v}.txt has an unexpected size")
            self.text[v] = t
            h.update(v.encode() + b"\0" + t.encode("utf-8") + b"\0")
        self.id = f"r{PROMPT_REVISION}-" + h.hexdigest()[:10]
        p = d / "probes.json"
        if not p.is_file():
            p = _PROMPT_DIR / "probes.json"
        raw = json.loads(p.read_text(encoding="utf-8"))
        self.probes = {k: [(x["variant"], x["text"]) for x in raw[k] if x.get("variant") in VARIANTS]
                       for k in ("clean", "inject")}
        if not self.probes["clean"] or not self.probes["inject"]:
            raise ValueError("probes.json needs clean and inject probes")


_DEFAULT_PROMPTS: Prompts | None = None
_PROMPTS_LOCK = threading.Lock()


def default_prompts() -> Prompts:
    global _DEFAULT_PROMPTS
    with _PROMPTS_LOCK:
        if _DEFAULT_PROMPTS is None:
            _DEFAULT_PROMPTS = Prompts()
        return _DEFAULT_PROMPTS


# ------------------------------------------------------------------ text preparation
def _cjk(ch: str) -> bool:
    o = ord(ch)
    return (0x2E80 <= o <= 0x9FFF or 0xAC00 <= o <= 0xD7AF or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFFEF
            or 0x20000 <= o <= 0x3FFFF)


def est_tokens(text: str) -> float:
    """CJK characters x 1 plus other characters / 4 (design 2.1)."""
    n = sum(1 for ch in text if _cjk(ch))
    return n + (len(text) - n) / 4.0


def chunks(text: str, size: int, overlap: int = OVERLAP_CHARS) -> list[str]:
    """Character chunks (kept for callers that size by characters)."""
    if len(text) <= size:
        return [text]
    out, i = [], 0
    step = max(1, size - overlap)
    while i < len(text):
        out.append(text[i:i + size])
        if i + size >= len(text):
            break
        i += step
    return out


def token_chunks(text: str, max_tokens: int = 1500, max_chars: int = 6000, overlap: int = OVERLAP_CHARS) -> list[str]:
    """Chunks of at most max_tokens (estimated) and max_chars characters, overlapping by `overlap` chars."""
    if len(text) <= max_chars and est_tokens(text) <= max_tokens:
        return [text]
    out, i, n = [], 0, len(text)
    while i < n:
        j, cost = i, 0.0
        while j < n and j - i < max_chars:
            c = 1.0 if _cjk(text[j]) else 0.25
            if cost + c > max_tokens:
                break
            cost += c
            j += 1
        j = max(j, i + 1)
        out.append(text[i:j])
        if j >= n:
            break
        i = max(i + 1, j - min(overlap, (j - i) // 2))
    return out


def select_chunks(parts: list[str], max_chunks: int, scorer=None) -> list[int]:
    """Which chunks to check: the first, the ones with the highest rule signals, then the last (design 2.1)."""
    n = len(parts)
    if n <= max_chunks:
        return list(range(n))
    picked = [0]
    if max_chunks >= 2:
        picked.append(n - 1)
    middle = list(range(1, n - 1))
    if scorer is not None:
        scores = {}
        for i in middle:
            try:
                scores[i] = float(scorer(parts[i]))
            except Exception:
                scores[i] = 0.0
        rng = secrets.SystemRandom()
        rng.shuffle(middle)                   # equal scores in an unpredictable order (review MC-2)
        middle.sort(key=lambda i: -scores[i])
    for i in middle:
        if len(picked) >= max_chunks:
            break
        picked.append(i)
    return sorted(picked)


def defuse(text: str) -> str:
    """Defuse anything that could pass for our markers or the check-code line."""
    t = _FENCE_LOOKALIKE.sub("··", text)
    t = _MARKER_LINE.sub(lambda m: m.group(1) + "·" + m.group(2), t)
    return _CODE_LINE.sub("check·code", t)


def number_lines(text: str) -> tuple[str, list[str]]:
    """'001| ...' per line; lines past 999 are joined into line 999. -> (numbered text, the guard's lines)."""
    lines = text.split("\n")
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES - 1] + [" / ".join(lines[MAX_LINES - 1:])]
    return "\n".join(f"{i:03d}| {ln}" for i, ln in enumerate(lines, 1)), lines


_COMMON = frozenset("the a an and or to of in on for at by with from is are be you your me my we our it this "
                    "that please send give tell all any now then also do not if when what how here there".split())
_WORD = re.compile(r"[a-z]{1,20}")
_SKIP_LAYERS = ("reversed", "words-reversed")


def _english(t: str) -> float:
    w = _WORD.findall(t[:4000].lower())
    return sum(1 for x in w if x in _COMMON) / len(w) if len(w) >= 4 else 0.0


def decoded_layers(text: str, limit: int = DECODED_CHARS) -> str:
    """Design 2.1 (review MC-1): the layers the rules decoded (base64, hex, rot13, escapes ...) as plain
    text for the checker, each line tagged with its path, capped at `limit` characters together.
    Whole-text transforms (rot13, a Caesar shift) count only when they read more like English than the
    text as written; reversed text is left out (it is the same words)."""
    from . import decode                     # local: keeps this module importable on its own
    out, used = [], 0
    try:
        layers = decode.expand(text)
    except Exception:
        return ""
    base = _english(text)
    for path, dec in layers:
        if not dec or path.startswith("limit:") or path.split(">")[-1] in _SKIP_LAYERS:
            continue
        if path.split(">")[-1] in ("rot13", "caesar") and not (_english(dec) >= max(0.15, base + 0.1)):
            continue
        if path == "unescape" and " ".join(dec.split()) == " ".join(text.split()):
            continue
        line = f"[{path}] " + " ".join(dec.split())
        if used + len(line) > limit:
            line = line[:max(0, limit - used)]
        if line:
            out.append(line)
            used += len(line) + 1
        if used >= limit:
            break
    return "\n".join(out)


def checker_words(text: str) -> bool:
    return bool(_CHECKER_WORDS.search(text or ""))


def new_nonce() -> str:
    return secrets.token_hex(6)


def new_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(6))


USER_HEAD = "Excerpt to check:\n"


def build_request(excerpt: str, variant: str, nonce: str, code: str, *, model: str = "local",
                  prompts: Prompts | None = None, json_mode: str = "schema", slot: int = -1,
                  score_mode: bool = False) -> dict:
    """The fixed part first (system prompt and the fixed start of the user message) so the server's
    prompt cache reuses it; everything that changes per call comes after it."""
    prompts = prompts or default_prompts()
    user = (USER_HEAD + f"<<UNTRUSTED {nonce}>>\n{excerpt}\n<<END {nonce}>>\n\n"
            f"The check code is {code}. Copy it into \"code\".")
    body = {
        "model": model,
        "messages": [{"role": "system", "content": prompts.text[variant]}, {"role": "user", "content": user}],
        "temperature": 0, "top_p": 1, "seed": 0, "max_tokens": MAX_OUTPUT_TOKENS, "stream": False,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    if json_mode == "schema":
        body["response_format"] = {"type": "json_schema",
                                   "json_schema": {"name": "verdict", "strict": True, "schema": SCHEMA}}
    elif json_mode == "json_object":
        body["response_format"] = {"type": "json_object"}
    if slot >= 0:
        body["id_slot"] = slot
    if score_mode:
        body["logprobs"], body["top_logprobs"] = True, 5
    return body


# ------------------------------------------------------------------ reply parsing (strict)
def _no_dupes(pairs):
    keys = [k for k, _v in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key")
    return dict(pairs)


def parse_reply(data, code: str) -> tuple[str, tuple, int]:
    """Strict parse of a chat-completions reply. -> (verdict, kinds, line). Raises CheckTampered."""
    try:
        choices = data["choices"]
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise CheckTampered("checker reply has the wrong shape")
        ch = choices[0]
        msg = ch["message"]
        content = msg.get("content")
    except CheckError:
        raise
    except Exception as e:
        raise CheckTampered(f"checker reply has the wrong shape ({type(e).__name__})") from None
    if ch.get("finish_reason") != "stop":
        raise CheckTampered("checker reply did not finish normally")
    if msg.get("tool_calls") or msg.get("function_call"):
        raise CheckToolCall(TOOL_CALL_REPLY)
    if not isinstance(content, str):
        raise CheckTampered("unexpected checker reply type")
    if len(content.encode("utf-8", "surrogatepass")) > MAX_REPLY_BYTES:
        raise CheckTampered("checker reply too large")
    try:
        obj = json.loads(content, object_pairs_hook=_no_dupes,
                         parse_constant=lambda c: (_ for _ in ()).throw(ValueError(c)))
    except Exception:
        raise CheckTampered("checker reply is not one JSON object") from None
    if not isinstance(obj, dict) or set(obj) != {"verdict", "kinds", "line", "code"}:
        raise CheckTampered("checker reply has missing or extra keys")
    verdict, kinds, line, got = obj["verdict"], obj["kinds"], obj["line"], obj["code"]
    if not isinstance(verdict, str) or verdict not in VERDICTS:
        raise CheckTampered("checker verdict outside the allowed set")
    if (not isinstance(kinds, list) or len(kinds) > 3
            or any(not isinstance(k, str) or k not in KINDS for k in kinds)):
        raise CheckTampered("checker kinds outside the allowed set")
    if not isinstance(line, int) or isinstance(line, bool) or not 0 <= line <= MAX_LINES:
        raise CheckTampered("checker line out of range")
    if not isinstance(got, str) or got != code:
        raise CheckTampered("checker-mismatch")          # the known-answer copy failed: a hijack sign
    return verdict, tuple(dict.fromkeys(kinds)), line


def score_of(data) -> float | None:
    """Score mode (design 2.4): P(inject) + 0.5 P(suspicious) at the first verdict value token."""
    try:
        toks = data["choices"][0]["logprobs"]["content"]
        acc = ""
        for t in toks:
            if re.search(r'"verdict"\s*:\s*"$', acc):
                p = {"n": 0.0, "s": 0.0, "i": 0.0}
                for alt in t.get("top_logprobs") or []:
                    k = (alt.get("token") or "").lstrip()[:1].lower()
                    if k in p:
                        p[k] += math.exp(float(alt["logprob"]))
                return round(min(1.0, p["i"] + 0.5 * p["s"]), 4)
            acc += t.get("token") or ""
    except Exception:
        return None
    return None


# ------------------------------------------------------------------ transport
def _transport_failure(e: BaseException) -> bool:
    import socket
    import urllib.error
    if isinstance(e, urllib.error.HTTPError):
        code = getattr(e, "code", 0)
        return 500 <= code <= 599 or code in (408, 425, 429)     # busy or timed out: an outage (review MC-5)
    return isinstance(e, (TimeoutError, socket.timeout, ConnectionError, urllib.error.URLError, OSError))


def _post(url: str, body: dict, timeout: float, headers: dict | None = None) -> dict:
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=h, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    end = time.monotonic() + timeout          # one deadline for the whole reply, not per socket read
    raw = b""
    with opener.open(req, timeout=timeout) as r:
        while len(raw) <= 64_000:
            if time.monotonic() > end:
                raise TimeoutError("checker reply too slow")
            part = r.read1(4096) if hasattr(r, "read1") else r.read(4096)
            if not part:
                break
            raw += part
    if len(raw) > 64_000:
        raise CheckTampered("reply too large")
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        raise CheckTampered("reply is not JSON") from None


def _call(post, url: str, body: dict, timeout: float, headers: dict | None):
    try:
        return post(url, body, timeout, headers) if headers else post(url, body, timeout)
    except CheckError:
        raise
    except Exception as e:
        if _transport_failure(e):              # down or busy: the only kind a recheck may retry
            raise CheckUnavailable(f"checker unavailable ({type(e).__name__})") from None
        raise CheckTampered(f"checker reply unreadable ({type(e).__name__})") from None


def one_call(excerpt_text: str, variant: str, *, endpoint: str, model: str = "local", timeout: float = 8.0,
             post=None, prompts: Prompts | None = None, json_mode: str = "schema", slot: int = -1,
             headers: dict | None = None, score_mode: bool = False) -> tuple[str, tuple, int, list, float | None]:
    """One checker call on one chunk. -> (verdict, kinds, line, the guard's numbered lines, score)."""
    post = post or _post
    numbered, lines = number_lines(defuse(excerpt_text))
    nonce, code = new_nonce(), new_code()
    body = build_request(numbered, variant, nonce, code, model=model, prompts=prompts, json_mode=json_mode,
                         slot=slot, score_mode=score_mode)
    data = _call(post, endpoint.rstrip("/") + "/chat/completions", body, timeout, headers)
    verdict, kinds, line = parse_reply(data, code)
    return verdict, kinds, line, lines, (score_of(data) if score_mode else None)


# ------------------------------------------------------------------ health (canary probes)
class Health:
    """Canary probe state (design 2.3 item 6). 'degraded' means hold, and the recheck queue releases
    nothing while it lasts (3.3.1 rule 4)."""

    def __init__(self, every_s: float = 1800.0, retry_s: float = 60.0, clock=time.monotonic):
        self.every_s, self.retry_s, self.clock = every_s, retry_s, clock
        self.state, self.reason, self.last = "unknown", "", None
        self._i = 0
        self._lock = threading.Lock()

    @property
    def degraded(self) -> bool:
        return self.state == "degraded"

    def due(self) -> bool:
        if self.last is None:
            return True
        wait = self.retry_s if self.degraded else self.every_s
        return self.clock() - self.last >= wait

    def run(self, call) -> None:
        """call(text, variant) -> verdict. One clean and one injection probe, rotating through the set.
        A wrong answer or a bad reply marks the check degraded; an outage changes nothing and raises."""
        with self._lock:
            if not self.due():
                return
            prompts = getattr(call, "prompts", None) or default_prompts()
            clean = prompts.probes["clean"][self._i % len(prompts.probes["clean"])]
            bad = prompts.probes["inject"][self._i % len(prompts.probes["inject"])]
            self._i += 1
            try:
                ok = call(clean[1], clean[0]) == "none" and call(bad[1], bad[0]) == "inject"
                why = "" if ok else "canary probe got the wrong answer"
            except CheckTampered:
                ok, why = False, "canary probe reply not in the agreed shape"
            except CheckUnavailable:
                self.last = self.clock() - (self.every_s - self.retry_s) if self.state == "ok" else None
                raise
            self.last = self.clock()
            self.state, self.reason = ("ok", "") if ok else ("degraded", why)

    def mark(self, state: str, reason: str = "") -> None:      # tests and status
        self.state, self.reason, self.last = state, reason, self.clock()


# ------------------------------------------------------------------ the checker
class Checker:
    """Settings + health for the guard's model check. check() raises CheckUnavailable/CheckTampered."""

    def __init__(self, sc, *, clock=time.monotonic, post=None, prompts: Prompts | None = None):
        self.sc = sc
        self.post = post
        self.clock = clock
        self.prompts = prompts or (Prompts(sc.prompt_variant_dir) if getattr(sc, "prompt_variant_dir", "")
                                   else default_prompts())
        self.health = Health(every_s=60.0 * getattr(sc, "probe_every_min", 30), clock=clock)
        self.calls = 0

    @property
    def prompt_id(self) -> str:
        return self.prompts.id

    def _headers(self) -> dict | None:
        env = getattr(self.sc, "api_key_env", "")
        key = os.environ.get(env, "") if env else ""
        return {"Authorization": "Bearer " + key} if key else None

    def paused(self) -> bool:
        flag = getattr(self.sc, "pause_flag", "")
        try:
            return bool(flag) and os.path.exists(flag)
        except Exception:
            return True

    def _one(self, text: str, variant: str, timeout: float):
        self.calls += 1
        return one_call(text, variant, endpoint=self.sc.endpoint, model=self.sc.model, timeout=timeout,
                        post=self.post, prompts=self.prompts, json_mode=self.sc.json_mode, slot=self.sc.slot,
                        headers=self._headers(), score_mode=getattr(self.sc, "score_mode", False))

    def ensure_healthy(self, timeout: float) -> None:
        if self.paused():
            raise CheckUnavailable("checker paused")
        if getattr(self.sc, "probes", True) and self.health.due():
            def call(t, v):
                return self._one(t, v, timeout)[0]
            call.prompts = self.prompts
            self.health.run(call)
        if self.health.degraded:
            raise CheckDegraded("checker degraded: " + self.health.reason)

    def check(self, text: str, variant: str = "content", *, timeout: float | None = None, scorer=None,
              decoded: str = "", cancel: "threading.Event | None" = None, max_chunks: int | None = None,
              retry_ok=None) -> Result:
        t0 = time.perf_counter()
        timeout = self.sc.timeout_s if timeout is None else timeout
        _stop_if(cancel)
        self.ensure_healthy(timeout)
        res = check_text(text, variant, call=lambda t: self._one(t, variant, timeout),
                         max_chunks=self.sc.max_chunks if max_chunks is None else max_chunks,
                         chunk_tokens=self.sc.chunk_tokens, max_chars=self.sc.max_chars, scorer=scorer,
                         decoded=decoded, cancel=cancel, retry_ok=retry_ok)
        res.prompt_id = self.prompt_id
        res.ms = (time.perf_counter() - t0) * 1000
        return res


def _stop_if(cancel) -> None:
    if cancel is not None and cancel.is_set():
        raise CheckUnavailable("check cancelled (its time ran out)")


def check_text(text: str, variant: str, *, call, max_chunks: int = 4, chunk_tokens: int = 1500,
               max_chars: int = 6000, scorer=None, decoded: str = "", cancel=None, retry_ok=None) -> Result:
    """Chunk, select and check. The strictest chunk verdict wins; any failure raises at once. cancel (a
    threading.Event) is looked at before every call: a check whose time ran out stops (review MC-4).
    retry_ok: None = never retry (decision review pick 8); else a callable asked once, after the first
    bad answer of this item: True = one more call with a fresh nonce and code (a tool-call reply is
    never retried), and a second bad answer raises CheckTampered."""
    if variant not in VARIANTS:
        raise ValueError("unknown checker variant")
    parts = token_chunks(text, chunk_tokens, max_chars)
    picked = select_chunks(parts, max_chunks, scorer)
    res = Result(chunks_total=len(parts), partial=len(picked) < len(parts),
                 checker_words=checker_words(text) or checker_words(decoded))
    extra = ""
    if decoded and decoded.strip():
        extra = "\n" + DECODED_HEAD + "\n" + decoded[:DECODED_CHARS]
    scores = []
    for n, i in enumerate(picked):
        _stop_if(cancel)
        chunk = parts[i] + (extra if n == 0 else "")
        try:
            verdict, kinds, line, lines, score = call(chunk)
        except CheckTampered as e:
            why = str(e.args[0]) if e.args else "tamper"
            if retry_ok is None or res.retried or isinstance(e, CheckToolCall) or not retry_ok():
                raise
            res.retried = why
            _stop_if(cancel)
            verdict, kinds, line, lines, score = call(chunk)       # fresh nonce and code (one_call)
        res.chunks += 1
        if score is not None:
            scores.append(score)
        if _RANK[verdict] > _RANK[res.verdict]:
            res.verdict, res.kinds, res.line = verdict, kinds, line
            res.line_text = lines[line - 1][:300] if 1 <= line <= len(lines) else ""
    res.score = max(scores) if scores else None
    return res


def check(text: str, endpoint: str, model: str = "local", timeout: float = 8.0, max_chars: int = 6000,
          post=None, *, variant: str = "content", max_chunks: int = 4, chunk_tokens: int = 1500,
          json_mode: str = "schema", slot: int = -1, prompts: Prompts | None = None, score_mode: bool = False,
          scorer=None, decoded: str = "", headers: dict | None = None, checker: "Checker | None" = None,
          cancel=None, chunk_cap: int | None = None, retry_ok=None) -> Result:
    """Check one item. With `checker` (the guard): its settings, pause flag and canary probes apply.
    Without (bench and tools): a one-shot check, no probes. Raises CheckUnavailable/CheckTampered."""
    if checker is not None:
        return checker.check(text, variant, timeout=timeout, scorer=scorer, decoded=decoded, cancel=cancel,
                             max_chunks=chunk_cap, retry_ok=retry_ok)
    t0 = time.perf_counter()
    prompts = prompts or default_prompts()
    res = check_text(text, variant, call=lambda t: one_call(
        t, variant, endpoint=endpoint, model=model, timeout=timeout, post=post, prompts=prompts,
        json_mode=json_mode, slot=slot, headers=headers, score_mode=score_mode),
        max_chunks=max_chunks, chunk_tokens=chunk_tokens, max_chars=max_chars, scorer=scorer, decoded=decoded,
        retry_ok=retry_ok)
    res.prompt_id = prompts.id
    res.ms = (time.perf_counter() - t0) * 1000
    return res
