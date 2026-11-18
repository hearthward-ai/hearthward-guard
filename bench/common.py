"""Shared helpers for the benchmark kit (Python standard library only).

Every result is one JSON line: {label, config_id, metric, value, unit, n, ts, ...extra}. Extra keys describe the
cell (scenario, lang, ctx, run). Rows never contain file paths, host names or prompt text.
"""
import json, os, statistics, threading, time, urllib.request, math, datetime

HERE = os.path.dirname(os.path.abspath(__file__))


def load_json(rel):
    with open(os.path.join(HERE, rel), encoding="utf-8") as f:
        return json.load(f)


class Server:
    def __init__(self, base_url, timeout=1800):
        self.base = base_url.rstrip("/")
        self.timeout = timeout

    def get(self, path, timeout=5):
        with urllib.request.urlopen(self.base + path, timeout=timeout) as r:
            return json.load(r)

    def post(self, path, body, timeout=None):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
        return urllib.request.urlopen(req, timeout=timeout or self.timeout)

    def ntok(self, text):
        with self.post("/tokenize", {"content": text}, 120) as r:
            return len(json.load(r)["tokens"])

    def props(self):
        """/props never wakes a sleeping llama-server (/slots does: never use it)."""
        return self.get("/props")

    def chat(self, body):
        """Streamed chat completion. Returns timings measured on the client plus the assembled reply:
        ttft (first token of any kind, thinking included), t_answer (first visible content or tool call),
        total, server timings (prompt_n, cache_n, prompt_ms, predicted_n, ...), content, reasoning, tool_calls."""
        body = dict(body, stream=True)
        body.setdefault("stream_options", {"include_usage": True})
        t0 = time.perf_counter()
        ttft = t_answer = None
        timings, finish = {}, None
        content, reasoning, calls = [], [], {}
        with self.post("/v1/chat/completions", body) as r:
            for raw in r:
                line = raw.decode("utf-8", "replace").strip()
                if not line.startswith("data: ") or line == "data: [DONE]":
                    continue
                d = json.loads(line[6:])
                if "timings" in d:
                    timings = d["timings"]
                for c in d.get("choices", []):
                    dl = c.get("delta", {}) or {}
                    finish = c.get("finish_reason") or finish
                    if dl.get("reasoning_content") or dl.get("content") or dl.get("tool_calls"):
                        now = time.perf_counter()
                        if ttft is None:
                            ttft = now - t0
                        if t_answer is None and (dl.get("content") or dl.get("tool_calls")):
                            t_answer = now - t0
                    if dl.get("reasoning_content"):
                        reasoning.append(dl["reasoning_content"])
                    if dl.get("content"):
                        content.append(dl["content"])
                    for tc in dl.get("tool_calls") or []:
                        k = tc.get("index", 0)
                        e = calls.setdefault(k, {"id": None, "name": "", "arguments": ""})
                        e["id"] = tc.get("id") or e["id"]
                        fn = tc.get("function") or {}
                        e["name"] += fn.get("name") or ""
                        e["arguments"] += fn.get("arguments") or ""
        total = time.perf_counter() - t0
        return {"ttft": ttft, "t_answer": t_answer, "total": total, "timings": timings, "finish": finish,
                "content": "".join(content), "reasoning": "".join(reasoning),
                "tool_calls": [calls[k] for k in sorted(calls)]}


# ---------------------------------------------------------------- results
class Results:
    def __init__(self, path, label, config_id):
        self.path, self.label, self.config_id = path, label, config_id
        d = os.path.dirname(os.path.abspath(path))
        os.makedirs(d, exist_ok=True)

    def emit(self, metric, value, unit, n=1, **extra):
        row = {"label": self.label, "config_id": self.config_id, "metric": metric,
               "value": None if value is None else (round(value, 4) if isinstance(value, float) else value),
               "unit": unit, "n": n, "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        row.update(extra)
        with open(self.path, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row


def read_rows(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            rows += [json.loads(l) for l in f if l.strip()]
    return rows


# ---------------------------------------------------------------- run control
def stop_requested():
    """Graceful end: a runner may create the file named in EVAL_STOP_FILE; finish the current measurement, then stop."""
    p = os.environ.get("EVAL_STOP_FILE")
    return bool(p) and os.path.exists(p)


def tag(text):
    """Optional: tell a running powerlog.py what is happening right now (file named in BENCH_TAG_FILE)."""
    p = os.environ.get("BENCH_TAG_FILE")
    if not p:
        return
    tmp = f"{p}.{os.getpid()}.{threading.get_ident()}.tmp"   # one temp file per thread (concurrency.py tags from threads)
    for _ in range(5):   # the reader may hold the file for a moment; a lost tag only blurs one power row
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text or "")
            os.replace(tmp, p)
            return
        except OSError:
            time.sleep(0.05)
    try:
        os.remove(tmp)
    except OSError:
        pass


# ---------------------------------------------------------------- stats
def median(v):
    v = [x for x in v if x is not None]
    return statistics.median(v) if v else None


def pct(v, q):
    """Nearest-rank percentile (q in 0..100); with few samples P95 is the worst run."""
    v = sorted(x for x in v if x is not None)
    if not v:
        return None
    return v[max(0, math.ceil(q / 100 * len(v)) - 1)]


def wilson(k, n, z=1.96):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


# ---------------------------------------------------------------- prompts
def hermes():
    """System prompt + tool schemas of Hermes Agent's default chat session (see prompts/hermes_prompt.json)."""
    d = load_json("prompts/hermes_prompt.json")
    return d["system"], d["tools"]


def filler():
    return load_json("prompts/filler.json")["turns"]


def history(server, target_tokens, base_tokens, lang="en", seed=0):
    """Neutral synthetic chat history so that base_tokens + history ~= target_tokens (never below zero turns).
    Turns alternate languages by seed so caches never match across runs with different seeds."""
    turns = [t for t in filler() if lang == "mix" or t["lang"] == lang] or filler()
    msgs, total, i = [], base_tokens, seed
    cost = {}
    while total < target_tokens - 300:
        k = i % len(turns)
        t = turns[k]
        if k not in cost:
            cost[k] = server.ntok(t["user"]) + server.ntok(t["assistant"]) + 10
        msgs += [{"role": "user", "content": f"(#{len(msgs) // 2 + 1}) " + t["user"]},
                 {"role": "assistant", "content": t["assistant"]}]
        total += cost[k]
        i += 1
    return msgs, total


SAMPLING = {"temperature": 0.6, "top_p": 0.95, "parallel_tool_calls": False}


def thinking(on=True):
    if on:
        return {"chat_template_kwargs": {"enable_thinking": True, "reasoning_effort": "medium"}, "reasoning_effort": "medium"}
    return {"chat_template_kwargs": {"enable_thinking": False}}
