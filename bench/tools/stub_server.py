#!/usr/bin/env python3
"""Fake llama-server for a smoke test of the kit without a GPU or a model (not a benchmark: every number is made up).
Answers /health, /props, /tokenize, /completion and streamed /v1/chat/completions (a tool call when tools are offered
and the last message is from the user, otherwise a short answer), with llama.cpp-style 'timings'.
--np N emulates N slots (a request waits for a free slot; 'id_slot' pins it to one slot, out of range = HTTP 400) and
/props reports total_slots and the per-slot n_ctx (n_ctx / np, or all of it with --kv-unified). A request with 'response_format' gets a JSON object reply that
copies the 6-character check code found in the prompt ("The check code is xxxxxx").
usage: python tools/stub_server.py [--port 8099] [--n-ctx 131072] [--np 1] [--kv-unified]"""
import argparse, json, re, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def take_slot(want):
    """Block until a slot is free (the pinned one, or any); returns its index."""
    while True:
        for i, lk in enumerate(SLOTS):
            if (want is None or i == want) and lk.acquire(blocking=False):
                return i
        time.sleep(0.005)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self.send({"status": "ok"})
        if self.path == "/props":
            return self.send({"default_generation_settings": {"n_ctx": A.n_ctx if A.kv_unified else A.n_ctx // A.np},
                              "total_slots": A.np, "is_sleeping": False})
        self.send({"error": "not found"}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/tokenize":
            return self.send({"tokens": list(range(max(1, len(body.get("content", "")) // 4)))})
        if self.path == "/completion":
            n = len(body.get("prompt", "")) // 4
            s = take_slot(None)
            try:
                time.sleep(0.01)
            finally:
                SLOTS[s].release()
            return self.send({"content": "ok", "timings": {"prompt_n": n, "prompt_ms": n / 2, "prompt_per_second": 2000.0,
                                                         "predicted_n": 1, "predicted_ms": 20, "predicted_per_second": 50.0}})
        if self.path == "/v1/chat/completions":
            want = body.get("id_slot")
            if want is not None and (isinstance(want, bool) or not isinstance(want, int) or want >= A.np):
                return self.send({"error": {"code": 400, "message": "invalid slot id"}}, 400)
            msgs = body.get("messages", [])
            n = sum(len(json.dumps(m.get("content", ""))) for m in msgs) // 4 + len(json.dumps(body.get("tools", []))) // 4
            s = take_slot(None if want is None or want < 0 else want)
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()

                def ev(d):
                    self.wfile.write(b"data: " + json.dumps(d).encode() + b"\n\n")
                    self.wfile.flush()
                if body.get("response_format"):
                    m = re.search(r"check code is ([a-z0-9]{6})", json.dumps(msgs))
                    ev({"choices": [{"delta": {"content": json.dumps({"verdict": "none", "kinds": [], "line": 0,
                                                                      "code": m.group(1) if m else ""})}}]})
                    fin = "stop"
                else:
                    ev({"choices": [{"delta": {"reasoning_content": "thinking"}}]})
                    time.sleep(0.02)
                    if body.get("tools") and msgs and msgs[-1].get("role") == "user":
                        name = body["tools"][0]["function"]["name"]
                        ev({"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c1", "function": {"name": name, "arguments": "{}"}}]}}]})
                        fin = "tool_calls"
                    else:
                        ev({"choices": [{"delta": {"content": "Here is a short answer."}}]})
                        fin = "stop"
                ev({"choices": [{"delta": {}, "finish_reason": fin}],
                    "timings": {"prompt_n": n, "cache_n": 0, "prompt_ms": n / 2, "prompt_per_second": 2000.0,
                                "predicted_n": 20, "predicted_ms": 400, "predicted_per_second": 50.0}})
                self.wfile.write(b"data: [DONE]\n\n")
            finally:
                SLOTS[s].release()
            return
        self.send({"error": "not found"}, 404)


ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=8099)
ap.add_argument("--n-ctx", type=int, default=131072)
ap.add_argument("--np", type=int, default=1)
ap.add_argument("--kv-unified", action="store_true", help="per-slot n_ctx = the whole pool (like --kv-unified)")
A = ap.parse_args()
A.np = max(1, A.np)
SLOTS = [threading.Lock() for _ in range(max(1, A.np))]
ThreadingHTTPServer(("127.0.0.1", A.port), H).serve_forever()
