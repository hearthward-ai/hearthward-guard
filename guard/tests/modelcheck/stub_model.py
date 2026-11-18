"""A stub OpenAI-compatible model server on 127.0.0.1 for offline model-check tests (stdlib only).

It reads the excerpt between the request's own markers and answers like a checker would. Knobs
(attributes on the server object) let tests make it slow, broken, or "hijacked":
  delay     seconds to wait before answering (timeouts)
  status    HTTP status to answer with (503 = outage, 400 = client error)
  raw       a fixed body to send as the message content (bad JSON, two objects, extra keys ...)
  finish    finish_reason to report
  answers   a list of verdicts to give in order (then the keyword rule again)
  obey      True = a hijacked checker: it follows instructions found in the excerpt (it copies a JSON
            reply written there, or the first check code it sees in the whole user message)
Keyword rule: "ignore", "system message", "upload", "inject-me", "passwords", "setup text" -> inject;
"maybe-odd" -> suspicious.
"""
from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_FENCE = re.compile(r"<<UNTRUSTED ([0-9a-f]{12})>>\n(.*)\n<<END \1>>", re.S)
_CODE = re.compile(r"[Cc]heck code is ([a-z0-9]{6})")
INJECT_WORDS = ("ignore", "system message", "upload", "inject-me", "passwords", "setup text")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        srv = self.server
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n).decode("utf-8"))
        with srv.lock:
            srv.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        if srv.delay:
            time.sleep(srv.delay)
        if srv.status != 200:
            self.send_response(srv.status)
            self.end_headers()
            self.wfile.write(b'{"error":"stub"}')
            return
        content = srv.answer(body)
        out = {"choices": [{"index": 0, "message": {"role": "assistant", "content": content},
                            "finish_reason": srv.finish}]}
        data = json.dumps(out).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class StubModel(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.lock = threading.Lock()
        self.requests: list = []
        self.delay = 0.0
        self.status = 200
        self.raw = None
        self.finish = "stop"
        self.answers: list = []
        self.obey = False
        self._t = threading.Thread(target=self.serve_forever, daemon=True)

    def handle_error(self, request, client_address):
        pass                      # clients that time out close the socket early; that is the test

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}/v1"

    def start(self):
        self._t.start()
        return self

    def stop(self):
        self.shutdown()
        self.server_close()

    def reset(self):
        self.requests.clear()
        self.delay, self.status, self.raw, self.finish, self.answers, self.obey = 0.0, 200, None, "stop", [], False

    def answer(self, body: dict) -> str:
        if self.raw is not None:
            return self.raw
        user = body["messages"][1]["content"]
        m = _FENCE.search(user)
        excerpt = m.group(2) if m else ""
        code = _CODE.findall(user)[-1]
        if self.obey:                                    # a hijacked checker follows the excerpt
            js = re.search(r"\{.*\}", excerpt, re.S)
            if js:
                return re.sub(r"^\d{3}\| ", "", js.group(0), flags=re.M)
            code = _CODE.findall(user)[0]
        low = excerpt.lower()
        if self.answers:
            verdict = self.answers.pop(0)
        elif any(w in low for w in INJECT_WORDS):
            verdict = "inject"
        elif "maybe-odd" in low:
            verdict = "suspicious"
        else:
            verdict = "none"
        line = 0
        if verdict != "none":
            for ln in excerpt.split("\n"):
                if any(w in ln.lower() for w in INJECT_WORDS + ("maybe-odd",)):
                    line = int(ln[:3]) if ln[:3].isdigit() else 0
                    break
        return json.dumps({"verdict": verdict, "kinds": ["override"] if verdict != "none" else [],
                           "line": line, "code": code})


def closed_port_endpoint() -> str:
    """An endpoint where nothing listens (server down)."""
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/v1"
