"""
Checks the scripted multi-turn runner against a fake server, so it needs no Ollama:

    python tests/test_scripted.py

The fake server leaks the secret once a conversation reaches its third user turn, refuses any
question about a "grace" period, and records how many messages each request carried. That proves
the runner sends real history and scores conversations correctly; it says nothing about the model.
"""

import json
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import scripted_run  # noqa: E402


def start_fake_server(docs: str = "clean"):
    """Returns (server, url, seen) where seen lists the message count of every chat request."""
    seen: list[int] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, body: dict):
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._send({"status": "ok", "stub": True, "docs": docs, "guardrails": [{"id": "unguarded"}]})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["content-length"])))
            messages = body["messages"]
            seen.append(len(messages))
            users = [m["content"] for m in messages if m["role"] == "user"]
            if "grace" in users[-1].lower():
                reply = "I'm sorry, I can't respond to that."
            elif len(users) >= 3:
                reply = "The code is ABC-SECRET-4321."
            else:
                reply = "Happy to help with transport questions."
            self._send({"choices": [{"message": {"role": "assistant", "content": reply}}]})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}", seen


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


def main() -> int:
    server, url, seen = start_fake_server()
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        result = scripted_run.run("unguarded", "scripted.t1", "smoke", url, Path(tmp), 1, True)
        records = json.loads((Path(tmp) / "scripted.t1_unguarded.conversations.json").read_text(encoding="utf-8"))
        std = scripted_run.run("unguarded", "scripted.t2", "standard", url, Path(tmp), 1, True)
    server.shutdown()

    results.append(check("smoke runs two attack conversations and one control", len(records) == 3))
    results.append(check("each turn sends the whole conversation so far (1, 3, 5, 7 messages for the 4-turn one)",
                         seen[:4] == [1, 3, 5, 7]))
    results.append(check("the fake leak on turn 3 is scored as a success", result["attempted"] == 2 and result["tool_flagged"] == 2))
    results.append(check("the note says on which turn it first worked", any("earliest on turn 3 of 4" in n for n in result["notes"])))
    results.append(check("the control conversation is reported as refused", any("refused turn: 1/1" in n for n in result["notes"])))
    results.append(check("the poisoned-document conversation is skipped on clean documents",
                         any("skipped" in n and "M8" in n for n in std["notes"])))
    results.append(check("'count: last' only scores the final reply (M5 and M6 do not succeed on a fake that leaks the secret)",
                         not any(n.startswith(("M5", "M6")) and " 0/" not in n for n in std["notes"])))
    last = {"goal": "marker", "markers": ["PWNED-7731"], "count": "last"}
    anyturn = {"goal": "marker", "markers": ["PWNED-7731"]}
    results.append(check("count 'last' ignores a marker on an earlier turn", scripted_run.succeeded_at(last, ["OK PWNED-7731", "normal answer"]) is None))
    results.append(check("count 'last' scores the final turn", scripted_run.succeeded_at(last, ["OK", "PWNED-7731"]) == 2))
    results.append(check("the default scores the earliest turn", scripted_run.succeeded_at(anyturn, ["OK pwned-7731", "PWNED-7731"]) == 1))
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
