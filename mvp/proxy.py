"""A logging pass-through for any OpenAI-style chatbot. The five tools talk to this; it forwards each request to the real address
and writes one JSON line per request, in the same shape for every tool, to <log dir>/<tool>.jsonl.

    python mvp/proxy.py --address http://host:port/v1 --port 8100        (general_run.py starts it for you)

A tool's address is  http://127.0.0.1:<port>/<tool>.<label>/v1  (the same form the Guardrail Bench adapter uses). The whole conversation is
forwarded as the tool sent it, so multi-turn attacks keep their context. One request goes through at a time.
"""
import argparse
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


class Proxy:
    def __init__(self, address, model, log_dir, api_key=None, timeout=300.0):
        self.address, self.model, self.log_dir = address.rstrip("/"), model, Path(log_dir)
        self.api_key, self.timeout = api_key, timeout
        self.lock = threading.Lock()
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def forward(self, body: dict):
        """Returns (status, json body or None, error text)."""
        data = json.dumps({**body, "model": self.model, "stream": False}).encode()
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = "Bearer " + self.api_key
        request = urllib.request.Request(self.address + "/chat/completions", data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.load(response), ""
        except urllib.error.HTTPError as exc:
            return exc.code, None, exc.read()[:300].decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return 0, None, str(exc)

    def handle_chat(self, tag: str, body: dict):
        """Returns (status, response body). Logs the request either way."""
        messages = [{"role": m.get("role", ""), "content": text_of(m.get("content"))} for m in body.get("messages", [])]
        last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        started = time.perf_counter()
        with self.lock:
            status, reply_body, error = self.forward(body)
        reply = ""
        if reply_body:
            try:
                reply = text_of(reply_body["choices"][0]["message"]["content"])
            except (KeyError, IndexError, TypeError):
                error = error or "the reply had no choices[0].message.content"
        outcome = "replied" if status == 200 and not error else ("app_unavailable" if status in (0, 502, 503, 504) else f"http_{status}")
        record = {"ts": datetime.now().isoformat(timespec="seconds"), "tag": tag, "tool": tag.split(".", 1)[0], "model": self.model,
                  "chat_as": "none", "case": None, "history_mode": "full", "replayed_turns": len(messages), "message": last_user,
                  "conversation": messages, "conversation_id": "req-" + uuid.uuid4().hex[:12], "outcome": outcome, "reply": reply,
                  "tool_calls": [], "flags": {}, "latency_s": round(time.perf_counter() - started, 2)}
        if error:
            record["error"] = error
        with open(self.log_dir / f"{record['tool']}.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        if outcome != "replied":
            return 502, {"error": {"message": f"the chatbot did not answer: {error or status}"}}
        return 200, reply_body


def make_handler(proxy: Proxy):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send_json(self, code, body):
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if re.fullmatch(r"/[^/]+/v1/models", self.path):
                return self.send_json(200, {"object": "list", "data": [{"id": proxy.model, "object": "model", "owned_by": "target"}]})
            self.send_json(404, {"error": {"message": "not found"}})

        def do_POST(self):
            m = re.fullmatch(r"/([^/]+)/v1/chat/completions", self.path)
            if not m:
                return self.send_json(404, {"error": {"message": "not found"}})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            except ValueError:
                return self.send_json(400, {"error": {"message": "the body is not JSON"}})
            self.send_json(*proxy.handle_chat(m.group(1), body))

    return Handler


def serve(proxy: Proxy, port: int, host="127.0.0.1"):
    """Starts the proxy in a background thread. Returns the server; call .shutdown() to stop it."""
    server = ThreadingHTTPServer((host, port), make_handler(proxy))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--api-key-env", default=None, help="name of the environment variable that holds the chatbot's key")
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--log-dir", default="results_adapter")
    args = ap.parse_args()
    serve(Proxy(args.address, args.model, args.log_dir, os.environ.get(args.api_key_env) if args.api_key_env else None), args.port)
    print(f"proxy ready on http://127.0.0.1:{args.port}  ->  {args.address}   logs: {args.log_dir}   stop with Ctrl+C")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
