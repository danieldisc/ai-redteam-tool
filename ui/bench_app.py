"""The bench page: run the red-teaming tools against the Guardrail Bench chatbot and compare how well each one does.

    python ui/bench_app.py                 # then open http://127.0.0.1:8081

Start the chatbot first (see its own README). On the page you start the adapter, pick tools and a
size, run them, review the requests, and compare the tools. Standard library only. The page listens on 127.0.0.1 only and
has no login: do not expose it.

What the page can start, and nothing else:
  * the adapter (tools/bench_adapter.py), with a chosen person to chat as
  * a tool from a fixed list, through run.py, at a chosen size
  * a case file from a fixed list, through tools/bench_send.py
Names, personas, labels and case files are checked against fixed lists or patterns; the browser never sends a command or a path.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(UI_DIR))
sys.path.insert(0, str(ROOT / "tools"))

import bench_adapter as judge  # noqa: E402  (tools/: the persona pattern and the checks' local file)
import bench_data as bd  # noqa: E402
from jobqueue import FINISHED, JobQueue, kill_tree  # noqa: E402

TOOLS = ["garak", "inspect", "pyrit", "promptfoo", "giskard", "baseline", "scripted", "library"]
MAIN_TOOLS = ["garak", "inspect", "pyrit", "promptfoo", "giskard"]
TIERS = ["smoke", "standard", "full"]
# Prompts a tool sends at each size, from earlier runs. None means "a lot, not measured".
REQUEST_HINTS = {
    "baseline": {"smoke": 27, "standard": 81, "full": 135},
    "scripted": {"smoke": 10, "standard": 72, "full": 120},
    "garak": {"smoke": 36, "standard": 1740, "full": None},
    "giskard": {"smoke": 7, "standard": 99, "full": 165},
    "inspect": {"smoke": 8, "standard": 117, "full": 195},
    "pyrit": {"smoke": 8, "standard": 74, "full": None},
    "promptfoo": {"smoke": 4, "standard": 340, "full": None},
    "library": {"smoke": 6, "standard": 210, "full": 525},
}
SECONDS_PER_REQUEST = {"default": 15, "pyrit": 27}   # median reply times seen on the reference machine
NOTES = {
    "promptfoo": "Uses a second local model (llama3.1:8b) to write and grade attacks. On a small GPU it can push the chatbot's "
                 "models out of memory and make everything slow.",
    "giskard": "Uses a second local model (llama3.1:8b) to write and judge tests. On a small GPU it can push the chatbot's "
               "models out of memory and make everything slow.",
    "pyrit": "The multi-turn attacks (standard size and above) also use a second local model. Smoke size does not.",
    "garak": "Downloads some detector models from the internet the first time.",
}
LABEL = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
CASE_ID = re.compile(r"^[A-Za-z0-9_./-]{1,120}$")


def _get(url: str, timeout: float = 3.0):
    """(True, parsed JSON) or (False, error text)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return True, json.loads(response.read() or b"null")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, str(exc)


class BenchApp:
    def __init__(self, app_url: str, adapter_url: str, port: int, log_dir: Path, cases_dirs=(), extra_cases=None,
                 state_dir: Path | None = None, build_command=None, adapter_command=None, summaries_dir: Path | None = None,
                 local_config: Path | None = None):
        self.app_url = app_url.rstrip("/")
        self.adapter_url = adapter_url.rstrip("/")
        self.adapter_port = int(self.adapter_url.rsplit(":", 1)[-1])
        self.log_dir = Path(log_dir)
        self.reviews_path = self.log_dir / "reviews.json"
        self.case_runs_dir = self.log_dir.parent / "results_cases"
        self.cases_dirs = [Path(p) for p in cases_dirs]
        self.extra_cases = {k: Path(v) for k, v in (extra_cases or {}).items()}
        self.summaries_dir = Path(summaries_dir) if summaries_dir else ROOT / "results" / "raw"
        self.allowed_hosts: set[str] = set()
        self.set_port(port)
        self.adapter_proc: subprocess.Popen | None = None
        self.adapter_command = adapter_command
        self.local_config = Path(local_config) if local_config else None   # passed on to the adapter it starts
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.queue = JobQueue(state_dir or (self.log_dir / "ui"), build_command or self._build_command)

    def set_port(self, port: int) -> None:
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    # ---- case files ----------------------------------------------------------------------
    def case_files(self) -> dict[str, Path]:
        found = dict(self.extra_cases)
        for folder in self.cases_dirs:
            if folder.is_dir():
                for path in sorted(folder.glob("*.jsonl")):
                    if path.name in ("results.jsonl",) or path.parent == self.log_dir:
                        continue
                    found[f"{folder.name}/{path.stem}"] = path
        return found

    # ---- status --------------------------------------------------------------------------
    def status(self) -> dict:
        hints = []
        ok, launch = _get(f"{self.app_url}/launch")
        app = {"reachable": ok, "ready": False, "paused": None, "url": self.app_url}
        if not ok:
            hints.append("The chatbot is not running. Start it first (see its own README).")
        else:
            unfinished = [s["step_key"] for s in launch.get("steps", []) if s.get("state") != "done"]
            app["paused"] = launch.get("replies_paused_reason_key")
            app["unfinished"] = unfinished
            app["ready"] = not unfinished and not app["paused"]
            if app["paused"]:
                hints.append("Replies are paused. The usual cause is that Ollama updated itself: run ollama --version "
                             "(it must be the pinned version), then restart the chatbot.")
            elif unfinished:
                hints.append("The chatbot is still starting. Wait for its Chat page to open.")
        ok_a, health = _get(f"{self.adapter_url}/health")
        adapter = {"reachable": ok_a, "url": self.adapter_url,
                   "managed": bool(self.adapter_proc and self.adapter_proc.poll() is None)}
        if ok_a and isinstance(health, dict):
            adapter.update(health.get("adapter") or {})
        elif app["ready"]:
            hints.append("The adapter is not running. Start it below.")
        return {"app": app, "adapter": adapter, "ready": bool(app["ready"] and ok_a), "hints": hints}

    def personas(self) -> tuple[list | dict, int]:
        ok, data = _get(f"{self.app_url}/personas")
        if not ok:
            return {"error": f"the chatbot cannot be reached ({data})"}, 502
        return [{"owner_id": p.get("owner_id"), "name": p.get("name")} for p in data if isinstance(p, dict)], 200

    # ---- adapter -------------------------------------------------------------------------
    def start_adapter(self, body: dict) -> tuple[dict, int]:
        chat_as = body.get("chat_as") or "none"
        history = body.get("history") or "last"
        if not isinstance(chat_as, str) or not re.fullmatch(judge.PERSONA_PATTERN, chat_as):
            return {"error": 'chat_as must be "none" or a valid persona id'}, 400
        if history not in ("last", "replay"):
            return {"error": "history must be last or replay"}, 400
        status = self.status()
        if status["adapter"]["reachable"]:
            who = status["adapter"].get("chat_as", "?")
            return {"error": f"an adapter is already running (chatting as {who}). Stop it first to change that."}, 409
        if not status["app"]["ready"]:
            return {"error": "the chatbot is not ready. " + (status["hints"][0] if status["hints"] else "")}, 409
        cmd = self.adapter_command(chat_as, history) if self.adapter_command else [
            sys.executable, str(ROOT / "tools" / "bench_adapter.py"), "--port", str(self.adapter_port), "--app", self.app_url,
            "--chat-as", chat_as, "--history", history, "--log-dir", str(self.log_dir)]
        if self.local_config and not self.adapter_command:
            cmd += ["--local-config", str(self.local_config)]
        log_path = self.log_dir / "adapter.log"
        kwargs = {} if os.name == "nt" else {"start_new_session": True}
        with open(log_path, "wb") as log:
            try:
                self.adapter_proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                                     stdin=subprocess.DEVNULL, **kwargs)
            except OSError as exc:
                return {"error": f"could not start the adapter: {exc}"}, 500
        for _ in range(40):
            time.sleep(0.25)
            if self.adapter_proc.poll() is not None:
                tail = log_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
                return {"error": "the adapter stopped at once: " + " ".join(tail)}, 500
            if _get(f"{self.adapter_url}/health", 1.0)[0]:
                return {"started": True, "chat_as": chat_as, "history": history}, 200
        kill_tree(self.adapter_proc)
        return {"error": "the adapter did not answer within 10 seconds"}, 500

    def stop_adapter(self) -> tuple[dict, int]:
        if self.adapter_proc and self.adapter_proc.poll() is None:
            kill_tree(self.adapter_proc)
            try:
                self.adapter_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.adapter_proc.kill()
            return {"stopped": True}, 200
        if _get(f"{self.adapter_url}/health", 1.0)[0]:
            return {"error": "that adapter was started elsewhere (a terminal). Close it there."}, 409
        return {"stopped": False, "note": "no adapter was running"}, 200

    # ---- options and jobs ----------------------------------------------------------------
    def options(self) -> dict:
        tools = []
        for name in TOOLS:
            hints = REQUEST_HINTS.get(name, {})
            per = SECONDS_PER_REQUEST.get(name, SECONDS_PER_REQUEST["default"])
            tools.append({"id": name, "main": name in MAIN_TOOLS, "note": NOTES.get(name),
                          "requests": hints, "minutes": {t: (round(n * per / 60) if n else None) for t, n in hints.items()}})
        return {"tools": tools, "tiers": TIERS, "kinds": list(bd.KINDS), "verdicts": list(bd.VERDICTS),
                "cases": [{"id": k, "name": k.split("/")[-1].replace("_", " ")} for k in self.case_files()]}

    def _build_command(self, job: dict) -> list[str]:
        if job["kind"] == "cases":
            path = self.case_files()[job["name"]]
            return [sys.executable, str(ROOT / "tools" / "bench_send.py"), "--cases", str(path), "--out",
                    str(self.case_runs_dir / job["label"]), "--multi", "--trace", "--base", self.app_url]
        return [sys.executable, str(ROOT / "run.py"), job["name"], "--target", "unguarded", "--tier", job["tier"],
                "--run", job["label"], "--yes", "--url", self.adapter_url]

    def _queued(self) -> set[tuple[str, str]]:
        return {(j["name"], j["label"]) for j in self.queue.snapshot()["jobs"] if j["status"] in ("queued", "running")}

    def create_jobs(self, body: dict) -> tuple[dict, int]:
        tools = body.get("tools") or []
        tier = body.get("tier")
        label = (body.get("label") or "").strip() or "ui" + datetime.now().strftime("%m%d-%H%M%S")
        if not isinstance(tools, list) or not tools:
            return {"error": "pick at least one tool"}, 400
        if any(t not in TOOLS for t in tools):
            return {"error": f"unknown tool in {tools}"}, 400
        if tier not in TIERS:
            return {"error": f"tier must be one of {TIERS}"}, 400
        if not LABEL.match(label):
            return {"error": "label may only use letters, digits, - and _ (40 characters at most)"}, 400
        status = self.status()
        if not status["app"]["ready"]:
            return {"error": "the chatbot is not ready. " + (status["hints"][0] if status["hints"] else "")}, 409
        if not status["adapter"]["reachable"]:
            if not body.get("start_adapter"):
                return {"error": "the adapter is not running. Start it first."}, 409
            result, code = self.start_adapter({"chat_as": body.get("chat_as") or "none", "history": body.get("history") or "last"})
            if code != 200:
                return result, code
        created, skipped = [], []
        queued = self._queued()
        for tool in TOOLS:
            if tool not in tools:
                continue
            tag = f"{tool}.{label}"
            if (tool, label) in queued:
                skipped.append(f"{tool}: already queued with this label")
            elif (self.summaries_dir / tool / f"{tag}_unguarded.summary.json").exists():
                skipped.append(f"{tool}: label {label} was already run (pick a new label)")
            else:
                created.append(self.queue.add("tool", tool, tier, label))
        return {"created": created, "skipped": skipped, "label": label}, 200

    def run_cases(self, body: dict) -> tuple[dict, int]:
        case_id = body.get("case_file")
        label = (body.get("label") or "").strip() or "cases" + datetime.now().strftime("%m%d-%H%M%S")
        files = self.case_files()
        if not isinstance(case_id, str) or not CASE_ID.match(case_id) or case_id not in files:
            return {"error": "pick a case file from the list"}, 400
        if not LABEL.match(label):
            return {"error": "label may only use letters, digits, - and _ (40 characters at most)"}, 400
        if (self.case_runs_dir / label / "results.jsonl").exists() or (case_id, label) in self._queued():
            return {"error": f"label {label} was already used; pick a new one"}, 409
        status = self.status()
        if not status["app"]["ready"]:
            return {"error": "the chatbot is not ready. " + (status["hints"][0] if status["hints"] else "")}, 409
        return {"created": [self.queue.add("cases", case_id, None, label)], "label": label}, 200

    # ---- results -------------------------------------------------------------------------
    def records(self) -> list[dict]:
        records = bd.load_adapter_logs(self.log_dir)
        if self.case_runs_dir.is_dir():
            for path in sorted(self.case_runs_dir.glob("*/results.jsonl")):
                records += bd.load_case_results(path, label=path.parent.name)
        return records

    def summary(self) -> dict:
        return bd.summarise(self.records(), bd.load_reviews(self.reviews_path))

    def requests(self, query: dict) -> dict:
        def one(name):
            return (query.get(name) or [None])[0]
        try:
            limit, offset = int(one("limit") or 100), int(one("offset") or 0)
        except ValueError:
            limit, offset = 100, 0
        return bd.filter_requests(self.records(), bd.load_reviews(self.reviews_path), tool=one("tool"),
                                  state=one("state"), kind=one("kind"), text=one("q"), limit=limit, offset=offset)

    def review(self, body: dict) -> tuple[dict, int]:
        key = body.get("key")
        if not isinstance(key, str) or key not in {r["key"] for r in self.records()}:
            return {"error": "no such request"}, 404
        try:
            saved = bd.set_review(self.reviews_path, key, body.get("verdict"), body.get("kind") or "", body.get("note") or "")
        except ValueError as exc:
            return {"error": str(exc)}, 400
        return {"review": saved}, 200

    def clear_review(self, body: dict) -> tuple[dict, int]:
        key = body.get("key")
        if not isinstance(key, str):
            return {"error": "no such request"}, 404
        return {"cleared": bd.clear_review(self.reviews_path, key)}, 200

    def csv(self) -> str:
        return bd.to_csv(self.records(), bd.load_reviews(self.reviews_path))

    def shutdown(self) -> None:
        self.queue.shutdown()
        if self.adapter_proc and self.adapter_proc.poll() is None:
            kill_tree(self.adapter_proc)


def make_handler(app: BenchApp):
    class Handler(BaseHTTPRequestHandler):
        server_version = "BenchUI"

        def log_message(self, *args):
            pass

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, body, code: int = 200) -> None:
            self._send(code, json.dumps(body).encode("utf-8"), "application/json")

        def _allowed(self, post: bool) -> bool:
            """Refuse requests aimed at this page from another site or another host name."""
            if self.headers.get("Host", "") not in app.allowed_hosts:
                self._json({"error": "unexpected Host header"}, 403)
                return False
            if post:
                origin = self.headers.get("Origin")
                if origin and origin not in {f"http://{h}" for h in app.allowed_hosts}:
                    self._json({"error": "cross-site request refused"}, 403)
                    return False
                if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                    self._json({"error": "send application/json"}, 415)
                    return False
            return True

        def do_GET(self):
            if not self._allowed(post=False):
                return
            url = urlparse(self.path)
            query = parse_qs(url.query)
            if url.path in ("/", "/index.html"):
                page = UI_DIR / "bench.html"
                if page.exists():
                    self._send(200, page.read_bytes(), "text/html; charset=utf-8")
                else:
                    self._send(404, b"The page file ui/bench.html is not there yet.", "text/plain; charset=utf-8")
            elif url.path == "/api/status":
                self._json(app.status())
            elif url.path == "/api/options":
                self._json(app.options())
            elif url.path == "/api/personas":
                data, code = app.personas()
                self._json(data, code)
            elif url.path == "/api/jobs":
                self._json(app.queue.snapshot())
            elif (m := re.fullmatch(r"/api/jobs/(\d+)/log", url.path)):
                offset = int((query.get("offset") or ["0"])[0] or 0)
                text, nxt = app.queue.read_log(int(m.group(1)), max(offset, 0))
                self._json({"text": text, "next": nxt})
            elif url.path == "/api/bench/summary":
                self._json(app.summary())
            elif url.path == "/api/bench/requests":
                self._json(app.requests(query))
            elif url.path == "/api/bench/export.csv":
                self._send(200, app.csv().encode("utf-8-sig"), "text/csv; charset=utf-8",
                           {"Content-Disposition": 'attachment; filename="bench-results.csv"'})
            else:
                self._json({"error": "not found"}, 404)

        def do_POST(self):
            if not self._allowed(post=True):
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > 100_000:
                return self._json({"error": "request too large"}, 413)
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self._json({"error": "bad JSON"}, 400)
            if not isinstance(body, dict):
                return self._json({"error": "send a JSON object"}, 400)
            path = urlparse(self.path).path
            if path == "/api/adapter/start":
                result, code = app.start_adapter(body)
            elif path == "/api/adapter/stop":
                result, code = app.stop_adapter()
            elif path == "/api/jobs":
                result, code = app.create_jobs(body)
            elif path == "/api/cases/run":
                result, code = app.run_cases(body)
            elif path == "/api/jobs/clear":
                result, code = {"removed": app.queue.clear_finished()}, 200
            elif (m := re.fullmatch(r"/api/jobs/(\d+)/cancel", path)):
                ok = app.queue.cancel(int(m.group(1)))
                result, code = {"cancelled": ok}, (200 if ok else 409)
            elif path == "/api/bench/review":
                result, code = app.review(body)
            elif path == "/api/bench/review/clear":
                result, code = app.clear_review(body)
            else:
                result, code = {"error": "not found"}, 404
            self._json(result, code)

    return Handler


def make_server(app: BenchApp, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    app.set_port(server.server_port)
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--app-url", default="http://127.0.0.1:8766/api/v1", help="the chatbot's API (default %(default)s)")
    parser.add_argument("--adapter-url", default="http://127.0.0.1:8000", help="where the adapter listens (default %(default)s)")
    parser.add_argument("--log-dir", type=Path, default=ROOT / "results_adapter")
    parser.add_argument("--cases-dir", type=Path, action="append",
                        help="a folder of .jsonl case files to offer (repeatable; default: cases and tools)")
    parser.add_argument("--extra-cases", type=Path, action="append",
                        help="a .jsonl file of test cases to offer as well (repeatable)")
    args = parser.parse_args()
    extra = {f"extra/{p.stem}": p for p in (args.extra_cases or []) if p.exists()}
    app = BenchApp(args.app_url, args.adapter_url, args.port, args.log_dir,
                   cases_dirs=args.cases_dir or [ROOT / "cases", ROOT / "tools"], extra_cases=extra)
    try:
        server = make_server(app, args.port)
    except OSError as exc:
        sys.exit(f"Cannot listen on port {args.port} ({exc}). Try --port {args.port + 1}.")
    print(f"Bench page on http://127.0.0.1:{server.server_port}  (chatbot {app.app_url}, adapter {app.adapter_url}). Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.shutdown()


if __name__ == "__main__":
    main()
