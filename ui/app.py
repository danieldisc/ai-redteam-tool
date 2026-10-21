"""
A local web page for running the attack tools and reading the results.

    python ui/app.py                                   # then open http://127.0.0.1:8080
    python ui/app.py --port 8090 --target-url http://127.0.0.1:8000

Start the target server yourself first (python target/server.py). On the page you tick tools and
guardrails, pick a tier, and queue the runs. Jobs run one at a time, because the target answers one
request at once. Each job is its own `python run.py <tool> --target <guardrail> ...` process, so
PyRIT still uses its own environment, and a job that crashes does not stop the others.

All jobs queued together share one run label, so every guardrail gets the same attacks (Promptfoo
reuses the test cases it generated for the first one). The page only listens on 127.0.0.1 and has no
login: do not expose it. It uses nothing but the standard library.
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
UI_DIR = Path(__file__).resolve().parent
RESULTS_RAW = ROOT / "results" / "raw"

TOOLS = ["baseline", "scripted", "garak", "giskard", "inspect", "pyrit", "promptfoo"]
TIERS = ["smoke", "standard", "full"]
KNOWN_GUARDRAILS = [{"id": "unguarded"}, {"id": "guarded"}]  # for a server that predates /health listing them
NAME = re.compile(r"^[a-z0-9_-]{1,30}$")
LABEL = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
FINISHED = ("done", "failed", "cancelled", "interrupted")

# Rough requests to the target per guardrail, from earlier runs. None means "a lot, not measured".
REQUEST_HINTS = {
    "baseline": {"smoke": 27, "standard": 81, "full": 135},
    "scripted": {"smoke": 10, "standard": 72, "full": 120},
    "garak": {"smoke": 36, "standard": 1740, "full": None},
    "giskard": {"smoke": 7, "standard": 99, "full": 165},
    "inspect": {"smoke": 8, "standard": 117, "full": 195},
    "pyrit": {"smoke": 8, "standard": 74, "full": None},
    "promptfoo": {"smoke": 4, "standard": 340, "full": None},
}


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def kill_tree(proc: subprocess.Popen) -> None:
    """Stop a job and everything it started (Garak and Promptfoo start their own processes)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


class JobQueue:
    """Runs jobs one at a time in a background thread. State is kept in jobs.json so a restart keeps history."""

    def __init__(self, state_dir: Path, build_command):
        self.state_dir = state_dir
        self.log_dir = state_dir / "jobs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.build_command = build_command
        self.cond = threading.Condition()
        self.current: subprocess.Popen | None = None
        self.current_id: int | None = None
        self.jobs = self._load()
        threading.Thread(target=self._worker, daemon=True).start()

    # ---- state ---------------------------------------------------------------------------
    def _load(self) -> list[dict]:
        path = self.state_dir / "jobs.json"
        if not path.exists():
            return []
        try:
            jobs = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        for job in jobs:
            if job["status"] in ("queued", "running"):
                job["status"] = "interrupted"
        return jobs

    def _save(self) -> None:
        tmp = self.state_dir / "jobs.json.tmp"
        tmp.write_text(json.dumps(self.jobs, indent=1), encoding="utf-8")
        os.replace(tmp, self.state_dir / "jobs.json")

    def log_path(self, job_id: int) -> Path:
        return self.log_dir / f"{job_id}.log"

    # ---- public --------------------------------------------------------------------------
    def add(self, tool: str, target: str, tier: str, label: str) -> dict:
        with self.cond:
            job = {"id": max((j["id"] for j in self.jobs), default=0) + 1, "tool": tool, "target": target,
                   "tier": tier, "label": label, "status": "queued", "created": now(), "started": None,
                   "finished": None, "returncode": None, "result": None}
            self.jobs.append(job)
            self._save()
            self.cond.notify_all()
            return job

    def snapshot(self) -> dict:
        with self.cond:
            return {"jobs": [dict(j) for j in self.jobs], "running": self.current_id}

    def cancel(self, job_id: int) -> bool:
        with self.cond:
            job = next((j for j in self.jobs if j["id"] == job_id), None)
            if job is None:
                return False
            if job["status"] == "queued":
                job["status"], job["finished"] = "cancelled", now()
                self._save()
                return True
            if job["status"] == "running":
                # The process may not exist yet (a job is marked running a moment before it starts, and
                # starting is slower on Windows): remember the request and _run applies it on start.
                job["cancel"] = True
                if self.current is not None and self.current_id == job_id:
                    kill_tree(self.current)
                return True
            return False

    def clear_finished(self) -> int:
        with self.cond:
            before = len(self.jobs)
            self.jobs = [j for j in self.jobs if j["status"] not in FINISHED]
            self._save()
            return before - len(self.jobs)

    def read_log(self, job_id: int, offset: int) -> tuple[str, int]:
        path = self.log_path(job_id)
        if not path.exists():
            return "", offset
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(200_000)
        return data.decode("utf-8", errors="replace"), offset + len(data)

    def shutdown(self) -> None:
        with self.cond:
            for job in self.jobs:
                if job["status"] == "queued":
                    job["status"] = "cancelled"
            if self.current is not None:
                kill_tree(self.current)
            self._save()

    # ---- worker --------------------------------------------------------------------------
    def _worker(self) -> None:
        while True:
            with self.cond:
                job = None
                while job is None:
                    job = next((j for j in self.jobs if j["status"] == "queued"), None)
                    if job is None:
                        self.cond.wait()
                job["status"], job["started"] = "running", now()
                self._save()
            self._run(job)

    def _run(self, job: dict) -> None:
        cmd = self.build_command(job)
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        kwargs = {} if os.name == "nt" else {"start_new_session": True}
        code, error = None, None
        with open(self.log_path(job["id"]), "wb") as log:
            log.write(("$ " + " ".join(cmd) + "\n\n").encode("utf-8"))
            log.flush()
            with self.cond:
                cancelled_early = bool(job.get("cancel"))
            if cancelled_early:
                error = "cancelled before it started"
            else:
                try:
                    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, env=env, **kwargs)
                except OSError as exc:
                    error = f"could not start: {exc}"
                else:
                    with self.cond:
                        self.current, self.current_id = proc, job["id"]
                        if job.get("cancel"):  # cancel arrived while the process was starting
                            kill_tree(proc)
                    code = proc.wait()
        with self.cond:
            self.current, self.current_id = None, None
            job["returncode"], job["finished"] = code, now()
            if job.pop("cancel", False):
                job["status"] = "cancelled"
            else:
                job["status"] = "done" if code == 0 else "failed"
            job["result"] = error or self._result_line(job["id"])
            self._save()

    def _result_line(self, job_id: int) -> str | None:
        """'flagged/attempted' from the line run.py prints at the end of a run."""
        try:
            text = self.log_path(job_id).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        found = re.findall(r"attempted (\d+), flagged by the tool itself (\d+)", text)
        return f"{found[-1][1]}/{found[-1][0]} flagged" if found else None


class App:
    def __init__(self, target_url: str, port: int, state_dir: Path = RESULTS_RAW / "ui",
                 results_raw: Path = RESULTS_RAW, build_command=None):
        self.target_url = target_url.rstrip("/")
        self.results_raw = results_raw
        self.allowed_hosts: set[str] = set()
        self.set_port(port)
        self.queue = JobQueue(state_dir, build_command or self._run_command)

    def set_port(self, port: int) -> None:
        self.allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    def _run_command(self, job: dict) -> list[str]:
        return [sys.executable, str(ROOT / "run.py"), job["tool"], "--target", job["target"], "--tier", job["tier"],
                "--run", job["label"], "--yes", "--url", self.target_url]

    # ---- target --------------------------------------------------------------------------
    def status(self) -> dict:
        try:
            with urllib.request.urlopen(f"{self.target_url}/health", timeout=3) as r:
                data = json.load(r)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return {"reachable": False, "url": self.target_url, "error": str(exc), "guardrails": []}
        return {"reachable": True, "url": self.target_url, "stub": bool(data.get("stub")), "docs": data.get("docs"),
                "guardrails": data.get("guardrails") or KNOWN_GUARDRAILS}

    def options(self) -> dict:
        return {"tools": TOOLS, "tiers": TIERS, "hints": REQUEST_HINTS}

    # ---- jobs ----------------------------------------------------------------------------
    def create_jobs(self, body: dict) -> tuple[dict, int]:
        tools, targets = body.get("tools") or [], body.get("guardrails") or []
        tier, label = body.get("tier"), (body.get("label") or "").strip()
        label = label or "ui" + datetime.now().strftime("%m%d-%H%M%S")
        if not tools or not targets:
            return {"error": "pick at least one tool and one guardrail"}, 400
        if any(t not in TOOLS for t in tools):
            return {"error": f"unknown tool in {tools}"}, 400
        if tier not in TIERS:
            return {"error": f"tier must be one of {TIERS}"}, 400
        if not LABEL.match(label):
            return {"error": "label may only use letters, digits, - and _ (40 characters at most)"}, 400
        if any(not isinstance(t, str) or not NAME.match(t) for t in targets):
            return {"error": "bad guardrail name"}, 400
        status = self.status()
        if not status["reachable"]:
            return {"error": f"the target is not reachable at {self.target_url}. Start python target/server.py first."}, 409
        offered = {g["id"] for g in status["guardrails"]}
        if any(t not in offered for t in targets):
            return {"error": f"the target offers {sorted(offered)}"}, 400

        existing = {(j["tool"], j["target"], j["label"]) for j in self.queue.snapshot()["jobs"]
                    if j["status"] in ("queued", "running")}
        created, skipped = [], []
        for tool in TOOLS:
            if tool not in tools:
                continue
            for target in targets:
                tag = f"{tool}.{label}"
                if (tool, target, label) in existing:
                    skipped.append(f"{tool} on {target}: already queued with this label")
                elif (self.results_raw / tool / f"{tag}_{target}.summary.json").exists():
                    skipped.append(f"{tool} on {target}: label {label} was already run (pick a new label)")
                else:
                    created.append(self.queue.add(tool, target, tier, label))
        return {"created": created, "skipped": skipped, "label": label}, 200

    # ---- reports -------------------------------------------------------------------------
    def report(self, kind: str, include_stub: bool) -> str:
        script = {"summary": "analyse.py", "compare": "compare.py"}[kind]
        cmd = [sys.executable, str(ROOT / "report" / script)] + (["--include-stub"] if include_stub else [])
        done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=120)
        return done.stdout + (("\n" + done.stderr) if done.returncode else "")


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RedTeamUI"

        def log_message(self, *args):
            pass

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, body: dict, code: int = 200) -> None:
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
            if url.path in ("/", "/index.html"):
                self._send(200, (UI_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
            elif url.path == "/api/options":
                self._json(app.options())
            elif url.path == "/api/status":
                self._json(app.status())
            elif url.path == "/api/jobs":
                self._json(app.queue.snapshot())
            elif (m := re.fullmatch(r"/api/jobs/(\d+)/log", url.path)):
                offset = int((parse_qs(url.query).get("offset") or ["0"])[0] or 0)
                text, nxt = app.queue.read_log(int(m.group(1)), max(offset, 0))
                self._json({"text": text, "next": nxt})
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
            path = urlparse(self.path).path
            if path == "/api/jobs":
                result, code = app.create_jobs(body)
                self._json(result, code)
            elif path == "/api/jobs/clear":
                self._json({"removed": app.queue.clear_finished()})
            elif (m := re.fullmatch(r"/api/jobs/(\d+)/cancel", path)):
                ok = app.queue.cancel(int(m.group(1)))
                self._json({"cancelled": ok}, 200 if ok else 409)
            elif path == "/api/report":
                kind = body.get("kind")
                if kind not in ("summary", "compare"):
                    return self._json({"error": "kind must be summary or compare"}, 400)
                self._json({"text": app.report(kind, bool(body.get("include_stub")))})
            else:
                self._json({"error": "not found"}, 404)

    return Handler


def make_server(app: App, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    app.set_port(server.server_port)
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--target-url", default="http://127.0.0.1:8000", help="the target server (default %(default)s)")
    args = parser.parse_args()
    app = App(args.target_url, args.port)
    try:
        server = make_server(app, args.port)
    except OSError as exc:
        sys.exit(f"Cannot listen on port {args.port} ({exc}). Try --port {args.port + 1}.")
    print(f"Red team bench on http://127.0.0.1:{server.server_port}  (target {app.target_url}). Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.queue.shutdown()


if __name__ == "__main__":
    main()
