"""Runs jobs one at a time in a background thread, with live logs, cancel and a history that survives a restart.

Standard library only. Used by the bench page (ui/bench_app.py). It is the same idea as the queue in ui/app.py, with two
changes: a job has a kind ("tool" or "cases") and a name, and the result line is read from either kind of job's output.
When ui/app.py is retired it can import this instead of keeping its own copy.
"""

import json
import os
import re
import signal
import subprocess
import threading
from datetime import datetime
from pathlib import Path

FINISHED = ("done", "failed", "cancelled", "interrupted")


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def kill_tree(proc: subprocess.Popen) -> None:
    """Stop a process and everything it started (Garak and Promptfoo start their own processes)."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass


class JobQueue:
    def __init__(self, state_dir: Path, build_command):
        self.state_dir = Path(state_dir)
        self.log_dir = self.state_dir / "jobs"
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
    def add(self, kind: str, name: str, tier: str | None, label: str, extra: dict | None = None) -> dict:
        with self.cond:
            job = {"id": max((j["id"] for j in self.jobs), default=0) + 1, "kind": kind, "name": name, "tier": tier,
                   "label": label, "status": "queued", "created": now(), "started": None, "finished": None,
                   "returncode": None, "result": None, "extra": extra or {}}
            self.jobs.append(job)
            self._save()
            self.cond.notify_all()
            return dict(job)

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
                # The process may not exist yet (starting is slower on Windows): remember the request and _run applies it.
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
            log.write(("$ " + " ".join(str(c) for c in cmd) + "\n\n").encode("utf-8"))
            log.flush()
            with self.cond:
                cancelled_early = bool(job.get("cancel"))
            if cancelled_early:
                error = "cancelled before it started"
            else:
                try:
                    proc = subprocess.Popen(cmd, cwd=Path(__file__).resolve().parent.parent, stdout=log,
                                            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env, **kwargs)
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
        """A short result from the job's output: the prompts a tool sent, or where a case run saved its results."""
        try:
            text = self.log_path(job_id).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        sent = re.findall(r"attempted (\d+)", text)
        if sent:
            return f"{sent[-1]} prompts sent"
        saved = re.findall(r"saved to .*results\.jsonl", text)
        if saved:
            return "results saved"
        return None
