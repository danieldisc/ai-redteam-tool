"""The combined tool, first version: one queue, one job at a time, first in first out.

    python mvp/queue_run.py --data /path/to/benchproject/data                 # every brief, all five tools
    python mvp/queue_run.py --data ... --only inspect pyrit --threats THR-012 # a smaller run

Why one at a time: the chatbot answers one turn at a time across the whole app, and the adapter takes a lock, so running
tools together only adds waiting and timeouts. A job is one tool on one brief. A job that fails is recorded and the queue
carries on; a runner may also return "skipped". Start the chatbot and the adapter first (see README.md). Each tool may live in its own virtual environment:
set DEMO_PYTHON_<TOOL> to that environment's Python. Requests reach the adapter as <tool>.<brief id>, so the adapter log
says which brief each request belongs to. Afterwards:  python mvp/results.py
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_builder  # noqa: E402

ORDER = ["inspect", "giskard", "pyrit", "promptfoo", "garak"]


def make_jobs(briefs: list, tools: list) -> list:
    """Queue order: all tools on the first brief, then all tools on the next, and so on."""
    return [{"tool": t, "brief": b["brief_id"], "status": "queued", "seconds": None, "exit": None} for b in briefs for t in tools]


def write_status(path: Path, jobs: list) -> None:
    path.write_text(json.dumps({"updated": time.strftime("%Y-%m-%dT%H:%M:%S"), "jobs": jobs}, indent=1), encoding="utf-8")


def default_runner(job, pack, env):
    """Runs the tool's demo Python file in its own environment (DEMO_PYTHON_<TOOL>) and returns its exit code."""
    python = os.environ.get(f"DEMO_PYTHON_{job['tool'].upper()}", sys.executable)
    return subprocess.run([python, str(HERE.parent / "demo" / f"{job['tool']}_demo.py")], env=env).returncode


def run_queue(briefs: list, tools: list, workdir: Path, runner=None) -> list:
    """Runs the jobs in order. runner(job, pack_path, env) returns an exit code; the default launches the demo script."""
    workdir.mkdir(parents=True, exist_ok=True)
    packs = {}
    for b in briefs:
        packs[b["brief_id"]] = workdir / f"{b['brief_id']}.pack.json"
        packs[b["brief_id"]].write_text(json.dumps(b, ensure_ascii=False, indent=1), encoding="utf-8")
    jobs = make_jobs(briefs, tools)
    status = workdir / "status.json"

    runner = runner or default_runner
    for job in jobs:
        job["status"] = "running"
        write_status(status, jobs)
        env = dict(os.environ, DEMO_PACK=str(packs[job["brief"]]), DEMO_LABEL=job["brief"])
        started = time.time()
        try:
            job["exit"] = runner(job, packs[job["brief"]], env)
        except Exception as error:  # a broken tool must not stop the queue
            job["exit"], job["error"] = -1, str(error)
        job["seconds"] = round(time.time() - started)
        job["status"] = "done" if job["exit"] == 0 else "skipped" if job["exit"] == "skipped" else "failed"
        write_status(status, jobs)
        print(f"{job['tool']:<10} {job['brief']:<40} {job['status']:<7} {job['seconds']} s", flush=True)
    return jobs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="the benchproject data folder")
    ap.add_argument("--persona", default="OWN-007")
    ap.add_argument("--threats", nargs="*")
    ap.add_argument("--only", nargs="*", choices=ORDER, help="run only these tools")
    ap.add_argument("--workdir", default=str(HERE / "run"))
    args = ap.parse_args()
    briefs = case_builder.build(Path(args.data), args.persona, args.threats)
    jobs = run_queue(briefs, args.only or ORDER, Path(args.workdir))
    failed = [j for j in jobs if j["status"] == "failed"]
    print(f"\n{len(jobs) - len(failed)} of {len(jobs)} jobs finished. Next:  python mvp/results.py")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
