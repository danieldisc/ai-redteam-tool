"""Inspect AI, barebones. We write the attack messages (from grey.json); Inspect sends them and keeps a log.

    pip install inspect-ai==0.3.276 agent-client-protocol==0.12.1 "openai>=3.1.0"   (use a venv just for Inspect)
    python demo/inspect_demo.py
"""
import json
import os
from pathlib import Path

from inspect_ai import Task, eval
from inspect_ai.dataset import Sample
from inspect_ai.scorer import includes
from inspect_ai.solver import generate

pack = json.loads(Path(os.environ.get("DEMO_PACK") or Path(__file__).with_name("grey.json")).read_text(encoding="utf-8"))
adapter = os.environ.get("DEMO_ADAPTER", "http://127.0.0.1:8000")
os.environ.setdefault("BENCH_API_KEY", "not-needed")  # the adapter ignores the key; Inspect wants one

samples = [Sample(id=o["id"], input=o["attack_message"], target=pack["judge_only"][o["id"]]["success_text"]) for o in pack["objectives"]]
task = Task(dataset=samples, solver=[generate()], scorer=includes())  # includes() is a rough text match; the adapter's flag is the verdict

eval(task, model="openai-api/bench/" + pack["persona"]["model"], model_base_url=adapter + "/inspect." + os.environ.get("DEMO_LABEL", "demo") + "/v1",
     log_dir=str(Path(__file__).parent / "logs" / "inspect"), display="plain")
