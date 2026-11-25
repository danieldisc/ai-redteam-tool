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

def messages_of(o):
    """One message (a brief with an attack_message) or several (general mode: the attacks Promptfoo wrote)."""
    return o.get("attack_messages") or ([o["attack_message"]] if o.get("attack_message") else [])


judged = pack["judge_only"]  # general mode has no marker text, so there is no scorer: a judge reads the replies afterwards
samples = [Sample(id=f"{o['id']}-{i}", input=m, target=judged.get(o["id"], {}).get("success_text") or "")
           for o in pack["objectives"] for i, m in enumerate(messages_of(o), 1)]
if not samples:
    raise SystemExit("no attack messages in the pack")
has_markers = all(o["id"] in judged for o in pack["objectives"])
task = Task(dataset=samples, solver=[generate()], scorer=includes() if has_markers else None)  # includes() is a rough text match; the verdict is elsewhere

eval(task, model="openai-api/bench/" + pack["persona"]["model"], model_base_url=adapter + "/inspect." + os.environ.get("DEMO_LABEL", "demo") + "/v1",
     log_dir=str(Path(__file__).parent / "logs" / "inspect"), display="plain")
