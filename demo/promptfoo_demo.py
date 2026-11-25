"""Promptfoo, barebones. We give a description of the chatbot and one rule per objective; Claude writes the attacks.

Needs Node.js 20 or newer. No pip install of Promptfoo itself: it runs through npx.

    pip install pyyaml
    export ANTHROPIC_API_KEY=...   (PowerShell: $env:ANTHROPIC_API_KEY = "...")
    python demo/promptfoo_demo.py
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

pack = json.loads(Path(os.environ.get("DEMO_PACK") or Path(__file__).with_name("grey.json")).read_text(encoding="utf-8"))
adapter = os.environ.get("DEMO_ADAPTER", "http://127.0.0.1:8000")
out = Path(__file__).parent / "logs" / "promptfoo"
out.mkdir(parents=True, exist_ok=True)
if not os.environ.get("ANTHROPIC_API_KEY"):
    sys.exit("ANTHROPIC_API_KEY is not set: Claude writes and marks the attacks.")

PROMPTFOO = ["npx", "--yes", "promptfoo@0.124.0"]
env = {**os.environ, "PROMPTFOO_DISABLE_REMOTE_GENERATION": "true", "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "true",
       "PROMPTFOO_DISABLE_TELEMETRY": "1", "PROMPTFOO_DISABLE_UPDATE": "1"}
if not shutil.which("npx") and not shutil.which("npx.cmd"):
    sys.exit("npx not found. Install Node.js 20 or newer.")
npx = shutil.which("npx") or shutil.which("npx.cmd")

target = {"id": "openai:chat:" + pack["persona"]["model"], "label": pack["persona"]["model"],
          "config": {"apiBaseUrl": adapter + "/promptfoo." + os.environ.get("DEMO_LABEL", "demo") + "/v1", "apiKey": "not-needed", "max_tokens": 150}}
config = {
    "targets": [target],
    "prompts": ["{{prompt}}"],
    "redteam": {
        "purpose": pack["chatbot"] + " The person using it is signed in as: " + pack["persona"]["who"],
        "provider": "anthropic:messages:claude-sonnet-5-5",
        "numTests": 3,
        "plugins": [{"id": "policy", "numTests": 3, "config": {"policy": o["policy"]}} for o in pack["objectives"]],
        "strategies": [],
    },
}
config_path, tests_path, eval_path, results_path = (out / n for n in ("config.yaml", "tests.yaml", "eval.yaml", "results.json"))
config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

# Step 1: Claude writes the attack messages.
subprocess.run([npx, "--yes", "promptfoo@0.124.0", "redteam", "generate", "-c", str(config_path), "-o", str(tests_path),
                "--no-cache", "--force"], env=env, cwd=out, check=True)
# Step 2: send them to the chatbot one at a time, and let Claude mark the replies.
tests = yaml.safe_load(tests_path.read_text(encoding="utf-8"))
tests.pop("providers", None)
tests["targets"] = [target]
eval_path.write_text(yaml.safe_dump(tests, sort_keys=False), encoding="utf-8")
subprocess.run([npx, "--yes", "promptfoo@0.124.0", "eval", "-c", str(eval_path), "-o", str(results_path), "-j", "1",
                "--no-cache", "--grader", "anthropic:messages:claude-sonnet-5-5", "--no-progress-bar"], env=env, cwd=out)
print("Promptfoo results:", results_path)
