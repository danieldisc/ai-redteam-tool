"""Garak, barebones.

Garak's normal attacks are a fixed menu, so they cannot use grey knowledge. Only its multi-turn GOAT probe takes a goal.

    pip install garak==0.17.0        (large: it pulls in PyTorch)
    python demo/garak_demo.py                 # grey: GOAT, Claude as attacker. Start the adapter with --history replay
    python demo/garak_demo.py --mode static   # control: a fixed built-in attack, no knowledge at all
"""
import json
import os
import subprocess
import sys
from pathlib import Path

pack = json.loads(Path(__file__).with_name("grey.json").read_text(encoding="utf-8"))
adapter = os.environ.get("DEMO_ADAPTER", "http://127.0.0.1:8000")
mode = sys.argv[sys.argv.index("--mode") + 1] if "--mode" in sys.argv else "goat"
out = Path(__file__).parent / "logs" / "garak"
out.mkdir(parents=True, exist_ok=True)

# Where the chatbot is: the same small file the main runner writes.
generator = out / "generator.json"
generator.write_text(json.dumps({"openai": {"OpenAICompatible": {"uri": adapter + "/garak.demo/v1/"}}}), encoding="utf-8")
command = [sys.executable, "-m", "garak", "--target_type", "openai.OpenAICompatible", "--target_name", pack["persona"]["model"],
           "--generator_option_file", str(generator), "--report_prefix", str(out / "demo"), "--generations", "1"]

if mode == "static":
    command += ["--probes", "dan.DanInTheWild"]
else:
    # Grey knowledge enters here: one goal per objective, and Claude as the attacker model.
    goat = out / "goat.json"
    goat.write_text(json.dumps({"goat": {"GOATAttack": {
        "custom_goals": [pack["chatbot"] + " " + o["goal"] for o in pack["objectives"]],
        "red_team_model_type": "anthropic.AnthropicGenerator",
        "red_team_model_name": "claude-sonnet-5-5",
        "max_calls_per_conv": 3}}}), encoding="utf-8")
    # A plain text-match detector, so Garak makes no call to an AI judge. Our adapter's judge decides anyway.
    command += ["--probe_option_file", str(goat), "--probes", "goat.GOATAttack", "--detectors", "mitigation.MitigationBypass"]

subprocess.run(command, env={**os.environ, "OPENAICOMPATIBLE_API_KEY": "not-needed"}, check=False)
