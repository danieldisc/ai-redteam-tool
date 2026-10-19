"""
PyRIT against the target. PyRIT lives in its own environment (it needs a newer
`datasets` package than Garak allows), so this starts tools/pyrit_attacks.py with
that environment's Python and reads back its result file.

The PyRIT Python is taken from, in order:
    the PYRIT_PYTHON environment variable
    venv-pyrit/Scripts/python.exe  (Windows)  or  venv-pyrit/bin/python

tool_flagged = attacks PyRIT's own scorer counted as achieved (deterministic
substring: the secret or the injection marker). Errored attacks (for example an
attacker model that returns invalid JSON) are counted and left out of both numbers.
"""

import json
import os
import subprocess
from pathlib import Path

from common import ROOT, base_url, confirm, model_for, summary

# Rough request counts to the TARGET (single-turn only; multi-turn varies with the attacker).
ESTIMATE = {"smoke": 2 * (1 + 3), "standard": 5 * (1 + 8) + 5 + 3 * 2 * 3, "full": 5 * (1 + 18) + 5 + 5 * 2 * 5}


def pyrit_python() -> str:
    env = os.environ.get("PYRIT_PYTHON")
    if env:
        return env
    for rel in ("venv-pyrit/Scripts/python.exe", "venv-pyrit/bin/python"):
        if (ROOT / rel).exists():
            return str(ROOT / rel)
    raise SystemExit("PyRIT environment not found. Create it (see README, 'Setup') or set PYRIT_PYTHON.")


def run(target, tag, tier, url, outdir: Path, seed=1, yes=False) -> dict:
    python = pyrit_python()
    confirm(f"pyrit {tier}: about {ESTIMATE[tier]} requests to the {target} target"
            + ("" if tier == "smoke" else ", plus the local attacker model for the multi-turn attacks (Ollama must be running)")
            + ".", yes)
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"{tag}_{target}.attacks.json"
    out.unlink(missing_ok=True)
    proc = subprocess.run([python, str(ROOT / "tools" / "pyrit_attacks.py"), "--url", base_url(url, tag),
                           "--model", model_for(target), "--tier", tier, "--out", str(out)])
    if not out.exists():
        return summary("pyrit", tag, target, tier, 0, 0, [f"pyrit_attacks.py exited with code {proc.returncode} and wrote nothing"])

    records = json.loads(out.read_text(encoding="utf-8"))["records"]
    done = [r for r in records if not r["error"]]
    flagged = sum(r["success"] for r in done)
    by_kind: dict[str, list[int]] = {}
    errors: dict[str, int] = {}
    for r in records:
        if r["error"]:
            errors[r["kind"]] = errors.get(r["kind"], 0) + 1
            continue
        k = by_kind.setdefault(r["kind"], [0, 0])
        k[0] += 1
        k[1] += r["success"]
    notes = [f"{k}: {v[1]} achieved of {v[0]}" for k, v in by_kind.items()]
    if errors:
        notes.append("errored, excluded: " + ", ".join(f"{k} {n}" for k, n in errors.items())
                     + " (see the .attacks.json file; multi-turn errors usually mean the local attacker model did not return the JSON PyRIT needs)")
    if "red_teaming" in by_kind or "crescendo" in by_kind or "red_teaming" in errors or "crescendo" in errors:
        notes.append("multi-turn attacks use the local Llama 3.1 8B as attacker, which is far weaker than the models these attacks were built for")
    return summary("pyrit", tag, target, tier, len(done), flagged, notes)
