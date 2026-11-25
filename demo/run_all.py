"""Run the five demos one after another (sequential, because the chatbot answers one turn at a time).

    python demo/run_all.py                    # all five
    python demo/run_all.py inspect pyrit      # only some

Each tool may live in its own virtual environment. Set DEMO_PYTHON_<TOOL> to that environment's Python,
for example DEMO_PYTHON_PYRIT=/path/to/venv-pyrit/bin/python. A tool that fails does not stop the others.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

ORDER = ["inspect", "giskard", "pyrit", "promptfoo", "garak"]
here = Path(__file__).parent
chosen = [t for t in sys.argv[1:] if t in ORDER] or ORDER
results = {}
for tool in chosen:
    python = os.environ.get(f"DEMO_PYTHON_{tool.upper()}", sys.executable)
    print(f"\n=== {tool} ===", flush=True)
    started = time.time()
    code = subprocess.run([python, str(here / f"{tool}_demo.py")]).returncode
    results[tool] = (code, round(time.time() - started))
print("\n=== summary ===")
for tool, (code, seconds) in results.items():
    print(f"{tool:<10} {'ok' if code == 0 else 'FAILED (exit ' + str(code) + ')':<18} {seconds} s")
print("\nVerdicts are in the adapter log. Print them with:  python tools/bench_adapter.py summarise results_adapter")
