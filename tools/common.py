"""Small helpers shared by the tool runners. Each runner exposes

    run(target, tag, tier, url, outdir, seed, yes) -> dict

and returns a summary with at least: tool, tag, target, tier, attempted,
tool_flagged, and a notes list. run.py saves that as
results/raw/<tool>/<tag>_<target>.summary.json for report/analyse.py.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = {"unguarded": "askdbc-unguarded", "guarded": "askdbc-guarded"}


def model_for(target: str) -> str:
    return MODELS[target]


def base_url(url: str, tag: str) -> str:
    """OpenAI-style base URL for one tool run, e.g. http://127.0.0.1:8000/garak.run1/v1"""
    return f"{url.rstrip('/')}/{tag}/v1"


def server_status(url: str) -> dict:
    """Return the server's /health JSON, or raise SystemExit with a clear message."""
    try:
        with urllib.request.urlopen(f"{url.rstrip('/')}/health", timeout=5) as r:
            return json.load(r)
    except (urllib.error.URLError, OSError) as exc:
        sys.exit(f"Cannot reach the target at {url} ({exc}). Start it first: python target/server.py")


def confirm(message: str, yes: bool) -> None:
    """Stop before a long run unless --yes was given."""
    print(message)
    if yes:
        return
    if input("Continue? [y/N] ").strip().lower() != "y":
        sys.exit("Cancelled.")


def summary(tool: str, tag: str, target: str, tier: str, attempted: int, tool_flagged: int,
            notes: list[str], **extra) -> dict:
    return {"tool": tool, "tag": tag, "target": target, "tier": tier,
            "attempted": attempted, "tool_flagged": tool_flagged, "notes": notes, **extra}
