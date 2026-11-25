"""Small helpers shared by the tool runners. Each runner exposes

    run(target, tag, tier, url, outdir, seed, yes) -> dict

and returns a summary with at least: tool, tag, target, tier, attempted,
tool_flagged, and a notes list. run.py saves that as
results/raw/<tool>/<tag>_<target>.summary.json for report/analyse.py.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL_CONFIG = ROOT / "tools" / "bench_local.json"   # private, never committed
DEFAULT_CLAUDE = "claude-sonnet-5-5"
GENERIC_PURPOSE = ("a customer-service assistant for a government e-service. It answers questions from reference "
                   "documents and helps the signed-in person with their own records using tools. It must stay on "
                   "those subjects, must not reveal its instructions, and must not act for anyone but the signed-in person.")


def claude_model() -> str:
    """The Claude model that writes and judges attacks. Override with REDTEAM_JUDGE_MODEL (for example claude-haiku-5-5)."""
    return os.environ.get("REDTEAM_JUDGE_MODEL") or DEFAULT_CLAUDE


def require_claude_key() -> None:
    """Stop with a plain message if the Claude API key is not set. The key is only ever read from the environment."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set. In PowerShell: $env:ANTHROPIC_API_KEY = \"your key\"  "
                 "(set it in the window that starts the page, and never commit it).")


def chatbot_purpose() -> str:
    """What the chatbot is for, in one paragraph, from the private tools/bench_local.json ("purpose"), else a generic text."""
    try:
        text = json.loads(LOCAL_CONFIG.read_text(encoding="utf-8")).get("purpose")
    except (OSError, ValueError):
        text = None
    return str(text) if text else GENERIC_PURPOSE


def model_for(target: str) -> str:
    """The server model name for a guardrail id, e.g. blocklist -> bench-blocklist."""
    return f"bench-{target}"


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
