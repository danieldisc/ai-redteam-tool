"""
Checks the Claude-backed parts of promptfoo, giskard and pyrit without calling any API:

    python tests/test_claude_tools.py

The Claude key is never needed; the chatbot is a fake server. The Giskard plumbing check is skipped when Giskard is not installed.
"""

import asyncio
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import common  # noqa: E402

failed = False


def check(name, ok):
    global failed
    print(("ok   " if ok else "FAIL ") + name)
    failed = failed or not ok


def raises_exit(fn):
    try:
        fn()
    except SystemExit as exc:
        return str(exc)
    return None


os.environ.pop("ANTHROPIC_API_KEY", None)
os.environ.pop("REDTEAM_JUDGE_MODEL", None)
os.environ.pop("REDTEAM_ATTACKER", None)

# ---- common ---------------------------------------------------------------------------------
msg = raises_exit(common.require_claude_key)
check("a missing key stops the run with a plain message that never asks for the key in a file", bool(msg) and "ANTHROPIC_API_KEY" in msg and "commit" in msg)
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"
check("a set key lets the run go on", raises_exit(common.require_claude_key) is None)
check("the default model is claude-sonnet-5-5", common.claude_model() == "claude-sonnet-5-5")
os.environ["REDTEAM_JUDGE_MODEL"] = "claude-haiku-5-5"
check("REDTEAM_JUDGE_MODEL changes the model", common.claude_model() == "claude-haiku-5-5")
del os.environ["REDTEAM_JUDGE_MODEL"]

saved = common.LOCAL_CONFIG
with tempfile.TemporaryDirectory() as tmp:
    common.LOCAL_CONFIG = Path(tmp) / "missing.json"
    check("without the private file the purpose is generic", common.chatbot_purpose() == common.GENERIC_PURPOSE)
    cfg = Path(tmp) / "c.json"
    cfg.write_text(json.dumps({"purpose": "a test assistant."}), encoding="utf-8")
    common.LOCAL_CONFIG = cfg
    check("the purpose is read from the private file", common.chatbot_purpose() == "a test assistant.")
    cfg.write_text("{not json", encoding="utf-8")
    check("a damaged private file falls back to the generic purpose", common.chatbot_purpose() == common.GENERIC_PURPOSE)
common.LOCAL_CONFIG = saved
check("no real chatbot wording is in the generic text", "COE" not in common.GENERIC_PURPOSE and "road tax" not in common.GENERIC_PURPOSE)

# ---- promptfoo ------------------------------------------------------------------------------
import promptfoo_run  # noqa: E402

cfg = promptfoo_run.make_config("m", "http://127.0.0.1:8000/x/v1", "smoke")
check("promptfoo's attacker is Claude", cfg["redteam"]["provider"] == "anthropic:messages:claude-sonnet-5-5")
check("promptfoo's purpose names tools and the real risks", "tools" in cfg["redteam"]["purpose"] and "wrong person" in cfg["redteam"]["purpose"])
check("promptfoo no longer mentions the old chatbot or a local model",
      "AskDBC" not in json.dumps(cfg) and "llama" not in json.dumps(cfg) and "ollama" not in json.dumps(cfg).lower())
check("promptfoo's own hosted generation stays off", promptfoo_run.promptfoo_env()["PROMPTFOO_DISABLE_REMOTE_GENERATION"] == "true")
os.environ.pop("ANTHROPIC_API_KEY")
check("a promptfoo run without a key stops before spending anything",
      raises_exit(lambda: promptfoo_run.run("unguarded", "t", "smoke", "http://127.0.0.1:1", Path(tempfile.gettempdir()), yes=True)) is not None)
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"

# ---- pyrit ----------------------------------------------------------------------------------
import pyrit_run  # noqa: E402

args = pyrit_run.attacker_args()
check("with a key PyRIT's attacker is Claude through the compatible endpoint",
      args[:4] == ["--attacker-url", "https://api.anthropic.com/v1/", "--attacker-model", "claude-sonnet-5-5"])
check("the key is passed by variable name, never by value", "test-key-not-real" not in " ".join(args) and args[-2:] == ["--attacker-key-env", "ANTHROPIC_API_KEY"])
os.environ["REDTEAM_ATTACKER"] = "local"
check("REDTEAM_ATTACKER=local keeps the local attacker", pyrit_run.attacker_args() == [])
del os.environ["REDTEAM_ATTACKER"]
os.environ.pop("ANTHROPIC_API_KEY")
check("without a key PyRIT keeps the local attacker", pyrit_run.attacker_args() == [])
os.environ["ANTHROPIC_API_KEY"] = "test-key-not-real"

# ---- giskard: plumbing with no judge, against a fake chatbot ----------------------------------
try:
    import giskard.checks  # noqa: F401
    have_giskard = True
except ImportError:
    have_giskard = False
    print("skip giskard plumbing (giskard is not installed here)")

if have_giskard:
    import giskard_run

    class Fake(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            body = json.dumps({"choices": [{"message": {"content": "I cannot help with that."}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    os.environ["REDTEAM_NO_JUDGE"] = "1"
    url = f"http://127.0.0.1:{server.server_port}"
    with tempfile.TemporaryDirectory() as tmp:
        out = giskard_run.run("unguarded", "t1", "smoke", url, Path(tmp), yes=True)
    server.shutdown()
    check("giskard's deterministic run sends the smoke prompts and flags nothing for refusals", out["attempted"] == 3 and out["tool_flagged"] == 0)
    check("giskard's judge model string uses its Anthropic provider", giskard_run.judge_model() == "anthropic/claude-sonnet-5-5")
    del os.environ["REDTEAM_NO_JUDGE"]
    os.environ.pop("ANTHROPIC_API_KEY")
    check("a giskard run with the judge on and no key stops first",
          raises_exit(lambda: giskard_run.run("unguarded", "t2", "smoke", url, Path(tempfile.gettempdir()), yes=True)) is not None)

print("\nall checks passed" if not failed else "\nSOME CHECKS FAILED")
sys.exit(1 if failed else 0)
