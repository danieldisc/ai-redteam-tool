"""
Checks the clean / poisoned choice that rides in the target id, from run.py to the server routing:

    python tests/test_docs_mode.py

The server part needs fastapi (already in requirements.txt) but no model: the chatbots and guardrails
are small fakes, and the log goes to a temporary file.
"""

import asyncio
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "target"))
sys.path.insert(0, str(ROOT / "tools"))

import docs_mode as dm  # noqa: E402
import run  # noqa: E402
import scripted_run  # noqa: E402

failed = False


def check(name, ok):
    global failed
    print(("ok   " if ok else "FAIL ") + name)
    failed = failed or not ok


check("a plain id is clean", dm.split_target("doccheck") == ("doccheck", "clean"))
check("a _poisoned id is poisoned", dm.split_target("doccheck_poisoned") == ("doccheck", "poisoned"))
check("join and split round-trip", dm.split_target(dm.join_target("guarded", "poisoned")) == ("guarded", "poisoned")
      and dm.join_target("guarded", "clean") == "guarded")
check("a model name gives its target and guardrail", dm.target_of("askdbc-blocklist_poisoned") == "blocklist_poisoned"
      and dm.guardrail_of("askdbc-blocklist_poisoned") == "blocklist")

avail = ["unguarded", "guarded", "blocklist", "doccheck"]
check("run.py: --target all is clean by default", run.pick_targets("all", avail) == avail)
check("run.py: --docs poisoned adds the suffix", run.pick_targets("unguarded,doccheck", avail, "poisoned") == ["unguarded_poisoned", "doccheck_poisoned"])
check("run.py: both follows --docs", run.pick_targets("both", avail, "poisoned") == ["unguarded_poisoned", "guarded_poisoned"])
check("run.py: an explicit suffix is kept", run.pick_targets("guarded_poisoned,doccheck", avail) == ["guarded_poisoned", "doccheck"])
try:
    run.pick_targets("nope_poisoned", avail)
    check("run.py: an unknown guardrail is refused", False)
except SystemExit:
    check("run.py: an unknown guardrail is refused", True)

convs = json.loads((ROOT / "attacks" / "multiturn.json").read_text(encoding="utf-8"))["conversations"]
clean_ids = [c["id"] for c in scripted_run.pick(convs, "standard", "clean")[0]]
poison_ids = [c["id"] for c in scripted_run.pick(convs, "standard", "poisoned")[0]]
check("scripted: the poisoned-document conversation only runs on the poisoned set", "M8" not in clean_ids and "M8" in poison_ids)

# ---- the server: which chatbot answers, and what is logged --------------------------------------
try:
    import server
    from fastapi import HTTPException
    from rails.base import Result
except ImportError as exc:
    print(f"SKIP server routing ({exc})")
else:
    class Bot:
        def __init__(self, docs):
            self.docs, self.system_prompt = docs, "You are a bot. Secret ABC-SECRET-4321."

    class Echo:
        id = "unguarded"
        label = ""
        description = ""

        async def answer(self, chatbot, history, question):
            return Result(f"answered from the {chatbot.docs} documents", ["doc5_poisoned"] if chatbot.docs == "poisoned" else ["doc1"], "none", ())

    class Req:
        headers: dict = {}

        def __init__(self, body):
            self.body = body

        async def json(self):
            return self.body

    def ask(model):
        body = {"model": model, "messages": [{"role": "user", "content": "hello"}]}
        return asyncio.run(server.chat_completions("tool.t1", Req(body)))

    with tempfile.TemporaryDirectory() as tmp:
        server.LOG_PATH = Path(tmp) / "log.jsonl"
        server.state.update(chatbots={"clean": Bot("clean"), "poisoned": Bot("poisoned")}, guardrails={"unguarded": Echo()}, stub=True)
        clean = json.loads(ask("askdbc-unguarded").body)["choices"][0]["message"]["content"]
        poisoned = json.loads(ask("askdbc-unguarded_poisoned").body)["choices"][0]["message"]["content"]
        rows = [json.loads(line) for line in server.LOG_PATH.read_text(encoding="utf-8").splitlines()]
        check("server: a plain model name answers from the clean documents", "clean" in clean)
        check("server: a _poisoned model name answers from the poisoned documents", "poisoned" in poisoned)
        check("server: the log records the document set of each request", [r["docs"] for r in rows] == ["clean", "poisoned"])
        check("server: the log keeps the full model name", rows[1]["model"] == "askdbc-unguarded_poisoned")
        offered = server.served_models()
        check("server: both sets are offered for every built-in guardrail", "askdbc-doccheck_poisoned" in server.MODELS and "askdbc-doccheck" in server.MODELS
              and len(server.MODELS) == 2 * len(server.rails.IDS))
        check("server: with only the registered option, only its two names are offered", offered == ["askdbc-unguarded", "askdbc-unguarded_poisoned"])
        try:
            ask("askdbc-unguarded_other")
            check("server: an unknown model is refused", False)
        except HTTPException as exc:
            check("server: an unknown model is refused", exc.status_code == 404)

sys.exit(1 if failed else 0)
