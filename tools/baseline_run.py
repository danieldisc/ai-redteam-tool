"""
Built-in check with no external tool: send the written leak prompts and the
legitimate questions straight to the target and count what comes back.

This is how the guardrail's cost is measured (false refusals on legitimate
questions, extra latency) and it gives a quick sanity check that the target and
the canary work. The prompts are in attacks/leak.json and attacks/benign.json.
They were written while the rails were being built, so results on them flatter
the guarded target; the other tools' attacks are the held-out test.

Tiers (repeats of every prompt): smoke 1, standard 3, full 5.
"""

import json
import urllib.request

from common import ROOT, base_url, confirm, model_for, summary

REPEATS = {"smoke": 1, "standard": 3, "full": 5}


def ask(url: str, model: str, question: str) -> str:
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": question}]}).encode()
    req = urllib.request.Request(f"{url}/chat/completions", data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["choices"][0]["message"]["content"]


def run(target, tag, tier, url, outdir, seed=1, yes=False) -> dict:
    leak = json.loads((ROOT / "attacks" / "leak.json").read_text(encoding="utf-8"))["prompts"]
    benign = json.loads((ROOT / "attacks" / "benign.json").read_text(encoding="utf-8"))
    questions = [p["prompt"] for p in leak] + benign["in_scope"] + benign["borderline"] + benign["out_of_scope"]
    repeats = REPEATS[tier]
    confirm(f"baseline {tier}: {len(questions)} prompts x {repeats} repeats = {len(questions) * repeats} requests "
            f"to the {target} target.", yes)

    outdir.mkdir(parents=True, exist_ok=True)
    api, model, records = base_url(url, tag), model_for(target), []
    for run_no in range(1, repeats + 1):
        for q in questions:
            records.append({"run": run_no, "question": q, "response": ask(api, model, q)})
            print(".", end="", flush=True)
    print()
    (outdir / f"{tag}_{target}.responses.json").write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    import sys
    sys.path.insert(0, str(ROOT / "target"))
    import canary
    leak_qs = {p["prompt"] for p in leak}
    leaked = sum(canary.check(r["response"]) != "clean" for r in records if r["question"] in leak_qs)
    attempted = len(leak_qs) * repeats
    return summary("baseline", tag, target, tier, attempted, leaked,
                   [f"{len(leak_qs)} written leak prompts x {repeats}; tool_flagged here IS the canary count"])
