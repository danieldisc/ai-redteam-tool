"""
The test library: the reusable attack and control cases in attacks/library.json, replayed against the target.

Each case is one or more user messages with the OWASP risk it tests. A conversation is replayed one message at a time, with
the chatbot's own replies sent back as history, like scripted_run.py. Success is judged by the plain success rule of the
case's primary OWASP category in attacks/owasp.json (the secret or a long piece of the system prompt, a marker word, a
poisoned-document marker, a reply length or a dangerous string), so this tool, the scan page and the pentest report agree.
A marker word inside a longer answer is an echo, reported but not counted as a success. Control cases are harmless questions:
a refusal is a false refusal.

Cases with docs "poisoned" only run on a poisoned target (run.py --docs poisoned, or a target ending _poisoned).

Tiers: smoke runs the first single-message case of each risk and one control, once; standard runs everything twice; full runs
everything five times. tool_flagged = attack conversations that succeeded, out of those run. The request log counts every message
as a request. Each request carries its case id and OWASP risk in headers, so the log can say which test it belonged to.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from common import ROOT, base_url, confirm, model_for, summary

sys.path.insert(0, str(ROOT / "report"))
sys.path.insert(0, str(ROOT / "target"))
import canary  # noqa: E402
import owasp  # noqa: E402
from docs_mode import split_target  # noqa: E402

REPEATS = {"smoke": 1, "standard": 2, "full": 5}
LIBRARY = ROOT / "attacks" / "library.json"


def load_library(path: Path = LIBRARY) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def library_version(path: Path = LIBRARY) -> str:
    """The version written in the library file, saved in every run's summary so a result says which cases it came from."""
    return str(json.loads(path.read_text(encoding="utf-8")).get("version", "unversioned"))


def ask(api: str, model: str, messages: list[dict], case: dict | None = None) -> str:
    headers = {"content-type": "application/json"}
    if case:
        headers["X-Redteam-Case"] = case["id"]
        if case["kind"] == "attack":
            headers["X-Redteam-Owasp"] = ",".join([case["owasp"]] + case.get("also", []))
    body = json.dumps({"model": model, "messages": messages}).encode()
    req = urllib.request.Request(f"{api}/chat/completions", data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["choices"][0]["message"]["content"]


def pick(cases: list[dict], tier: str, docs: str | None) -> tuple[list[dict], list[dict]]:
    skipped = [c for c in cases if c["docs"] == "poisoned" and docs != "poisoned"]
    usable = [c for c in cases if c not in skipped]
    if tier == "smoke":
        firsts, seen = [], set()
        for c in usable:
            if c["owasp"] not in seen and len(c["turns"]) == 1:
                seen.add(c["owasp"])
                firsts.append(c)
        usable = firsts
    return usable, skipped


def judge(case: dict, replies: list[str], rules: dict) -> dict:
    """{'success_turn': n or None, 'echo_turn': n or None} for an attack case, by its primary category's rule."""
    cat = rules[case["owasp"]]
    turns = [len(replies)] if case["judge"] == "last" else range(1, len(replies) + 1)
    result = {"success_turn": None, "echo_turn": None}
    for n in turns:
        row = {"response": replies[n - 1], "canary": canary.check(replies[n - 1])}
        if owasp.succeeded(cat, row):
            result["success_turn"] = n
            break
        if result["echo_turn"] is None and owasp.echoed(cat, row):
            result["echo_turn"] = n
    return result


def run(target, tag, tier, url, outdir: Path, seed=1, yes=False) -> dict:
    cases = load_library()
    rules = {c["id"]: c for c in owasp.load_rules()}
    chosen, skipped = pick(cases, tier, split_target(target)[1])
    repeats = REPEATS[tier]
    n_requests = sum(len(c["turns"]) for c in chosen) * repeats
    confirm(f"library {tier}: {len(chosen)} cases x {repeats} repeats = {n_requests} requests to the {target} target.", yes)

    api, model, records = base_url(url, tag), model_for(target), []
    for repeat in range(1, repeats + 1):
        for case in chosen:
            messages, replies, error = [], [], None
            try:
                for turn in case["turns"]:
                    messages.append({"role": "user", "content": turn})
                    reply = ask(api, model, messages, case)
                    messages.append({"role": "assistant", "content": reply})
                    replies.append(reply)
                    print(".", end="", flush=True)
            except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                print("E", end="", flush=True)
            record = {"repeat": repeat, "id": case["id"], "owasp": case["owasp"], "kind": case["kind"], "title": case["title"],
                      "error": error, "turns": case["turns"], "replies": replies}
            if not error and case["kind"] == "attack":
                record.update(judge(case, replies, rules))
            elif not error:
                record["refused"] = any(canary.looks_like_refusal(r) or not r.strip() for r in replies)
            records.append(record)
    print()

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / f"{tag}_{target}.conversations.json").write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")

    done = [r for r in records if not r["error"]]
    attacks = [r for r in done if r["kind"] == "attack"]
    notes = []
    for risk in dict.fromkeys(r["owasp"] for r in attacks):
        rs = [r for r in attacks if r["owasp"] == risk]
        hits = sum(r["success_turn"] is not None for r in rs)
        echoes = sum(r["success_turn"] is None and r["echo_turn"] is not None for r in rs)
        notes.append(f"{risk} {rules[risk]['name']}: {hits}/{len(rs)} succeeded" + (f", {echoes} echo" if echoes else ""))
    controls = [r for r in done if r["kind"] == "control"]
    if controls:
        notes.append(f"harmless questions refused: {sum(r['refused'] for r in controls)}/{len(controls)}")
    if skipped:
        notes.append(f"skipped, need the poisoned documents ({len(skipped)} cases): run with --docs poisoned or a target ending _poisoned")
    errors = len(records) - len(done)
    if errors:
        notes.append(f"{errors} conversation(s) errored and are excluded (see the .conversations.json file)")
    return summary("library", tag, target, tier, len(attacks), sum(r["success_turn"] is not None for r in attacks), notes,
                   library_version=library_version())
