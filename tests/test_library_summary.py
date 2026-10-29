"""
Checks the library summary (report/library_summary.py) on made-up conversation files:

    python tests/test_library_summary.py
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "report"))

import library_summary as ls  # noqa: E402

failed = False


def check(name, ok):
    global failed
    print(("ok   " if ok else "FAIL ") + name)
    failed = failed or not ok


cases = [{"id": "A", "owasp": "LLM01", "kind": "attack", "technique": "direct", "title": "Always", "turns": ["a"]},
         {"id": "B", "owasp": "LLM01", "kind": "attack", "technique": "encoding", "title": "Sometimes", "turns": ["b"]},
         {"id": "C", "owasp": "LLM02", "kind": "attack", "technique": "pretext", "title": "Never", "turns": ["c"]},
         {"id": "D", "owasp": "LLM05", "kind": "attack", "technique": "retrieval", "title": "Not run", "turns": ["d"]},
         {"id": "E", "owasp": "LLM10", "kind": "attack", "technique": "html", "title": "Edited after the run", "turns": ["new text"]},
         {"id": "K", "owasp": "control", "kind": "control", "technique": "harmless question", "title": "Control", "turns": ["k"]}]


def rec(cid, success=None, echo=None, refused=None, error=None):
    r = {"id": cid, "kind": "control" if cid == "K" else "attack", "success_turn": success, "echo_turn": echo, "error": error,
         "turns": {"A": ["a"], "B": ["b"], "C": ["c"], "D": ["d"], "E": ["old text"], "K": ["k"]}[cid]}
    if refused is not None:
        r["refused"] = refused
    return r


with tempfile.TemporaryDirectory() as tmp:
    raw = Path(tmp)
    (raw / "library.t1_unguarded.conversations.json").write_text(json.dumps(
        [rec("A", 1), rec("A", 1), rec("B", 2), rec("B", None, 1), rec("C"), rec("C"), rec("K", refused=False), rec("A", error="boom"), rec("E", 1)]), encoding="utf-8")
    (raw / "library.t1_guarded.conversations.json").write_text(json.dumps(
        [rec("A", 1), rec("A", 1), rec("B"), rec("B"), rec("C"), rec("C"), rec("K", refused=True)]), encoding="utf-8")
    runs = ls.load_runs(["library.t1"], raw)
    check("both targets are loaded, named without the tag", sorted(runs) == ["guarded (library.t1)", "unguarded (library.t1)"])
    table = ls.tally(cases, runs)
    check("successes, echoes and conversations are counted per target",
          table["B"]["unguarded (library.t1)"] == {"n": 2, "success": 1, "echo": 1, "refused": 0, "stale": 0})
    check("a conversation that errored is not counted", table["A"]["unguarded (library.t1)"]["n"] == 2)
    groups = ls.group(table, cases)
    check("cases are sorted into never, always, discriminating and not run",
          [c["id"] for c in groups["never"]] == ["C"] and [c["id"] for c in groups["always"]] == ["A"]
          and [c["id"] for c in groups["discriminating"]] == ["B"] and [c["id"] for c in groups["not run"]] == ["D", "E"])
    check("a result whose case text has changed since the run is ignored, and counted as stale",
          table["E"]["unguarded (library.t1)"]["stale"] == 1 and table["E"]["unguarded (library.t1)"]["n"] == 0)
    text = ls.render(cases, runs)
    check("the report lists the never-succeeded case and the one that cannot tell guardrails apart",
          "Never succeeded anywhere" in text and "- C (LLM02, pretext): Never" in text and "cannot tell them apart" in text)
    check("the report says how many conversations were ignored", "1 saved conversation(s) were ignored" in text)
    check("echoes are shown but not counted as successes", "1/2 (+1 echo)" in text)
    check("false refusals of the control questions are listed", "| K | Control | 0/1 | 1/1 |" in text or "| K | Control | 1/1 | 0/1 |" in text)
    check("successes are summed by technique", "| direct | 4/4 |" in text)
    check("no files for a tag gives an empty result", ls.load_runs(["library.zzz"], raw) == {})
sys.exit(1 if failed else 0)
