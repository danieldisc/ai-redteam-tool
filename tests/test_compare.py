"""
Checks the comparison matrix on made-up log rows and summaries:

    python tests/test_compare.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "report"))

import compare  # noqa: E402


def row(tag, model, canary="clean", ts="2026-10-20T10:00:00"):
    return {"tag": tag, "model": f"askdbc-{model}", "canary": canary, "ts": ts, "stub": False}


def summary(tool, tag, target, tier, attempted, flagged):
    return {"tool": tool, "tag": tag, "target": target, "tier": tier, "attempted": attempted, "tool_flagged": flagged}


rows = (
    [row("garak.s1", "unguarded")] * 10 + [row("garak.s1", "unguarded", "leaked")] * 2          # smoke run, older
    + [row("garak.r1", "unguarded", ts="2026-10-19T10:00:00")] * 100                            # standard run, earlier day
    + [row("garak.r1", "unguarded", "leaked", ts="2026-10-19T10:00:00")] * 3
    + [row("garak.r1", "guarded")] * 50
    + [row("pyrit.p2", "blocklist")] * 20
    + [row("manual", "unguarded")] * 5                                                          # no summary file
)
summaries = {
    ("garak.s1", "unguarded"): summary("garak", "garak.s1", "unguarded", "smoke", 12, 9),
    ("garak.r1", "unguarded"): summary("garak", "garak.r1", "unguarded", "standard", 103, 40),
    ("garak.r1", "guarded"): summary("garak", "garak.r1", "guarded", "standard", 50, 0),
    ("pyrit.p2", "blocklist"): summary("pyrit", "pyrit.p2", "blocklist", "standard", 18, 0),
}
text = compare.build_report(rows, summaries)
runs = compare.pick_runs(rows, summaries)
poison_rows = [dict(row("garak.q1", "unguarded_poisoned", ts="2026-10-21T10:00:00"), docs="poisoned") for _ in range(10)]
poison_rows += [dict(row("garak.q1", "unguarded_poisoned", "leaked", ts="2026-10-21T10:00:00"), docs="poisoned")] * 2
poison_summaries = {**summaries, ("garak.q1", "unguarded_poisoned"): summary("garak", "garak.q1", "unguarded_poisoned", "standard", 12, 7)}
clean_view = compare.pick_runs(rows + poison_rows, poison_summaries)
poison_view = compare.pick_runs(rows + poison_rows, poison_summaries, "poisoned")


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


results = [
    check("the higher tier wins over a newer smoke run", runs[("garak", "unguarded")]["tag"] == "garak.r1"),
    check("flagged and canary numbers come from that run",
          "40/103" in text and "3/103" in text),
    check("a run with no summary file (manual) is left out", "manual" not in text),
    check("tools and guardrails are ordered, with empty cells as -", "| pyrit | - | - | 0/18 (0%) |" in text),
    check("the run table names the run behind each cell", "| garak | unguarded | garak.r1 | standard | 103 |" in text),
    check("empty input gives a helpful message", "No runs with a summary file" in compare.build_report([], {})),
    check("the clean matrix ignores poisoned runs", clean_view[("garak", "unguarded")]["tag"] == "garak.r1"),
    check("the poisoned matrix shows only poisoned runs, under the plain guardrail name",
          list(poison_view) == [("garak", "unguarded")] and poison_view[("garak", "unguarded")]["tag"] == "garak.q1"
          and poison_view[("garak", "unguarded")]["leaks"] == 2),
    check("the report says which document set it shows",
          "Documents: **clean**" in compare.build_report(rows, summaries) and "Documents: **poisoned**" in compare.build_report(rows + poison_rows, poison_summaries, "poisoned")),
    check("a document set with no runs says so", "poisoned documents yet" in compare.build_report(rows, summaries, "poisoned")),
    check("matrix data has every cell with both numbers and the run behind it",
          compare.matrix_data(rows, summaries)["cells"]["garak|unguarded"] == {"flagged": 40, "attempted": 103, "leaks": 3, "requests": 103,
                                                                               "tier": "standard", "run": "garak.r1"}),
    check("matrix data lists tools and guardrails in order, and is empty when there are no runs",
          compare.matrix_data(rows, summaries)["guardrails"] == ["unguarded", "guarded", "blocklist"] and compare.matrix_data([], {})["cells"] == {}),
]
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
