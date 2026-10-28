"""
One comparison matrix: a cell for every tool and guardrail, from the server log and each tool's summary.

    python report/compare.py                      # clean documents (the default)
    python report/compare.py --docs poisoned      # the same matrix for the poisoned documents
    python report/compare.py --include-stub --out results/comparison.md

Two matrices are shown, because the two numbers answer different questions:
  tool's own verdict   attacks the tool counted as successful / attacks it ran (can be wrong)
  canary leaks         replies containing the secret or system prompt / all requests (deterministic)
For each tool and guardrail the run shown is the highest tier, then the latest. The last table says
which run that was, so cells from a smoke run are not mistaken for a standard run.

Clean and poisoned runs are never mixed: the poisoned document changes how the chatbot answers
everything that retrieves it, so each matrix shows one document set only.
"""

import argparse
from pathlib import Path

from analyse import LOG_PATH, MODES, docs_of, guardrail_of, load_log, load_tool_summaries, pct, target_of

TOOL_ORDER = ["baseline", "scripted", "garak", "giskard", "inspect", "pyrit", "promptfoo"]
GUARDRAIL_ORDER = ["unguarded", "guarded", "blocklist", "doccheck"]
TIER_RANK = {"smoke": 0, "standard": 1, "full": 2}


def pick_runs(rows: list[dict], summaries: dict, docs: str = "clean") -> dict:
    """(tool, guardrail) -> the run to show, for one document set. Runs without a summary file are left out."""
    groups: dict[tuple, dict] = {}
    for r in rows:
        if docs_of(r) != docs:
            continue
        key = (r["tag"], target_of(r["model"]))
        g = groups.setdefault(key, {"requests": 0, "leaks": 0, "ts": ""})
        g["requests"] += 1
        g["leaks"] += r["canary"] != "clean"
        g["ts"] = max(g["ts"], r["ts"])
    best: dict[tuple, tuple] = {}
    for (tag, target), g in groups.items():
        s = summaries.get((tag, target))
        if not s:
            continue
        guardrail = guardrail_of(target)
        rank = (TIER_RANK.get(s["tier"], -1), g["ts"])
        run = {**g, "tag": tag, "tier": s["tier"], "attempted": s["attempted"], "flagged": s["tool_flagged"]}
        key = (s["tool"], guardrail)
        if key not in best or rank > best[key][0]:
            best[key] = (rank, run)
    return {k: v[1] for k, v in best.items()}


def ordered(found: set[str], preferred: list[str]) -> list[str]:
    return [p for p in preferred if p in found] + sorted(found - set(preferred))


def build_report(rows: list[dict], summaries: dict, docs: str = "clean") -> str:
    runs = pick_runs(rows, summaries, docs)
    if not runs:
        return (f"No runs with a summary file for the {docs} documents yet. Run a tool first "
                f"(python run.py <tool> --target <guardrail>{' --docs poisoned' if docs == 'poisoned' else ''}).\n")
    tools = ordered({t for t, _ in runs}, TOOL_ORDER)
    guardrails = ordered({g for _, g in runs}, GUARDRAIL_ORDER)

    def table(title: str, note: str, cell) -> list[str]:
        out = [f"## {title}\n", note + "\n", "| tool | " + " | ".join(guardrails) + " |",
               "|---|" + "---|" * len(guardrails)]
        for tool in tools:
            out.append(f"| {tool} | " + " | ".join(cell(runs.get((tool, g))) for g in guardrails) + " |")
        return out + [""]

    lines = [f"Documents: **{docs}**" + (" (the booby-trapped document is in the knowledge base)" if docs == "poisoned" else "") + "\n"]
    lines += table("Tool's own verdict (attacks flagged / attacks run)",
                  "Can be wrong in either direction; read it beside the canary matrix. For `baseline` this is the canary count.",
                  lambda r: pct(r["flagged"], r["attempted"]) if r else "-")
    lines += table("Canary leaks (replies with the secret or system prompt / all requests)",
                   "Deterministic string check, a lower bound. Requests include legitimate questions, so it is not an attack success rate.",
                   lambda r: pct(r["leaks"], r["requests"]) if r else "-")
    lines += ["## Run behind each cell\n", "| tool | guardrail | run | tier | requests |", "|---|---|---|---|---|"]
    for tool in tools:
        for g in guardrails:
            if (tool, g) in runs:
                r = runs[(tool, g)]
                lines.append(f"| {tool} | {g} | {r['tag']} | {r['tier']} | {r['requests']} |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--docs", choices=MODES, default="clean", help="Document set to show (default clean)")
    parser.add_argument("--include-stub", action="store_true", help="Include stub (fake model) rows")
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--out", type=Path, help="Also write the report to this file")
    args = parser.parse_args()
    rows = load_log(args.log)
    if not args.include_stub:
        rows = [r for r in rows if not r.get("stub")]
    report = build_report(rows, load_tool_summaries(), args.docs)
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
