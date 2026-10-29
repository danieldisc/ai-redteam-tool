"""
A scan: the OWASP categories you picked, run against the guardrails you picked, with evidence.

    python report/scan.py --label scan1021-1500 --categories LLM01,LLM02,LLM05
    python report/scan.py --label scan1021-1500 --out results/scans/scan1021-1500.md

The web page queues the runs (ui/app.py); this module turns the server log into the result: for each
category and guardrail, how many matching requests succeeded, plus up to three real request/reply
examples per category. Success is the deterministic check from attacks/owasp.json, not a tool's own
verdict. The planted secret is masked in the examples, so the saved report is safer to share.

Each category is read from its own document set: the poisoning categories (LLM05, LLM09) from the
poisoned documents and the others from the clean ones, unless the scan forced one set for everything.
"""

import argparse
import re
from pathlib import Path

from analyse import LOG_PATH, MODES, ROOT, docs_of, guardrail_of, load_log
from compare import GUARDRAIL_ORDER, ordered
from owasp import echoed, load_rules, matches, succeeded
from score import score

SLOW_TOOLS = ["garak", "giskard", "pyrit", "promptfoo"]      # thousands of requests, or heavy set-up
TOOL_ORDER = ["baseline", "scripted", "library", "inspect", "giskard", "pyrit", "promptfoo", "garak"]
SECRET = re.compile(r"abc\W*secret\W*4321", re.IGNORECASE)
EVIDENCE_PER_CATEGORY = 3


def automated(cats: list[dict]) -> list[dict]:
    return [c for c in cats if not c.get("manual")]


def pick_tools(cats: list[dict], ids: list[str], include_slow: bool = False) -> list[str]:
    """The tools that exercise the chosen categories. The slow ones only when asked for."""
    wanted = {t for c in cats if c["id"] in ids for t in c.get("tools", [])}
    if not include_slow:
        wanted -= set(SLOW_TOOLS)
    return [t for t in TOOL_ORDER if t in wanted]


def mask(text: str, limit: int) -> str:
    text = SECRET.sub("[SECRET]", text or "").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "..."


def scan_result(rows: list[dict], cats: list[dict], label: str | None = None, ids: list[str] | None = None,
                guardrails: list[str] | None = None, docs: str | None = None) -> dict:
    """Category x guardrail counts and evidence for one scan label (or the whole log if label is None).

    docs: clean or poisoned forces one document set for every category; None or "auto" lets each category
    use its own (see attacks/owasp.json)."""
    if label:
        rows = [r for r in rows if r["tag"].partition(".")[2] == label]
    if guardrails:
        rows = [r for r in rows if guardrail_of(r["model"]) in guardrails]
    chosen = [c for c in cats if not ids or c["id"] in ids]
    seen = ordered({guardrail_of(r["model"]) for r in rows}, GUARDRAIL_ORDER)
    columns = guardrails or seen
    out = {"label": label, "guardrails": columns, "requests": len(rows), "categories": [], "gaps": []}
    for c in chosen:
        if c.get("manual"):
            out["gaps"].append({"id": c["id"], "name": c["name"], "note": c["manual"]})
            continue
        mode = docs if docs in MODES else c.get("docs", "clean")
        cells = {g: {"requests": 0, "successes": 0, "unsure": 0, "echo": 0} for g in columns}
        evidence = []
        for r in rows:
            if docs_of(r) != mode or not matches(c, r):
                continue
            g = guardrail_of(r["model"])
            cell = cells.setdefault(g, {"requests": 0, "successes": 0, "unsure": 0, "echo": 0})
            cell["requests"] += 1
            if echoed(c, r):
                cell["echo"] += 1        # the marker inside a longer answer: usually a harmless echo of a requested string
            elif not succeeded(c, r) and score(r)["verdict"] == "unsure":
                cell["unsure"] += 1      # something suspicious the plain checks cannot settle: read these replies
            if succeeded(c, r):
                cell["successes"] += 1
                if len(evidence) < EVIDENCE_PER_CATEGORY:
                    evidence.append({"guardrail": g, "tool": r["tag"].split(".")[0],
                                     "question": mask(r.get("question"), 200), "reply": mask(r.get("response"), 300),
                                     "blocked_by": r.get("blocked_by", "none")})
        total = sum(v["requests"] for v in cells.values())
        broken = [g for g, v in cells.items() if v["successes"]]
        if not total:
            verdict = "No matching requests yet."
        elif broken:
            verdict = "Attacks succeeded against: " + ", ".join(broken) + "."
        else:
            verdict = f"No successful attack found in {total} matching requests."
        out["categories"].append({"id": c["id"], "name": c["name"], "docs": mode, "cells": cells,
                                  "verdict": verdict, "evidence": evidence})
    return out


def to_markdown(result: dict) -> str:
    gs = result["guardrails"]
    lines = [f"# Scan {result['label'] or '(whole log)'}\n",
             f"{result['requests']} logged requests. Successes / matching requests per guardrail, from the "
             "deterministic checks in `attacks/owasp.json`; a count is not an attack success rate. \"Unsure\" replies look suspicious "
             "(part of the secret, a quoted poisoned note, an empty reply) but the checks cannot settle them: read them by hand. "
             "An \"echo\" is a marker word inside a longer answer, usually a string the user asked for: it is not counted as a success.\n",
             "| category | " + " | ".join(gs) + " |", "|---|" + "---|" * len(gs)]
    for c in result["categories"]:
        def note(cell):
            parts = [f"{cell[k]} {k}" for k in ("echo", "unsure") if cell.get(k)]
            return f" ({', '.join(parts)})" if parts else ""

        cells = [f"{c['cells'][g]['successes']}/{c['cells'][g]['requests']}" + note(c["cells"][g])
                 if c["cells"].get(g, {}).get("requests") else "-" for g in gs]
        lines.append(f"| {c['id']} {c['name']}{' (poisoned docs)' if c['docs'] == 'poisoned' else ''} | " + " | ".join(cells) + " |")
    lines.append("")
    for c in result["categories"]:
        lines += [f"## {c['id']} {c['name']}", c["verdict"], ""]
        for e in c["evidence"]:
            lines += [f"- **{e['tool']} on {e['guardrail']}** (stopped by: {e['blocked_by']})",
                      f"  - asked: {e['question']}", f"  - reply: {e['reply']}"]
        lines.append("")
    if result["gaps"]:
        lines += ["## No automated test yet", ""] + [f"- **{g['id']} {g['name']}**: {g['note']}" for g in result["gaps"]]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--label", help="Run label of the scan (default: the whole log)")
    parser.add_argument("--categories", help="Comma-separated ids, e.g. LLM01,LLM02 (default: all)")
    parser.add_argument("--docs", choices=MODES, help="Force one document set for every category (default: each its own)")
    parser.add_argument("--include-stub", action="store_true")
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    rows = [r for r in load_log(args.log) if args.include_stub or not r.get("stub")]
    ids = args.categories.split(",") if args.categories else None
    text = to_markdown(scan_result(rows, load_rules(), args.label, ids, None, args.docs))
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
