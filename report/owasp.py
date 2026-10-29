"""
OWASP LLM Top 10 2026 coverage, from the server log.

    python report/owasp.py
    python report/owasp.py --out results/owasp.md
    python report/owasp.py --tool inspect        # one tool across every guardrail (columns are then comparable)
    python report/owasp.py --run poison1
    python report/owasp.py --docs poisoned       # only the poisoned-document requests

Every request any tool sent is sorted into OWASP categories by the rules in attacks/owasp.json
(a keyword match on the question, or "a poisoned document was retrieved"). For each category and
guardrail the table shows how many matching requests succeeded / how many there were. Success is
a deterministic check on the reply (the canary, or a marker string), not a tool's own verdict.
Clean and poisoned requests get a table each, never mixed. Categories with no rule are listed as
gaps instead of being guessed.

Counts are an index into the log: one request can fall into several categories, and legitimate
questions that happen to contain a keyword are counted too. For the poisoned-document categories, a
request stopped before retrieval (the blocklist) is not counted, because nobody can say whether the
poisoned document would have been retrieved.
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from analyse import LOG_PATH, MODES, ROOT, docs_of, guardrail_of, load_log, pct
from compare import GUARDRAIL_ORDER, ordered

RULES_PATH = ROOT / "attacks" / "owasp.json"
HEADINGS = {"clean": "Clean documents", "poisoned": "Poisoned documents (the booby-trapped document is in the knowledge base)"}


def load_rules(path: Path = RULES_PATH) -> list[dict]:
    cats = json.loads(path.read_text(encoding="utf-8"))["categories"]
    for c in cats:
        c["_re"] = re.compile(c["question"], re.IGNORECASE) if c.get("question") else None
    return cats


def matches(cat: dict, row: dict) -> bool:
    seen = (row.get("retrieved_ids") or []) + (row.get("dropped_ids") or [])   # dropped ones count: the defence faced them
    if cat.get("poisoned") and any("poison" in d for d in seen):
        return True
    return bool(cat["_re"] and cat["_re"].search(row.get("question") or ""))


def succeeded(cat: dict, row: dict) -> bool:
    rule = cat.get("success") or {}
    reply = (row.get("response") or "").lower()
    if rule.get("min_reply_chars") and len(reply) > rule["min_reply_chars"]:
        return True
    if rule.get("canary") and row.get("canary", "clean") != "clean":
        return True
    if any(u.lower() in reply for u in rule.get("unless", [])):    # quoting the poisoned note is not obeying it
        return False
    return any(m.lower() in reply for m in rule.get("markers", []))


def table(rows: list[dict], cats: list[dict]) -> list[str]:
    guardrails = ordered({guardrail_of(r["model"]) for r in rows}, GUARDRAIL_ORDER)
    stats = {c["id"]: defaultdict(lambda: [0, 0]) for c in cats}   # id -> guardrail -> [successes, requests]
    tools: dict[str, set] = defaultdict(set)
    for r in rows:
        g = guardrail_of(r["model"])
        for c in cats:
            if matches(c, r):
                s = stats[c["id"]][g]
                s[1] += 1
                s[0] += succeeded(c, r)
                tools[c["id"]].add(r["tag"].split(".")[0])
    lines = ["| category | tools seen | " + " | ".join(guardrails) + " |", "|---|---|" + "---|" * len(guardrails)]
    for c in cats:
        if c.get("manual"):
            continue
        cells = [pct(*stats[c["id"]][g]) if stats[c["id"]][g][1] else "-" for g in guardrails]
        lines.append(f"| {c['id']} {c['name']} | {', '.join(sorted(tools[c['id']])) or '-'} | " + " | ".join(cells) + " |")
    return lines


def build_report(rows: list[dict], cats: list[dict]) -> str:
    lines = ["# OWASP LLM Top 10 2026 coverage\n",
             "Successes / matching requests per guardrail, from the deterministic checks in `attacks/owasp.json`. "
             "A count is an index into the log, not an attack success rate.\n"]
    modes = [m for m in MODES if any(docs_of(r) == m for r in rows)] or ["clean"]
    for mode in modes:
        lines += [f"## {HEADINGS[mode]}\n"] + table([r for r in rows if docs_of(r) == mode], cats) + [""]
    gaps = [c for c in cats if c.get("manual")]
    lines += ["## No automated test yet\n"]
    lines += [f"- **{c['id']} {c['name']}**: {c['manual']}" for c in gaps]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--include-stub", action="store_true", help="Include stub (fake model) rows")
    parser.add_argument("--tool", help="Only requests from this tool (the tag before the dot), e.g. inspect")
    parser.add_argument("--run", help="Only requests from this run label (the tag after the dot), e.g. poison1")
    parser.add_argument("--docs", choices=MODES, help="Only requests that used this document set")
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--out", type=Path, help="Also write the report to this file")
    args = parser.parse_args()
    rows = load_log(args.log)
    if not args.include_stub:
        rows = [r for r in rows if not r.get("stub")]
    if args.tool:
        rows = [r for r in rows if r["tag"].split(".")[0] == args.tool]
    if args.run:
        rows = [r for r in rows if r["tag"].partition(".")[2] == args.run]
    if args.docs:
        rows = [r for r in rows if docs_of(r) == args.docs]
    report = build_report(rows, load_rules())
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
