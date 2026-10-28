"""
How accurate is the scoring layer? Compare it with your own hand labels.

    python report/score_check.py                       # every labelled sample in results/audit/
    python report/score_check.py results/audit/garak.r1_unguarded.json
    python report/score_check.py --out results/score_check.md

report/audit.py lets you label a random sample of real replies: s (the attack worked), f (it failed) or a (ambiguous).
This reads those labels, scores the same replies with report/score.py (without looking at the label) and counts where
the two disagree:

    missed       you said the attack worked, the scorer said held        (a false negative: the dangerous one)
    false alarm  you said it failed, the scorer said worked             (a false positive)
    unsure       the scorer could not decide; each one is a reply to read by hand

With few hand-labelled successes the miss rate is not reliable: the tool says so. Label until you have 30 or more.
A scorer that was tuned while looking at the same samples will look better on them than on new replies, so label a fresh
sample before quoting the numbers. One rater only: two raters would show how much people disagree.
"""

import argparse
import json
from collections import Counter
from pathlib import Path

from analyse import ROOT
from score import score

AUDIT_DIR = ROOT / "results" / "audit"
LABELS = {"s": "attack worked", "f": "attack failed", "a": "ambiguous"}
VERDICTS = ("worked", "unsure", "held")
MIN_SUCCESSES = 30


def load_labelled(paths: list[Path]) -> list[dict]:
    items = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("labels"), list):
            for x in data["labels"]:
                if x.get("label") in LABELS and "response" in x:
                    items.append({**x, "file": path.name})
    return items


def confusion(items: list[dict]) -> tuple[Counter, list[dict]]:
    counts, scored = Counter(), []
    for x in items:
        s = score({"response": x["response"], "canary": x.get("canary"), "question": x.get("question")})
        counts[(x["label"], s["verdict"])] += 1
        scored.append({**x, "scored": s})
    return counts, scored


def build_report(items: list[dict]) -> str:
    if not items:
        return "# Scorer against hand labels\n\nNo hand labels yet. Label a sample first: `python report/audit.py <tag> <target> --n 25`.\n"
    counts, scored = confusion(items)
    n = len(items)
    humans = {k: sum(v for (h, _), v in counts.items() if h == k) for k in LABELS}
    lines = ["# Scorer against hand labels\n",
             f"{n} replies labelled by hand ({len(set(x['file'] for x in items))} sample file(s)), then scored by `report/score.py` "
             "without looking at the label.\n",
             "| you said | scorer: worked | scorer: unsure | scorer: held | total |", "|---|---|---|---|---|"]
    for k, name in LABELS.items():
        lines.append(f"| {name} | " + " | ".join(str(counts[(k, v)]) for v in VERDICTS) + f" | {humans[k]} |")
    missed, alarms = counts[("s", "held")], counts[("f", "worked")]
    lines += ["", f"- **Missed** (you said worked, scorer said held): **{missed} of {humans['s']}**",
              f"- **False alarms** (you said failed, scorer said worked): **{alarms} of {humans['f']}**",
              f"- **Unsure** replies to read by hand: {sum(v for (_, s), v in counts.items() if s == 'unsure')}"]
    if humans["s"] < MIN_SUCCESSES:
        lines.append(f"\n**Too few hand-labelled successes ({humans['s']}) to trust the miss rate.** Aim for {MIN_SUCCESSES} or more: "
                     "attacks that worked are rare in a random sample, so label more replies, or label the ones the tools flagged.")
    problems = [x for x in scored if (x["label"] == "s" and x["scored"]["verdict"] == "held") or (x["label"] == "f" and x["scored"]["verdict"] == "worked")]
    if problems:
        lines += ["", "## Disagreements to read\n"]
        for x in problems[:10]:
            lines += [f"- {x['file']}: you said **{LABELS[x['label']]}**, scorer said **{x['scored']['verdict']}** ({x['scored']['reason']})",
                      f"  - asked: {(x.get('question') or '')[:140]}", f"  - reply: {(x.get('response') or '').replace(chr(10), ' ')[:240]}"]
    lines += ["", "One rater only. A scorer tuned on these same samples looks better here than it will on new replies.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="*", type=Path, help="label files (default: every results/audit/*.json)")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    paths = args.files or sorted(AUDIT_DIR.glob("*.json"))
    text = build_report(load_labelled(paths))
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
