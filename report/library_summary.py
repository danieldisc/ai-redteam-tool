"""
Which cases of the test library work? Reads the conversation files that tools/library_run.py saved and shows, for every case,
how often it succeeded against each guardrail, then sorts the cases into three groups:

    python report/library_summary.py --tag library.l2 --tag library.l3
    python report/library_summary.py --tag library.l2 --out results/library_summary.md

    never succeeded       the case did nothing against any guardrail (including the unguarded one): rewrite or remove it
    always succeeded      the case succeeded against every guardrail: it cannot tell them apart
    discriminating        succeeded against some guardrails and not others: these are the useful cases

A case counts for a guardrail only in the runs where it was actually run (cases for poisoned documents only run on poisoned targets).
A saved conversation is ignored, and counted as "stale", if its messages differ from the case's current text in attacks/library.json:
the case was changed after the run, so the result says nothing about the new text. Run the library again to get fresh results.
"Echo" means the marker word appeared inside a longer answer: it is shown but not counted as a success.
Files are read from results/raw/library/<tag>_<target>.conversations.json. Standard library only.
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBRARY = ROOT / "attacks" / "library.json"
RAW = ROOT / "results" / "raw" / "library"


def load_runs(tags: list[str], raw: Path = RAW) -> dict[str, list[dict]]:
    """target (with its tag) -> conversation records."""
    runs = {}
    for tag in tags:
        for path in sorted(raw.glob(f"{tag}_*.conversations.json")):
            target = re.sub(rf"^{re.escape(tag)}_", "", path.name.removesuffix(".conversations.json"))
            runs[f"{target} ({tag})"] = json.loads(path.read_text(encoding="utf-8"))
    return runs


def tally(cases: list[dict], runs: dict[str, list[dict]]) -> dict:
    """case id -> target -> {'n': conversations, 'success': n, 'echo': n, 'refused': n, 'stale': n}."""
    table = defaultdict(lambda: defaultdict(lambda: {"n": 0, "success": 0, "echo": 0, "refused": 0, "stale": 0}))
    turns = {c["id"]: c["turns"] for c in cases}
    for target, records in runs.items():
        for r in records:
            if r.get("error"):
                continue
            cell = table[r["id"]][target]
            if r["id"] in turns and r.get("turns") != turns[r["id"]]:
                cell["stale"] += 1       # the case was edited after this run
                continue
            cell["n"] += 1
            cell["success"] += r.get("success_turn") is not None
            cell["echo"] += r.get("success_turn") is None and r.get("echo_turn") is not None
            cell["refused"] += bool(r.get("refused"))
    return table


def group(table: dict, cases: list[dict]) -> dict[str, list[dict]]:
    out = {"never": [], "always": [], "discriminating": [], "not run": []}
    for c in cases:
        if c["kind"] != "attack":
            continue
        cells = {t: v for t, v in (table.get(c["id"]) or {}).items() if v["n"]}
        if not cells:
            out["not run"].append(c)
            continue
        hit = [t for t, v in cells.items() if v["success"]]
        out["never" if not hit else "always" if len(hit) == len(cells) else "discriminating"].append(c)
    return out


def render(cases: list[dict], runs: dict[str, list[dict]]) -> str:
    table, targets = tally(cases, runs), list(runs)
    groups = group(table, cases)
    attacks = [c for c in cases if c["kind"] == "attack"]
    stale = sum(v["stale"] for cells in table.values() for v in cells.values())
    lines = [f"# Test library: which cases work\n", f"{len(attacks)} attack cases, {len(targets)} run(s): " + ", ".join(targets) + "\n"]
    if stale:
        lines += [f"**{stale} saved conversation(s) were ignored because their case was changed after the run** (the messages no longer match "
                  "attacks/library.json). Cases with no current result are listed under \"Not run\". Run the library again to get fresh results.\n"]
    lines += [
             "| group | cases |", "|---|---|"] + [f"| {name} | {len(items)} |" for name, items in groups.items()] + [""]
    for name, text in (("never", "Never succeeded anywhere (rewrite or remove)"), ("always", "Succeeded against every guardrail (cannot tell them apart)"),
                       ("not run", "Not run in these files")):
        if groups[name]:
            lines += [f"## {text}", ""] + [f"- {c['id']} ({c['owasp']}, {c['technique']}): {c['title']}" for c in groups[name]] + [""]
    lines += ["## Every attack case", "", "| case | risk | technique | title | " + " | ".join(targets) + " |", "|---|---|---|---|" + "---|" * len(targets)]
    for c in attacks:
        cells = []
        for t in targets:
            v = table.get(c["id"], {}).get(t)
            cells.append("-" if not v or not v["n"] else f"{v['success']}/{v['n']}" + (f" (+{v['echo']} echo)" if v["echo"] else ""))
        lines.append(f"| {c['id']} | {c['owasp']} | {c['technique']} | {c['title']} | " + " | ".join(cells) + " |")
    by_tech = defaultdict(lambda: [0, 0])
    for c in attacks:
        for v in table.get(c["id"], {}).values():
            by_tech[c["technique"]][0] += v["success"]
            by_tech[c["technique"]][1] += v["n"]
    lines += ["", "## Successes by technique (all guardrails together)", "", "| technique | successes / conversations |", "|---|---|"]
    lines += [f"| {t} | {s}/{n} |" for t, (s, n) in sorted(by_tech.items(), key=lambda kv: -kv[1][0] / max(kv[1][1], 1))]
    controls = [c for c in cases if c["kind"] == "control"]
    if controls:
        lines += ["", "## Harmless questions refused (false refusals)", "", "| case | title | " + " | ".join(targets) + " |", "|---|---|" + "---|" * len(targets)]
        for c in controls:
            lines.append(f"| {c['id']} | {c['title']} | " + " | ".join(
                "-" if not table.get(c["id"], {}).get(t, {}).get("n") else f"{table[c['id']][t]['refused']}/{table[c['id']][t]['n']}" for t in targets) + " |")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tag", action="append", required=True, help="Run tag, e.g. library.l2 (repeat for several)")
    parser.add_argument("--raw", type=Path, default=RAW)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    runs = load_runs(args.tag, args.raw)
    if not runs:
        sys.exit(f"No conversation files for {args.tag} in {args.raw}. Run: python run.py library --target all --tier standard --run <label>")
    text = render(json.loads(LIBRARY.read_text(encoding="utf-8"))["cases"], runs)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
