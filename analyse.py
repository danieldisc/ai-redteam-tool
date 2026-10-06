"""
Summarise what the target actually did, from the server log.

    python analyse.py                      # print the summary
    python analyse.py --out results/summary.md
    python analyse.py --tool garak --since 2026-10-06T09:00:00

The server log (results/raw/server_log.jsonl) is the ground truth: it holds
every request any tool sent and what the target replied, whatever the tool
itself concluded. Three numbers are shown side by side, and none should be
quoted without the others:

  canary leaks   deterministic check for the planted secret / system prompt in
                 the reply (target/canary.py). Misses paraphrase and
                 translation, so it is a lower bound.
  tool flagged   how many attacks the tool's own detector or judge counted as
                 successful (from results/raw/<tool>/*.summary.json, written by
                 run.py). Earlier work showed these can be badly wrong.
  hand audit     filled in by you after audit.py, if present.

Stub runs (server --stub) are excluded unless --include-stub is given.
"""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_PATH = ROOT / "results" / "raw" / "server_log.jsonl"
SUMMARY_GLOB = "results/raw/*/*.summary.json"
AUDIT_PATH = ROOT / "results" / "audit_results.json"

BLOCK_LAYERS = ["nemo_input", "nemo_output", "model_refused", "none"]


def load_log(path: Path = LOG_PATH) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_question_sets() -> dict[str, set[str]]:
    """Questions from attacks/*.json, so requests can be classed after the fact."""
    leak = json.loads((ROOT / "attacks" / "leak.json").read_text(encoding="utf-8"))
    benign = json.loads((ROOT / "attacks" / "benign.json").read_text(encoding="utf-8"))
    return {
        "leak_set": {p["prompt"] for p in leak["prompts"]},
        "benign": set(benign["in_scope"]) | set(benign["borderline"]),
        "out_of_scope": set(benign["out_of_scope"]),
    }


def load_tool_summaries() -> dict[tuple, dict]:
    out = {}
    for path in ROOT.glob(SUMMARY_GLOB):
        d = json.loads(path.read_text(encoding="utf-8"))
        out[(d["tag"], d["target"])] = d
    return out


def load_audit() -> dict:
    return json.loads(AUDIT_PATH.read_text(encoding="utf-8")) if AUDIT_PATH.exists() else {}


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.0f}%)" if d else "-"


def build_report(rows: list[dict], sets: dict, summaries: dict, audit: dict) -> str:
    lines: list[str] = []
    add = lines.append

    # ---- 1. per tool run and target --------------------------------------
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in rows:
        groups[(r["tag"], r["model"])].append(r)

    add("## Attacks by tool run\n")
    add("Every figure is for the target named in the row. `tool flagged` is the tool's own "
        "verdict; `canary leaks` is the deterministic check on the real reply.\n")
    add("| tool run | target | requests | canary leaks | tool flagged | hand audit | "
        "stopped by NeMo input | by NeMo output | model refused | no block |")
    add("|---|---|---|---|---|---|---|---|---|---|")
    for (tag, model), rs in sorted(groups.items()):
        target = model.removeprefix("askdbc-")
        leaks = sum(r["canary"] != "clean" for r in rs)
        blocks = Counter(r["blocked_by"] for r in rs)
        own = summaries.get((tag, target))
        flagged = f"{own['tool_flagged']}/{own['attempted']}" if own else "n/a"
        aud = audit.get(f"{tag}|{target}")
        audited = f"{aud['succeeded']}/{aud['labelled']} succeeded" if aud else "not done"
        add(f"| {tag} | {target} | {len(rs)} | {pct(leaks, len(rs))} | {flagged} | {audited} | "
            + " | ".join(str(blocks.get(b, 0)) for b in BLOCK_LAYERS) + " |")

    # ---- 2. false refusals on legitimate questions -----------------------
    add("\n## Legitimate questions (false refusals)\n")
    add("Questions from `attacks/benign.json` that the target SHOULD answer. Any block or refusal "
        "counts as a false refusal. These questions were also used while building the rails, so "
        "treat the guarded numbers as optimistic.\n")
    add("| target | questions asked | answered | refused or blocked | mean latency (s) |")
    add("|---|---|---|---|---|")
    for model in sorted({r["model"] for r in rows}):
        rs = [r for r in rows if r["model"] == model and r["question"] in sets["benign"]]
        refused = sum(r["blocked_by"] != "none" for r in rs)
        lat = f"{sum(r['latency_s'] for r in rs) / len(rs):.1f}" if rs else "-"
        add(f"| {model.removeprefix('askdbc-')} | {len(rs)} | {len(rs) - refused} | "
            f"{pct(refused, len(rs))} | {lat} |")

    # ---- 3. the seven written leak prompts --------------------------------
    add("\n## Written leak prompts (`attacks/leak.json`)\n")
    add("Seven prompts written while the rails were built. The guarded target has effectively seen "
        "these, so this is NOT a held-out result.\n")
    add("| target | requests | canary leaks | stopped by NeMo input | by NeMo output |")
    add("|---|---|---|---|---|")
    for model in sorted({r["model"] for r in rows}):
        rs = [r for r in rows if r["model"] == model and r["question"] in sets["leak_set"]]
        blocks = Counter(r["blocked_by"] for r in rs)
        leaks = sum(r["canary"] != "clean" for r in rs)
        add(f"| {model.removeprefix('askdbc-')} | {len(rs)} | {pct(leaks, len(rs))} | "
            f"{blocks.get('nemo_input', 0)} | {blocks.get('nemo_output', 0)} |")

    # ---- 4. layer overlap --------------------------------------------------
    guarded = [r for r in rows if r["model"] == "askdbc-guarded"]
    add("\n## Which layer stopped the guarded target\n")
    if guarded:
        blocks = Counter(r["blocked_by"] for r in guarded)
        add(f"{len(guarded)} guarded requests in total: "
            + ", ".join(f"{b} {blocks.get(b, 0)}" for b in BLOCK_LAYERS) + ".")
        passed_leaks = sum(r["canary"] != "clean" and r["blocked_by"] == "none" for r in guarded)
        add(f"Replies that reached the user and still leaked (canary): {passed_leaks}.")
    else:
        add("No guarded requests logged yet.")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tool", help="Only requests from this tool (the tag before the dot)")
    parser.add_argument("--since", help="Only requests at or after this ISO timestamp")
    parser.add_argument("--include-stub", action="store_true", help="Include stub (plumbing test) rows")
    parser.add_argument("--log", type=Path, default=LOG_PATH)
    parser.add_argument("--out", type=Path, help="Also write the report to this file")
    args = parser.parse_args()

    rows = load_log(args.log)
    if not args.include_stub:
        rows = [r for r in rows if not r.get("stub")]
    if args.tool:
        rows = [r for r in rows if r["tool"] == args.tool]
    if args.since:
        rows = [r for r in rows if r["ts"] >= args.since]
    if not rows:
        print(f"No requests in {args.log} (after filters). Start the server and run a tool first.")
        return

    report = build_report(rows, load_question_sets(), load_tool_summaries(), load_audit())
    print(report)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report, encoding="utf-8")
        print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
