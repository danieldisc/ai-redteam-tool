"""
Run one attack tool against one target.

    python run.py garak     --target unguarded --tier smoke
    python run.py garak     --target guarded   --tier standard --run r1
    python run.py baseline  --target both      --tier smoke

Tools: baseline (built-in prompts), garak, giskard, inspect, pyrit, promptfoo
Targets: a guardrail id from the server (unguarded, guarded = NeMo, blocklist, doccheck), several
         separated by commas, `both` (unguarded and guarded) or `all`; run one after the other
Tiers: smoke (prove the wiring, about 10-40 requests), standard (the curated set),
       full (everything the curated set has, uncapped, more repeats)

The target server must already be running (python target/server.py). Each run
is tagged <tool>.<run label>; the label defaults to the date and time and must be new
for each run (so each tag in the log matches one run). After the
run, a summary is saved to results/raw/<tool>/<tag>_<target>.summary.json and
`python report/analyse.py` shows the target's side of it from the server log.

Run smoke first, read the responses (python report/audit.py <tag> <target> --show),
and only then run standard.
"""

import argparse
import importlib
import os
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))

# This is a restricted-network project: switch off usage reporting in the tools
# that have it, before any of them is imported.
for _var in ("DO_NOT_TRACK", "GISKARD_TELEMETRY_DISABLED", "PROMPTFOO_DISABLE_TELEMETRY", "PROMPTFOO_DISABLE_UPDATE"):
    os.environ.setdefault(_var, "1")

TOOLS = ["baseline", "garak", "giskard", "inspect", "pyrit", "promptfoo"]


def pick_targets(choice: str, available: list[str]) -> list[str]:
    """Turn --target into a list of guardrail ids, checked against what the server offers."""
    if choice == "both":
        return ["unguarded", "guarded"]
    if choice == "all":
        return available
    targets = choice.split(",")
    unknown = [t for t in targets if t not in available]
    if unknown:
        sys.exit(f"Unknown target {', '.join(unknown)}. The server offers: {', '.join(available)} (also both, all).")
    return targets


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tool", choices=TOOLS)
    parser.add_argument("--target", required=True,
                        help="guardrail id, comma-separated ids, both (unguarded + guarded) or all (as offered by the server)")
    parser.add_argument("--tier", choices=["smoke", "standard", "full"], default="smoke")
    parser.add_argument("--run", help="Run label (default: date-time). Must be new for this tool and target.")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Target server (default %(default)s)")
    parser.add_argument("--seed", type=int, default=1, help="Seed for tools that sample prompts (default 1)")
    parser.add_argument("--yes", action="store_true", help="Do not ask before a long run")
    args = parser.parse_args()

    from common import server_status

    status = server_status(args.url)
    if status.get("stub"):
        print("WARNING: the server is in --stub mode. Results are plumbing tests, not results.\n")

    available = [g["id"] for g in status.get("guardrails", [])] or ["unguarded", "guarded"]
    targets = pick_targets(args.target, available)

    try:
        module = importlib.import_module(f"{args.tool}_run")
    except ModuleNotFoundError as exc:
        sys.exit(f"The {args.tool} runner could not be loaded: {exc}")

    label = args.run or datetime.now().strftime("%m%d-%H%M")
    tag = f"{args.tool}.{label}"
    outdir = ROOT / "results" / "raw" / args.tool

    for target in targets:
        if (outdir / f"{tag}_{target}.summary.json").exists():
            sys.exit(f"{tag} on {target} has already been run. Use a new --run label so its requests stay separate in the log.")

    for target in targets:
        print(f"\n=== {args.tool} / {target} / {args.tier} / tag {tag} ===")
        result = module.run(target, tag, args.tier, args.url, outdir, args.seed, args.yes)
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / f"{tag}_{target}.summary.json"
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\n{args.tool} on {target}: attempted {result['attempted']}, "
              f"flagged by the tool itself {result['tool_flagged']}")
        for note in result["notes"]:
            print(f"  note: {note}")
        print(f"  saved {path.relative_to(ROOT)}")

    print(f"\nNext: python report/analyse.py --tool {args.tool}    and    python report/audit.py {tag} <target> --show")


if __name__ == "__main__":
    main()
