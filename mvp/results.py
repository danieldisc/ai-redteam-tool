"""Groups the adapter log by brief and tool and writes one CSV. The adapter's flags are the verdict, not a tool's own mark.

    python mvp/results.py                    # reads results_adapter/, writes mvp/results.csv

One row per brief and tool: how many requests were sent, how many got a reply, and how many were flagged by each check.
A row with no flag is "not yet reviewed", not "safe": open the bench page or the log and read the replies.
"""
import argparse
import csv
import io
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "ui"))
import bench_data  # noqa: E402

FLAGS = ["rule1_breach", "rule2_breach", "hidden_context_leak", "tool_schema_leak", "declined"]
COLUMNS = ["brief", "threat", "variant", "tool", "requests", "replied"] + FLAGS + ["any_flag", "needs_review"]


def split_brief(brief: str) -> tuple:
    """'THR-008-owner_from_plate-OWN-007' gives ('THR-008', 'owner_from_plate'). Anything else gives ('', '')."""
    parts = brief.split("-")
    return (f"{parts[0]}-{parts[1]}", parts[2]) if len(parts) >= 4 and parts[0] == "THR" else ("", "")


def summarise(records: list) -> list:
    rows = {}
    for r in records:
        brief = r["label"].split(".", 1)[1] if "." in r["label"] else r["label"]
        row = rows.setdefault((brief, r["tool"]), dict.fromkeys(["requests", "replied"] + FLAGS, 0))
        row["requests"] += 1
        row["replied"] += r["outcome"] == "replied"
        for f in FLAGS:
            row[f] += bool(r["flags"].get(f))
    out = []
    for (brief, tool), row in sorted(rows.items()):
        threat, variant = split_brief(brief)
        flagged = any(row[f] for f in FLAGS[:4])
        out.append({"brief": brief, "threat": threat, "variant": variant, "tool": tool, **row, "any_flag": int(flagged),
                    "needs_review": "check the replies" if flagged else "not yet reviewed"})
    return out


GENERAL_COLUMNS = ["brief", "tool", "requests", "replied", "judged_breach", "judged_ok", "judged_unsure", "needs_review"]


def summarise_general(records: list, verdicts: list) -> list:
    """General mode: one row per objective and tool, counting the judge's verdicts. The judge is approximate, so any breach needs a person."""
    by_key = {v["key"]: v["verdict"] for v in verdicts}
    rows = {}
    for r in records:
        brief = r["label"].split(".", 1)[1] if "." in r["label"] else r["label"]
        row = rows.setdefault((brief, r["tool"]), dict.fromkeys(["requests", "replied", "judged_breach", "judged_ok", "judged_unsure"], 0))
        row["requests"] += 1
        row["replied"] += r["outcome"] == "replied"
        verdict = by_key.get(r["key"])
        if verdict:
            row["judged_" + verdict] += 1
    return [{"brief": brief, "tool": tool, **row,
             "needs_review": "read the breaches" if row["judged_breach"] else ("read the unsure ones" if row["judged_unsure"] else "no breach judged")}
            for (brief, tool), row in sorted(rows.items())]


def to_csv(rows: list, columns=None) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns or COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="results_adapter")
    ap.add_argument("--out", default=str(HERE / "results.csv"))
    ap.add_argument("--verdicts", help="general mode: the judge's verdicts.jsonl; groups by objective and counts breaches")
    ap.add_argument("--since", default="", help="only requests logged at or after this time")
    args = ap.parse_args()
    records = [r for r in bench_data.load_adapter_logs(Path(args.logs)) if r["ts"] >= args.since]
    if args.verdicts:
        verdicts = [json.loads(line) for line in Path(args.verdicts).read_text(encoding="utf-8").splitlines() if line.strip()]
        rows, columns = summarise_general(records, verdicts), GENERAL_COLUMNS
    else:
        rows, columns = summarise(records), None
    Path(args.out).write_text(to_csv(rows, columns), encoding="utf-8", newline="")
    print(to_csv(rows, columns))
    print(f"wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
