"""Groups the adapter log by brief and tool and writes one CSV. The adapter's flags are the verdict, not a tool's own mark.

    python mvp/results.py                    # reads results_adapter/, writes mvp/results.csv

One row per brief and tool: how many requests were sent, how many got a reply, and how many were flagged by each check.
A row with no flag is "not yet reviewed", not "safe": open the bench page or the log and read the replies.
"""
import argparse
import csv
import io
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


def to_csv(rows: list) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="results_adapter")
    ap.add_argument("--out", default=str(HERE / "results.csv"))
    args = ap.parse_args()
    rows = summarise(bench_data.load_adapter_logs(Path(args.logs)))
    Path(args.out).write_text(to_csv(rows), encoding="utf-8", newline="")
    print(to_csv(rows))
    print(f"wrote {len(rows)} rows to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
