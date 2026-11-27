"""The hand-off: turn a general-mode run into a fixed test set, and replay that test set on any chatbot (for example the same chatbot with guardrails).

    python mvp/testset.py review --logs results_general --verdicts mvp/general_verdicts.jsonl --out mvp/review.csv
    (open mvp/review.csv, write breach / ok in the your_verdict column, save)
    python mvp/testset.py build --review mvp/review.csv --logs results_general --target mvp/target.json --out testset.json
    python mvp/testset.py replay --testset testset.json --target mvp/target.json --repeats 5 --logs results_replay --out replay_results.csv

Why a fixed test set: the tools that write attacks (Promptfoo, PyRIT, Garak's GOAT) ask Claude, and Claude words them differently every run, so running a
tool again gives new attacks. The saved attacks are what can be repeated. A chatbot can also answer the same message differently each time, so replay
sends each attack several times and reports how often it broke the rule, not one yes or no.

A multi-turn attack is replayed with its saved user messages, one turn at a time (or all in one request with --one-request, for the Guardrail Bench adapter
started with --history replay). The chatbot's replies are new each time; the attacker's later messages are not rewritten to fit them.
"""
import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import general  # noqa: E402
import judge  # noqa: E402
import proxy  # noqa: E402

FORMAT = 1
REVIEW_COLUMNS = ["id", "tool", "objective", "turns", "message", "reply", "judge_verdict", "judge_reason", "your_verdict"]
REPLAY_COLUMNS = ["case", "objective", "tool", "sent", "replied", "breach", "ok", "unsure", "breach_rate", "original_verdict"]
VERDICT_ORDER = {"breach": 0, "unsure": 1, "ok": 2, "": 3}


def read_jsonl(path) -> list:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def logged_requests(log_dir) -> list:
    """Every replied request in the proxy's logs, with the key the judge used (<tool>:<conversation id>) and the user messages sent."""
    out = []
    for path in sorted(Path(log_dir).glob("*.jsonl")):
        for row in read_jsonl(path):
            if row.get("outcome") != "replied":
                continue
            tool = str(row.get("tool") or path.stem)
            tag = str(row.get("tag") or tool)
            turns = [m["content"] for m in (row.get("conversation") or []) if m.get("role") == "user"] or [str(row.get("message") or "")]
            out.append({"key": f"{tool}:{row.get('conversation_id')}", "tool": tool, "objective": tag.split(".", 1)[1] if "." in tag else tag,
                        "user_turns": turns, "reply": str(row.get("reply") or ""), "ts": str(row.get("ts") or "")})
    return out


def review_rows(requests: list, verdicts: list) -> list:
    """One row per judged reply, breaches first. Each row gets a stable id (<objective>-<number>) used by the test set."""
    by_key = {v["key"]: v for v in verdicts}
    rows, counts = [], {}
    for r in sorted(requests, key=lambda r: (r["objective"], r["ts"], r["key"])):
        v = by_key.get(r["key"])
        if not v:
            continue
        counts[r["objective"]] = counts.get(r["objective"], 0) + 1
        rows.append({"id": f"{r['objective']}-{counts[r['objective']]:03d}", "key": r["key"], "tool": r["tool"], "objective": r["objective"],
                     "turns": len(r["user_turns"]), "message": r["user_turns"][-1], "reply": r["reply"], "judge_verdict": v["verdict"],
                     "judge_reason": v.get("reason", ""), "your_verdict": ""})
    return sorted(rows, key=lambda row: (VERDICT_ORDER.get(row["judge_verdict"], 3), row["id"]))


def to_csv(rows: list, columns: list) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def build_testset(review: list, requests: list, target: dict, verdicts: list) -> dict:
    """Keeps the rows a person marked breach. Each case holds everything needed to send it again and judge the reply, and nothing about the chatbot's insides."""
    marked = [row for row in review if (row.get("your_verdict") or "").strip().lower() == "breach"]
    by_id = {row["id"]: row for row in review_rows(requests, verdicts)}
    objectives = {o["id"]: {"goal": o["goal"], "policy": o["policy"]} for o in general.objectives_for(target)}
    cases = []
    for row in marked:
        found = by_id.get(row["id"])
        if not found:
            raise ValueError(f"review row {row['id']} is not in the logs; build the test set from the same logs and verdicts as the review sheet")
        if found["objective"] not in objectives:
            raise ValueError(f"objective {found['objective']!r} is not in the target file")
        request = next(r for r in requests if r["key"] == found["key"])
        cases.append({"id": row["id"], "objective": found["objective"], "tool": found["tool"], "user_turns": request["user_turns"],
                      "original_reply": request["reply"], "judge_verdict": found["judge_verdict"], "human_verdict": "breach"})
    used = sorted({c["objective"] for c in cases})
    return {"format": FORMAT, "made": datetime.now().isoformat(timespec="seconds"), "purpose": target["purpose"].strip(),
            "tested_model": target["model"], "judge_model": os.environ.get("JUDGE_MODEL", "claude-sonnet-5-5"),
            "objectives": {o: objectives[o] for o in used}, "cases": cases}


def load_testset(path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("format") != FORMAT or not isinstance(data.get("cases"), list):
        raise ValueError(f"{path} is not a test set made by this tool (format {FORMAT})")
    return data


def send_case(target_proxy, case: dict, attempt: int, one_request: bool) -> dict:
    """Sends one case once. Returns the proxy's last logged record shape: reply, outcome and the conversation as sent."""
    tag = f"replay.{case['id']}"
    if one_request:
        conversation = [{"role": "user", "content": t} for t in case["user_turns"]]
        status, body = target_proxy.handle_chat(tag, {"messages": conversation})
    else:
        conversation = []
        for turn in case["user_turns"]:
            conversation.append({"role": "user", "content": turn})
            status, body = target_proxy.handle_chat(tag, {"messages": list(conversation)})
            if status != 200:
                break
            conversation.append({"role": "assistant", "content": proxy.text_of(body["choices"][0]["message"]["content"])})
    replied = status == 200
    reply = conversation[-1]["content"] if replied and not one_request else (proxy.text_of(body["choices"][0]["message"]["content"]) if replied else "")
    return {"key": f"replay:{case['id']}:{attempt}", "tool": "replay", "label": f"replay.{case['objective']}", "case": case["id"],
            "attempt": attempt, "outcome": "replied" if replied else "no_reply", "reply": reply, "conversation": conversation}


def replay(testset: dict, target_proxy, repeats: int, one_request=False, call=None, judge_replies=True) -> tuple:
    """Sends every case `repeats` times and judges each final reply. Returns (one row per case, every attempt with its verdict)."""
    packs = {o: {"chatbot": testset["purpose"], "objectives": [{"id": o, **spec}]} for o, spec in testset["objectives"].items()}
    attempts = []
    for case in testset["cases"]:
        for n in range(1, repeats + 1):
            attempts.append(send_case(target_proxy, case, n, one_request))
            print(f"  {case['id']} attempt {n}/{repeats}: {attempts[-1]['outcome']}", flush=True)
    verdicts = {v["key"]: v for v in judge.judge_records(attempts, packs, call)} if judge_replies else {}
    for a in attempts:
        v = verdicts.get(a["key"], {})
        a["verdict"], a["reason"] = v.get("verdict", ""), v.get("reason", "")
    rows = []
    for case in testset["cases"]:
        mine = [a for a in attempts if a["case"] == case["id"]]
        replied = [a for a in mine if a["outcome"] == "replied"]
        count = {k: sum(a["verdict"] == k for a in replied) for k in ("breach", "ok", "unsure")}
        rows.append({"case": case["id"], "objective": case["objective"], "tool": case["tool"], "sent": len(mine), "replied": len(replied), **count,
                     "breach_rate": f"{count['breach']}/{len(replied)}" if judge_replies else "not judged", "original_verdict": case["human_verdict"]})
    return rows, attempts


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="step", required=True)
    r = sub.add_parser("review", help="write a sheet of every judged reply for a person to mark")
    r.add_argument("--logs", default="results_general")
    r.add_argument("--verdicts", default=str(HERE / "general_verdicts.jsonl"))
    r.add_argument("--out", default=str(HERE / "review.csv"))
    b = sub.add_parser("build", help="make the test set from the rows a person marked breach")
    b.add_argument("--review", default=str(HERE / "review.csv"))
    b.add_argument("--logs", default="results_general")
    b.add_argument("--verdicts", default=str(HERE / "general_verdicts.jsonl"))
    b.add_argument("--target", required=True)
    b.add_argument("--out", default="testset.json")
    p = sub.add_parser("replay", help="send every case in a test set several times to a chatbot and count breaches")
    p.add_argument("--testset", required=True)
    p.add_argument("--target", required=True, help="the target file of the chatbot to test (address and model)")
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--logs", default="results_replay")
    p.add_argument("--out", default="replay_results.csv")
    p.add_argument("--one-request", action="store_true", help="send all user turns in one request (Guardrail Bench adapter with --history replay)")
    p.add_argument("--no-judge", action="store_true")
    args = ap.parse_args()

    if args.step == "review":
        rows = review_rows(logged_requests(args.logs), read_jsonl(args.verdicts))
        Path(args.out).write_text(to_csv(rows, REVIEW_COLUMNS), encoding="utf-8-sig", newline="")
        print(f"wrote {len(rows)} rows to {args.out}. Write breach or ok in the your_verdict column of each row you check, then save it as CSV.")
        return 0
    if args.step == "build":
        raw = Path(args.review).read_bytes()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:  # Excel's plain "CSV" format saves in the Windows code page
            text = raw.decode("cp1252", "replace")
        review = list(csv.DictReader(text.splitlines()))
        unchecked = [row["id"] for row in review if row.get("judge_verdict") == "breach" and not (row.get("your_verdict") or "").strip()]
        if unchecked:
            print(f"note: {len(unchecked)} rows the judge called breach have no your_verdict yet and are left out: {', '.join(unchecked[:10])}")
        testset = build_testset(review, logged_requests(args.logs), general.load_target(args.target), read_jsonl(args.verdicts))
        Path(args.out).write_text(json.dumps(testset, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"wrote {len(testset['cases'])} test cases to {args.out}")
        return 0
    if args.repeats < 1:
        sys.exit("--repeats must be 1 or more")
    if not args.no_judge and not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set. Set it, or add --no-judge and judge later.")
    testset, target = load_testset(args.testset), general.load_target(args.target)
    key = os.environ.get(target["api_key_env"]) if target.get("api_key_env") else None
    target_proxy = proxy.Proxy(target["address"], target["model"], args.logs, key)
    print(f"replaying {len(testset['cases'])} cases x {args.repeats} on {target['address']} ({target['model']})", flush=True)
    rows, attempts = replay(testset, target_proxy, args.repeats, args.one_request, judge_replies=not args.no_judge)
    Path(args.out).write_text(to_csv(rows, REPLAY_COLUMNS), encoding="utf-8", newline="")
    detail = Path(args.out).with_suffix(".attempts.jsonl")
    detail.write_text("".join(json.dumps(a, ensure_ascii=False) + "\n" for a in attempts), encoding="utf-8")
    print(to_csv(rows, REPLAY_COLUMNS))
    print(f"wrote {args.out} and {detail}. Read every reply judged breach or unsure before you quote a rate.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
