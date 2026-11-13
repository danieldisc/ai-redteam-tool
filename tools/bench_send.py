"""Send test cases to a running Guardrail Bench app and save every reply.

Standard library only. Talks to the app's HTTP API, the same one the Chat page uses, so each case becomes a
recorded conversation in the app (they appear in its conversation list). It makes no paid call.

    python bench_send.py --cases PATH\\test_cases.jsonl --out results_dev

Options:
    --base URL      app address, default http://127.0.0.1:8766/api/v1
    --limit N       send only the first N cases (try 3 first)
    --multi         also send multi-turn cases (their later user turns, one after another); default is single-turn only
    --timeout S     seconds to wait for one turn to end, default 300
    --trace         also save each turn's recorded steps (tool calls, passages) in the result

Results go to OUT/results.jsonl, one line per case, written as each case ends. Run it again with the same
--out and finished cases are skipped. Stops at once if the app is not ready, replies are paused, or the
app goes away: carrying on would only record failures that say nothing about the chatbot.
"""

import argparse
import ast
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MESSAGE_MAX_CHARS = 4000  # the app's message limit (README of the development test cases)


class AppGone(RuntimeError):
    """The app cannot be reached or is not ready; stop the run."""


def call(base: str, method: str, path: str, body: dict | None = None, timeout: float = 30.0):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        base + path, data=data, method=method, headers={"content-type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw[:200].decode("utf-8", "replace")}
    except (urllib.error.URLError, OSError) as exc:
        raise AppGone(f"cannot reach the app at {base}: {exc}") from exc


def check_ready(base: str) -> None:
    status, launch = call(base, "GET", "/launch")
    if status != 200:
        raise AppGone(f"/launch answered {status}")
    if launch.get("replies_paused_reason_key"):
        raise AppGone(f"replies are paused: {launch['replies_paused_reason_key']} {launch.get('replies_paused_values')}")
    unfinished = [s["step_key"] for s in launch.get("steps", []) if s.get("state") != "done"]
    if unfinished:
        raise AppGone(f"the app has not finished launching: {unfinished}")


def wait_for_turn(base: str, conversation_id: str, turn_id: str, timeout: float) -> dict:
    """Poll the conversation until the turn has ended; return that turn's item."""
    deadline = time.monotonic() + timeout
    while True:
        status, body = call(base, "GET", f"/conversations/{conversation_id}")
        if status != 200:
            raise AppGone(f"GET conversation answered {status}: {body}")
        for turn in body["turns"]:
            if turn["turn_id"] == turn_id and turn["state"] == "ended":
                return turn
        if time.monotonic() > deadline:
            raise AppGone(f"turn {turn_id} did not end within {timeout:.0f} s")
        time.sleep(2)


def user_turns(case: dict) -> list[str]:
    """The case's first message, then its later user turns (the field may be a list or a Python-style string)."""
    turns = [case["message"]]
    later = case.get("later_turns") or []
    if isinstance(later, str):
        try:
            later = ast.literal_eval(later)
        except (ValueError, SyntaxError):
            later = []
    for item in later:
        if isinstance(item, dict) and item.get("role") == "user" and item.get("content"):
            turns.append(item["content"])
    return turns


def run_case(base: str, case: dict, multi: bool, timeout: float, trace: bool) -> dict:
    messages = user_turns(case) if multi else [case["message"]]
    record = {
        "test_case_id": case["test_case_id"],
        "harm": case.get("harm"),
        "turns_kind": case.get("turns"),
        "chat_as": case.get("chat_as") or "none",
        "source": case.get("source"),
        "source_tags": case.get("source_tags"),
        "source_expected_action": case.get("source_expected_action"),
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "conversation_id": None,
        "turns": [],
    }
    for index, message in enumerate(messages):
        if len(message) > MESSAGE_MAX_CHARS:
            record["turns"].append({"message": message[:200], "skipped": f"longer than {MESSAGE_MAX_CHARS} characters"})
            break
        if index == 0:
            status, body = call(base, "POST", "/conversations", {"chat_as": record["chat_as"], "message": message})
            if status == 201:
                record["conversation_id"] = body["conversation_id"]
        else:
            status, body = call(base, "POST", f"/conversations/{record['conversation_id']}/turns", {"message": message})
        if status != 201:
            record["turns"].append({"message": message, "refused": {"status": status, "body": body}})
            if status in (503, 409):
                raise AppGone(f"the app refused a send ({status}): {body}")
            break
        turn = wait_for_turn(base, record["conversation_id"], body["turn_id"], timeout)
        item = {
            "message": message,
            "outcome": turn["outcome"],
            "reply": turn["reply"],
            "reply_cut": turn["reply_cut"],
            "seen_by_chatbot": turn["seen_by_chatbot"],
            "started_at": turn["started_at"],
            "ended_at": turn["ended_at"],
        }
        if trace:
            t_status, t_body = call(base, "GET", f"/conversations/{record['conversation_id']}/turns/{body['turn_id']}")
            item["trace"] = t_body if t_status == 200 else {"status": t_status}
        record["turns"].append(item)
        if turn["outcome"] in ("error", "interrupted"):
            break
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--base", default="http://127.0.0.1:8766/api/v1")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--multi", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--trace", action="store_true")
    args = parser.parse_args()

    cases = [json.loads(line) for line in args.cases.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not args.multi:
        cases = [c for c in cases if c.get("turns") == "single"]
    if args.limit:
        cases = cases[: args.limit]
    args.out.mkdir(parents=True, exist_ok=True)
    results_path = args.out / "results.jsonl"
    done = set()
    if results_path.exists():
        done = {json.loads(line)["test_case_id"] for line in results_path.read_text(encoding="utf-8").splitlines() if line.strip()}

    try:
        check_ready(args.base)
        todo = [c for c in cases if c["test_case_id"] not in done]
        print(f"{len(cases)} cases selected, {len(done)} already done, {len(todo)} to send")
        for number, case in enumerate(todo, 1):
            record = run_case(args.base, case, args.multi, args.timeout, args.trace)
            with results_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            last = record["turns"][-1] if record["turns"] else {}
            print(f"[{number}/{len(todo)}] {case['test_case_id']} {case.get('harm')}: {last.get('outcome') or last.get('skipped') or 'refused'}")
    except AppGone as exc:
        print(f"STOPPED: {exc}", file=sys.stderr)
        return 1
    print(f"saved to {results_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
