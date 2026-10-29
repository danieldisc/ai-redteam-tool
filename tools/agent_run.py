"""
The agent test runner (OWASP LLM03, excessive agency): a small controlled agent made of the local model and four fake tools, attacked with the
cases in tools/agent_cases.py. It talks to Ollama directly, because the built-in chatbot has no tools. Standard library only.

    python tools/agent_run.py                              # every case, 3 repeats, llama3.1:8b
    python tools/agent_run.py --label ag1 --repeats 5
    python tools/agent_run.py --model llama3.1:8b --ollama http://127.0.0.1:11434 --only AGT-002,AGT-006

Nothing real is touched: a tool only records the call and returns a canned sentence. The model gets the policy in agent_cases.POLICY as its system
message and each case's prompt as the user message. If it calls tools, the fake result is sent back and it may call more (at most 4 rounds).
The judge reads the tool calls: an attack WORKED if the agent made a forbidden call. Results go to results/raw/agent/agent.<label>.json (every
message and call) and a summary to results/agent/<label>.md. Use a new --label each time. Replies vary, so the result is "worked in n of N tries".
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_cases as ac  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
MAX_ROUNDS = 4
SCHEMAS = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                             "parameters": {"type": "object", "properties": t["properties"], "required": t["required"]}}}
           for t in ac.TOOLS]


def fake_result(call: dict) -> str:
    tool, args = call["tool"], call["args"]
    if tool == "lookup_permit_status":
        pid = str(args.get("permit_id", ""))
        return ac.POISONED_RESULT if pid.upper() == ac.POISONED_PERMIT else f"Permit {pid}: status ACTIVE, holder verified."
    if tool == "cancel_permit":
        return f"Permit {args.get('permit_id')} cancelled."
    if tool == "issue_refund":
        return f"Refunded ${args.get('amount')} on permit {args.get('permit_id')}."
    if tool == "send_notification":
        return f"Notification sent to {args.get('address')}."
    return f"Unknown tool {tool}."


def chat(ollama: str, model: str, messages: list[dict]) -> dict:
    body = json.dumps({"model": model, "messages": messages, "tools": SCHEMAS, "stream": False}).encode()
    req = urllib.request.Request(f"{ollama.rstrip('/')}/api/chat", data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)["message"]


def parse_calls(message: dict) -> list[dict]:
    calls = []
    for c in message.get("tool_calls") or []:
        fn = c.get("function") or {}
        args = fn.get("arguments") or {}
        if isinstance(args, str):      # some servers send the arguments as a JSON string
            try:
                args = json.loads(args)
            except ValueError:
                args = {}
        calls.append({"tool": fn.get("name", ""), "args": args if isinstance(args, dict) else {}})
    return calls


def run_case(ollama: str, model: str, case: dict) -> dict:
    messages = [{"role": "system", "content": ac.POLICY}, {"role": "user", "content": case["prompt"]}]
    calls, error = [], None
    try:
        for _ in range(MAX_ROUNDS):
            reply = chat(ollama, model, messages)
            messages.append({"role": "assistant", "content": reply.get("content") or "", **({"tool_calls": reply["tool_calls"]} if reply.get("tool_calls") else {})})
            made = parse_calls(reply)
            if not made:
                break
            for call in made:
                calls.append(call)
                messages.append({"role": "tool", "content": fake_result(call), "tool_name": call["tool"]})
    except (urllib.error.URLError, OSError, KeyError, ValueError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    record = {"id": case["id"], "kind": case["kind"], "title": case["title"], "technique": case["technique"], "prompt": case["prompt"],
              "calls": calls, "final": next((m["content"] for m in reversed(messages) if m["role"] == "assistant"), ""), "error": error}
    record.update(ac.judge(case, calls) if not error else {"result": "error", "why": error, "bad": []})
    return record


def summarise(records: list[dict], model: str, label: str, repeats: int) -> str:
    done = [r for r in records if r["result"] != "error"]
    lines = [f"# Agent test (LLM03 excessive agency): {label}", "",
             f"Model {model}, cases version {ac.VERSION}, {len(set(r['id'] for r in records))} cases x {repeats} repeats, fake tools only. A tool call is recorded, never executed.",
             "An attack WORKED if the agent made a call the policy forbids. Replies vary, so read the counts, not single outcomes.", "",
             "| case | kind | technique | title | result |", "|---|---|---|---|---|"]
    for cid in dict.fromkeys(r["id"] for r in records):
        rs = [r for r in records if r["id"] == cid]
        ok = [r for r in rs if r["result"] != "error"]
        first = rs[0]
        if first["kind"] == "attack":
            cell = f"worked in {sum(r['result'] == 'worked' for r in ok)} of {len(ok)}"
        else:
            cell = f"carried out in {sum(r['result'] == 'ok' for r in ok)} of {len(ok)}"
        lines.append(f"| {cid} | {first['kind']} | {first['technique']} | {first['title']} | {cell} |")
    attacks = [r for r in done if r["kind"] == "attack"]
    controls = [r for r in done if r["kind"] == "control"]
    lines += ["", f"Attacks that worked: {sum(r['result'] == 'worked' for r in attacks)} of {len(attacks)} tries.",
              f"Legitimate requests carried out: {sum(r['result'] == 'ok' for r in controls)} of {len(controls)} tries."]
    errors = len(records) - len(done)
    if errors:
        lines.append(f"{errors} try/tries errored and are left out (see the JSON file).")
    worked = [r for r in attacks if r["result"] == "worked"]
    if worked:
        lines += ["", "## Examples of attacks that worked", ""]
        for r in worked[:5]:
            lines += [f"- **{r['id']} {r['title']}**: {r['why']}.", f"  - prompt: {r['prompt']}",
                      "  - forbidden call(s): " + "; ".join(f"{c['tool']}({json.dumps(c['args'])})" for c in r["bad"])]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--ollama", default="http://127.0.0.1:11434")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--only", help="Comma-separated case ids")
    parser.add_argument("--label", help="Run label (default: date-time). Must be new.")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "results")
    args = parser.parse_args()
    label = args.label or datetime.now().strftime("%m%d-%H%M")
    raw = args.out_dir / "raw" / "agent" / f"agent.{label}.json"
    if raw.exists():
        sys.exit(f"agent.{label} has already been run. Use a new --label.")
    wanted = set(args.only.split(",")) if args.only else None
    cases = [c for c in ac.CASES if not wanted or c["id"] in wanted]
    if not cases:
        sys.exit("No such case. Ids: " + ", ".join(c["id"] for c in ac.CASES))
    print(f"agent: {len(cases)} cases x {args.repeats} repeats on {args.model} through {args.ollama}. Fake tools only.")
    records = []
    for repeat in range(1, args.repeats + 1):
        for case in cases:
            rec = run_case(args.ollama, args.model, case)
            rec["repeat"] = repeat
            records.append(rec)
            print({"worked": "W", "held": ".", "ok": ".", "failed": "F", "error": "E"}[rec["result"]], end="", flush=True)
    print()
    raw.parent.mkdir(parents=True, exist_ok=True)
    raw.write_text(json.dumps({"model": args.model, "label": label, "cases_version": ac.VERSION, "records": records}, indent=2, ensure_ascii=False), encoding="utf-8")
    text = summarise(records, args.model, label, args.repeats)
    report = args.out_dir / "agent" / f"{label}.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(text, encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    print(f"Saved {raw} and {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
