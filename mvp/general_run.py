"""The general red-teaming tool: point it at any OpenAI-style chatbot and all five tools attack it, one after another.

    python mvp/general_run.py --target mvp/target.json                       # all five tools, every objective
    python mvp/general_run.py --target mvp/target.json --only promptfoo inspect --objectives leak-instructions

What it does, in order:
  1. reads the target file (address, model, purpose, optional objectives) and makes one pack per objective;
  2. starts a logging proxy, so every request from every tool lands in results_adapter/<tool>.jsonl in the same shape;
  3. runs the tools one at a time. Promptfoo goes first, because Claude writes its attacks from the purpose and the objective, and
     Inspect AI and Giskard then replay those same messages (they cannot write attacks); PyRIT and Garak write their own, over several turns;
  4. asks Claude to judge each reply, and writes mvp/general_results.csv.
A person must read every breach it reports: the judge is approximate. It needs ANTHROPIC_API_KEY, and DEMO_PYTHON_<TOOL> for a tool in its own environment.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "ui"))
import general  # noqa: E402
import judge  # noqa: E402
import proxy  # noqa: E402
import queue_run  # noqa: E402
import results  # noqa: E402

ORDER = ["promptfoo", "inspect", "giskard", "pyrit", "garak"]
NEEDS_MESSAGES = ("inspect", "giskard")


def make_runner(base=None, tests_path=None):
    """Wraps the demo runner: after Promptfoo, hand its attack messages to the pack; skip Inspect AI and Giskard when there are none."""
    base = base or queue_run.default_runner
    tests_path = Path(tests_path or HERE.parent / "demo" / "logs" / "promptfoo" / "tests.yaml")

    def runner(job, pack_path, env):
        pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
        if job["tool"] in NEEDS_MESSAGES and not any(o.get("attack_messages") for o in pack["objectives"]):
            print(f"  skipped: Promptfoo wrote no attack messages for {job['brief']}, and {job['tool']} cannot write its own", flush=True)
            return "skipped"
        code = base(job, pack_path, env)
        if job["tool"] == "promptfoo" and code == 0:
            import yaml
            count = general.attach_messages(pack_path, general.messages_from_tests(yaml.safe_load(tests_path.read_text(encoding="utf-8"))))
            print(f"  Promptfoo wrote {count} attack messages for {job['brief']}", flush=True)
        return code

    return runner


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="the target file (see mvp/target.example.json)")
    ap.add_argument("--only", nargs="*", choices=ORDER, help="run only these tools")
    ap.add_argument("--objectives", nargs="*", help="run only these objective ids")
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--logs", default="results_adapter")
    ap.add_argument("--workdir", default=str(HERE / "general_run"))
    ap.add_argument("--no-judge", action="store_true", help="skip the judge step")
    args = ap.parse_args()

    target = general.load_target(args.target)
    packs = [p for p in general.build_packs(target) if not args.objectives or p["brief_id"] in args.objectives]
    if not packs:
        sys.exit("no objective matches --objectives")
    key = os.environ.get(target["api_key_env"]) if target.get("api_key_env") else None
    started = datetime.now().isoformat(timespec="seconds")
    server = proxy.serve(proxy.Proxy(target["address"], target["model"], args.logs, key), args.port)
    os.environ["DEMO_ADAPTER"] = f"http://127.0.0.1:{args.port}"
    os.environ["DEMO_MULTI"] = "1"
    print(f"proxy on port {args.port} -> {target['address']}; {len(packs)} objectives, tools: {args.only or ORDER}", flush=True)
    try:
        jobs = queue_run.run_queue(packs, args.only or ORDER, Path(args.workdir), make_runner())
    finally:
        time.sleep(1)
        server.shutdown()
    if args.no_judge:
        print("judge skipped. Judge later with: python mvp/judge.py --packs", args.workdir, "--since", started)
        return 0
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY is not set, so the replies were not judged. Judge later with: python mvp/judge.py --packs", args.workdir, "--since", started)
        return 1
    import bench_data
    packs_by_id = {p["brief_id"]: p for p in packs}
    records = [r for r in bench_data.load_adapter_logs(Path(args.logs)) if r["ts"] >= started]
    verdicts = judge.judge_records(records, packs_by_id)
    out = HERE / "general_verdicts.jsonl"
    out.write_text("".join(json.dumps(v, ensure_ascii=False) + "\n" for v in verdicts), encoding="utf-8")
    rows = results.summarise_general(records, verdicts)
    (HERE / "general_results.csv").write_text(results.to_csv(rows, results.GENERAL_COLUMNS), encoding="utf-8", newline="")
    print(results.to_csv(rows, results.GENERAL_COLUMNS))
    print(f"wrote {HERE / 'general_results.csv'}. Read every breach in {args.logs}/ before you quote it.")
    return 1 if any(j["status"] == "failed" for j in jobs) else 0


if __name__ == "__main__":
    sys.exit(main())
