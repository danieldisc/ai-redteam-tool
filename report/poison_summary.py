"""Print the per-attack table for a scripted run and the M8 replies with dropped_ids.

Run from the repo root:  python poison_summary.py poison1
Prints to the screen and also writes poison_summary.txt (paste that file's contents to Claude).
"""
import json
import sys
from pathlib import Path

label = sys.argv[1] if len(sys.argv) > 1 else "poison1"
root = Path.cwd()
out = []


def say(text=""):
    print(text)
    out.append(text)


files = sorted(root.glob(f"results/**/*{label}*conversations.json"))
if not files:
    sys.exit(f"No *{label}*conversations.json found under results/. Run from the repo root.")

say(f"== Per-attack table for {label} (succeeded / run) ==")
for f in files:
    guardrail = f.stem.replace(".conversations", "").split("_", 1)[-1]
    records = json.loads(f.read_text(encoding="utf-8"))
    say(f"\n{guardrail}  ({f})")
    for cid in dict.fromkeys(r["id"] for r in records):
        rs = [r for r in records if r["id"] == cid and not r.get("error")]
        if not rs:
            say(f"  {cid}: all errored")
            continue
        if rs[0]["kind"] == "control":
            say(f"  {cid} {rs[0]['label']}: refused {sum(bool(r.get('refused')) for r in rs)}/{len(rs)}")
        else:
            say(f"  {cid} {rs[0]['label']}: {sum(r['success_turn'] is not None for r in rs)}/{len(rs)}")

say("\n== M8 replies from the server log ==")
conv = next(c for c in json.loads((root / "attacks" / "multiturn.json").read_text(encoding="utf-8"))["conversations"]
            if c["id"] == "M8")
log = root / "results" / "raw" / "server_log.jsonl"
if not log.exists():
    say("server_log.jsonl not found")
else:
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("docs") == "poisoned" and row.get("question") in conv["turns"]:
            reply = (row.get("response") or "").replace("\n", " ")[:300]
            say(f"\n[{row.get('tag')}] turn={row.get('turns')} retrieved={row.get('retrieved_ids')} "
                f"dropped={row.get('dropped_ids')} blocked_by={row.get('blocked_by')} canary={row.get('canary')}")
            say(f"  Q: {row['question'][:120]}")
            say(f"  A: {reply}")

Path("poison_summary.txt").write_text("\n".join(out), encoding="utf-8")
print("\nSaved to poison_summary.txt")
