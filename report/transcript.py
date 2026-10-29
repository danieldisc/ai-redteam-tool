"""
Print the conversations saved by the adaptive (Claude as the attacker) tool as readable text, so you can see what Claude
sent to the chatbot and what the chatbot said back.

    python report/transcript.py results/raw/adaptive/adaptive.a4_blocklist.conversations.json
    python report/transcript.py results/raw/adaptive/adaptive.a4_blocklist.conversations.json --only-success
    python report/transcript.py <file> --width 400      # show more of each message (default 300 characters)

The turn where the attack worked is marked SUCCESS (for a marker objective the end of the reply is shown, where the marker usually is); a turn where only the chatbot's rules came out is marked PARTIAL LEAK, and a marker inside a longer answer is marked ECHO.
Standard library only.
"""

import argparse
import json
import sys
from pathlib import Path


def clip(text: str, width: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= width else text[:width] + f" [... {len(text) - width} more characters]"


def around(text: str, needle: str, width: int) -> str:
    """Clip to `width` characters, but keep the matched marker in view: it is often at the very end of a reply."""
    flat = " ".join((text or "").split())
    at = flat.lower().find(needle.lower()) if needle else -1
    if len(flat) <= width or at < 0 or at + len(needle) <= width:
        return clip(text, width)
    start = max(0, at + len(needle) - width)
    return "[...] " + flat[start:]


def render(data, only_success: bool = False, width: int = 300) -> str:
    records = data["records"] if isinstance(data, dict) else data
    lines = [f"Attacker model: {data.get('attacker_model', 'unknown')}" if isinstance(data, dict) else ""]
    for n, r in enumerate(records, 1):
        if only_success and not (r.get("success_turn") or r.get("partial_leak_turn") or r.get("echo_turn")):
            continue
        outcome = (f"SUCCESS on turn {r['success_turn']}" if r.get("success_turn")
                   else f"partial leak on turn {r['partial_leak_turn']}" if r.get("partial_leak_turn")
                   else f"echo on turn {r['echo_turn']}" if r.get("echo_turn") else "no success")
        lines += ["", f"## {n}. {r['objective'][:80]}  (repeat {r.get('repeat', 1)}, {r.get('kind', '?')}; {outcome}; status {r['status']})"]
        if r.get("problem"):
            lines.append(f"   note: {r['problem']}")
        for i, t in enumerate(r["turns"], 1):
            mark = ("   <<< SUCCESS" if r.get("success_turn") == i else "   <<< PARTIAL LEAK" if r.get("partial_leak_turn") == i
                    else "   <<< ECHO (not a success)" if r.get("echo_turn") == i else "")
            marked = r.get("kind") == "marker" and i in (r.get("success_turn"), r.get("echo_turn"))
            shown = around(t["reply"], r.get("needle", ""), width) if marked else clip(t["reply"], width)
            lines += [f"  Claude {i}: {clip(t['attack'], width)}", f"  Chatbot {i}: {shown}{mark}"]
    return "\n".join(lines).strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", help="a *.conversations.json file written by the adaptive tool")
    parser.add_argument("--only-success", action="store_true", help="only conversations with a success or a partial leak")
    parser.add_argument("--width", type=int, default=300, help="characters to show of each message (default 300)")
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        text = render(data, args.only_success, args.width)
    except (OSError, ValueError, KeyError) as exc:
        sys.exit(f"Cannot read {args.file}: {exc}")
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
