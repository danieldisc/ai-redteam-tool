"""
Pretty-print a Garak hitlog.jsonl file for manual review.

Usage:
    python tools/garak_hitlog.py results/raw/garak/garak_..._hitlog.jsonl
    python tools/garak_hitlog.py results/raw/garak/garak_..._hitlog.jsonl --probe dan.DanInTheWild
    python tools/garak_hitlog.py results/raw/garak/garak_..._hitlog.jsonl --limit 20 --sample
"""

import argparse
import json
import random


def load_hits(path):
    hits = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                hits.append(json.loads(line))
    return hits


def print_hit(hit, index):
    prompt_text = hit["prompt"]["turns"][0]["content"]["text"]
    output = hit.get("output", "")
    output_text = output.get("text", "") if isinstance(output, dict) else str(output)

    print(f"\n{'=' * 70}")
    print(f"[{index}] Probe: {hit.get('probe')}  |  Detector: {hit.get('detector')}  |  Score: {hit.get('score')}")
    print(f"Goal: {hit.get('goal')}")
    print(f"\n--- PROMPT ---\n{prompt_text[:500]}{'...' if len(prompt_text) > 500 else ''}")
    print(f"\n--- MODEL OUTPUT ---\n{output_text[:500]}{'...' if len(output_text) > 500 else ''}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hitlog_path", help="Path to the *_hitlog.jsonl file")
    parser.add_argument("--probe", help="Only show hits from this probe (e.g. dan.DanInTheWild)")
    parser.add_argument("--limit", type=int, default=10, help="Max number of hits to show")
    parser.add_argument("--sample", action="store_true", help="Show a random sample instead of the first N")
    args = parser.parse_args()

    hits = load_hits(args.hitlog_path)

    if args.probe:
        hits = [h for h in hits if h.get("probe") == args.probe]

    print(f"Total matching hits: {len(hits)}")

    if args.sample:
        hits = random.sample(hits, min(args.limit, len(hits)))
    else:
        hits = hits[: args.limit]

    for i, hit in enumerate(hits, 1):
        print_hit(hit, i)


if __name__ == "__main__":
    main()