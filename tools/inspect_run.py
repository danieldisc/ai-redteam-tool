"""
Inspect AI against the target (tasks in tools/inspect_tasks.py).

Inspect reaches the target through the small provider in tools/inspect_provider.py
(its built-in openai-api provider needs a newer openai package than Garak allows):
    model askdbc/askdbc-guarded, base URL http://127.0.0.1:8000/<tag>/v1

Tiers: smoke = 5 attacks + 3 questions, 1 epoch; standard = all, 3 epochs; full = all, 5 epochs.
(An epoch repeats every prompt, because one run of an LLM proves little.)

tool_flagged = attacks Inspect scored as SUCCEEDED (deterministic: canary or marker).
False refusals on legitimate questions are reported in the notes.
"""

from pathlib import Path

from common import base_url, confirm, model_for, summary

EPOCHS = {"smoke": 1, "standard": 3, "full": 5}
SMOKE_LIMIT = {"attacks_on_target": 5, "legitimate_questions": 3}


def run(target, tag, tier, url, outdir: Path, seed=1, yes=False) -> dict:
    from inspect_ai import eval as inspect_eval

    import inspect_tasks

    epochs = EPOCHS[tier]
    n_attacks = SMOKE_LIMIT["attacks_on_target"] if tier == "smoke" else len(inspect_tasks.ATTACKS)
    n_benign = SMOKE_LIMIT["legitimate_questions"] if tier == "smoke" else len(inspect_tasks.benign_questions())
    confirm(f"inspect {tier}: {n_attacks} attacks + {n_benign} legitimate questions x {epochs} epochs "
            f"= {(n_attacks + n_benign) * epochs} requests to the {target} target.", yes)

    import inspect_provider  # noqa: F401  (registers the "askdbc" model provider)

    log_dir = outdir / f"{tag}_{target}"
    log_dir.mkdir(parents=True, exist_ok=True)

    logs = []
    for name, task_fn in (("attacks_on_target", inspect_tasks.attacks_on_target),
                          ("legitimate_questions", inspect_tasks.legitimate_questions)):
        logs += inspect_eval(
            task_fn(), model=f"askdbc/{model_for(target)}", model_base_url=base_url(url, tag), epochs=epochs,
            limit=SMOKE_LIMIT[name] if tier == "smoke" else None,
            log_dir=str(log_dir), max_connections=1, display="plain",
        )

    notes, attempted, flagged = [], 0, 0
    for log in logs:
        if log.status != "success" or not log.samples:
            notes.append(f"{log.eval.task}: status {log.status}" + (f" ({log.error.message})" if log.error else ""))
            continue
        bad = sum(1 for s in log.samples if next(iter(s.scores.values())).value == "I")
        if log.eval.task == "attacks_on_target":
            attempted, flagged = len(log.samples), bad
            by_cat: dict[str, list[int]] = {}
            for s in log.samples:
                c = by_cat.setdefault(s.metadata["category"], [0, 0])
                c[0] += 1
                c[1] += next(iter(s.scores.values())).value == "I"
            notes.append("attacks succeeded by category: " + ", ".join(f"{k} {v[1]}/{v[0]}" for k, v in by_cat.items()))
        else:
            notes.append(f"legitimate questions refused or empty: {bad}/{len(log.samples)}")
    notes.append(f"{epochs} epoch(s); logs in {log_dir} (browse with: inspect view --log-dir {log_dir})")
    return summary("inspect", tag, target, tier, attempted, flagged, notes)
