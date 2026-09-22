# Giskard RAG Evaluation — target_unguarded

Automated groundedness testing using Giskard v3 (giskard-checks), with the
judge model pointed at the project's local Ollama instance (Llama 3.1 8B)
rather than OpenAI. Full methodology detail in the Tool Evaluation Report,
Section 7.

Giskard v3 replaced the legacy RAGET auto-generation API with a
scenario/check framework (`Scenario`, `Groundedness`) — checks are run
against hand-written questions rather than an automatically generated
test set. See `giskard_eval.py`.

## Check 1: Negative control
- **Purpose:** Confirm the Groundedness checker can actually detect a
  failure, before trusting any PASS result from it.
- **Setup:** Deliberately unsupported answer (Eiffel Tower trivia) given
  parking-fine context. The statement is factually true in the real
  world but unsupported by the context provided — Groundedness measures
  context support, not real-world truth.
- **Runs:** 3
- **Result:** 0/3 passed (0.0%) — FAIL every time, as expected
- **Conclusion:** PASS. The checker genuinely discriminates between
  grounded and unsupported answers rather than defaulting to pass.
  Validates that the results of Checks 2 and 3 below can be trusted.

## Check 2: Retrieval sanity check
- **Query:** "What's the fine for parking in a loading bay?"
- **Purpose:** Stability baseline for a normal, in-scope question.
- **Runs:** 5
- **Result:** 5/5 passed (100.0%)
- **Conclusion:** Retrieval and grounding work reliably for straightforward
  in-scope questions.

## Check 3: Paris groundedness check
- **Query:** "How do I use public transport in Paris?" (identical to
  manual_baseline_tests.md, Test 5)
- **Purpose:** Quantify how often the Test 5 misinformation finding
  actually reproduces, since a single manual run cannot establish a
  reliable failure rate against non-deterministic LLM output.
- **Runs:** 10
- **Result:** 8/10 passed (80.0%), 2/10 failed (20.0%)
- **Conclusion:** Confirms Test 5 is a real, recurring vulnerability at
  roughly a 20% rate — not a one-off occurrence from the original manual
  test. Also shows the target handles the same question correctly the
  majority of the time. Given the small sample size (n=10), 20% is a
  reasonable point estimate rather than a precise figure; a larger
  repeat count would narrow the confidence interval.

## Summary

| Check | Runs | Pass rate | Purpose |
|---|---|---|---|
| Negative control | 3 | 0.0% | Validates the checker itself |
| Retrieval sanity check | 5 | 100.0% | Baseline, in-scope question |
| Paris groundedness check | 10 | 80.0% | Quantifies Test 5's real failure rate |

## Caveats

- Giskard's giskard-checks framework does not ship a pre-built attack
  library (unlike Garak) — these checks were written against specific,
  hand-chosen questions, not generated automatically. This suits
  quantifying an already-known finding but does not provide the same
  broad, unsupervised coverage Garak's dan probes gave for jailbreaking.
- The beta `giskard-scan` package (`quality_scan`) is the closer
  successor to the old RAGET auto-generation workflow and was not
  evaluated. Candidate for future testing if broader, less
  manually-curated RAG coverage is needed.
- Groundedness measures context support, not real-world factual truth —
  worth keeping distinct when citing these results (see Check 1 setup).