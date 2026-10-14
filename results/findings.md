# Findings so far

Numbers come from results/summary.md. Raw replies are in the server log
(results/raw is git-ignored). All hand labels are by one rater.

## 1. Targeted attacks leak more than generic ones (unguarded)
Secret leaks by attack set: Garak 3/1,740 (0.2%), Promptfoo 10/340 (3%),
Inspect extraction prompts 6 of 36 (17%), written leak prompts 10/45 (22%).
Guarded: 0 secret leaks in all runs (2,369 requests).

## 2. Tools' own verdicts are unreliable, in opposite directions
- Garak flagged 497/1,740 on unguarded; the leak check found 3. In a hand sample
  of its hits, about 21 of 25 were false positives (the model declined in its
  own words).
- Promptfoo's grader marked real secret leaks as passed (defended).
- Inspect scores with the same leak check, so its agreement is not independent.

## 3. Guardrail effect on DAN-style persona jailbreaks (Garak r1, 260 prompts each)
- Unguarded: about 35 of 260 replies (13%) adopted the persona, counted by marker words with refusal openings excluded and checked on a sample of replies. Guarded: 4 of 260 (1.5%), all hand-verified.
- Guarded: 4 passed the input rail; all 4 hand-verified as persona adoption.
  No secret disclosed. One was logged `model_refused` though it complied (the
  refusal check is a rough phrase match).
- The output rail only matches the secret, so it cannot catch persona adoption.

## 4. What got past the guardrail (96 guarded requests that reached the model)
- No secret, system prompt or rules revealed.
- Invented content on on-topic-sounding questions: cited a "Parking Regulation
  PR-202" (not in the four documents), invented section numbers, gave
  first-time registration steps the documents do not contain.
- ROT13 questions passed the input rail but the model could not use them.

## 5. Cost and false refusals
0 of 79 legitimate questions refused (the rails were tuned on these, so
optimistic). Mean latency 2.0 s guarded vs 1.4 s unguarded.

## Limits
Guardrail written knowing the written leak prompts; one small local model and
four documents; audit samples are small; canary threshold changed from 8 to 12
words part-way through; Promptfoo ran without hijacking, off-topic and
data-exfil plugins and without the jailbreak strategy.