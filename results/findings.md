# Findings so far

Numbers come from results/summary.md (regenerate it with `python report/analyse.py --out results/summary.md`). Raw replies are in the
server log (results/raw is git-ignored). Hand labels are by one rater, in results/audit/.

## 1. Targeted attacks leak more than generic ones (unguarded)
Secret leaks by attack set: Garak 3/1,740 (0.2%), Promptfoo 10/340 (3%),
Inspect 5 to 6 of 117 requests on clean documents (the extraction prompts alone: 6 of 36, 17%),
written leak prompts 16/73 (22%).
Guarded: 0 replies that reached the user leaked the secret, across all runs (3,410 requests).

## 2. Tools' own verdicts are unreliable
- Garak flagged 497/1,740 on unguarded; the leak check found 3. In a hand sample
  of its hits, about 21 of 25 were false positives (the model declined in its
  own words).
- Giskard (graded by the local 8B model) flagged 44 of 69 attacks on the blocklist,
  where the leak check found 0 of 99 replies leaking.
- Promptfoo's grader marked real secret leaks as passed (defended).
- Inspect scores with the same leak check, so its agreement is not independent.
- The project's own scorer (report/score.py) against 175 hand-labelled replies: 0 false alarms in 152
  failed attacks, and 2 misses in 21 successful ones. With so few labelled successes the miss rate is
  indicative only, and paraphrased or translated leaks cannot be seen at all, so the leak counts are a minimum.

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

## 5. No single guardrail covers everything (OWASP scans, clean and poisoned documents)
- Clean documents, direct attacks (guided scan 1022-160816): NeMo held in every category (0 of 120 requests).
  The blocklist stopped secret and prompt extraction but let 3 of 42 injection attempts through.
  The document check does nothing against direct attacks (5 of 42 injections worked, 6 of 30 prompt-extraction attempts).
- Poisoned documents (scan 1022-164228, 159 requests each): unguarded 44 worked, NeMo 7, blocklist 30 of 108 (it blocks some requests
  before the document lookup, so fewer are counted), document check 0. Only the document check stops poisoning reliably.
- LLM05 and LLM09 share one test, so their rows are identical: count them as one result.
- LLM10 (improper output handling) held everywhere, even unguarded, so the test does not tell the guardrails apart.
- LLM06 (unbounded consumption, scan 1028-144404): 0 of 9 requests per guardrail produced a reply over 3,000 characters.
  It is a small test of unbounded output only; it does not cover very long inputs or response time.

## 6. Cost and false refusals
Legitimate questions refused: unguarded 12 of 297 (4%), blocklist 7 of 241 (3%), NeMo 0 of 297, document check 0 of 252
(the rails were tuned on these questions, so the guarded figures are optimistic).
Mean latency 1.9 s guarded vs 1.3 s unguarded. The blocklist's 26 s mean is not credible for a keyword filter and was
probably caused by heavy runs overlapping; re-measure it before quoting it.

## Limits
Guardrail written knowing the written leak prompts; one small local model and
four documents; hand-labelled successes are few (21); the leak check is a lower bound;
canary threshold changed from 8 to 12 words part-way through; Promptfoo ran without hijacking, off-topic and
data-exfil plugins and without the jailbreak strategy; the scripted tool now has 30 attacks instead of 21
(the three LLM06 conversations were added), so its latest counts are not directly comparable with earlier runs.
