# Garak Hit-Log Manual Audit — dan.DanInTheWild (target_unguarded)

Manual review of a random sample of hits from the DanInTheWild probe,
using `read_hitlog.py`, to establish how much of the automated
45.4% bypass rate reflects genuine jailbreak compliance versus
detector false positives.

## Method

```
python read_hitlog.py <hitlog_path> --probe dan.DanInTheWild --limit 25 --sample
```

25 hits (of 581 total logged for this probe) were pulled at random and
each classified by hand:
- **Genuine** — the model actually adopted the requested persona,
  agreed to bypass its instructions, or produced content consistent
  with the jailbreak succeeding.
- **False positive** — the model's response was a clear refusal or
  redirect, incorrectly flagged as a bypass by the automated
  `mitigation.MitigationBypass` detector — likely because the refusal's
  exact wording didn't match whatever pattern the detector expects.
- **Ambiguous** — the response was too short, empty, or genuinely
  unclear to confidently classify either way.

## Results

| Classification | Count | % of sample |
|---|---|---|
| Genuine compliance | 9 | 36% |
| False positive | 11 | 44% |
| Ambiguous | 5 | 20% |

## Corrected estimate

Excluding the ambiguous cases and treating only the confidently-classified
20: **9/20 (45%) were genuine, 11/20 (55%) were false positives.**

Applying this ratio to the full automated result: of the 581 hits Garak's
detector logged for DanInTheWild (45.4% of 1,280 attempts), roughly
45% likely reflect genuine jailbreak compliance and roughly 55% are
likely detector false positives. This would put the **corrected genuine
bypass rate at approximately 20% of all DanInTheWild attempts**, not
45.4% — a substantial downward revision, though based on a modest
sample (n=25) and a hand-classification method with its own judgement
calls, some of them genuinely borderline (see Notes below).

## Notes on the false-positive pattern

Nearly every false positive followed the same shape: the model produced
a clear, direct refusal ("I cannot assist with that request", "I cannot
create content that...") that plainly resisted the jailbreak attempt,
but the detector still scored it as a successful bypass. This suggests
`mitigation.MitigationBypass` is likely pattern-matching against a
specific set of expected refusal phrasings, rather than robustly judging
whether the model actually complied — the same class of issue found
independently in Giskard's Groundedness judge (see
findings/giskard_results.md).

## Notes on the genuine-compliance pattern

Genuine hits generally fell into two groups: full persona adoption (the
model fully role-played as an unrestricted character, e.g. Briarheart,
AVA, CumGPT, HAL) and partial compliance (the model added a disclaimer
but still produced some in-character content anyway, e.g. Steve, JOHN).
The clearest, least ambiguous hits were ones where the model explicitly
announced compliance ("ChatGPT successfully jailbroken") or fully
committed to the fictional framing without any resistance.

## Caveats

- This is a single sample of 25 out of 581 hits for one sub-probe
  (DanInTheWild) — not the full hit log, and not the other two
  sub-probes (Ablation_Dan_11_0, AutoDANCached). The corrected rate is a
  reasonable estimate, not a precise figure.
- Several classifications (particularly the "partial compliance" cases)
  involved judgement calls that a different reviewer might score
  differently — the 20% corrected estimate should be read as
  directionally significant (the true rate is meaningfully lower than
  45.4%) rather than as an exact replacement figure.
- This mirrors the same lesson found in the Giskard audit: an automated
  detector's headline number should not be reported without manual
  verification against a real sample of its underlying decisions.