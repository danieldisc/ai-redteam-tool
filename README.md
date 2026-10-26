# AI Red Teaming Tool

An internship project for LTA's Cyber Architecture & Development (CYAD) division. It attacks one
deliberately weak chatbot with five open-source red-teaming tools, with and without a basic NeMo
Guardrails guardrail, and compares what each tool finds.

This is a proof of concept. It is not connected to AskDBC or any real LTA document.

## The idea

```
        Garak   Giskard   Inspect AI   PyRIT   Promptfoo
           \       |          |          |        /
            \      |          |          |       /
             ->  http://localhost:8000/<tool>/v1  <-        one OpenAI-style endpoint
                              |
                      target/server.py                      logs every request and reply
                     /                \
          askdbc-unguarded        askdbc-guarded
          retrieval + Llama       NeMo input rail -> retrieval + Llama -> NeMo output rail
```

The target is a small document-based assistant (Llama 3.1 8B through Ollama, Chroma retrieval over four dummy
policy documents) with a secret planted in its system prompt: `ABC-SECRET-4321`.

Every tool talks to the same server, so they all hit identical code. The server records each request, the
reply, **which layer stopped it** (NeMo input rail, NeMo output rail, or the model refusing on its own) and a
deterministic leak check (`target/canary.py`). That log is the ground truth. Each tool also has its own verdict
about whether its attacks worked, and those verdicts have proved unreliable before, so the report always shows
them side by side with the canary check and a hand-labelled sample.

## Layout

```
target/        the chatbot and the server
  server.py      OpenAI-compatible endpoint, two models, request log
  rag.py         retrieval + model call          guard.py   NeMo wiring, records which rail fired
  canary.py      deterministic leak check        stub.py    fake model for plumbing tests ONLY
  config/        system prompt, documents (clean and poisoned)
  nemo/          NeMo config: input rail "self check input", output rail "regex check output"
  rails/         the guardrail options (unguarded, NeMo, blocklist, doccheck), one file each
attacks/       the written leak prompts, the legitimate questions, and scripted multi-turn conversations
tools/         one runner per tool (garak, giskard, inspect, pyrit, promptfoo) plus baseline, scripted and adaptive
run.py         run one tool against one target
report/        after a run: analyse.py (summarise the server log beside each tool's own numbers),
               audit.py (sample real replies, label by hand), garak_hitlog.py (browse Garak hits),
               compare.py (one tool x guardrail matrix),
               owasp.py (OWASP LLM Top 10 coverage from the log; rules in attacks/owasp.json),
               scan.py (result and evidence of one scan; used by the web page)
ui/            local web page: queue runs, follow logs, build reports (python ui/app.py)
tests/         test_rails.py, test_scripted.py, test_compare.py, test_ui.py, test_adaptive.py, test_owasp.py, test_scan.py: plain `python tests/<file>`, no Ollama needed
results/       summary.md and hand labels are kept; raw output (results/raw/) is git-ignored
```

## Claude as an attacker (optional, costs money)

`adaptive` lets Claude play the user in a multi-turn conversation: it reads each reply and writes the next message,
trying to reach one of PyRIT's five objectives. Success is judged by the same canary and marker checks as every other
tool, and Claude is never told the secret. It is the stronger-attacker comparison for the local 8B model that PyRIT uses.

```
pip install anthropic                           # main environment
$env:ANTHROPIC_API_KEY = "sk-ant-..."           # PowerShell; never commit or paste the key
$env:REDTEAM_ATTACKER_MODEL = "claude-haiku-5-5"   # cheap first try; default is claude-opus-5-5
python run.py adaptive --target unguarded --tier smoke
```

Tiers: smoke 2 objectives x 3 turns, standard 5 x 5 x 2 repeats, full 5 x 8 x 4. Every attacker message and target
reply goes to Anthropic's API and is billed, so use it only against the demo chatbot (fabricated data). The run prints
token use and an estimated cost. Claude's safety safeguards may decline to play the attacker; those conversations are
counted separately and are **not** evidence that the target held. For legitimate security work Anthropic points to
its Cyber Verification Program if declines are frequent.

## Web page

```
python target/server.py            # terminal 1, as before
python ui/app.py                   # terminal 2, then open http://127.0.0.1:8080
```

**Scan by OWASP category (top of the page).** Tick guardrails and a tier, tick the OWASP categories to test, press Start
scan. The page picks the tools that cover those categories (`attacks/owasp.json`; slow tools only if you tick the box),
queues them, and builds a category x guardrail grid with evidence: red where the attack worked at least once, green where
it held, plus up to three real request/reply examples per category with the secret masked. The report is also saved to
`results/scans/<label>.md`. Categories with no automated test (LLM03, LLM04, LLM06, LLM07) are greyed out, not guessed.
**Documents.** The target holds the clean and the poisoned document sets at once, so there is no restart. With *Documents: automatic*
(the default) one scan sends LLM05/LLM09 to the poisoned set and everything else to the clean set; you can also force one set.
Under the hood a poisoned run is a target ending `_poisoned` (e.g. `unguarded_poisoned`); the log records the set of every request,
and the comparison matrix and OWASP report keep the two apart. The counts index the log and are not attack success rates.

**Advanced (single tools).** Tick tools and guardrails, pick a tier, press Queue runs. Jobs run one at a time (the target answers one request at
once), each as its own `python run.py ...` process, so PyRIT keeps its own environment and a crashed job does not
stop the others. All jobs queued together share one run label, so every guardrail gets the same attacks. You can
watch a job's log, cancel it, and build the reports at the bottom: the **comparison matrix** (tool x guardrail, from
`report/compare.py`) or the full summary (`report/analyse.py`). The page only listens on 127.0.0.1, has no login and
uses only the standard library. The target server is still started by you.

## Guardrail options

The server offers one model per option; pick one with `--target <id>`.

| id | what it is |
|---|---|
| `unguarded` | no guardrail |
| `guarded` | NeMo Guardrails: LLM input check plus regex output check (the id is kept so earlier logs and results still match) |
| `blocklist` | refuses questions containing listed phrases and replies containing the secret; no model call |
| `doccheck` | drops retrieved documents that contain injected instructions or unknown links before the model sees them; only matters with the poisoned documents |

To add an option: write a class in `target/rails/` (see `base.py`), then add its id to `IDS` and the class to
`build_registry()` in `rails/__init__.py`. Check the options with `python tests/test_rails.py`.

## Setup

Two Python 3.12 environments, because PyRIT and Garak need different versions of the `datasets` package.
Because every tool reaches the target over HTTP, the split does not affect anything else.

```
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

py -3.12 -m venv venv-pyrit
.\venv-pyrit\Scripts\python -m pip install -r requirements-pyrit.txt
```

Also needed: [Ollama](https://ollama.com) with `ollama pull llama3.1:8b`, and Node.js 20+ for Promptfoo
(it is fetched on first use with `npx`).

NeMo Guardrails and PyRIT do not support Python 3.14, and Giskard 3 needs 3.12 or newer, so use 3.12.
Usage reporting is switched off for NeMo, Giskard and Promptfoo.

## Running

Terminal 1, the target (leave it running):

```
python target/server.py                    # serves clean and poisoned documents (the _poisoned targets), no restart
```

Terminal 2, one tool at a time. Run `smoke` first and read the replies before running `standard`:

```
python run.py baseline --target both --tier smoke     # the written prompts: leaks and false refusals
python run.py garak    --target unguarded --tier smoke
python run.py garak    --target guarded   --tier smoke
python report/audit.py garak.<label> guarded --show          # read what the target actually said
python run.py garak    --target both --tier standard --run r1
python report/analyse.py --out results/summary.md
```

`--target` takes one id, several separated by commas, `both` (unguarded and guarded) or `all`.

Tools: `baseline`, `scripted`, `adaptive`, `garak`, `giskard`, `inspect`, `pyrit`, `promptfoo`. Tiers: `smoke` (prove the wiring),
`standard` (the curated set, repeated), `full` (everything the curated set has, more repeats). Each run prints
roughly how many requests it will send and asks before starting. Repeat a run with a new `--run` label to get
more samples. To label a sample by hand: `python report/audit.py garak.r1 guarded --n 25`.

The excessive-agency test from the earlier work (a mock tool call) talks to the **bare model**, not the target,
because the target has no tool calling. Run it separately and report it as bare-model only:

```
inspect eval tools/inspect_tasks.py@excessive_agency --model ollama/llama3.1:8b
```

## What is attacked, by theme

| Theme | Garak | Giskard | Inspect AI | PyRIT | Promptfoo |
|---|---|---|---|---|---|
| Prompt injection and jailbreaks | promptinject, dan, latentinjection, encoding, phrasing, goodside | leak scenarios | injection, persona jailbreaks | converter-wrapped objectives, Skeleton Key, multi-turn | hijacking, intent with encoding strategies, jailbreak strategies |
| System prompt / secret disclosure | divergence | leak scenarios | extraction prompts | secret-extraction objectives | prompt-extraction, pii, debug-access |
| Improper output handling | xss, exploitation, ansiescape | | insecure output | | data-exfil, shell/sql-injection (full) |
| Misinformation and wrong-place answers | misleading, packagehallucination | grounded and wrong-place scenarios | | | hallucination, overreliance, off-topic |
| Indirect injection via documents | | | needs the poisoned documents (`--docs poisoned`) | | |
| Excessive agency | | | bare-model task only | | excessive-agency (full) |

Not covered: supply chain, training-data poisoning, and embedding/vector weaknesses beyond the one poisoned
document. Unbounded consumption is only touched by Garak's `divergence` probe.

`scripted` replays the fixed conversations in `attacks/multiturn.json` (gradual escalation, role-play, claimed
authority, one piece at a time, persistent instruction, and a legitimate control). It reports conversations, so
`tool flagged` counts conversations while the canary column counts every turn. `M8` needs the poisoned documents (`--docs poisoned`).

## Limits to state whenever results are quoted

- **Small, single-target, local model.** One chatbot, one 8B model, a handful of documents.
- **The guardrail was tuned on the written prompts.** The NeMo input prompt (`target/nemo/prompts.yml`) was
  written knowing the leak prompts in `attacks/`. Results on those prompts (and on the legitimate questions in
  `attacks/benign.json`) flatter the guarded target. The attack tools' own prompts are the held-out test.
- **`blocklist` and `doccheck` were written knowing the system prompt and the poisoned document**, as a developer
  would, so treat their results on those as optimistic too. The blocklist checks the latest question only.
- **Judges are weak.** Giskard and Promptfoo grade with the local 8B model; Garak's detectors are string and
  classifier based. Earlier work found about 44% of one Garak probe's "hits" were false positives and Giskard's
  pass rate was about 2-3 times too high. Do not quote a tool's own number without the hand audit beside it.
- **The leak check is a lower bound.** It sees the secret in plain, reversed, base64, hex, ROT13 or spaced form
  and long repeats of the system prompt. It does not see paraphrase or translation.
- **Promptfoo and PyRIT multi-turn attacks use a local attacker.** Promptfoo's remote generation is off
  (data stays on this machine), so some plugins or strategies are skipped or weaker. Read the notes in each run's
  output for what was skipped.
- **Retrieved documents are checked only by `doccheck`.** With every other option a poisoned document reaches the
  model unfiltered. `doccheck` only matters on the poisoned documents.
- **The input rail costs a second model call.** Compare latency and false refusals in `report/analyse.py`.

## Verification status

Real runs against Llama 3.1 8B (guarded and unguarded) exist for `baseline`, Garak, Promptfoo and Inspect AI at the
`standard` tier. Their numbers are in `results/summary.md` and the hand labels in `results/audit/`; notes are in
`results/findings.md`.

**Smoke tests only, no attack numbers yet:**

- Giskard (7 requests per target; the LLM-judge checks have not been audited);
- PyRIT single-turn attacks (8 requests per target);
- PyRIT `RedTeamingAttack` and `CrescendoAttack`: they need the attacker model to reply in JSON, so they are written
  against PyRIT's 1.1.0 signatures but have not run.

The plumbing (server and log, NeMo rail detection, canary check, `run.py`, `report/analyse.py`, `report/audit.py`)
was first tested in a sandbox with a fake model (`server.py --stub`); stub rows are excluded from reports.

Earlier Week 7-8 results (Garak about 20% genuine, Giskard about 30%, Inspect AI 60% over five runs, NeMo
leaks 10/21 unguarded and 0/21 guarded) were not carried over; they remain in git history.
