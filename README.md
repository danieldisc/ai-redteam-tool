# AI Red Teaming Tool

An internship project for LTA's Cyber Architecture & Development (CYAD) division. It attacks one deliberately weak chatbot
with five open-source red-teaming tools (Garak, Giskard, Inspect AI, PyRIT, Promptfoo), with and without different guardrails,
and compares what each tool finds. This is a proof of concept. It is not connected to AskDBC or any real LTA document.

## How it works

```
   Garak   Giskard   Inspect AI   PyRIT   Promptfoo        your own scripted and baseline prompts
      \       |          |          |        /                          |
       ->        http://localhost:8000/<tool>/v1        <-   one OpenAI-style endpoint
                              |
                      target/server.py        logs every request and reply, and checks for a leak
                              |
        unguarded | NeMo | blocklist | doccheck  (+ an optional external chatbot, "relay")
```

- **The chatbot** is a small document-based assistant (Llama 3.1 8B through Ollama, four dummy documents) with a made-up secret in its
  instructions. There is also a poisoned document with hidden instructions, used for the poisoning tests.
- **The guardrails:** `unguarded` (none), `guarded` (NeMo Guardrails), `blocklist` (keyword filter) and `doccheck` (removes suspicious
  retrieved documents).
- **The scoreboard** is the scoring layer: `target/canary.py` plus `report/score.py`. Plain string checks decide, for every reply,
  whether the attack *worked*, *held* or is *unsure* (with the detector and reason). Every tool also gives its own verdict, but those have
  proved unreliable, so the reports always show both side by side.

## Quick start

Set up once (two Python 3.12 environments, because PyRIT and Garak need different packages; also install [Ollama](https://ollama.com)
with `ollama pull llama3.1:8b`, and Node.js 20+ for Promptfoo):

```
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

py -3.12 -m venv venv-pyrit
.\venv-pyrit\Scripts\python -m pip install -r requirements-pyrit.txt
```

Every time (two terminals, leave both open):

```
python target/server.py     # terminal 1: the chatbot. Wait for "Target ready".
python ui/app.py            # terminal 2: the web page, then open http://127.0.0.1:8080
```

On the page, work through three steps:

1. **Settings:** tick the guardrails to test (each card explains what it does), pick the tier and the documents.
2. **How do you want to run?** Choose **Guided scan** (recommended): tick the OWASP risks to test and press *Start guided scan*. The page
   picks the tools. Or choose **Run single tools** (advanced) to pick tools yourself, for example a quick Garak check.
3. **Read the results:** the scan grid (red = the attack worked at least once, green = it held, with real example replies, secret
   masked), the Queue (every job, one at a time, with logs), and Log reports (comparison matrix and full summary).

Tiers: `smoke` proves the wiring (tens of requests per tool), `standard` is the curated set, `full` is everything (some tools need
hours). Documents: *automatic* sends the poisoning tests (LLM05, LLM09) to the poisoned documents and everything else to the clean
ones, with no restart. A guided scan is also saved to `results/scans/<name>.md`.

## The same thing from the command line

```
python run.py scripted --target all --tier standard --run r1            # tools: baseline scripted garak giskard inspect pyrit promptfoo
python run.py garak    --target blocklist,doccheck --tier smoke --docs poisoned
python report/compare.py                  # tool x guardrail matrix (add --docs poisoned for the poisoned documents)
python report/owasp.py                    # OWASP coverage from the log (--tool inspect, --run r1 to narrow)
python report/analyse.py                  # full summary of the server log
python report/audit.py garak.r1 guarded   # sample real replies and label them by hand
python report/score_check.py              # how often the scorer disagrees with your hand labels (misses and false alarms)
python report/test_cases.py --out results/test_cases.md --csv results/test_cases.csv   # the catalogue of every attack and what counts as a failure
```

`--target` takes one guardrail id, several separated by commas, `both` (unguarded and guarded) or `all`. Run `smoke` first and read the
replies before running `standard`. Every run is tagged `<tool>.<label>`; use a new `--run` label each time.

## Attacking another chatbot (relay and oracle)

From the web page, choose **Another chatbot** under Settings and enter its address, the planted fake secret and (if it needs a key) the name of the environment variable that holds the key. No restart is needed. The same thing from the command line:

```
python target/server.py --relay-url http://localhost:9000/v1 --oracle oracle.json
```

The `relay` option forwards every request to another chatbot's OpenAI-compatible endpoint (`--relay-model`, and `--relay-key-env` naming
an environment variable that holds its API key). The **oracle** (`oracle.json`, copy `target/config/oracle.example.json`) lists the fake
secrets planted in that chatbot, so the leak check can judge its replies whatever any tool or its guardrail says. If it reports its own
guardrail decision (`{"guardrail": {"verdict": "blocked" or "passed", ...}}` in the body, or `X-Guardrail-Verdict` headers), it is logged,
and `python report/external.py` compares that with the oracle (missed attacks, contradictions, false blocks). `relay` is one more
column in the comparison matrix. It has no poisoned variant. It sends every attack prompt to that chatbot: use fake data only and check
your organisation's rules first.

## Folders

```
target/    the chatbot and server (server.py, rag.py, canary.py, guard.py, rails/ = the guardrails, config/ = prompt and documents)
attacks/   written leak prompts, legitimate questions, multi-turn conversations, and the OWASP category rules
tools/     one runner per tool, plus baseline and scripted
report/    compare, owasp, scan (used by the page), analyse, audit, external, score (the scorer), score_check, test_cases
ui/        the web page (app.py + index.html, standard library only, listens on 127.0.0.1 only)
tests/     python tests/<file>, no Ollama needed. Run them all: Get-ChildItem tests\test_*.py | ForEach-Object { python $_.FullName }
extras/    parked: the Claude-as-attacker tool (see extras/README.md)
results/   hand labels and notes are kept; raw output (results/raw/, including the request log) is git-ignored: back it up yourself
```

## Limits to state whenever results are quoted

- **One small chatbot, one 8B model, a handful of documents, and few repeats.** Counts move between runs, so small differences mean little.
- **The defences were written knowing the tests** (NeMo's input prompt, the blocklist and the document check), so they look better than
  they would on someone else's chatbot. The tools' own prompts are the held-out test.
- **The tools' judges are weak.** Garak flagged 497 attacks where 3 leaked; Promptfoo and Giskard grade with the local 8B model.
  Do not quote a tool's own number without your own check beside it.
- **The leak check is a lower bound.** It sees the secret plain, reversed, base64, hex, ROT13 or spaced out, and long repeats of the system
  prompt. It misses paraphrase and translation, and false negatives are not measured.
- **Multi-turn attacks with a local attacker are weak.** PyRIT's attacker is the same small model, so a failed attack proves little.
- **Giskard, and Garak and Promptfoo on the blocklist and document check, have only had short runs.**
- **Excessive agency** is only tested on the bare model, not the chatbot, which has no tools: `inspect eval tools/inspect_tasks.py@excessive_agency --model ollama/llama3.1:8b`.
