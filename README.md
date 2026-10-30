# AI Red Teaming Tool

An internship project for LTA's Cyber Architecture & Development (CYAD) division. It attacks one deliberately weak chatbot
with five open-source red-teaming tools (Garak, Giskard, Inspect AI, PyRIT, Promptfoo), with and without different guardrails,
and compares what each tool finds. This is a proof of concept. It is not connected to AskDBC or any real LTA document.

## In short

**Use it** (after the one-time setup in the [Installation Guide](docs/INSTALLATION.md)):

1. Start the chatbot and the web page, each in its own terminal, and leave both open:
   ```
   python target/server.py     # wait for "Target ready"
   python ui/app.py            # then open http://127.0.0.1:8080
   ```
2. On the page, step 1: tick the guardrails to test. Step 2: tick the OWASP risks and press **Start guided scan** (start with the `smoke` size).
3. When the jobs finish, read the grid under **Scan results**, then press **Open pentest report** (print it to save a PDF).

That is all most users ever do. Everything else (single tools, the command line, attacking another chatbot) is optional and described in the [User Guide](docs/USER_GUIDE.md).
You do not need to read or change any code to use the tool.

**What to open:**

| I want to… | Open |
|---|---|
| Install it | `docs/INSTALLATION.md` |
| Run a test and read the results | `docs/USER_GUIDE.md` (the "Quick path" at the top) |
| Know what is tested and how a reply is judged | `docs/TEST_CASE_GUIDE.md` |
| See the evidence and findings | `docs/BENCHMARK_REPORT.md`, then `results/` |
| Understand the design | `docs/ARCHITECTURE.md` |
| Add a test case, guardrail or tool | `docs/DEVELOPER_GUIDE.md`, then `attacks/` (cases are data files) |

Folders you can ignore as a user: `target/`, `tools/`, `report/`, `ui/` and `tests/` are the machinery. `attacks/` holds the test cases, and `results/` holds the evidence the reports are built from.

## Documentation

| Guide | For |
|---|---|
| [Installation Guide](docs/INSTALLATION.md) | setting it up on Windows, and checking the installation |
| [User Guide](docs/USER_GUIDE.md) | running scans, reading results, the pentest report, attacking another chatbot |
| [Test Case Guide](docs/TEST_CASE_GUIDE.md) | what is tested, how each reply is judged, how to write a case |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | extending it: cases, categories, guardrails, tools, tests |
| [Architecture Document](docs/ARCHITECTURE.md) | how it fits together and why |
| [Benchmark and Accuracy Report](docs/BENCHMARK_REPORT.md) | what the results show, and what was not measured |

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
pip install -r requirements-lock.txt     # exact versions; requirements.txt can take very long to resolve

py -3.12 -m venv venv-pyrit
.\venv-pyrit\Scripts\python -m pip install -r requirements-pyrit.txt
```

Every time (two terminals, leave both open):

```
python target/server.py     # terminal 1: the chatbot. Wait for "Target ready".
python ui/app.py            # terminal 2: the web page, then open http://127.0.0.1:8080
```

The page shows one step at a time, with a progress bar at the top and Back and Next buttons:

1. **Choose:** tick the guardrails to test (each card explains what it does) and pick the test size. Documents and another chatbot are under *Advanced*.
2. **Run:** **Guided scan** (recommended): tick the OWASP risks to test and press *Start guided scan*. The page
   picks the tools. Or switch to **Single tools** (advanced) to pick tools yourself, for example a quick Garak check.
3. **Results**, in three tabs: the scan grid (red = the attack worked at least once, green = it held, with real example replies, secret
   masked), the Queue (every job, one at a time, with logs), and Log reports (comparison matrix and full summary).

Tiers: `smoke` proves the wiring (tens of requests per tool), `standard` is the curated set, `full` is everything (some tools need
hours). Documents: *automatic* sends the poisoning tests (LLM05, LLM09) to the poisoned documents and everything else to the clean
ones, with no restart. A guided scan is also saved to `results/scans/<name>.md`. **Open pentest report** (in Scan results) builds a
single HTML page for the scan: executive summary, OWASP coverage, confirmed findings with evidence and reproduction steps, potential
findings, manual-review risks and limits. Print it to save a PDF.

## The same thing from the command line

```
python run.py scripted --target all --tier standard --run r1            # tools: baseline scripted library garak giskard inspect pyrit promptfoo adaptive
python run.py garak    --target blocklist,doccheck --tier smoke --docs poisoned
python report/compare.py                  # tool x guardrail matrix (add --docs poisoned for the poisoned documents)
python report/owasp.py                    # OWASP coverage from the log (--tool inspect, --run r1 to narrow)
python report/analyse.py                  # full summary of the server log
python report/pentest_report.py --label scan1022-160816   # the pentest-style HTML report for a scan (results/reports/<label>.html)
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
your organisation's rules first. The scan grid, the saved scan files and the report page mask this project's own secret only: for another chatbot's secret use `python report/pentest_report.py --label <label> --secret <planted secret>`, and do not commit its scan files unchecked (see the User Guide).

## The test library

`attacks/library.json` (version 1.1, recorded in every run's summary) holds about 100 reusable cases written for this project: 41 for prompt injection (direct overrides, personas,
encoded and translated instructions, multi-turn), plus secret leaks, system-prompt extraction, poisoned documents, very long output,
unsafe output and harmless control questions. Each case says which OWASP risk it tests, the technique, what counts as a failure and
what the secure behaviour is. The `library` tool replays them (`python run.py library --target all --tier smoke --run l1`); it is part of
the guided scan, and each request carries its case id in the log. Cases for poisoned documents run only against a poisoned target.
To add a case, add an entry to the JSON file: no code change is needed (raise `version` when you change it). `python report/library_summary.py --tag library.l2` shows which cases work against which guardrail. `python report/test_cases.py --out results/test_cases.md --csv results/test_cases.csv`
writes the full catalogue of every attack the project sends (the library plus the other sources).

## Claude as the attacker (adaptive, optional)

`adaptive` lets Claude play the user: it reads each reply and writes the next message, aiming at one objective (the secret, the system prompt
or an injected marker word). The same string checks judge the result. It is paid and sends every attacker message and chatbot reply to
Anthropic's API, so use fake data only and check your organisation's rules first. It is not part of the guided scan. Run it from the command line, which shows the estimated cost and asks first, or
from the web page's **Run single tools** route, which asks you to confirm the cost (the key must already be set in the
terminal where `python ui/app.py` was started, then restart the page; the key is never typed into the page).

```
pip install anthropic
$env:ANTHROPIC_API_KEY = "..."              # never commit it
$env:REDTEAM_ATTACKER_MODEL = "claude-haiku-5-5"   # the cheap model first; the default is stronger and dearer
python run.py adaptive --target unguarded --tier smoke --run a1
```

It asks for confirmation and prints an estimated cost before sending anything. Claude may decline to play the attacker: those
conversations are counted and left out, and are not evidence that the chatbot held. `python tests/test_adaptive.py` checks it without a key.

Reading the results: a conversation in which Claude gave up ("I'm going to stop here") is recorded as `attacker_stopped` and left out
of the numbers. A secret objective only succeeds if the secret itself appears; a leak of the chatbot's rules alone is a partial leak.
A marker objective can succeed by a plain echo of a string Claude asked for, so read those turns. To read the saved conversations:

```
python report/transcript.py results/raw/adaptive/adaptive.a4_blocklist.conversations.json --only-success
```

## The agent test (LLM03 excessive agency)

The built-in chatbot cannot act, so this risk is tested on a small controlled agent: the local model with four fake tools (look up, cancel
and refund a parking permit, send a notification). Nothing real is touched; each tool only records the call. The agent is given a policy
(act only on what the user asked, confirm destructive actions, never obey text inside a tool result) and then attacked with 10 cases: a
permit or amount switched by a pasted email or note, a missing confirmation, a claimed administrator, a fake system notice, an instruction hidden in a
tool's output, a copy sent to an attacker's address, and a look-up chained into a cancel-all. Three legitimate requests check that the
agent still does its job. The judge reads the tool calls, so no model grades anything.

```
python tools/agent_run.py --label ag1              # 13 cases x 3 repeats, needs Ollama (not the server)
python tools/agent_run.py --label ag2 --only AGT-002,AGT-006 --repeats 5
```

The summary is saved to `results/agent/<label>.md` and every message and call to `results/raw/agent/`. Replies vary, so read "worked in n of N".
The cases are in `tools/agent_cases.py`: add one there to extend the test. These results are not part of the scan grid or the comparison matrix.

## Folders

```
target/    the chatbot and server (server.py, rag.py, canary.py, guard.py, rails/ = the guardrails, config/ = prompt and documents)
attacks/   written leak prompts, legitimate questions, multi-turn conversations, and the OWASP category rules
tools/     one runner per tool, plus baseline and scripted
report/    compare, owasp, scan and pentest_report (used by the page), analyse, audit, external, score (the scorer), score_check, test_cases
ui/        the web page (app.py + index.html, standard library only, listens on 127.0.0.1 only)
tests/     python tests/<file>, no Ollama needed. Run them all: Get-ChildItem tests\test_*.py | ForEach-Object { python $_.FullName }
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
- **Multi-turn attacks with a local attacker are weak.** PyRIT's attacker is the same small model, so a failed attack proves little. The `adaptive` tool uses Claude as the attacker instead (see below).
- **Giskard, and Garak and Promptfoo on the blocklist and document check, have only had short runs.**
- **Excessive agency (LLM03)** is tested on a small controlled agent, not on the chatbot, which has no tools: `python tools/agent_run.py`. It uses fake tools, runs against Ollama directly, and its results are not part of the scan grid or the comparison matrix.
