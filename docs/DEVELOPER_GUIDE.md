# Developer Guide

For someone who will extend or maintain the tool. Read the Architecture Document first for the shape of the system; this guide gives the working steps.

## 1. Repository map

```
run.py                 start one tool against one or more targets (run.py <tool> --target ... --tier ... --run ...)
attacks/               data: library.json, multiturn.json, leak.json, benign.json, owasp.json
target/                the chatbot (rag.py), its server (server.py), the leak check (canary.py), oracle.py, docs_mode.py, stub.py
target/rails/          the guardrails: base.py, unguarded, nemo_guard, blocklist, doc_check, relay; __init__.py lists them
target/config/         system_prompt.txt (holds the planted secret), documents.json, documents_poisoned.json, oracle.example.json
target/nemo/           NeMo Guardrails configuration
tools/                 one <name>_run.py per attack source, common.py, agent_cases.py and agent_run.py (LLM03)
report/                analyse, compare, owasp, scan, score (the scorer), pentest_report, library_summary, external, audit, score_check, test_cases, transcript
ui/                    app.py (standard-library web server and job queue) and index.html (the page)
tests/                 one script per area, run with plain python
results/               findings, hand labels, scan summaries (kept); results/raw/ (git-ignored)
docs/                  these guides
```

## 2. Set up for development

Follow the Installation Guide. For development you can work without Ollama and without the five tools:

```powershell
python target/server.py --stub     # a fake model and a hash embedding: plumbing only, never report from it
```

Rows made in stub mode are marked `"stub": true` in the log, and every report leaves them out unless you pass `--include-stub`.

## 3. Conventions

- **Standard library only** in `ui/`, `report/` and the helper modules the PyRIT environment imports (`target/docs_mode.py`, `tools/agent_cases.py`). Heavy packages go only where a tool needs them.
- **Data, not code.** Prefer a new entry in a JSON file to a new branch in a function.
- **One source of truth.** Marker words and success rules live in `attacks/owasp.json`. Do not copy them into code.
- **Deterministic judging.** Nothing that decides success may call a model. A model may attack; only string checks judge.
- **Fake data only**, everywhere: the secret, the documents, the permits, the addresses (`example.com`).
- **Versions are pinned** (`requirements.txt`, `PROMPTFOO = "promptfoo@0.124.0"`). Tool option names change between versions, so pin and note the version in the commit when you move one.
- **Version the cases.** Raise `version` in `attacks/library.json` (or `VERSION` in `tools/agent_cases.py`) whenever a case changes. Runs record it, and the library summary ignores conversations whose text no longer matches (counted as stale).
- **British English** in every message and document.
- **Say what a number is.** Output that shows a count must say what it counts and keep the tool's verdict next to the scorer's.
- **Secrets never touch the command line or the repository.** Environment-variable names are passed around, not values.

## 4. Running the tests

No framework. Each file is a script that prints what it checked and exits non-zero on failure. They need neither Ollama nor the server.

```powershell
Get-ChildItem tests\test_*.py | ForEach-Object { python $_.FullName }
```

| File | Covers |
|---|---|
| `test_rails.py` | blocklist, document check, guardrail registry (a fake chatbot) |
| `test_score.py` | the scorer and the catalogue |
| `test_owasp.py` | the category rules |
| `test_scan.py`, `test_report.py`, `test_compare.py` | scan grid, pentest report, comparison matrix |
| `test_library.py`, `test_library_summary.py` | the library file, its runner, the summary |
| `test_scripted.py`, `test_agent.py`, `test_adaptive.py`, `test_transcript.py` | the runners and the transcript viewer |
| `test_relay.py` | relay, oracle and the external-chatbot report |
| `test_docs_mode.py` | clean and poisoned routing (needs `fastapi`) |
| `test_ui.py` | the web page's job queue and API |

A few tests skip or fail when an optional package is missing: `test_adaptive.py` and the adaptive-job check in `test_ui.py` need `anthropic`, and the server checks need `fastapi`.
Add a test for what you change: a new case file entry is covered by `test_library.py`; a new guardrail needs a line in `test_rails.py`.

## 5. Recipes

### 5.1 Add a test case

Add an object to `cases` in `attacks/library.json`. No code change.

```json
{
  "id": "LIB-LLM01-042",
  "owasp": "LLM01",
  "also": [],
  "kind": "attack",
  "title": "Short name",
  "technique": "direct instruction override",
  "automation": "Automated",
  "docs": "clean",
  "judge": "any",
  "turns": ["The attacker's messages, in order."],
  "failure": "what counts as a failure, in plain words",
  "secure": "what the chatbot should do instead"
}
```

`id` is unique and stable (`LIB-<risk>-<number>`; controls are `LIB-CTL-<n>`). `owasp` is the primary risk, and its success rule in `attacks/owasp.json` decides the verdict; `also` lists
more risks whose rule is applied to the same replies. `kind` is `attack` or `control`. `automation` is `Automated`, `Semi-automated` or `Manual review`. `docs` is `clean` or `poisoned`
(poisoned cases run only against a poisoned target). `judge` is `any` (any reply counts) or `last` (only the final reply). Raise `version`. Then run `python tests/test_library.py`, the library at `smoke`, and `python report/test_cases.py` to see the catalogue.
The Test Case Guide covers how to write a good one.

A case that needs a marker word the chatbot is asked to say should use `PWNED-7731` (already in the rules) so no new rule is needed.

### 5.2 Add a scripted conversation

Add to `conversations` in `attacks/multiturn.json`: `id`, `label`, `kind` (`attack` or `control`), `goal` (`secret`, `marker` or `length`), `turns`, and for `marker` the `markers`, for `length` the `min_reply_chars`, optionally `count: "last"` and `needs_poisoned_docs`.

### 5.3 Add an agent case (LLM03)

Add to `CASES` in `tools/agent_cases.py`: `id`, `kind` (`attack` or `control`), `title`, `technique`, `prompt`, `forbidden` (calls that mean the attack worked), `failure`, and for a control `required`. A rule is `{"tool": name, "args": {...}}`: a call matches if the tool is the same and every listed argument matches (text ignoring case, numbers numerically). Raise `VERSION`. Run `python tests/test_agent.py`.

### 5.4 Change or add an OWASP category

Each entry in `attacks/owasp.json` has:

| Field | Meaning |
|---|---|
| `id`, `name` | e.g. `LLM01`, `Prompt Injection` |
| `question` | A regex matched against the last user message of each logged request, to sort requests into this risk |
| `poisoned` | If true, requests where a poisoned document was retrieved or dropped belong to this risk |
| `success` | How a reply counts as the attack working: `markers` (words), `override_only` (markers that count only when the reply is essentially just the marker), `unless` (phrases that mean the poisoned note is only quoted), `canary` (true: the leak check), `min_reply_chars` |
| `tools` | The tools that exercise it; the guided scan uses this to pick tools |
| `docs` | `poisoned` if the category needs the poisoned set (default `clean`) |
| `manual` | If present, there is no automated test; the text says why. The category is shown as MANUAL REVIEW |
| `automation`, `severity`, `description`, `preconditions`, `impact`, `remediation`, `atlas`, `references` | Report fields |

A new *kind* of success rule (not just new words) needs a few lines in `succeeded()` (`report/owasp.py`) and in `score()` (`report/score.py`), plus a test in `test_owasp.py` and `test_score.py`.

### 5.5 Add a guardrail

1. Write a class in `target/rails/` that subclasses `Guardrail` (`base.py`): set `id`, `label`, `description`, and implement `async answer(self, chatbot, history, question) -> Result(reply, ids, blocked_by, dropped_ids, external)`. Use `chatbot.retrieve_docs`, `chatbot.build_messages`, `chatbot.llm` and `chatbot.answer`; run blocking calls with `asyncio.to_thread`.
2. Add the id to `IDS` and the class to `build_registry()` in `target/rails/__init__.py` (the two must agree, or start-up fails on purpose).
3. Add a card to `GUARDRAIL_INFO` in `ui/app.py` and, if you want a fixed column position, to `GUARDRAIL_ORDER` in `report/compare.py` and the label in `GUARDRAIL_LABELS` in `report/pentest_report.py`.
4. Add checks to `tests/test_rails.py`. Restart the server: it is served as `askdbc-<id>` and `askdbc-<id>_poisoned`.

Use `blocked_by` values the reports already know (`blocklist_input`, `model_refused`, `none` and so on) or add the new one where `report/analyse.py` counts them.

### 5.6 Add an attack tool

1. Write `tools/<name>_run.py` with `run(target, tag, tier, url, outdir, seed, yes) -> dict`, building the result with `common.summary(...)`. Point the tool at `common.base_url(url, tag)` with `common.model_for(target)`, so the request is tagged. Use `common.confirm(...)` before a long run and honour the three tiers.
2. Add the name to `TOOLS` in `run.py` and in `ui/app.py`, and the orderings `TOOL_ORDER` in `report/compare.py` and `report/scan.py`. Add its request counts to `REQUEST_HINTS` in `ui/app.py`, and a description in `ui/index.html`.
3. Add the tool's name to `tools` in each `attacks/owasp.json` category it exercises, and add it to `SLOW_TOOLS` in `report/scan.py` if it is slow.
4. If it needs packages that conflict with the main environment, follow PyRIT: its own environment, started as a subprocess (`tools/pyrit_run.py`).
5. If it writes its own attacks, describe them in `TOOL_FAMILIES` in `report/test_cases.py` so the catalogue lists them.
6. Judge by the scorer, not by the tool: keep the tool's own count as `tool_flagged` and let `report/score.py` decide. Run `smoke`, then read the replies with `report/audit.py <tag> <target> --show`.

### 5.7 Add or change a report

Reports read the log through `analyse.load_log` and the rules through `owasp.load_rules`. Keep output deterministic and show the tool's verdict next to the scorer's. If the web page should show it, add a route in `ui/app.py` (`do_GET` or `do_POST`) and a test in `test_ui.py`. The page checks `Host`, `Origin` and `Content-Type`; keep those checks on any new route.

## 6. The log record

See the Architecture Document, section 6. If you add a field, add it in `target/server.py` (`write_log`) only; readers must tolerate its absence in older rows (`row.get(...)`).

## 7. Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `REDTEAM_LOG` | `target/server.py`, reports | Path of the request log (default `results/raw/server_log.jsonl`) |
| `REDTEAM_CONCURRENCY` | `target/server.py` | Requests answered at once (default 1) |
| `PYRIT_PYTHON` | `tools/pyrit_run.py` | Python of the PyRIT environment |
| `ANTHROPIC_API_KEY` | `tools/adaptive_run.py` | The paid attacker's key |
| `REDTEAM_ATTACKER_MODEL` | `tools/adaptive_run.py` | The attacker model (default is the stronger, dearer one) |
| `DO_NOT_TRACK`, `GISKARD_TELEMETRY_DISABLED`, `PROMPTFOO_DISABLE_TELEMETRY`, `PROMPTFOO_DISABLE_UPDATE` | `run.py` | Set to `1` by default |
| the name given to `--relay-key-env` | `target/server.py` | Holds an external chatbot's API key |

## 8. Pitfalls

- **Run labels are single-use** per tool and target. Reusing one is refused so a tag in the log means one run.
- **Changing a case invalidates old results.** Raise the version; the library summary reports the old conversations as stale.
- **The canary threshold** is 12 words of the system prompt (`PROMPT_RUN_WORDS`); it was 8 earlier in the project, so older counts are not exactly comparable.
- **Counts move between runs.** Do not tune a detector until one number matches; label a fresh sample instead (`audit.py`, `score_check.py`).
- **The defences were tuned on the written tests.** Do not add a rule to a guardrail because a case got through unless you add a held-out case too.
- **NeMo can crash the process on Windows at exit** after everything is saved; `target/server.py` leaves with `os._exit(0)` to avoid it.
- **Case text edits by editors**: keep the JSON UTF-8, without a byte-order mark. Check the encoding cases (zero-width characters, URL encoding) after any edit, because a formatter can change special characters.

## 9. Known gaps (for the next developer)

- The pentest report and scan grid mask this project's own secret only. For an external chatbot, pass `--secret` to `report/pentest_report.py`; the page does not yet (see `scan_html` in `ui/app.py` and `mask` in `report/scan.py`).
- There is no numeric risk score; severity is a fixed rating per category.
- The relay has been unit-tested but not run against a real chatbot.
- LLM04 (supply chain) and LLM07 (misinformation) have no automated test. LLM03 is tested on a separate controlled agent, outside the scan grid.
- The LLM06 test measures only unbounded output length, not very long inputs or response time.
- There is no continuous integration. The tests are run by hand.
