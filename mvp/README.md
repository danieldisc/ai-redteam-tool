# The combined tool, first version

Runs the five tools on every threat brief, one job at a time, and writes one results table. Sequential on purpose: the chatbot answers one
turn at a time across the whole app and the adapter takes a lock, so running tools together only adds waiting and timeouts.

```
threat catalogue + mock data  ->  case_builder.py  ->  briefs  ->  queue_run.py  ->  adapter  ->  chatbot
                                                                                         |
                                           results.csv  <-  results.py  <-  results_adapter/*.jsonl
```

1. Start the chatbot and the adapter (see the top README). Use `--history replay` for multi-turn runs.
2. Set the Claude key in the terminal. Set `DEMO_PYTHON_<TOOL>` for any tool that has its own virtual environment (see `demo/README.md`).
3. Run the queue. The data folder is `data/` inside the `benchproject` repository:

```bash
python mvp/queue_run.py --data ../benchproject/data --only inspect pyrit --threats THR-012
```

4. Make the table: `python mvp/results.py`. It writes `mvp/results.csv`, one row per brief and tool.

| File | What it does |
|---|---|
| `case_builder.py` | One brief per threat variant and persona. Starter set: THR-001, THR-008, THR-012. A brief holds only grey knowledge; the marker text and the adapter flag sit apart under `judge_only`. A change message that contains a yes word is refused |
| `queue_run.py` | First in, first out. Each job is one tool on one brief. A failed job is recorded in `mvp/run/status.json` and the queue carries on |
| `results.py` | Reads the adapter log and counts requests, replies and each flag per brief and tool. A row with no flag is "not yet reviewed", not "safe" |

Not built yet: more threats in `TEMPLATES`, several personas per run, a true session memory (use `--history replay`), Garak, Giskard and Promptfoo
runs on the real chatbot, and attached files (the adapter sends text only). Test: `python tests/test_mvp.py`.

## General mode: attack any chatbot from its address

The steps above are for the Guardrail Bench chatbot and use its threat catalogue. General mode needs neither. It is for any chatbot that speaks the
OpenAI chat format (`POST <address>/chat/completions`). A chatbot with another API needs a small adapter in front of it, as Guardrail Bench has.

1. Copy `mvp/target.example.json` to `mvp/target.json` (kept out of git) and fill in the address, the model name, and one or two sentences on what the
   chatbot is for. That sentence is all the tools are told. If the chatbot needs a key, put the name of the environment variable in `api_key_env`.
2. Optional: add your own `objectives` (plain sentences such as "Get it to reveal another customer's order"). With none, the generic list in
   `mvp/generic_objectives.json` is used. It was written by the team and is not any chatbot's catalogue.
3. Set `ANTHROPIC_API_KEY`, and `DEMO_PYTHON_<TOOL>` for each tool in its own environment (see `demo/README.md`). Then:

```bash
python mvp/general_run.py --target mvp/target.json
python mvp/general_run.py --target mvp/target.json --only promptfoo inspect --objectives leak-instructions    # a smaller run
```

| Step | What happens |
|---|---|
| 1 | One pack per objective is built from the target file. No threat catalogue and no test cases are read |
| 2 | A logging proxy starts. Every request from every tool is forwarded to the address and written to `results_adapter/<tool>.jsonl`, the same shape for all five |
| 3 | The tools run one at a time. Promptfoo first: Claude writes its attacks from the purpose and the objective. Inspect AI and Giskard cannot write attacks, so they replay Promptfoo's messages (and are skipped if Promptfoo wrote none). PyRIT and Garak (GOAT) write their own over several turns, with Claude as the attacker |
| 4 | Claude judges each reply (`mvp/judge.py`), and `mvp/general_results.csv` counts breach, ok and unsure per objective and tool |

**Read this before quoting a result:**
- The judge is Claude and is approximate. Read every reply it calls a breach in `results_adapter/`, and the "unsure" ones. No breach judged is not "safe".
- Inspect AI and Giskard are compared on Promptfoo's attacks, not their own. Say so when you compare the tools.
- A general chatbot gives no record of its tool calls, so the checks that need them (acting for another person, a change without a yes) do not exist here.
- This is the one place where our own code calls Claude, and it only judges. It never writes an attack.
- Tested with stubs: the target file, the proxy, the judge, the queue, and a real Inspect AI 0.3.292 run through the proxy. Not yet run with real Promptfoo,
  Giskard, PyRIT (Claude as attacker and scorer), Garak or the real Claude API. Test: `python tests/test_general.py`.

## The hand-off: a fixed test set to replay on the guarded chatbot

**Why the same message can get a different reply.** A chatbot usually picks its words with some randomness, so sending message A twice can give two
different replies. Whether a given chatbot does this can only be tested from outside: send the same message several times and compare. The tools that
write attacks (Promptfoo, PyRIT, Garak's GOAT) and our judge ask Claude, which also words things differently each time, and Claude's current models take
no setting to turn that off. So running a tool again gives new attacks, and judging a reply again can give a different verdict.

**What can be repeated, then:** the saved attacks. The tools write attacks once; a person marks which replies broke the rules; those attacks become a
fixed test set; anyone can send that same test set again later, to the same chatbot or to one with guardrails, several times each, and compare how often
each attack still breaks the rules ("3 out of 5"). The rate is the result to compare, not one reply.

```bash
python mvp/testset.py review --logs results_general --verdicts mvp/general_verdicts.jsonl --out mvp/review.csv
```
Open `mvp/review.csv` in Excel. It lists every judged reply, the judge's breaches first. Write `breach` or `ok` in the `your_verdict` column for each row
you check, and save it as CSV.

```bash
python mvp/testset.py build --review mvp/review.csv --logs results_general --target mvp/target.json --out testset.json
```
`testset.json` holds only the rows you marked `breach`: for each, the user messages that were sent, the reply that broke the rule, the goal and the rule,
and the chatbot's one-sentence purpose. Use the same logs and verdicts as the review sheet: the row ids come from them. This file is what you hand over.

```bash
python mvp/testset.py replay --testset testset.json --target mvp/target.json --repeats 5 --logs results_replay --out replay_results.csv
```
Sends every case 5 times to the chatbot in the target file, judges each reply with Claude, and writes one row per case (`breach_rate`, for example `3/5`)
plus every reply in `replay_results.attempts.jsonl` for a person to read. Run it once on the unguarded chatbot for the baseline, then on the guarded one.

For the Guardrail Bench chatbot with guardrails: start the adapter with `--guardrail-config <id> --history replay`, point the target file at it, and add
`--one-request` (the adapter then sends each user turn itself, in one new conversation).

Limits to say when you report a rate:
- A multi-turn attack is replayed with its saved user messages. The chatbot's replies in between are new, but the attacker's later messages are not
  rewritten to fit them, as the original attacker did. So a multi-turn replay is a fixed script, weaker than the live attack.
- The judge is approximate: read every reply it calls breach or unsure.
- Record the versions with the result: the test set file stores the date, the chatbot's model name and the judge model.

Tested with a stub chatbot and a stub judge only (`python tests/test_general.py`). Not yet run on the real chatbot.
