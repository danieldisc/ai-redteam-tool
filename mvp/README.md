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
