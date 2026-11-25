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
