# AI Red Teaming Tool — Internship Project

An open-source-orchestrating AI red teaming tool for LLM/GenAI security
testing, built around the OWASP GenAI LLM Top 10 (2026) framework.
Internship project for LTA's Cyber Architecture & Development (CYAD)
division.

**Status:** Week 7-8 (Tool Hands-On Testing) — Garak, Giskard, and
Inspect AI all tested and manually audited. Guardrail built, broken,
and fixed. OWASP coverage matrix built. Second guardrail and
PyRIT/Promptfoo still to come.

---

## What this is

A custom Python-orchestrated red-teaming setup validating the tool
foundation recommended in the Week 5-6 Tool Comparison Matrix (Garak +
Giskard), extended with Inspect AI for agentic testing, tested against
a deliberately vulnerable RAG chatbot mirroring LTA's AskDBC. Findings
are consolidated against the OWASP LLM Top 10 (2026) in
`Tool_Evaluation_Report_Week7-8.docx`, Section 3.

---

## File structure — grouped by what each thing actually does

```
ai-redteam-tool/
├── config/                      # Data, not code — the target's "content"
│   ├── system_prompt.txt        #   system prompt + planted secret
│   └── documents.json           #   the four dummy policy documents
│
├── target_unguarded.py          # THE TARGET — raw pipeline, no protection.
│                                 # Run directly to chat, or imported by
│                                 # everything else below.
├── target_guarded.py            # THE TARGET, hardened — same pipeline
│                                 # wrapped with a Guardrails AI check.
│                                 # Imports from target_unguarded.py.
│
├── garak_targets.py              # ADAPTER — lets Garak attack either
│                                 # target. Not run directly; Garak loads
│                                 # it via --target_name garak_targets#...
├── giskard_eval.py                # RUNS a Giskard evaluation directly
│                                 # against target_unguarded. Run this
│                                 # one yourself: python giskard_eval.py
├── inspect_eval.py                # RUNS an Inspect AI evaluation for
│                                 # LLM03 (Excessive Agency). Runs against
│                                 # local Ollama directly, not through the
│                                 # RAG pipeline. Run: inspect eval
│                                 # inspect_eval.py --model ollama/llama3.1:8b
│
├── read_hitlog.py                 # ANALYSIS TOOL — makes a Garak hit-log
│                                 # file readable. Run manually, after a
│                                 # Garak scan, to inspect specific hits.
│                                 # Add --sample for a random sample;
│                                 # without it, shows the first N in
│                                 # file order.
│
├── findings/                     # THE EVIDENCE — write-ups of every test
│   ├── manual_baseline_tests.md  #   8 hand-run tests (Tests 1-8)
│   ├── giskard_results.md        #   3 Giskard checks + manual audit
│   │                             #   (corrected: ~30% pass, not the
│   │                             #   automated judge's ~80-90%)
│   ├── garak_audit.md             #   manual audit of Garak's hit log
│   │                             #   (corrected: ~20% genuine bypass,
│   │                             #   not the automated ~45.4%)
│   ├── inspect_ai_results.md      #   LLM03 excessive-agency finding
│   │                             #   (60% pass on 5 repeats, was 100% on 1)
│   ├── garak_reports/            #   saved HTML/hitlog files per run
│   └── screenshots/
│
├── docs/                          # DELIVERABLES — not imported by
│   │                             # anything, safe to reorganise freely
│   ├── Tool_Evaluation_Report_Week7-8.docx   # includes OWASP coverage matrix
│   ├── demo_script_concise.md
│   └── full_demo_script.md
│
├── requirements.txt
└── .gitignore                     # excludes venv/, __pycache__/, *.log,
                                   # and logs/ (Inspect AI's eval output)
```

**Why the Python files stay in the root folder, not a `src/` subfolder:**
`target_guarded.py`, `garak_targets.py`, and `giskard_eval.py` all import
each other by simple name (e.g. `from target_unguarded import ...`).
That only works when they're in the same folder as each other. Moving
them into subfolders would need proper Python package imports or
`sys.path` configuration — more complexity than this project's size
currently justifies. If the project grows much further, this is worth
revisiting.

---

## The core distinction, if you forget everything else

- **`target_*.py`** = the thing being attacked
- **`garak_targets.py` / `giskard_eval.py` / `inspect_eval.py`** = the tools attacking it
- **`read_hitlog.py`** = a magnifying glass for reading Garak's results afterward
- **`findings/*.md`** = what you actually concluded
- **`docs/`** = the polished write-up of all of the above, including the OWASP coverage matrix

---

## Key findings so far

| Finding | Detail |
|---|---|
| System prompt leakage (LLM08) | Debug-mode roleplay leaks the planted secret on the unguarded target (Test 4) |
| Guardrail bypass, then fix | First guardrail attempt evaded via paraphrasing (Test 7); fixed with a literal-match check (Test 8) |
| Misinformation (LLM07) | Jurisdiction-mismatched policy presented with confidence (Test 5); automated judge said ~80-90% grounded, manual audit found ~30% |
| Excessive agency (LLM03) | Mock tool-calling test via Inspect AI: single run showed 100% pass, repeated 5x showed 60% pass (40% failure) |
| Guardrail scope limit | Guardrail didn't reduce Garak's jailbreak bypass rate, or affect Giskard's or Inspect AI's results — it was never scoped to catch anything beyond secret leakage |
| Cross-tool pattern | All three automated tools (Garak, Giskard, Inspect AI) produced a headline number that required manual correction — single runs and raw detector/judge output were unreliable in every case |

Full detail and the consolidated OWASP coverage matrix (all 10
categories, mapped to tool/guardrail coverage and status) are in
`docs/Tool_Evaluation_Report_Week7-8.docx`, Section 3.

---

## Environment setup

```
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

Requires [Ollama](https://ollama.com) installed separately, with the
target model pulled:
```
ollama pull llama3.1:8b
```

## Running things

```
python target_unguarded.py                        # chat with the raw target
python target_guarded.py                           # chat with the guarded target
python giskard_eval.py                             # run Giskard's groundedness checks
inspect eval inspect_eval.py --model ollama/llama3.1:8b   # run the Inspect AI excessive-agency eval
inspect view                                        # browse individual Inspect AI eval runs
python -m garak --target_type function --target_name garak_targets#call_unguarded --probes dan
python -m garak --target_type function --target_name garak_targets#call_guarded --probes dan
python read_hitlog.py <hitlog_path> --probe dan.DanInTheWild --limit 25 --sample
```

## Next steps

- Build a second, differently-scoped guardrail (e.g. Llama Guard for
  jailbreaking, or a scope-check instruction for misinformation) —
  current guardrail only covers LLM08
- Test at least one more of PyRIT or Promptfoo against the target, per
  supervisor guidance to use multiple of the five originally evaluated
  tools
- Extend testing to the remaining coverage gaps (LLM02, LLM04, LLM05
  poisoning specifically, LLM06, LLM09, LLM10 — see the coverage matrix)
- Finalise the GO/NO-GO decision with supervisor sign-off

## Confidentiality note

This is a proof-of-concept target only. It is not connected to, and
contains no data from, LTA's actual AskDBC system or any real internal
documents.