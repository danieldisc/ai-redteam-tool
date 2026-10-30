# Installation Guide

For a Windows PC with PowerShell. Commands for Linux or macOS are given where they differ. Allow about an hour the first time, most of it downloads.

## 1. What you need

| Requirement | Why | Check |
|---|---|---|
| Windows 10 or 11 (Linux and macOS work with the notes below) | | |
| **Python 3.12** with the `py` launcher | Giskard 3 needs 3.12 or newer; NeMo Guardrails and PyRIT need 3.13 or older, so 3.12 is the one version all of them accept | `py -3.12 --version` |
| **Git** | to clone the repository | `git --version` |
| **Ollama** and the model `llama3.1:8b` | the chatbot being attacked, and the judge or attacker for Giskard, Promptfoo and PyRIT | `ollama list` shows `llama3.1:8b` |
| **Node.js 20 or newer** (with `npx`) | Promptfoo only | `node --version` |
| Disk space | the model is about 5 GB; the two Python environments are several GB more (Garak and its dependencies are large) | |
| Memory | enough to run an 8B model. Ollama advises at least 8 GB of RAM for models of this size; 16 GB is more comfortable | |
| Internet, at first | to download the Python packages, the model, Promptfoo (the first `npx` run), and the small embedding model Chroma fetches the first time the chatbot starts | |

After the first run everything works offline except the optional adaptive attacker (paid, Claude API). Usage reporting is switched off in the tools that have it
(`run.py` sets `DO_NOT_TRACK`, `GISKARD_TELEMETRY_DISABLED`, `PROMPTFOO_DISABLE_TELEMETRY`, `PROMPTFOO_DISABLE_UPDATE`).

## 2. Get the code

The repository is private, so a plain `git clone` from PowerShell fails with "Repository not found" unless you are logged in to GitHub. Clone it with GitHub Desktop
(**File**, **Clone repository**, pick `danieldisc/ai-redteam-tool`, choose an empty folder), or log in first with the GitHub CLI (`gh auth login`) and run
`gh repo clone danieldisc/ai-redteam-tool`. Then open PowerShell in the cloned folder:

```powershell
cd path\to\ai-redteam-tool
```

## 3. Install Ollama and the model

Install Ollama from <https://ollama.com>, leave it running, then:

```powershell
ollama pull llama3.1:8b
ollama run llama3.1:8b "Say hello"      # type /bye to leave
```

## 4. The main Python environment

This holds the target server, the web page and Garak, Giskard and Inspect AI.

```powershell
py -3.12 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-lock.txt
```

`requirements-lock.txt` has the exact versions of every package, so pip has nothing to search and the install takes a few minutes (plus the download). Do not use `requirements.txt` for a normal install: it lists
only the direct dependencies, and pip can spend half an hour or more trying combinations of the packages underneath (it appears stuck at `Collecting fastembed`). The lock file is for Windows; it includes
Windows-only packages.

If PowerShell refuses to run the activation script, allow it for your user once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

Linux or macOS: `python3.12 -m venv venv`, then `source venv/bin/activate`.

## 5. The PyRIT environment

PyRIT needs a newer `datasets` package than Garak allows, so it has its own environment. Do not activate it; the tool finds it by itself.

```powershell
py -3.12 -m venv venv-pyrit
.\venv-pyrit\Scripts\python -m pip install --upgrade pip
.\venv-pyrit\Scripts\python -m pip install -r requirements-pyrit.txt
```

The last step can show no output for several minutes while it unpacks the packages. That is normal; leave it.

The tool looks for `venv-pyrit\Scripts\python.exe` (or `venv-pyrit/bin/python`). To put it elsewhere, set `PYRIT_PYTHON` to the full path of that Python.

## 6. Node.js for Promptfoo

Install Node.js 20 or newer from <https://nodejs.org>. Nothing else is needed: the tool runs the pinned version `promptfoo@0.124.0` with `npx --yes`,
which downloads it on first use.

## 7. Optional: the adaptive attacker

Only if you want Claude to play the attacker. It is paid, and sends every attacker message and chatbot reply to Anthropic's API, so check your organisation's rules first.

```powershell
pip install anthropic
$env:ANTHROPIC_API_KEY = "..."       # in the terminal only; never write it into a file or commit it
```

## 8. Check the installation

Four checks, from the quickest. Do them in order and stop at the first that fails.

**a. The unit tests** (no Ollama and no server needed). From the repository folder with the main environment active:

```powershell
Get-ChildItem tests\test_*.py | ForEach-Object { Write-Host $_.Name; python $_.FullName }
```

Every file should end by reporting that its checks passed. The lock file installs `anthropic` and `fastapi`, so nothing should skip. If you installed from `requirements.txt` instead, `test_adaptive.py` and one check in `test_ui.py` need `anthropic`, and
the server tests in `test_docs_mode.py` and `test_library.py` print `SKIP` if `fastapi` is missing. (Linux or macOS: `for t in tests/test_*.py; do python $t; done`.)

**b. The target server with the fake model** (no Ollama; proves the wiring):

```powershell
python target/server.py --stub
```

Wait for `Target ready`, then in a second terminal: `Invoke-RestMethod http://127.0.0.1:8000/health`. It should list four guardrails. Stop the server with Ctrl+C. Never report results from `--stub`: they test plumbing only.

**c. The real target.** Start it without `--stub`:

```powershell
python target/server.py
```

The first start loads NeMo and Chroma, and Chroma downloads its small embedding model once, so wait for `Target ready on http://127.0.0.1:8000`. Leave this terminal open.

**d. One real smoke run and the web page.** In a second terminal (activate `venv` again):

```powershell
python run.py baseline --target both --tier smoke --run check1 --yes
python report/analyse.py --tool baseline
python ui/app.py
```

`--yes` skips the "Continue? [y/N]" question that every run asks first; without it, type `y`. The smoke run sends tens of requests and should finish in a few minutes. On a clean install the baseline run gives 2 of 27 requests leaking on `unguarded` and 0 of 27 on `guarded`; PyRIT's smoke run (`python run.py pyrit --target unguarded --tier smoke --run py1 --yes`) shows 0 achieved of 8. Open <http://127.0.0.1:8080>. The page should show the target as running. Run a **Guided scan** with one category and the *smoke* tier
to prove the whole path.

Every run label is single-use per tool and target: use a new one (`check2`, `check3`…) each time.

## 9. Where things end up

| Path | What | In git? |
|---|---|---|
| `results/raw/server_log.jsonl` | every request and reply (set `REDTEAM_LOG` to move it) | No: back it up yourself |
| `results/raw/<tool>/` | each tool's raw output and summaries | No |
| `results/raw/ui/` | the web page's job queue and logs | No |
| `results/scans/<label>.md` | a guided scan's saved result | Yes |
| `results/reports/<label>.html` | the pentest report | Yes if you add it |
| `oracle.json` | your settings for an external chatbot (contains its fake secret) | Never commit |

## 10. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `Cannot reach the target at http://127.0.0.1:8000` | The server is not running, or is still loading. Start `python target/server.py` and wait for `Target ready`. |
| `The server is in --stub mode` warning | You started it with `--stub`. Restart it without the flag before collecting results. |
| Server starts then every request fails | Ollama is not running, or the model is missing. `ollama list`. |
| `PyRIT environment not found` | Step 5 not done, or set `PYRIT_PYTHON`. |
| `npx not found` | Install Node.js 20 or newer and open a new terminal. |
| `<tag> on <target> has already been run` | Run labels are single-use. Pass a new `--run` label. |
| `pip install` seems stuck at `Collecting fastembed` or `huggingface_hub` | You are installing from `requirements.txt`. Press Ctrl+C and install from `requirements-lock.txt` instead. |
| `ModuleNotFoundError` for a tool | The main environment is not active (`.\venv\Scripts\Activate.ps1`), or step 4 did not finish. |
| `Cannot listen on port 8080` | Another program uses it. `python ui/app.py --port 8081`. The target's port is `--port` on `target/server.py` (and `--target-url` on the page). |
| Garak or Promptfoo seems to hang for a long time | It is not stuck: `standard` Garak sends about 1,700 requests per guardrail and Promptfoo about 340, one at a time. Use `smoke` first. See the request counts in the User Guide. |
| A stray `Process finished with exit code 3221225477` at the end of `target/server.py` | Known NeMo crash on Windows at interpreter exit after everything was saved. The server leaves without the normal shutdown to avoid it. Harmless. |
| `requirements.txt` fails to install with an encoding error | Do not edit it with PowerShell's `>` or `Out-File` (they write UTF-16). Use a text editor and save as UTF-8. |
| Dropped connection or slow answers while a heavy run is going | The target answers one request at a time. Run one heavy job at a time (the web page's queue does this). |

## 11. Updating and removing

Update: `git pull`, then `pip install -r requirements-lock.txt` again in the main environment (and the PyRIT one if `requirements-pyrit.txt` changed).
Remove: delete the repository folder (which holds both environments) and, if you wish, `ollama rm llama3.1:8b`. The Chroma embedding model is cached in your user profile.

**Changing a dependency.** Edit `requirements.txt`, install it in your working environment, then regenerate the lock file from that environment (never from a half-installed one), and commit both:

```powershell
pip freeze | Out-File -Encoding utf8 requirements-lock.txt
```

Open the file and delete any line that starts with `-e` or contains `@ file:///` (a local install). Windows PowerShell 5 writes a byte-order mark and Windows line endings here; pip reads both.
