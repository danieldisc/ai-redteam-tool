"""
Checks the web page's queue and server without Ollama, a real target or any tool run:

    python tests/test_ui.py

Jobs run tiny Python commands instead of run.py, and the target is the fake server from
test_scripted.py. Nothing is written under results/.
"""

import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ui"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import app as ui  # noqa: E402
import test_scripted  # noqa: E402

PY = sys.executable


def quick(job):
    return [PY, "-c", f"print('job {job['id']}: {job['tool']} on {job['target']}'); "
                      "print('x on y: attempted 7, flagged by the tool itself 2')"]


def slow(job):
    return [PY, "-c", "import time; print('started', flush=True); time.sleep(60)"]


def slow_start(job):
    """Takes a second to start, like process start-up can on Windows: cancel must still work."""
    time.sleep(1.0)
    return slow(job)


def wait_until(condition, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        if condition():
            return True
        time.sleep(0.1)
    return False


def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)
    return ok


def status_of(queue, job_id):
    return next(j["status"] for j in queue.snapshot()["jobs"] if j["id"] == job_id)


def call(url, path, body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    req = urllib.request.Request(url + path, data=data, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main() -> int:
    results = []
    fake, fake_url, _ = test_scripted.start_fake_server()
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # ---- queue: order, result line, logs -----------------------------------------------
        q = ui.JobQueue(tmp / "a", quick)
        ids = [q.add("baseline", g, "smoke", "t1")["id"] for g in ("unguarded", "guarded", "blocklist")]
        results.append(check("three jobs run to completion", wait_until(lambda: all(status_of(q, i) == "done" for i in ids))))
        job = q.snapshot()["jobs"][1]
        results.append(check("the result line is taken from the log", job["result"] == "2/7 flagged"))
        text, nxt = q.read_log(ids[1], 0)
        results.append(check("the log holds the command and its output", "baseline on guarded" in text and nxt > 0))
        results.append(check("jobs ran in the order queued", [j["started"] for j in q.snapshot()["jobs"]] == sorted(j["started"] for j in q.snapshot()["jobs"])))
        results.append(check("clear removes finished jobs", q.clear_finished() == 3 and q.snapshot()["jobs"] == []))

        # ---- cancel a running job and a queued one ------------------------------------------
        q2 = ui.JobQueue(tmp / "b", slow)
        first, second = q2.add("garak", "unguarded", "smoke", "c1")["id"], q2.add("garak", "guarded", "smoke", "c1")["id"]
        results.append(check("the first job starts, the second waits", wait_until(lambda: status_of(q2, first) == "running") and status_of(q2, second) == "queued"))
        results.append(check("a queued job can be cancelled", q2.cancel(second) and status_of(q2, second) == "cancelled"))
        started = time.time()
        results.append(check("a running job is killed on cancel", q2.cancel(first) and wait_until(lambda: status_of(q2, first) == "cancelled", 15) and time.time() - started < 15))
        results.append(check("cancelling a finished job is refused", not q2.cancel(first)))

        # ---- cancel in the gap between "running" and the process existing (this failed on Windows) ----
        q2b = ui.JobQueue(tmp / "b2", slow_start)
        jid = q2b.add("garak", "unguarded", "smoke", "c2")["id"]
        wait_until(lambda: status_of(q2b, jid) == "running")
        results.append(check("a cancel while the process is still starting is accepted", q2b.cancel(jid)))
        results.append(check("and the job ends cancelled without running", wait_until(lambda: status_of(q2b, jid) == "cancelled", 10)
                             and "started" not in q2b.read_log(jid, 0)[0].split("\n\n", 1)[-1]))  # first line is the echoed command
        q2b.shutdown()

        # ---- restart: leftover jobs are marked interrupted ----------------------------------
        (tmp / "c").mkdir()
        (tmp / "c" / "jobs.json").write_text(json.dumps([
            {"id": 1, "tool": "a", "target": "b", "tier": "smoke", "label": "x", "status": "running"},
            {"id": 2, "tool": "a", "target": "b", "tier": "smoke", "label": "x", "status": "queued"},
            {"id": 3, "tool": "a", "target": "b", "tier": "smoke", "label": "x", "status": "done"}]))
        q3 = ui.JobQueue(tmp / "c", quick)
        results.append(check("after a restart, running and queued jobs show as interrupted",
                             [j["status"] for j in q3.snapshot()["jobs"]] == ["interrupted", "interrupted", "done"]))

        # ---- the server: validation and safety ----------------------------------------------
        raw = tmp / "raw"
        (raw / "baseline").mkdir(parents=True)
        (raw / "baseline" / "baseline.used_unguarded.summary.json").write_text("{}")
        application = ui.App(fake_url, 0, state_dir=tmp / "d", results_raw=raw, build_command=quick)
        server = ui.make_server(application, 0)
        import threading
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f"http://127.0.0.1:{server.server_port}"

        code, status = call(url, "/api/status")
        results.append(check("status reports the target and its guardrails", code == 200 and status["reachable"] and status["guardrails"][0]["id"] == "unguarded"))
        code, body = call(url, "/api/jobs", {"tools": ["baseline", "garak"], "guardrails": ["unguarded"], "tier": "smoke", "label": "web1"})
        results.append(check("posting tools x guardrails creates one job each", code == 200 and [j["tool"] for j in body["created"]] == ["baseline", "garak"]))
        results.append(check("the jobs finish through the web route", wait_until(lambda: all(j["status"] == "done" for j in call(url, "/api/jobs")[1]["jobs"]))))
        code, rep = call(url, "/api/report", {"kind": "compare", "docs": "clean"})
        results.append(check("the compare report also returns the matrix as data", code == 200 and isinstance(rep.get("matrix"), dict) and {"tools", "guardrails", "cells"} <= set(rep["matrix"]) and "text" in rep))
        code, logbody = call(url, f"/api/jobs/{body['created'][0]['id']}/log?offset=0")
        results.append(check("the log route returns the output", "attempted 7" in logbody["text"]))
        code, body = call(url, "/api/jobs", {"tools": ["baseline"], "guardrails": ["unguarded"], "tier": "smoke", "label": "used"})
        results.append(check("a label that was already run is skipped", code == 200 and body["created"] == [] and "already run" in body["skipped"][0]))
        results.append(check("an unknown tool is refused", call(url, "/api/jobs", {"tools": ["rm"], "guardrails": ["unguarded"], "tier": "smoke"})[0] == 400))
        results.append(check("a guardrail the target does not offer is refused", call(url, "/api/jobs", {"tools": ["baseline"], "guardrails": ["nope"], "tier": "smoke"})[0] == 400))
        results.append(check("a label with spaces or symbols is refused", call(url, "/api/jobs", {"tools": ["baseline"], "guardrails": ["unguarded"], "tier": "smoke", "label": "a b;c"})[0] == 400))
        results.append(check("a cross-site Origin is refused", call(url, "/api/jobs", {"tools": ["baseline"], "guardrails": ["unguarded"], "tier": "smoke"}, {"Origin": "http://evil.example"})[0] == 403))
        results.append(check("a wrong Host header is refused", call(url, "/api/status", None, {"Host": "evil.example"})[0] == 403))
        req = urllib.request.Request(url + "/api/jobs/clear", data=b"{}", headers={"Content-Type": "text/plain"})
        try:
            urllib.request.urlopen(req, timeout=5)
            plain = 200
        except urllib.error.HTTPError as e:
            plain = e.code
        results.append(check("a text/plain POST (how a web form would send it) is refused", plain == 415))
        with urllib.request.urlopen(url + "/", timeout=5) as r:
            page = r.read().decode()
        results.append(check("the page is served", "Red team bench" in page))
        results.append(check("the page has the other-chatbot form and no hidden fold for untestable risks", 'id="cbForm"' in page and "catsManual" not in page))
        code, opts = call(url, "/api/options")
        results.append(check("all ten OWASP risks are offered, untestable ones marked", [c["id"] for c in opts["categories"]] == [f"LLM{n:02d}" for n in range(1, 11)]
                             and any(c["manual"] for c in opts["categories"]) and all(c["tools"] for c in opts["categories"] if not c["manual"])))

        # ---- guardrail descriptions, page copy and page hygiene (additive checks) ---------------
        offline = ui.App("http://127.0.0.1:9", 0, state_dir=tmp / "offline", results_raw=raw, build_command=quick)
        opts = offline.options()
        results.append(check("options list the four guardrails with a label and description, even with the target down",
                             [g["id"] for g in opts["guardrails"]] == ["unguarded", "guarded", "blocklist", "doccheck"]
                             and all(g["label"] and g["description"] for g in opts["guardrails"])))
        results.append(check("options keep the older keys",
                             all(k in opts for k in ("tools", "tiers", "hints", "categories", "slow_tools"))))
        code, http_opts = call(url, "/api/options")
        results.append(check("the same guardrails come over HTTP", code == 200 and [g["id"] for g in http_opts["guardrails"]]
                             == ["unguarded", "guarded", "blocklist", "doccheck"]))
        results.append(check("the page names both routes and both buttons",
                             all(t in page for t in ("Guided scan", "Run single tools", "Start guided scan", "Run selected tools"))))
        results.append(check("the page never builds markup from strings",
                             not any(t in page for t in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"))))

        class Scan(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids, self.external = [], []

            def handle_starttag(self, tag, attrs):
                for name, value in attrs:
                    if name == "id":
                        self.ids.append(value)
                    if name in ("src", "href") and (value or "").startswith(("http://", "https://")):
                        self.external.append(value)

        parsed = Scan()
        parsed.feed(page)
        dupes = sorted({i for i in parsed.ids if parsed.ids.count(i) > 1})
        results.append(check(f"no id appears twice in the page {dupes}", not dupes))
        results.append(check("the page makes no external requests", not parsed.external))
        server.shutdown()
        q2.shutdown()
    fake.shutdown()
    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
