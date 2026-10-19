"""
Garak against the target, through its OpenAI-compatible generator.

Probes are grouped by what they test, mapped to OWASP LLM Top 10 themes
(garak tags its own probes with older OWASP numbers; ignore those numbers).
Tiers:
    smoke      a few prompts from six probes, 1 generation each - proves the wiring
    standard   27 probes, at most 20 prompts each, 2 generations each
    full       the same probes uncapped (garak's own default cap is 256 prompts), 5 generations

Garak's own verdicts come from per-probe detectors. Some are string matches;
some are weak, and earlier work found about 44% of one probe's "hits" were
false positives. Always compare with the canary column in report/analyse.py and
audit a sample.

Probes whose detectors download a model from huggingface.co (toxicity, some
lmrc) are only in `full`, and need that site reachable.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from common import base_url, confirm, model_for, summary

ANSI = re.compile(r"\x1b\[[0-9;]*m")

# theme -> probes
THEMES = {
    "prompt injection / jailbreak (LLM01)": [
        "promptinject.HijackHateHumans", "promptinject.HijackKillHumans",
        "dan.Ablation_Dan_11_0", "dan.AutoDANCached", "dan.DanInTheWild",
        "goodside.Tag", "phrasing.PastTense", "grandma.Win10", "tap.TAPCached", "suffix.GCGCached",
    ],
    "encoded and latent injection (LLM01)": [
        "encoding.InjectBase64", "encoding.InjectROT13", "encoding.InjectHex",
        "latentinjection.LatentInjectionReport", "latentinjection.LatentJailbreak",
        "latentinjection.LatentWhois",
    ],
    "insecure output handling (LLM05)": [
        "xss.MarkdownImageExfil", "xss.ColabAIDataLeakage", "web_injection.MarkdownXSS", "web_injection.TaskXSS",
        "exploitation.JinjaTemplatePythonInjection", "exploitation.SQLInjectionEcho", "ansiescape.AnsiEscaped",
    ],
    "misinformation (LLM09)": [
        "misleading.FalseAssertion", "packagehallucination.Python", "goodside.WhoIsRiley",
    ],
    "data disclosure and unbounded output (LLM02 / LLM10)": [
        "divergence.Repeat",
    ],
}
# Extra probes only in `full`. Several need huggingface.co for their detectors.
FULL_EXTRA = [
    "dan.AutoDANCached", "encoding.InjectBase32", "encoding.InjectMorse",
    "latentinjection.LatentInjectionResume", "latentinjection.LatentInjectionTranslationEnFr",
    "latentinjection.LatentWhoisSnippet", "latentinjection.LatentInjectionFactSnippetEiffel",
    "malwaregen.Evasion", "malwaregen.Payload", "malwaregen.SubFunctions", "malwaregen.TopLevel",
    "packagehallucination.JavaScript", "snowball.GraphConnectivity", "grandma.Substances",
    "phrasing.FutureTense", "lmrc.Bullying", "lmrc.SlurUsage", "donotanswer",
    "realtoxicityprompts.RTPBlank",
]
# Newer garak renamed the xss family to web_injection. Names are resolved against
# what is installed; a probe that exists under neither name is reported and skipped.
ALIASES = {"xss.MarkdownImageExfil": "web_injection.MarkdownImageExfil",
           "xss.ColabAIDataLeakage": "web_injection.ColabAIDataLeakage"}
SMOKE = [
    "goodside.WhoIsRiley", "dan.AutoDANCached", "promptinject.HijackHateHumans",
    "encoding.InjectBase64", "xss.MarkdownImageExfil", "latentinjection.LatentInjectionReport",
]
TIERS = {
    "smoke": {"probes": SMOKE, "cap": 5, "generations": 1},
    "standard": {"probes": [p for ps in THEMES.values() for p in ps], "cap": 20, "generations": 2},
    "full": {"probes": [p for ps in THEMES.values() for p in ps] + FULL_EXTRA, "cap": 256, "generations": 5},
}


def garak(*args: str, env=None, capture=False):
    cmd = [sys.executable, "-m", "garak", *args]
    return subprocess.run(cmd, env=env, capture_output=capture, text=True)


def installed_probes() -> set[str]:
    out = garak("--list_probes", capture=True).stdout
    names = set()
    for line in out.splitlines():
        line = ANSI.sub("", line)
        if "probes:" in line:
            names.add(line.split("probes:")[1].split()[0].strip())
    return names


def target_flag() -> str:
    """garak renamed --model_type to --target_type in newer versions."""
    helptext = garak("--help", capture=True).stdout
    return "--target_type" if "--target_type" in helptext else "--model_type"


def name_flag(flag: str) -> str:
    return flag.replace("_type", "_name")


def parse_report(report: Path) -> tuple[int, int, list[dict]]:
    """(attempted, flagged, per-probe rows). If a probe has several detectors,
    its flagged count is the largest number of failures any one detector found."""
    per_probe: dict[str, dict] = {}
    with open(report, encoding="utf-8") as f:
        for line in f:
            entry = json.loads(line)
            if entry.get("entry_type") != "eval":
                continue
            # Older garak writes passed/total; newer writes passed/fails/total_evaluated.
            total = entry.get("total_evaluated", entry.get("total", 0))
            failed = entry["fails"] if "fails" in entry else total - entry["passed"]
            row = per_probe.setdefault(entry["probe"], {"probe": entry["probe"], "total": 0, "failed": 0, "detectors": {}})
            row["total"] = max(row["total"], total)
            row["failed"] = max(row["failed"], failed)
            row["detectors"][entry["detector"]] = f"{failed}/{total}"
    rows = sorted(per_probe.values(), key=lambda r: r["probe"])
    return sum(r["total"] for r in rows), sum(r["failed"] for r in rows), rows


def run(target, tag, tier, url, outdir: Path, seed=1, yes=False) -> dict:
    cfg = TIERS[tier]
    available = installed_probes()
    wanted = list(dict.fromkeys(cfg["probes"]))
    resolved = {p: (p if p in available else ALIASES.get(p, p)) for p in wanted}
    probes = list(dict.fromkeys(r for r in resolved.values() if r in available))
    missing = [p for p, r in resolved.items() if r not in available]
    notes = [f"probe not in this garak version, skipped: {', '.join(missing)}"] if missing else []

    upper = len(probes) * cfg["cap"] * cfg["generations"]
    confirm(f"garak {tier}: {len(probes)} probes, up to {cfg['cap']} prompts x {cfg['generations']} generations "
            f"= at most about {upper} requests to the {target} target.", yes)

    outdir.mkdir(parents=True, exist_ok=True)
    prefix = outdir / f"{tag}_{target}"
    options = outdir / f"{tag}_{target}.generator_options.json"
    options.write_text(json.dumps({"openai": {"OpenAICompatible": {"uri": base_url(url, tag) + "/"}}}), encoding="utf-8")
    config = outdir / f"{tag}_{target}.config.yaml"
    config.write_text(f"run:\n  soft_probe_prompt_cap: {cfg['cap']}\n", encoding="utf-8")

    flag = target_flag()
    env = {**os.environ, "OPENAICOMPATIBLE_API_KEY": "not-needed"}
    proc = garak(
        flag, "openai.OpenAICompatible", name_flag(flag), model_for(target),
        "--generator_option_file", str(options), "--config", str(config),
        "--probes", ",".join(probes), "--generations", str(cfg["generations"]),
        "--seed", str(seed), "--report_prefix", str(prefix), env=env,
    )

    report = Path(f"{prefix}.report.jsonl")
    if not report.exists():
        notes.append(f"garak exited with code {proc.returncode} and wrote no report")
        return summary("garak", tag, target, tier, 0, 0, notes, returncode=proc.returncode, probes=[])
    attempted, flagged, rows = parse_report(report)
    if proc.returncode:
        notes.append(f"garak exited with code {proc.returncode}; the report may be incomplete")
    notes.append(f"seed {seed}, soft prompt cap {cfg['cap']}, {cfg['generations']} generations per prompt")
    return summary("garak", tag, target, tier, attempted, flagged, notes,
                   returncode=proc.returncode, probes=rows, report=str(report))
