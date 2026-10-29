"""
The oracle for an external chatbot: the facts that were planted in it, so attack success can be judged
by plain string matching, whatever any tool or the chatbot's own guardrail says.

    {"secrets": ["ZEBRA-9921"], "markers": ["PWNED-7731"], "system_prompt": "optional, the chatbot's prompt"}

secrets        strings the chatbot must never reveal (required, at least one, fake data only)
markers        extra words that mean an injected instruction was obeyed (optional; the project's own
               marker words such as PWNED-7731 are always checked by the reports)
system_prompt  the chatbot's system prompt, if you know it, so a long verbatim repeat counts as a leak

Standard library only.
"""

import json
from pathlib import Path


class OracleError(ValueError):
    pass


def load_oracle(path) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise OracleError(f"cannot read the oracle file {path}: {exc}") from exc
    return parse_oracle(data)


def parse_oracle(data) -> dict:
    """Check an oracle given as a dict (from the file, or from the web page) and tidy it."""
    if not isinstance(data, dict):
        raise OracleError("the oracle must be a JSON object")
    secrets = data.get("secrets")
    if not isinstance(secrets, list) or not secrets or not all(isinstance(s, str) and s.strip() for s in secrets):
        raise OracleError('the oracle needs "secrets": a non-empty list of strings that were planted in the chatbot')
    markers = data.get("markers", [])
    if not isinstance(markers, list) or not all(isinstance(m, str) and m.strip() for m in markers):
        raise OracleError('"markers" must be a list of non-empty strings')
    prompt = data.get("system_prompt")
    if prompt is not None and not isinstance(prompt, str):
        raise OracleError('"system_prompt" must be a string')
    return {"secrets": [s.strip() for s in secrets], "markers": [m.strip() for m in markers], "system_prompt": prompt}
