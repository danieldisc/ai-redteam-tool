"""The general input: one small file describes any chatbot, and every tool's input is built from it.

    {"address": "http://host:port/v1", "model": "name", "api_key_env": "TARGET_API_KEY",   <- where the chatbot is
     "purpose": "what an outsider could know about it, in a sentence or two",             <- the only knowledge the tools get
     "objectives": []}                                                                    <- optional goals; empty uses generic_objectives.json

Nothing here reads a threat catalogue or any chatbot-specific test cases. The address must speak the OpenAI chat format
(POST <address>/chat/completions); a chatbot with another API needs a small adapter in front of it.
"""
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAFE_ID = re.compile(r"[A-Za-z0-9_-]+")


def load_target(path) -> dict:
    target = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("address", "model", "purpose"):
        if not str(target.get(key) or "").strip():
            raise ValueError(f"the target file needs a non-empty '{key}'")
    if not str(target["address"]).startswith(("http://", "https://")):
        raise ValueError("'address' must start with http:// or https://")
    return target


def objectives_for(target: dict, defaults_path=None) -> list:
    """The target's own objectives if it has any, otherwise the generic list. A plain string is a goal; its rule is derived from it."""
    given = target.get("objectives") or []
    if not given:
        given = json.loads(Path(defaults_path or HERE / "generic_objectives.json").read_text(encoding="utf-8"))["objectives"]
    out = []
    for i, item in enumerate(given, 1):
        if isinstance(item, str):
            item = {"id": f"custom-{i}", "goal": item, "policy": "The chatbot must not do this: " + item}
        item = {"id": str(item.get("id") or f"custom-{i}"), "goal": item["goal"], "policy": item.get("policy") or "The chatbot must not do this: " + item["goal"]}
        if not SAFE_ID.fullmatch(item["id"]):
            raise ValueError(f"objective id {item['id']!r} may only use letters, digits, - and _")
        out.append(item)
    ids = [o["id"] for o in out]
    if len(set(ids)) != len(ids):
        raise ValueError("objective ids must be different from each other")
    return out


def build_packs(target: dict, defaults_path=None) -> list:
    """One pack per objective, in the shape the demo scripts read. There is no judge-only part: no marker text is known for a general chatbot."""
    return [{"level": "grey", "brief_id": o["id"], "chatbot": target["purpose"].strip(),
             "persona": {"model": target["model"], "who": "an ordinary member of the public using the chatbot, not signed in as anyone in particular"},
             "objectives": [{"id": o["id"], "threat": None, "goal": o["goal"], "policy": o["policy"]}],
             "judge_only": {"note": "General mode: no marker text. A judge reads each reply."}}
            for o in objectives_for(target, defaults_path)]


def messages_from_tests(tests: dict) -> list:
    """The attack messages in a Promptfoo tests file (each test has vars {<inject var>: message}), without repeats."""
    seen, out = set(), []
    for test in (tests or {}).get("tests") or []:
        values = (test.get("vars") or {})
        message = values.get("prompt")
        if message is None:
            message = next((v for v in values.values() if isinstance(v, str)), None)
        if isinstance(message, str) and message.strip() and message not in seen:
            seen.add(message)
            out.append(message)
    return out


def attach_messages(pack_path, messages: list) -> int:
    """Stores the messages on the pack's objective so Inspect AI and Giskard can replay them. Returns how many were stored."""
    pack_path = Path(pack_path)
    pack = json.loads(pack_path.read_text(encoding="utf-8"))
    for objective in pack["objectives"]:
        objective["attack_messages"] = list(messages)
    pack_path.write_text(json.dumps(pack, ensure_ascii=False, indent=1), encoding="utf-8")
    return len(messages)
