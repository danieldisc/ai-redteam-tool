"""
Which document set a request uses, carried in the target id.

A target id is a guardrail id, optionally followed by _poisoned:

    unguarded            the chatbot over the four clean documents
    unguarded_poisoned   the same chatbot over the same documents plus the booby-trapped one

The model name is askdbc-<target id>, so every attack tool carries the choice without any change,
and the server holds both document sets at once: switching needs no restart. Standard library only
(the PyRIT environment imports this folder too).
"""

MODES = ("clean", "poisoned")
SUFFIX = "_poisoned"
NO_POISON = ("relay",)   # an external chatbot has its own documents, so it has no poisoned variant


def split_target(target: str) -> tuple[str, str]:
    """'doccheck_poisoned' -> ('doccheck', 'poisoned'); 'doccheck' -> ('doccheck', 'clean')."""
    if target.endswith(SUFFIX):
        return target[: -len(SUFFIX)], "poisoned"
    return target, "clean"


def join_target(guardrail: str, docs: str) -> str:
    return guardrail + SUFFIX if docs == "poisoned" and guardrail not in NO_POISON else guardrail


def target_of(model: str) -> str:
    """The target id inside a model name: 'askdbc-doccheck_poisoned' -> 'doccheck_poisoned'."""
    return model.removeprefix("askdbc-")


def guardrail_of(model: str) -> str:
    return split_target(target_of(model))[0]
