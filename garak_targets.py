"""
Garak "function" generator targets for target_unguarded.py / target_guarded.py.

Garak's built-in function generator calls a plain Python function matching
the signature: function(prompt: str, **kwargs) -> List[Union[str, None]]

This avoids needing a custom Generator class living inside garak's own
installed package - a plain module-level function is enough.

Usage:
    Unguarded target:
        python -m garak --target_type function --target_name garak_targets#call_unguarded --probes dan

    Guarded target:
        python -m garak --target_type function --target_name garak_targets#call_guarded --probes dan
"""

from target_unguarded import build_vector_store, load_documents, load_system_prompt, chat
from target_guarded import build_guard, guarded_chat

# Built once when garak imports this module, reused across every attack prompt.
_system_prompt = load_system_prompt()
_documents = load_documents()
_collection = build_vector_store(_documents)
_guard = build_guard(_system_prompt)
_secret = "ABC-SECRET-4321"  # match guarded_chat.py's current value


def call_unguarded(prompt: str, **kwargs):
    """Target: raw pipeline, no guardrail."""
    reply = chat(_collection, _system_prompt, prompt)
    return [reply]


def call_guarded(prompt: str, **kwargs):
    """Target: pipeline wrapped with the Guardrails AI check."""
    reply = guarded_chat(_collection, _system_prompt, _guard, _secret, prompt)
    return [reply]