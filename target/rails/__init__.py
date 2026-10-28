"""
Guardrail options for the target. Each option is one model name, askdbc-<id>.

    unguarded   no guardrail
    guarded     NeMo Guardrails (the id is kept so earlier logs and results still match)
    blocklist   keyword blocklist on the question, secret filter on the reply
    doccheck    drops retrieved documents that contain injected instructions

To add an option: write a Guardrail subclass in this folder, add its id to IDS and
the class to build_registry().

A fifth option, relay, exists only when the server is started with --relay-url: it forwards every request
to an external chatbot (see relay.py). It is not in IDS because it is optional.
"""

IDS = ("unguarded", "guarded", "blocklist", "doccheck")


def build_registry(chatbot, nemo_llm=None, relay=None) -> dict:
    """Build every option. NeMo is built here too, so a missing NeMo install fails at start-up.
    relay: an optional relay.Relay for an external chatbot, served as askdbc-relay."""
    from .blocklist import Blocklist
    from .doc_check import DocCheck
    from .nemo_guard import NeMoGuard
    from .unguarded import Unguarded

    options = (Unguarded(), NeMoGuard(chatbot.system_prompt, nemo_llm), Blocklist(), DocCheck())
    registry = {option.id: option for option in options}
    if tuple(registry) != IDS:
        raise RuntimeError(f"rails.IDS {IDS} does not match the options built: {tuple(registry)}")
    if relay is not None:
        registry[relay.id] = relay
    return registry
