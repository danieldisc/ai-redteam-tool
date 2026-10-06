"""
NVIDIA NeMo Guardrails wrapped around the chatbot in rag.py.

Rails (configured in target/nemo/config.yml and prompts.yml, built-in flows only):
    input   self check input    - an LLM call that decides whether to refuse the question
    output  regex check output  - a regex for the planted secret

NeMo is asked to return its log of activated rails, so every answer says which
rail (if any) stopped it. NeMo's own refusal text is not used to decide that.
"""

import os

# NeMo reports usage statistics to NVIDIA by default. Switch that off BEFORE
# importing it; this is a restricted-network project.
os.environ.setdefault("NEMO_GUARDRAILS_NO_USAGE_STATS", "1")
os.environ.setdefault("DO_NOT_TRACK", "1")

from pathlib import Path  # noqa: E402

from nemoguardrails import LLMRails, RailsConfig  # noqa: E402
from nemoguardrails.rails.llm.config import Instruction  # noqa: E402

from canary import looks_like_refusal  # noqa: E402
from rag import Chatbot  # noqa: E402

NEMO_CONFIG_DIR = Path(__file__).parent / "nemo"


def build_rails(system_prompt: str, llm=None) -> LLMRails:
    """Load the NeMo config and give it the real system prompt.

    The system prompt (with the secret) is injected here rather than stored in
    the NeMo config files, so the secret lives in one place. `llm` is only for
    tests (a LangChain LLM); normally NeMo uses the model named in config.yml.
    """
    config = RailsConfig.from_path(str(NEMO_CONFIG_DIR))
    config.instructions = [Instruction(type="general", content=system_prompt)]
    return LLMRails(config, llm=llm) if llm is not None else LLMRails(config)


def stopped_by(activated_rails) -> str:
    """Name the rail that stopped the answer: nemo_input, nemo_output or none."""
    for rail in activated_rails or []:
        if getattr(rail, "stop", False):
            if rail.type == "input":
                return "nemo_input"
            if rail.type == "output":
                return "nemo_output"
    return "none"


async def guarded_answer(
    rails: LLMRails, chatbot: Chatbot, history: list[dict], question: str
) -> tuple[str, list[str], str]:
    """Run one question through retrieval and NeMo.

    Returns (reply, retrieved document ids, blocked_by) where blocked_by is
    nemo_input, nemo_output, model_refused or none.
    """
    ids, context = chatbot.retrieve(question)
    messages = (
        [{"role": "context", "content": {"relevant_chunks": context}}]
        + history
        + [{"role": "user", "content": question}]
    )
    result = await rails.generate_async(
        messages=messages,
        options={"log": {"activated_rails": True}},
    )
    reply = result.response[0]["content"]
    blocked_by = stopped_by(result.log.activated_rails if result.log else None)
    if blocked_by == "none" and looks_like_refusal(reply):
        blocked_by = "model_refused"
    return reply, ids, blocked_by
