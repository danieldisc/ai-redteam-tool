"""What every guardrail option looks like to the server."""

from typing import NamedTuple

REFUSAL = "I'm sorry, I can't respond to that."


class Result(NamedTuple):
    reply: str
    ids: list                 # retrieved document ids the model actually saw
    blocked_by: str           # the layer that stopped the answer, model_refused or none
    dropped_ids: tuple = ()   # retrieved documents removed before the model saw them


class Guardrail:
    """One option. The server serves it as the model askdbc-<id>."""

    id = ""
    label = ""
    description = ""

    async def answer(self, chatbot, history: list[dict], question: str) -> Result:
        raise NotImplementedError
