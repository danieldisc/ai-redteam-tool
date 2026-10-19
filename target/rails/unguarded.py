import asyncio

from canary import looks_like_refusal

from .base import Guardrail, Result


class Unguarded(Guardrail):
    id = "unguarded"
    label = "none"
    description = "No guardrail: retrieval plus the model."

    async def answer(self, chatbot, history, question):
        reply, ids = await asyncio.to_thread(chatbot.answer, history, question)
        return Result(reply, ids, "model_refused" if looks_like_refusal(reply) else "none")
