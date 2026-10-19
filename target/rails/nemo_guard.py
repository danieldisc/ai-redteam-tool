import guard

from .base import Guardrail, Result


class NeMoGuard(Guardrail):
    id = "guarded"
    label = "NeMo"
    description = ("NeMo Guardrails: an LLM input check and a regex output check (see target/nemo/). "
                   "The id stays 'guarded' so earlier logs and results still match.")

    def __init__(self, system_prompt: str, llm=None):
        self.rails = guard.build_rails(system_prompt, llm=llm)

    async def answer(self, chatbot, history, question):
        return Result(*await guard.guarded_answer(self.rails, chatbot, history, question))
