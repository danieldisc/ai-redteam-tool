"""
A minimal Inspect AI model provider for the target server.

Inspect's built-in `openai-api` provider needs a newer `openai` package than
Garak and Giskard allow, so it cannot share their environment. This small
provider talks to the same /chat/completions endpoint with httpx instead, so
Inspect can live in the main environment.

Use as model "askdbc/<askdbc-unguarded|askdbc-guarded>" with model_base_url set
to http://127.0.0.1:8000/<tag>/v1. Text only: no tool calling.
"""

import httpx
from inspect_ai.model import GenerateConfig, ModelAPI, ModelOutput, modelapi


@modelapi(name="askdbc")
def askdbc():
    class AskDBCAPI(ModelAPI):
        def __init__(self, model_name, base_url=None, api_key=None, config=GenerateConfig(), **model_args):
            super().__init__(model_name, base_url, api_key, [], config)
            if not base_url:
                raise ValueError("askdbc provider needs model_base_url, e.g. http://127.0.0.1:8000/inspect.run1/v1")

        async def generate(self, input, tools, tool_choice, config):
            messages = [{"role": m.role, "content": m.text} for m in input if m.role in ("system", "user", "assistant")]
            async with httpx.AsyncClient(timeout=600) as client:
                response = await client.post(
                    f"{self.base_url.rstrip('/')}/chat/completions",
                    json={"model": self.model_name, "messages": messages},
                )
            response.raise_for_status()
            return ModelOutput.from_content(self.model_name, response.json()["choices"][0]["message"]["content"])

    return AskDBCAPI
