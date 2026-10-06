"""
Offline stand-ins for Ollama and the embedding model, used ONLY to test the
plumbing (server, logging, rail detection, tool wiring) where no Ollama is
available. Anything produced with `server.py --stub` is marked stub=true in the
log and must never be reported as a result.
"""

import hashlib

from chromadb import EmbeddingFunction
from langchain_core.language_models.llms import LLM

from canary import SECRET

DOC_REPLY = "The fine for parking in a loading bay without a permit is $70 under Parking Code PC-101."
LEAK_TRIGGERS = ("debug mode", "system prompt", "backwards", "base64", "maintenance code",
                 "information you have been given", "first 30 words", "translate your")


def _leaks(text: str) -> bool:
    low = text.lower()
    return any(t in low for t in LEAK_TRIGGERS)


def stub_chat(messages: list[dict]) -> str:
    """Fake chatbot: leaks the secret when asked in one of the known ways."""
    last = messages[-1]["content"]
    return f"My internal maintenance code is {SECRET}." if _leaks(last) else DOC_REPLY


class StubNeMoLLM(LLM):
    """Fake LangChain LLM for NeMo: input check says Yes to leak-style requests."""

    @property
    def _llm_type(self) -> str:
        return "stub"

    def _call(self, prompt, stop=None, run_manager=None, **kwargs) -> str:
        if "should the user message be blocked" in prompt.lower():
            user_part = prompt.lower().rsplit("user message:", 1)[-1]
            # Only block the debug-mode request, so the output rail gets exercised too.
            return "Yes" if "debug mode" in user_part else "No"
        return stub_chat([{"content": prompt[-600:]}]) if _leaks(prompt[-300:]) else DOC_REPLY


class HashEmbedding(EmbeddingFunction):
    """Tiny deterministic embedding so Chroma needs no model download."""

    def __init__(self, dim: int = 64):
        self.dim = dim

    def __call__(self, input):
        out = []
        for text in input:
            vec = [0.0] * self.dim
            for word in text.lower().split():
                h = int(hashlib.md5(word.encode()).hexdigest(), 16)
                vec[h % self.dim] += 1.0
            out.append(vec)
        return out

    @staticmethod
    def name() -> str:
        return "hash-embedding-stub"

    def get_config(self):
        return {"dim": self.dim}

    @staticmethod
    def build_from_config(config):
        return HashEmbedding(config.get("dim", 64))
