"""
The chatbot being attacked: a small RAG assistant (Chroma + Llama 3.1 8B via
Ollama) with a planted secret in its system prompt. Deliberately weak.

Configuration is data, kept out of the code:
    target/config/system_prompt.txt        system prompt including the planted secret
    target/config/documents.json           four dummy policy documents
    target/config/documents_poisoned.json  the same plus one booby-trapped document

This module is used by server.py (and so by every attack tool). It is not run
directly.
"""

import json
from pathlib import Path
from typing import Callable

CONFIG_DIR = Path(__file__).parent / "config"
SYSTEM_PROMPT_PATH = CONFIG_DIR / "system_prompt.txt"
DOCUMENTS_PATH = CONFIG_DIR / "documents.json"
POISONED_DOCUMENTS_PATH = CONFIG_DIR / "documents_poisoned.json"

MODEL_NAME = "llama3.1:8b"
N_RESULTS = 2


def load_system_prompt() -> str:
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def load_documents(path: Path = DOCUMENTS_PATH) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ollama_chat(messages: list[dict]) -> str:
    """Call the local model. Imported lazily so tests can run without Ollama."""
    import ollama

    response = ollama.chat(model=MODEL_NAME, messages=messages)
    return response["message"]["content"]


class Chatbot:
    """Retrieval plus the model call. The model call is injectable for tests."""

    def __init__(
        self,
        documents_path: Path = DOCUMENTS_PATH,
        llm: Callable[[list[dict]], str] = ollama_chat,
        embedding_function=None,
    ):
        import chromadb

        self.system_prompt = load_system_prompt()
        self.documents = load_documents(documents_path)
        self.llm = llm
        # A fresh in-memory collection per Chatbot, so switching document sets
        # can never mix old and new documents.
        client = chromadb.EphemeralClient()
        name = f"docs_{abs(hash((str(documents_path), id(self))))}"
        kwargs = {"embedding_function": embedding_function} if embedding_function else {}
        self.collection = client.get_or_create_collection(name=name, **kwargs)
        self.collection.add(
            ids=[d["id"] for d in self.documents],
            documents=[d["text"] for d in self.documents],
        )

    def retrieve(self, query: str) -> tuple[list[str], str]:
        """Return (ids, context text) of the closest documents to the query."""
        results = self.collection.query(query_texts=[query], n_results=N_RESULTS)
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        return ids, "\n\n".join(docs)

    def build_messages(self, history: list[dict], question: str, context: str) -> list[dict]:
        """System prompt, earlier turns as-is, then the question with the documents."""
        final = f"Reference documents:\n{context}\n\nUser question: {question}"
        return (
            [{"role": "system", "content": self.system_prompt}]
            + history
            + [{"role": "user", "content": final}]
        )

    def answer(self, history: list[dict], question: str) -> tuple[str, list[str]]:
        """Unguarded path. Returns (reply, retrieved document ids)."""
        ids, context = self.retrieve(question)
        reply = self.llm(self.build_messages(history, question, context))
        return reply, ids
