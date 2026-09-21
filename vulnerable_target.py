"""
Minimal deliberately-vulnerable RAG chatbot, mimicking AskDBC's shape.

Purpose: a controllable local target for Garak (prompt injection / jailbreak
scanning) and Giskard (RAGET retrieval evaluation) to attack. NOT for
production use - it is intentionally weak.

Configuration lives in config/system_prompt.txt and config/documents.json,
kept separate from this code so either can be edited or swapped without
touching any Python.

Requirements:
    pip install chromadb ollama

Run:
    ollama serve                # if not already running in the background
    ollama pull llama3.1:8b     # already done
    python vulnerable_target.py
"""

import json
from pathlib import Path

import chromadb
import ollama

MODEL_NAME = "llama3.1:8b"

CONFIG_DIR = Path(__file__).parent / "config"
SYSTEM_PROMPT_PATH = CONFIG_DIR / "system_prompt.txt"
DOCUMENTS_PATH = CONFIG_DIR / "documents.json"


def load_system_prompt() -> str:
    """Load the system prompt from config/system_prompt.txt."""
    return SYSTEM_PROMPT_PATH.read_text(encoding="utf-8")


def load_documents() -> list[dict]:
    """Load the dummy document set from config/documents.json."""
    with open(DOCUMENTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def build_vector_store(documents: list[dict]):
    """Load the given documents into a local Chroma collection."""
    client = chromadb.Client()
    collection = client.get_or_create_collection(name="lta_demo_docs")

    if collection.count() == 0:
        collection.add(
            ids=[d["id"] for d in documents],
            documents=[d["text"] for d in documents],
        )
    return collection


def retrieve_context(collection, query: str, n_results: int = 2) -> str:
    """Return the top-matching documents for a query, joined as plain text."""
    results = collection.query(query_texts=[query], n_results=n_results)
    docs = results.get("documents", [[]])[0]
    return "\n\n".join(docs)


def chat(collection, system_prompt: str, user_message: str) -> str:
    """Retrieve context, then call the local model with system + context + query."""
    context = retrieve_context(collection, user_message)

    full_prompt = (
        f"Reference documents:\n{context}\n\n"
        f"User question: {user_message}"
    )

    response = ollama.chat(
        model=MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": full_prompt},
        ],
    )
    return response["message"]["content"]


def main():
    system_prompt = load_system_prompt()
    documents = load_documents()
    collection = build_vector_store(documents)

    print("AskDBC-Demo target is ready. Type 'exit' to quit.\n")

    while True:
        user_message = input("You: ").strip()
        if user_message.lower() in {"exit", "quit"}:
            break
        reply = chat(collection, system_prompt, user_message)
        print(f"\nAskDBC-Demo: {reply}\n")


if __name__ == "__main__":
    main()