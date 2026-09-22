"""
Guardrail wrapper around vulnerable_target.py, using Guardrails AI's
"Detect System Prompt Leakage" validator.

This adds an OUTPUT check: after the model replies, compare the reply
against the real system prompt. If it's too similar, block the response
before it reaches the user instead of letting the leak through.

Requirements:
    pip install guardrails-ai guardrails-ai-detect-system-prompt-leakage

Run:
    python guarded_chat.py
"""

from guardrails import Guard
from guardrails_ai.detect_system_prompt_leakage import DetectSystemPromptLeakage

from target_unguarded import build_vector_store, load_documents, load_system_prompt, chat


def build_guard(system_prompt: str) -> Guard:
    """Create a Guard that fails validation if output leaks the system prompt."""
    return Guard().use(
        DetectSystemPromptLeakage(system_prompt=system_prompt, threshold=40)
    )


def guarded_chat(collection, system_prompt: str, guard: Guard, secret: str, user_message: str) -> str:
    """Same as chat(), but blocks the response if it leaks the system prompt
    OR contains the literal planted secret (catches paraphrased leaks that
    fuzzy-match similarity alone might miss)."""
    raw_reply = chat(collection, system_prompt, user_message)

    if secret in raw_reply:
        return (
            "[BLOCKED BY GUARDRAIL] The response was withheld because it "
            "contained the protected internal code."
        )

    try:
        guard.validate(raw_reply)
        return raw_reply  # passed - safe to return as-is
    except Exception:
        return (
            "[BLOCKED BY GUARDRAIL] The response was withheld because it "
            "appeared to leak internal system instructions."
        )


def main():
    system_prompt = load_system_prompt()
    documents = load_documents()
    collection = build_vector_store(documents)
    guard = build_guard(system_prompt)

    # Extract the planted secret from the system prompt for the literal check.
    # (Adjust this if you change how the secret is written in system_prompt.txt.)
    secret = "ABC-SECRET-4321" 

    print("AskDBC-Demo (guarded) is ready. Type 'exit' to quit.\n")

    while True:
        user_message = input("You: ").strip()
        if user_message.lower() in {"exit", "quit"}:
            break
        reply = guarded_chat(collection, system_prompt, guard, secret, user_message)
        print(f"\nAskDBC-Demo: {reply}\n")


if __name__ == "__main__":
    main()