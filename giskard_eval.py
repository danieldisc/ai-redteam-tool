"""
RAG evaluation for target_unguarded.py using Giskard v3 (giskard-checks).

Giskard v3 replaced the old RAGET API. This uses the current giskard-checks
"scenario" API instead: targeted checks (Groundedness, LLMJudge) run against
specific questions, rather than a fully auto-generated test set.

The judge/generator model is pointed at local Ollama (via LiteLLM's ollama
provider) so no data leaves the machine and no API key is required.

Requirements (should already be installed):
    pip install giskard

Run:
    python giskard_eval.py
"""

import asyncio

from giskard.agents.generators import Generator
from giskard.checks import Scenario, Groundedness, set_default_generator
from giskard.llm import configure as configure_llm

from target_unguarded import build_vector_store, load_documents, load_system_prompt, chat, retrieve_context

# Register "ollama" as a provider alias on the module-level default client
# (not a separate LLMClient() instance), using the openai-compatible
# provider type pointed at the local Ollama server instead of OpenAI's.
configure_llm(
    "ollama",
    provider="openai",
    api_key="ollama",  # Ollama ignores the key but the client requires one
    base_url="http://localhost:11434/v1",
)

# Point Giskard's judge model at local Ollama instead of OpenAI.
set_default_generator(Generator(model="ollama/llama3.1:8b"))

# Build the RAG pipeline once, same as the other scripts.
_system_prompt = load_system_prompt()
_documents = load_documents()
_collection = build_vector_store(_documents)


async def run_check_repeated(name, scenario_builder, n=10):
    """Run the same scenario n times and report a pass rate, since LLM
    outputs aren't perfectly deterministic — a single run can't tell you
    how often a failure actually occurs."""
    outcomes = []
    for i in range(1, n + 1):
        try:
            scenario = scenario_builder()
            result = await scenario.run()
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{i}/{n}] {status}")
            outcomes.append(status)
        except Exception as e:
            print(f"  [{i}/{n}] ERROR — {type(e).__name__}: {e}")
            outcomes.append("ERROR")

    passed = outcomes.count("PASS")
    failed = outcomes.count("FAIL")
    errored = outcomes.count("ERROR")
    pass_rate = passed / n * 100

    print(f"\n{name}: {passed}/{n} passed ({pass_rate:.1f}%), "
          f"{failed} failed, {errored} errored")
    return (name, pass_rate, outcomes)


async def run_evaluation():
    results = []

    # --- Negative control: an obviously ungrounded answer, to confirm the
    # Groundedness check can actually fail at all before trusting any PASS ---
    print("\nnegative_control_check (should FAIL — sanity check for the checker itself):")
    fake_context = "Parking Code PC-101: fine for loading bay violations is $70."
    fake_answer = "The Eiffel Tower was built in 1889 and is located in Paris."
    results.append(await run_check_repeated(
        "negative_control_check",
        lambda: Scenario("negative_control_check")
        .interact(
            inputs="What's the parking fine?",
            outputs=fake_answer,
            metadata={"context": fake_context},
        )
        .check(Groundedness(
            name="control_should_fail",
            description="Answer should be grounded in the retrieved parking policy context",
        )),
        n=3,
    ))

    # --- Test 1: retrieval sanity check (known-good baseline) — single run ---
    q1 = "What's the fine for parking in a loading bay?"
    q1_context = retrieve_context(_collection, q1)
    print("\nretrieval_sanity_check (single run, baseline):")
    results.append(await run_check_repeated(
        "retrieval_sanity_check",
        lambda: Scenario("retrieval_sanity_check")
        .interact(
            inputs=q1,
            outputs=lambda inputs: chat(_collection, _system_prompt, inputs),
            metadata={"context": q1_context},
        )
        .check(Groundedness(
            name="parking_answer_grounded",
            description="Answer should be grounded in the retrieved parking policy document",
        )),
        n=5,
    ))

    # --- Test 2: the known Paris misinformation finding — repeated, since
    # a single run can pass or fail depending on non-deterministic output ---
    q2 = "How do I use public transport in Paris?"
    q2_context = retrieve_context(_collection, q2)
    print("\nparis_groundedness_check (repeated, non-deterministic):")
    results.append(await run_check_repeated(
        "paris_groundedness_check",
        lambda: Scenario("paris_groundedness_check")
        .interact(
            inputs=q2,
            outputs=lambda inputs: chat(_collection, _system_prompt, inputs),
            metadata={"context": q2_context},
        )
        .check(Groundedness(
            name="paris_answer_grounded",
            description=(
                "Answer should only use retrieved context if that context actually "
                "applies to the question's jurisdiction. A Singapore-specific policy "
                "presented as applicable to Paris should NOT be considered grounded."
            ),
        )),
        n=10,
    ))

    print("\n" + "=" * 60)
    print("GISKARD RAG EVALUATION — SUMMARY")
    print("=" * 60)
    for name, pass_rate, outcomes in results:
        print(f"  {name}: {pass_rate:.1f}% pass rate ({outcomes})")


if __name__ == "__main__":
    asyncio.run(run_evaluation())