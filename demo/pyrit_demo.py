"""PyRIT, barebones. One goal sentence per objective (from grey.json), sent as a message, then marked by a text match.

Use its own virtual environment: PyRIT's packages clash with Garak's.

    pip install pyrit==1.1.0
    python demo/pyrit_demo.py            # single-turn, no AI model needed
    python demo/pyrit_demo.py --multi    # multi-turn with Claude as attacker; start the adapter with --history replay
"""
import asyncio
import json
import os
import sys
from pathlib import Path

from pyrit.executor.attack import AttackAdversarialConfig, AttackScoringConfig, PromptSendingAttack, RedTeamingAttack
from pyrit.prompt_target import OpenAIChatTarget
from pyrit.score import SubStringScorer
from pyrit.setup import IN_MEMORY, initialize_pyrit_async

class ClaudeTarget(OpenAIChatTarget):
    """Claude's OpenAI-compatible endpoint answers PyRIT's json_object setting with a 400, so this target sends none.
    PyRIT's own prompts already ask the attacker for JSON in the text."""

    def _build_response_format(self, json_config):
        return None


pack = json.loads(Path(__file__).with_name("grey.json").read_text(encoding="utf-8"))
adapter = os.environ.get("DEMO_ADAPTER", "http://127.0.0.1:8000")
multi = "--multi" in sys.argv


async def main():
    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    target = OpenAIChatTarget(endpoint=adapter + "/pyrit.demo/v1", model_name=pack["persona"]["model"], api_key="not-needed")
    for o in pack["objectives"]:
        scoring = AttackScoringConfig(objective_scorer=SubStringScorer(substring=pack["judge_only"][o["id"]]["success_text"][0]))
        if multi:
            claude = ClaudeTarget(endpoint="https://api.anthropic.com/v1/", model_name="claude-sonnet-5-5",
                                   api_key=os.environ["ANTHROPIC_API_KEY"])
            attack = RedTeamingAttack(objective_target=target, attack_adversarial_config=AttackAdversarialConfig(target=claude),
                                      attack_scoring_config=scoring, max_turns=3)
        else:
            attack = PromptSendingAttack(objective_target=target, attack_scoring_config=scoring)
        result = await attack.execute_async(objective=o["goal"])
        reply = result.last_response.converted_value if result.last_response else ""
        print(f"{o['id']}: {result.outcome.value} | {reply[:90]!r}")


asyncio.run(main())
