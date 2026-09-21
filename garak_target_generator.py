"""
Custom Garak generator for vulnerable_target.py.

Garak normally talks straight to a model (e.g. raw Ollama). This generator
instead routes every attack prompt through our actual RAG pipeline -
retrieval + system prompt included - so Garak is testing the real target,
not bare Llama.

Usage:
    garak --model_type garak_target_generator --probes <probe_name>

Garak discovers this file by its module name, so it must be importable
from wherever you run garak (i.e. sit in the same folder, with your venv
active).
"""

from garak.generators.base import Generator

from vulnerable_target import build_vector_store, load_documents, load_system_prompt, chat


class AskDBCDemoGenerator(Generator):
    """Wraps vulnerable_target.chat() so Garak attacks the full pipeline."""

    generator_family_name = "AskDBC-Demo"
    name = "askdbc-demo"

    def __init__(self, name="askdbc-demo", config_root=None):
        super().__init__(name, config_root=config_root)
        # Build the RAG pipeline once, reused across every attack Garak sends.
        self.system_prompt = load_system_prompt()
        self.documents = load_documents()
        self.collection = build_vector_store(self.documents)

    def _call_model(self, prompt, generations_this_call=1):
        """Garak calls this once per attack prompt. Must return a list of responses."""
        reply = chat(self.collection, self.system_prompt, prompt)
        return [reply]


# Garak looks for a variable/class it can instantiate as the generator.
DEFAULT_CLASS = "AskDBCDemoGenerator"