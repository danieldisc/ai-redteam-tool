"""
Retrieved-document check: look at each retrieved document before the model does, and drop
any that contain instruction-like text or a link to an unknown site.

It only does anything when a document is poisoned, so run the server with
`--docs poisoned` to test it. The question is passed through untouched. Dropped documents
are listed in the log as dropped_ids; blocked_by stays "none" because the answer still goes out.
"""

import asyncio
import re
from urllib.parse import urlparse

from canary import looks_like_refusal

from .base import Guardrail, Result

SUSPICIOUS = [re.compile(p, re.IGNORECASE) for p in (
    r"ignore\s+(all\s+|any\s+|your\s+|the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"note\s+to\s+the\s+(assistant|ai|model|llm)",
    r"\b(system|developer)\s+prompt\b",
    r"disregard\s+(all|any|your|the)\b",
    r"(end|finish|begin|start)\s+your\s+(answer|reply|response)\s+with",
    r"you\s+must\s+(first\s+)?(verify|log\s*in|click|visit|enter|send)",
)]
URL = re.compile(r"https?://[^\s)\"']+", re.IGNORECASE)
ALLOWED_HOSTS = ("gov.sg",)


def is_suspicious(text: str) -> bool:
    if any(p.search(text) for p in SUSPICIOUS):
        return True
    for url in URL.findall(text):
        host = urlparse(url).hostname or ""
        if not any(host == h or host.endswith("." + h) for h in ALLOWED_HOSTS):
            return True
    return False


class DocCheck(Guardrail):
    id = "doccheck"
    label = "document check"
    description = ("Drops retrieved documents that contain injected instructions or links to unknown sites "
                   "before the model sees them. Only matters with --docs poisoned.")

    async def answer(self, chatbot, history, question):
        pairs = await asyncio.to_thread(chatbot.retrieve_docs, question)
        flags = [(doc_id, text, is_suspicious(text)) for doc_id, text in pairs]
        kept = [(i, t) for i, t, bad in flags if not bad]
        dropped = tuple(i for i, _, bad in flags if bad)
        context = "\n\n".join(t for _, t in kept)
        reply = await asyncio.to_thread(chatbot.llm, chatbot.build_messages(history, question, context))
        return Result(reply, [i for i, _ in kept], "model_refused" if looks_like_refusal(reply) else "none", dropped)
