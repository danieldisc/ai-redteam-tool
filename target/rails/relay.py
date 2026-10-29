"""
Relay to an external chatbot: the target for someone else's chatbot, reached through this server.

Every attack tool still talks to this server (askdbc-relay), so the request log, the leak check and the
reports work exactly as they do for the built-in chatbot. This option forwards each request, with the whole
conversation so far, to an OpenAI-compatible chat endpoint and returns what it says.

If that chatbot has its own guardrail and reports what it decided, the verdict is kept next to the reply so
it can be compared with the oracle (report/external.py). It can arrive either way:

    JSON body    {"guardrail": {"verdict": "blocked" | "passed", "layer": "input rail", "reason": "..."}}
    HTTP headers X-Guardrail-Verdict, X-Guardrail-Layer, X-Guardrail-Reason

The URL is set at start-up or by the web page on this computer (PUT /admin/relay), never by an attack request. The
chatbot there sees every attack prompt: use fake data and check your organisation's rules first.
"""

import asyncio
import json
import urllib.error
import urllib.request

from canary import looks_like_refusal

from .base import Guardrail, Result

VERDICTS = ("blocked", "passed")


class RelayError(RuntimeError):
    """The external chatbot did not give a usable answer."""


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def read_verdict(body: dict, headers) -> dict | None:
    """The chatbot's own guardrail decision, from the JSON body or the headers, or None if it gave none."""
    raw = body.get("guardrail") if isinstance(body, dict) else None
    if isinstance(raw, dict):
        verdict, layer, reason = raw.get("verdict"), raw.get("layer"), raw.get("reason")
    else:
        verdict, layer, reason = (headers.get("X-Guardrail-Verdict"), headers.get("X-Guardrail-Layer"),
                                  headers.get("X-Guardrail-Reason"))
    if not verdict:
        return None
    verdict = str(verdict).strip().lower()
    return {"verdict": verdict if verdict in VERDICTS else "unknown",
            "layer": str(layer) if layer else None, "reason": str(reason)[:300] if reason else None}


class Relay(Guardrail):
    id = "relay"
    label = "External chatbot (relay)"
    description = "Another chatbot, reached through this server. Every request is forwarded to it. Fake data only."

    def __init__(self, url: str, model: str = "", api_key: str | None = None, timeout: float = 120.0):
        if not url.startswith(("http://", "https://")):
            raise ValueError("the relay URL must start with http:// or https://")
        self.url, self.model, self.api_key, self.timeout = url.rstrip("/"), model, api_key, timeout

    def _call(self, messages: list[dict]) -> tuple[str, dict | None]:
        payload = {"messages": messages}
        if self.model:
            payload["model"] = self.model
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(f"{self.url}/chat/completions", data=json.dumps(payload).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body, reply_headers = json.load(r), r.headers
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise RelayError(f"the external chatbot did not answer ({type(exc).__name__}: {exc})") from exc
        try:
            reply = text_of(body["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise RelayError("the external chatbot's reply is not in the OpenAI chat format") from exc
        return reply, read_verdict(body, reply_headers)

    async def answer(self, chatbot, history, question):
        messages = list(history) + [{"role": "user", "content": question}]
        reply, external = await asyncio.to_thread(self._call, messages)
        if external and external["verdict"] == "blocked":
            blocked_by = "external:" + (external["layer"] or "guardrail")
        else:
            blocked_by = "model_refused" if looks_like_refusal(reply) else "none"
        return Result(reply, [], blocked_by, (), external)
