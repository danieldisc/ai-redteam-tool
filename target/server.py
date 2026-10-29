"""
The target as an OpenAI-compatible chat endpoint. Every attack tool points at
this one server, so they all hit identical code.

    python target/server.py                  # port 8000
    python target/server.py --port 8001
    python target/server.py --relay-url http://localhost:9000/v1 --oracle oracle.json   # also serve another chatbot

One model is served per guardrail option (see target/rails/):
    askdbc-unguarded   retrieval + Llama 3.1 8B, no guardrail
    askdbc-guarded     the same, wrapped in NeMo Guardrails (input + output rail)
    askdbc-blocklist   keyword blocklist on the question, secret filter on the reply
    askdbc-doccheck    drops retrieved documents that contain injected instructions

Each option is served over two document sets, chosen by the model name and needing no restart:
askdbc-<id> uses the four clean documents, askdbc-<id>_poisoned adds the booby-trapped one
(target/docs_mode.py). The log records which set each request used.

With --relay-url the server also offers askdbc-relay: every request is forwarded to another chatbot (an
OpenAI-compatible endpoint, target/rails/relay.py) and its answer comes back, so the same tools, log and
reports work on it. --oracle names a JSON file with the secrets planted in that chatbot (target/oracle.py),
which is how the leak check judges its replies. Its own guardrail verdict, if it sends one, is logged
in the "external" field.

Point a tool at  http://localhost:8000/<tag>/v1  where <tag> is the tool name,
optionally with a run label after a dot (e.g. garak.run1). The tag is only used
to label requests in the log; it changes nothing about the answer.

Every request is appended to results/raw/server_log.jsonl (override with the
REDTEAM_LOG environment variable): who sent it, which model, the response, which
layer stopped it, and the deterministic leak verdict from canary.py.

Client-supplied system messages are dropped: a real chatbot would not let the
user replace its system prompt. Tool/function calling is not supported, and the
request settings max_tokens, temperature and stop are ignored, so every model
always answers with their own defaults and are compared like for like.

Requirements: see requirements.txt (Python 3.12). PyRIT has its own environment: requirements-pyrit.txt.
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import uvicorn  # noqa: E402
from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import JSONResponse, StreamingResponse  # noqa: E402

import canary  # noqa: E402
import docs_mode  # noqa: E402
import oracle  # noqa: E402
import rag  # noqa: E402
import rails  # noqa: E402
from rails.relay import Relay, RelayError  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = Path(os.environ.get("REDTEAM_LOG", ROOT / "results" / "raw" / "server_log.jsonl"))
MODELS = tuple(f"askdbc-{docs_mode.join_target(i, d)}" for d in docs_mode.MODES for i in rails.IDS)  # the built-in options
MAX_N = 10

app = FastAPI(title="AskDBC-Demo target")
state: dict = {}  # filled in by main(): chatbots (one per document set), guardrails, stub
_log_lock = asyncio.Lock()
_llm_lock = asyncio.Semaphore(int(os.environ.get("REDTEAM_CONCURRENCY", "1")))


def text_of(content) -> str:
    """OpenAI content can be a string or a list of {type, text} parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(p.get("text", "") for p in content if isinstance(p, dict))
    return "" if content is None else str(content)


def split_messages(messages: list[dict]) -> tuple[list[dict], str]:
    """Return (history, last user question). System messages are dropped."""
    turns = [
        {"role": m["role"], "content": text_of(m.get("content"))}
        for m in messages
        if m.get("role") in ("user", "assistant")
    ]
    if not turns or turns[-1]["role"] != "user":
        raise HTTPException(400, "the last message must be from the user")
    return turns[:-1], turns[-1]["content"]


async def write_log(record: dict) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with _log_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()


async def run_target(model: str, history: list[dict], question: str):
    """Run one question through the guardrail option and document set named by the model."""
    guardrail_id, docs = docs_mode.split_target(docs_mode.target_of(model))
    async with _llm_lock:
        try:
            return await state["guardrails"][guardrail_id].answer(state["chatbots"][docs], history, question)
        except RelayError as exc:
            raise HTTPException(502, str(exc)) from exc


def leak_verdict(model: str, reply: str) -> str:
    """The deterministic leak check. For the relay it uses the secrets planted in the external chatbot."""
    if docs_mode.guardrail_of(model) == "relay" and state.get("oracle"):
        return canary.check(reply, state["oracle"].get("system_prompt"), state["oracle"]["secrets"])
    return canary.check(reply, state["chatbots"]["clean"].system_prompt)


def served_models() -> list[str]:
    """Every model name this server answers: each option over clean and poisoned documents (relay: once)."""
    ids = list(state.get("guardrails") or rails.IDS)
    names = [f"askdbc-{docs_mode.join_target(i, d)}" for d in docs_mode.MODES for i in ids]
    return list(dict.fromkeys(names))


def completion_body(model: str, replies: list[str]) -> dict:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {"index": i, "message": {"role": "assistant", "content": r}, "finish_reason": "stop"}
            for i, r in enumerate(replies)
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def stream_body(model: str, replies: list[str]):
    cid = f"chatcmpl-{uuid.uuid4().hex[:12]}"
    created = int(time.time())

    def gen():
        for i, r in enumerate(replies):
            chunk = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
                     "choices": [{"index": i, "delta": {"role": "assistant", "content": r}, "finish_reason": None}]}
            yield f"data: {json.dumps(chunk)}\n\n"
        done = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
                "choices": [{"index": i, "delta": {}, "finish_reason": "stop"} for i in range(len(replies))]}
        yield f"data: {json.dumps(done)}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


KEY_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def admin_allowed(request: Request) -> bool:
    """The relay settings may only be changed by a program on this computer that sets a custom header.
    A web page on another site cannot send that header without a pre-flight check, which this server refuses."""
    client = request.client.host if request.client else ""
    return client in ("127.0.0.1", "::1") and request.headers.get("x-redteam-admin") == "1"


@app.put("/admin/relay")
async def connect_relay(request: Request):
    """Point the relay at another chatbot while the server runs: {url, model, key_env, secrets, markers, system_prompt}."""
    if not admin_allowed(request):
        raise HTTPException(403, "this route is for the web page on this computer only")
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "send a JSON object")
    key_env = (body.get("key_env") or "").strip()
    try:
        data = oracle.parse_oracle({k: body.get(k) for k in ("secrets", "markers", "system_prompt") if body.get(k) is not None})
        if key_env and not KEY_ENV.match(key_env):
            raise ValueError("key_env must be the NAME of an environment variable, not the key itself")
        if key_env and not os.environ.get(key_env):
            raise ValueError(f"the environment variable {key_env} is not set where the target server runs")
        relay = Relay(str(body.get("url") or "").strip(), str(body.get("model") or "").strip(), os.environ.get(key_env) if key_env else None)
    except (oracle.OracleError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    state["guardrails"][relay.id] = relay
    state["oracle"] = data
    return {"relay": {"url": relay.url, "model": relay.model}}


@app.delete("/admin/relay")
async def disconnect_relay(request: Request):
    if not admin_allowed(request):
        raise HTTPException(403, "this route is for the web page on this computer only")
    state["guardrails"].pop("relay", None)
    state["oracle"] = None
    return {"relay": None}


@app.get("/health")
async def health():
    guardrails = [{"id": g.id, "label": g.label, "description": g.description}
                  for g in state.get("guardrails", {}).values()]
    relay = state.get("guardrails", {}).get("relay")
    return {"status": "ok", "stub": state.get("stub", False), "docs": "both", "docs_modes": list(docs_mode.MODES),
            "guardrails": guardrails, "relay": {"url": relay.url, "model": relay.model} if relay else None}


@app.get("/{tag}/v1/models")
async def list_models(tag: str):
    return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "askdbc-demo"} for m in served_models()]}


@app.post("/{tag}/v1/chat/completions")
async def chat_completions(tag: str, request: Request):
    body = await request.json()
    model = body.get("model")
    if model not in served_models():
        raise HTTPException(404, f"unknown model {model!r}; use one of {served_models()}")
    messages = body.get("messages") or []
    history, question = split_messages(messages)
    n = max(1, min(int(body.get("n") or 1), MAX_N))
    case = (request.headers.get("x-redteam-case") or "")[:40] or None     # set by the test library, so the log says which test a request was
    owasp_ids = [x for x in (request.headers.get("x-redteam-owasp") or "").split(",") if re.fullmatch(r"LLM\d{2}", x)]

    replies = []
    for _ in range(n):
        started = time.perf_counter()
        result = await run_target(model, history, question)
        reply, ids, blocked_by, dropped = result.reply, result.ids, result.blocked_by, result.dropped_ids
        latency = round(time.perf_counter() - started, 2)
        replies.append(reply)
        await write_log({
            "ts": datetime.now().isoformat(timespec="seconds"),
            "tag": tag,
            "tool": tag.split(".", 1)[0],
            "model": model,
            "stub": state.get("stub", False),
            "docs": docs_mode.split_target(docs_mode.target_of(model))[1],
            "turns": len(history) + 1,
            "question": question,
            "history": history,
            "retrieved_ids": ids,
            "dropped_ids": list(dropped),
            "response": reply,
            "blocked_by": blocked_by,
            "external": result.external,
            "case": case,
            "owasp": owasp_ids,
            "canary": leak_verdict(model, reply),
            "latency_s": latency,
        })

    if body.get("stream"):
        return stream_body(model, replies)
    return JSONResponse(completion_body(model, replies))


def build_state(stub: bool, relay: Relay | None = None, oracle_data: dict | None = None) -> None:
    paths = {"clean": rag.DOCUMENTS_PATH, "poisoned": rag.POISONED_DOCUMENTS_PATH}
    if stub:
        import stub as stubs

        chatbots = {d: rag.Chatbot(p, llm=stubs.stub_chat, embedding_function=stubs.HashEmbedding()) for d, p in paths.items()}
        nemo_llm = stubs.StubNeMoLLM()
    else:
        chatbots = {d: rag.Chatbot(p) for d, p in paths.items()}
        nemo_llm = None
    state.update(
        chatbots=chatbots,
        guardrails=rails.build_registry(chatbots["clean"], nemo_llm, relay),  # the rails only use the system prompt, same for both sets
        stub=stub,
        oracle=oracle_data,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--docs", choices=["clean", "poisoned"], help=argparse.SUPPRESS)  # old flag, now ignored
    parser.add_argument("--relay-url", help="Also serve another chatbot as askdbc-relay: its OpenAI-compatible base URL, e.g. http://localhost:9000/v1")
    parser.add_argument("--relay-model", default="", help="Model name to send to that chatbot (if it needs one)")
    parser.add_argument("--relay-key-env", help="Name of the environment variable holding that chatbot's API key (never put the key on the command line)")
    parser.add_argument("--oracle", help="JSON file with the secrets planted in the external chatbot (required with --relay-url)")
    parser.add_argument("--stub", action="store_true", help="Fake model for plumbing tests only. Never report these results.")
    args = parser.parse_args()

    if args.docs:
        print("Note: --docs is ignored now. Both document sets are loaded; use a target ending _poisoned for the poisoned one.")
    relay = oracle_data = None
    if args.relay_url:
        if not args.oracle:
            sys.exit("--relay-url needs --oracle: a JSON file listing the secrets planted in that chatbot, so replies can be judged "
                     "(see target/oracle.py).")
        try:
            oracle_data = oracle.load_oracle(args.oracle)
            relay = Relay(args.relay_url, args.relay_model, os.environ.get(args.relay_key_env) if args.relay_key_env else None)
        except (oracle.OracleError, ValueError) as exc:
            sys.exit(str(exc))
        if args.relay_key_env and not os.environ.get(args.relay_key_env):
            sys.exit(f"The environment variable {args.relay_key_env} is not set.")
        print(f"Relay: askdbc-relay forwards every request to {args.relay_url}. That chatbot sees every attack prompt: use fake data only.")
    build_state(args.stub, relay, oracle_data)
    print(f"Target ready on http://{args.host}:{args.port}  documents=clean and poisoned  stub={args.stub}")
    print(f"Logging to {LOG_PATH}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    # Every request is already flushed to the log. NeMo has crashed on interpreter
    # exit on Windows (exit code 3221225477) after saving everything, so leave
    # without running the normal shutdown.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
