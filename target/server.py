"""
The target as an OpenAI-compatible chat endpoint. Every attack tool points at
this one server, so they all hit identical code.

    python target/server.py                  # port 8000, normal documents
    python target/server.py --docs poisoned  # include the booby-trapped document
    python target/server.py --port 8001

Two models are served:
    askdbc-unguarded   retrieval + Llama 3.1 8B
    askdbc-guarded     the same, wrapped in NeMo Guardrails (input + output rail)

Point a tool at  http://localhost:8000/<tag>/v1  where <tag> is the tool name,
optionally with a run label after a dot (e.g. garak.run1). The tag is only used
to label requests in the log; it changes nothing about the answer.

Every request is appended to results/raw/server_log.jsonl (override with the
REDTEAM_LOG environment variable): who sent it, which model, the response, which
layer stopped it, and the deterministic leak verdict from canary.py.

Client-supplied system messages are dropped: a real chatbot would not let the
user replace its system prompt. Tool/function calling is not supported, and the
request settings max_tokens, temperature and stop are ignored, so both models
always answer with their own defaults and are compared like for like.

Requirements: see requirements.txt (one Python 3.11 venv for everything).
"""

import argparse
import asyncio
import json
import os
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
import rag  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = Path(os.environ.get("REDTEAM_LOG", ROOT / "results" / "raw" / "server_log.jsonl"))
MODELS = ("askdbc-unguarded", "askdbc-guarded")
MAX_N = 10

app = FastAPI(title="AskDBC-Demo target")
state: dict = {}  # filled in by main(): chatbot, rails, stub, docs
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
    """Returns (reply, retrieved ids, blocked_by)."""
    async with _llm_lock:
        if model == "askdbc-unguarded":
            reply, ids = await asyncio.to_thread(state["chatbot"].answer, history, question)
            return reply, ids, "model_refused" if canary.looks_like_refusal(reply) else "none"
        import guard

        return await guard.guarded_answer(state["rails"], state["chatbot"], history, question)


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


@app.get("/health")
async def health():
    return {"status": "ok", "stub": state.get("stub", False), "docs": state.get("docs")}


@app.get("/{tag}/v1/models")
async def list_models(tag: str):
    return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "askdbc-demo"} for m in MODELS]}


@app.post("/{tag}/v1/chat/completions")
async def chat_completions(tag: str, request: Request):
    body = await request.json()
    model = body.get("model")
    if model not in MODELS:
        raise HTTPException(404, f"unknown model {model!r}; use one of {list(MODELS)}")
    messages = body.get("messages") or []
    history, question = split_messages(messages)
    n = max(1, min(int(body.get("n") or 1), MAX_N))

    replies = []
    for _ in range(n):
        started = time.perf_counter()
        reply, ids, blocked_by = await run_target(model, history, question)
        latency = round(time.perf_counter() - started, 2)
        replies.append(reply)
        await write_log({
            "ts": datetime.now().isoformat(timespec="seconds"),
            "tag": tag,
            "tool": tag.split(".", 1)[0],
            "model": model,
            "stub": state.get("stub", False),
            "docs": state.get("docs"),
            "turns": len(history) + 1,
            "question": question,
            "history": history,
            "retrieved_ids": ids,
            "response": reply,
            "blocked_by": blocked_by,
            "canary": canary.check(reply, state["chatbot"].system_prompt),
            "latency_s": latency,
        })

    if body.get("stream"):
        return stream_body(model, replies)
    return JSONResponse(completion_body(model, replies))


def build_state(docs: str, stub: bool) -> None:
    documents_path = rag.POISONED_DOCUMENTS_PATH if docs == "poisoned" else rag.DOCUMENTS_PATH
    if stub:
        import stub as stubs

        chatbot = rag.Chatbot(documents_path, llm=stubs.stub_chat, embedding_function=stubs.HashEmbedding())
        nemo_llm = stubs.StubNeMoLLM()
    else:
        chatbot = rag.Chatbot(documents_path)
        nemo_llm = None
    import guard

    state.update(
        chatbot=chatbot,
        rails=guard.build_rails(chatbot.system_prompt, llm=nemo_llm),
        stub=stub,
        docs=docs,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--docs", choices=["clean", "poisoned"], default="clean")
    parser.add_argument("--stub", action="store_true", help="Fake model for plumbing tests only. Never report these results.")
    args = parser.parse_args()

    build_state(args.docs, args.stub)
    print(f"Target ready on http://{args.host}:{args.port}  docs={args.docs}  stub={args.stub}")
    print(f"Logging to {LOG_PATH}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    # Every request is already flushed to the log. NeMo has crashed on interpreter
    # exit on Windows (exit code 3221225477) after saving everything, so leave
    # without running the normal shutdown.
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
