"""FastAPI wrapper around the agent. Binds to 127.0.0.1 and stays there.

This process is the system under test. It is deliberately weak by default —
see SAFETY.md before you even think about running it anywhere but localhost.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import agent, config, tools

app = FastAPI(
    title="Northwind Outfitters Support Agent (red team target)",
    description=(
        "A deliberately under-hardened support agent used as the system under "
        "test for a promptfoo red team POC. Synthetic data only. Do not deploy."
    ),
    version="1.0.0",
)


class ChatRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=200)
    message: str = Field(..., max_length=100_000)


class ResetRequest(BaseModel):
    session_id: str = Field(..., min_length=1, max_length=200)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness plus the active configuration, so scans can record the mode."""
    return {"status": "ok", "config": config.describe(), "active_sessions": len(agent.SESSIONS)}


@app.post("/chat")
def chat(request: ChatRequest) -> dict[str, Any]:
    """Send one message to the agent and get its reply plus the tools it ran."""
    try:
        result = agent.chat(request.session_id, request.message)
    except agent.BackendError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - surfaced to the scan, not swallowed
        raise HTTPException(status_code=500, detail=f"agent_error: {exc}") from exc

    return {
        "session_id": request.session_id,
        "reply": result.reply,
        "tool_calls": result.tool_calls,
        "usage": {
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
        },
        "iterations": result.iterations,
        "truncated": result.truncated,
        "hardened": config.HARDENED,
    }


@app.post("/reset")
def reset(request: ResetRequest) -> dict[str, Any]:
    """Clear a session's conversation state."""
    existed = agent.reset_session(request.session_id)
    return {"session_id": request.session_id, "reset": True, "existed": existed}


@app.get("/audit/{session_id}")
def audit(session_id: str) -> JSONResponse:
    """Every tool invocation recorded for a session, oldest first.

    This is the trace that takes a failed red team case back to the exact
    tool calls that caused it.
    """
    records = tools.read_audit(session_id)
    return JSONResponse(
        {"session_id": session_id, "count": len(records), "tool_calls": records}
    )


def main() -> None:
    """Run the target agent on 127.0.0.1. Never binds to a public interface."""
    import uvicorn

    host = config.HOST
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit(
            f"Refusing to bind to {host!r}. This target is intentionally "
            f"vulnerable and must only listen on 127.0.0.1."
        )
    uvicorn.run(app, host=host, port=config.PORT, log_level="warning")


if __name__ == "__main__":
    main()
