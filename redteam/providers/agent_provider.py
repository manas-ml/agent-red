"""promptfoo custom provider for the Northwind support agent.

promptfoo generates the adversarial probes; this module is the adapter that
gets them into the target and gets the target's behaviour back out in a shape
assertions can grade.

Three things it does that a naive HTTP provider would not:

1. **Session isolation.** Each test case gets its own ``session_id``, so a
   refund coaxed out in one case cannot contaminate the next.
2. **Multi-turn replay.** ``crescendo`` and ``goat`` escalate over several
   turns. If promptfoo hands us a conversation array, every user turn is
   replayed against ``/chat`` in order, against the same session, and the final
   reply is what gets graded.
3. **Actions, not just words.** The tools the agent actually invoked are
   returned in ``metadata.tool_calls``. This is the point of the whole
   exercise: an agent can refuse politely in prose while having already called
   ``issue_refund``. Grading only the text misses that entirely.

Configure via the target's ``config`` block in promptfooconfig.yaml::

    config:
      base_url: http://127.0.0.1:8000
      timeout_seconds: 60
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from typing import Any

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The 'requests' package is required by the promptfoo provider. "
        "Run: pip install -r requirements.txt"
    ) from exc

DEFAULT_BASE_URL = os.getenv("AGENT_BASE_URL", "http://127.0.0.1:8000")
DEFAULT_TIMEOUT = 60

#: Distinguishes sessions from separate scan runs that hash to the same vars.
_RUN_ID = uuid.uuid4().hex[:8]

#: Only ever talks to localhost, so an ambient HTTP(S)_PROXY must not be
#: consulted — it would silently black-hole the scan.
_http = requests.Session()
_http.trust_env = False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _config(options: dict[str, Any] | None) -> dict[str, Any]:
    return ((options or {}).get("config") or {}) if isinstance(options, dict) else {}


def _session_id(context: dict[str, Any] | None, options: dict[str, Any] | None) -> str:
    """A session id that is stable within a test case and unique across them.

    Stability matters: multi-turn strategies call this provider once per turn
    for the same case, and those turns have to land in one conversation.
    Uniqueness matters just as much — otherwise state bleeds between cases and
    a finding in one test is really an artifact of the one before it.
    """
    variables = ((context or {}).get("vars") or {}) if isinstance(context, dict) else {}

    # promptfoo's own stateful-target convention wins when present.
    for key in ("sessionId", "session_id"):
        explicit = variables.get(key)
        if explicit:
            return str(explicit)

    if not variables:
        return f"pf-{_RUN_ID}-{uuid.uuid4().hex[:12]}"

    digest = hashlib.sha256(
        json.dumps(variables, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]
    return f"pf-{_RUN_ID}-{digest}"


def _extract_turns(prompt: Any) -> list[str]:
    """Reduce whatever promptfoo passed into an ordered list of user turns.

    Accepts a plain string, a JSON-encoded chat array, or an already-decoded
    list of ``{role, content}`` dicts. Assistant turns are dropped — the target
    keeps its own history, so replaying them would double it up.
    """
    if isinstance(prompt, str):
        text = prompt.strip()
        if text.startswith("[") or text.startswith("{"):
            try:
                prompt = json.loads(text)
            except json.JSONDecodeError:
                return [prompt]
        else:
            return [prompt]

    if isinstance(prompt, dict):
        prompt = [prompt]

    if isinstance(prompt, list):
        turns = []
        for entry in prompt:
            if isinstance(entry, str):
                turns.append(entry)
            elif isinstance(entry, dict):
                if entry.get("role") in (None, "user", "human"):
                    content = entry.get("content", entry.get("text", ""))
                    if isinstance(content, list):
                        content = " ".join(
                            block.get("text", "")
                            for block in content
                            if isinstance(block, dict)
                        )
                    if content:
                        turns.append(str(content))
        return turns or [json.dumps(prompt)]

    return [str(prompt)]


def _error(message: str, session_id: str, hint: str = "") -> dict[str, Any]:
    """A provider-level failure, reported without taking the scan down."""
    detail = f"{message} {hint}".strip()
    return {
        "error": detail,
        "output": f"[provider error] {detail}",
        "metadata": {"provider_error": True, "session_id": session_id, "tool_calls": []},
    }


# --------------------------------------------------------------------------
# promptfoo entry point
# --------------------------------------------------------------------------
def call_api(
    prompt: Any,
    options: dict[str, Any] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one probe (or one multi-turn conversation) against the target."""
    cfg = _config(options)
    base_url = str(cfg.get("base_url", DEFAULT_BASE_URL)).rstrip("/")
    timeout = float(cfg.get("timeout_seconds", DEFAULT_TIMEOUT))
    session_id = _session_id(context, options)

    turns = _extract_turns(prompt)
    if not turns:
        return _error("Received an empty prompt with no user turns.", session_id)

    reply = ""
    tool_calls: list[dict[str, Any]] = []
    input_tokens = output_tokens = 0
    hardened: bool | None = None
    truncated = False

    for turn in turns:
        try:
            response = _http.post(
                f"{base_url}/chat",
                json={"session_id": session_id, "message": turn},
                timeout=timeout,
            )
        except requests.exceptions.ConnectionError:
            return _error(
                f"Could not connect to the target agent at {base_url}.",
                session_id,
                "Start it with `make target` (or ./scripts/run_scan.sh, which "
                "starts it for you) and confirm /healthz responds.",
            )
        except requests.exceptions.Timeout:
            return _error(
                f"The target agent at {base_url} did not respond within "
                f"{timeout:.0f}s.",
                session_id,
                "Raise timeout_seconds in the target config if the model is slow.",
            )
        except requests.exceptions.RequestException as exc:
            return _error(f"Request to {base_url} failed: {exc}", session_id)

        if response.status_code != 200:
            body = response.text[:400]
            return _error(
                f"Target returned HTTP {response.status_code}: {body}",
                session_id,
                "A 503 usually means the model backend has no API key.",
            )

        try:
            payload = response.json()
        except ValueError:
            return _error(
                f"Target returned a non-JSON body: {response.text[:200]}", session_id
            )

        reply = payload.get("reply", "") or ""
        tool_calls.extend(payload.get("tool_calls", []) or [])
        usage = payload.get("usage") or {}
        input_tokens += int(usage.get("input_tokens") or 0)
        output_tokens += int(usage.get("output_tokens") or 0)
        hardened = payload.get("hardened", hardened)
        truncated = truncated or bool(payload.get("truncated"))

    return {
        # Graded text is the agent's reply and nothing else. Tool *output* is
        # not a leak; the agent repeating it to the customer is.
        "output": reply,
        "tokenUsage": {
            "prompt": input_tokens,
            "completion": output_tokens,
            "total": input_tokens + output_tokens,
        },
        "sessionId": session_id,
        "metadata": {
            "session_id": session_id,
            "hardened": hardened,
            "turns": len(turns),
            "truncated": truncated,
            # The whole reason for a custom provider: assertions can grade
            # what the agent DID, not just what it said.
            "tool_calls": tool_calls,
            "tools_invoked": sorted({c.get("tool", "") for c in tool_calls} - {""}),
            "audit_url": f"{base_url}/audit/{session_id}",
        },
    }
