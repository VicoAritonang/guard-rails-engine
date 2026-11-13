"""Python client for a Guardrails Engine gateway.

Standard library only, so it adds nothing to your dependency tree::

    from guard_rails_engine import Client, Blocked

    gr = Client("http://localhost:8080", api_key="...")
    try:
        inbound = gr.inbound(messages=[{"role": "user", "content": prompt}])
        # Send inbound.messages, the rewritten payload, not your originals.
        answer = call_your_model(inbound.messages)
        outbound = gr.outbound(completion=answer, vault_token=inbound.vault_token)
        print(outbound.completion)  # placeholders are restored here
    except Blocked as refused:
        print("refused:", refused.reason)
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

__all__ = ["AsyncClient", "Blocked", "Client", "GatewayError", "Result"]
__version__ = "0.1.0"


class GatewayError(Exception):
    """The gateway could not be reached, or refused the request itself."""

    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


class Blocked(Exception):
    """Policy refused the payload. ``reason`` is safe to show to a user."""

    def __init__(self, reason: str, result: "Result"):
        super().__init__(f"blocked by policy: {reason}")
        self.reason = reason
        self.result = result


@dataclass
class Result:
    """A decision plus the payload as the engine left it.

    ``messages``, ``completion`` and ``tool_results`` come back rewritten. Send
    these onward: forwarding your originals silently defeats the redaction.
    """

    decision: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    reason: str = ""
    system: str = ""
    messages: List[Dict[str, Any]] = field(default_factory=list)
    completion: str = ""
    tool_results: List[Dict[str, Any]] = field(default_factory=list)
    vault_token: str = ""
    session: Optional[Dict[str, Any]] = None
    degraded: bool = False

    @property
    def action(self) -> str:
        return self.decision.get("action", "")

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self.decision.get("findings") or []


class Client:
    """Synchronous client. Safe to share between threads.

    ``fail_open`` decides what happens when the gateway itself is unreachable.
    The default refuses, which is right when the guardrail is a compliance
    control. ``True`` keeps a consumer product serving: the payload passes
    through unchecked, and ``Result.degraded`` is set so you can log it.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        fail_open: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.fail_open = fail_open

    def inbound(self, messages: List[Dict[str, Any]], **fields: Any) -> Result:
        """Check a prompt before it reaches a provider."""
        return self._guard("inbound", {"messages": messages, **fields})

    def runtime(self, tool_calls: List[Dict[str, Any]], **fields: Any) -> Result:
        """Check proposed tool calls inside an agent loop."""
        return self._guard("runtime", {"tool_calls": tool_calls, **fields})

    def tool_result(self, tool_results: List[Dict[str, Any]], **fields: Any) -> Result:
        """Check what a tool returned, before the model reads it."""
        return self._guard("tool_result", {"tool_results": tool_results, **fields})

    def outbound(self, completion: str, **fields: Any) -> Result:
        """Check a completion before it reaches the user.

        Pass ``vault_token=inbound.vault_token`` to restore the masked values.
        """
        return self._guard("outbound", {"completion": completion, **fields})

    def health(self) -> bool:
        """Report whether the gateway is serving."""
        try:
            self._request("GET", "/healthz", None)
            return True
        except GatewayError:
            return False

    def _guard(self, stage: str, body: Dict[str, Any]) -> Result:
        try:
            data = self._request("POST", f"/v1/guard/{stage}", body)
        except GatewayError as err:
            if self.fail_open and (err.status is None or err.status >= 500):
                return _passthrough(stage, body)
            raise
        result = Result(
            decision=data.get("decision") or {},
            blocked=bool(data.get("blocked")),
            reason=data.get("reason", ""),
            system=data.get("system", ""),
            messages=data.get("messages") or [],
            completion=data.get("completion", ""),
            tool_results=data.get("tool_results") or [],
            vault_token=data.get("vault_token", ""),
            session=data.get("session"),
        )
        if result.blocked:
            raise Blocked(result.reason, result)
        return result

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.base_url + path, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            detail = err.read().decode("utf-8", "replace")[:300]
            raise GatewayError(f"gateway returned {err.code}: {detail}", err.code) from err
        except (urllib.error.URLError, TimeoutError, ValueError) as err:
            raise GatewayError(f"gateway unreachable: {err}") from err


class AsyncClient:
    """The same API for asyncio code. Each call runs on a worker thread."""

    def __init__(self, *args: Any, **kwargs: Any):
        self._client = Client(*args, **kwargs)

    async def inbound(self, messages: List[Dict[str, Any]], **fields: Any) -> Result:
        return await asyncio.to_thread(self._client.inbound, messages, **fields)

    async def runtime(self, tool_calls: List[Dict[str, Any]], **fields: Any) -> Result:
        return await asyncio.to_thread(self._client.runtime, tool_calls, **fields)

    async def tool_result(self, tool_results: List[Dict[str, Any]], **fields: Any) -> Result:
        return await asyncio.to_thread(self._client.tool_result, tool_results, **fields)

    async def outbound(self, completion: str, **fields: Any) -> Result:
        return await asyncio.to_thread(self._client.outbound, completion, **fields)

    async def health(self) -> bool:
        return await asyncio.to_thread(self._client.health)


def _passthrough(stage: str, body: Dict[str, Any]) -> Result:
    return Result(
        decision={"stage": stage, "action": "allow", "degraded": True},
        system=body.get("system", ""),
        messages=body.get("messages") or [],
        completion=body.get("completion", ""),
        tool_results=body.get("tool_results") or [],
        vault_token=body.get("vault_token", ""),
        session=body.get("session"),
        degraded=True,
    )
