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

Attachments (images, PDFs, Office files, audio) ride on a message as
``parts``, or go straight to the upload endpoint::

    from guard_rails_engine import attachment

    gr.inbound(messages=[{"role": "user", "content": "Summarise this",
                          "parts": [attachment("contract.pdf")]}])
    report = gr.scan_file("upload.docx")              # an upload form
    report = gr.scan_file("page.html", stage="tool_result", origin="web")  # RAG ingestion
"""

from __future__ import annotations

import asyncio
import base64
import json
import mimetypes
import os
import urllib.error
import uuid
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

__all__ = ["AsyncClient", "Blocked", "Client", "GatewayError", "Result", "attachment"]
__version__ = "0.1.0"

FileLike = Union[str, "os.PathLike[str]", bytes]


def _read(file: FileLike, name: Optional[str]) -> Tuple[bytes, str]:
    if isinstance(file, (bytes, bytearray)):
        return bytes(file), name or "upload.bin"
    path = os.fspath(file)
    with open(path, "rb") as fh:
        return fh.read(), name or os.path.basename(path)


def attachment(file: FileLike, name: Optional[str] = None, mime: Optional[str] = None) -> Dict[str, Any]:
    """Build a message part from a path or bytes.

    The gateway identifies the format from the bytes, so ``mime`` is a hint;
    a file whose bytes contradict its name is reported as a mismatch.
    """
    data, name = _read(file, name)
    part: Dict[str, Any] = {"name": name, "data": base64.b64encode(data).decode("ascii")}
    guessed = mime or mimetypes.guess_type(name)[0]
    if guessed:
        part["mime"] = guessed
    return part


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
    semantic: Optional[Dict[str, Any]] = None

    @property
    def action(self) -> str:
        return self.decision.get("action", "")

    @property
    def findings(self) -> List[Dict[str, Any]]:
        return self.decision.get("findings") or []

    @property
    def extractions(self) -> List[Dict[str, Any]]:
        """The ingest report of every attachment: coverage, methods, findings."""
        out: List[Dict[str, Any]] = []
        for item in list(self.messages) + list(self.tool_results):
            for part in item.get("parts") or []:
                if part.get("extraction"):
                    out.append({"name": part.get("name", ""), "type": part.get("type", ""), **part["extraction"]})
        return out


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

    def scan_file(
        self,
        file: FileLike,
        name: Optional[str] = None,
        stage: str = "inbound",
        text: str = "",
        origin: Optional[str] = None,
        tool: Optional[str] = None,
        tenant: Optional[str] = None,
    ) -> Result:
        """Upload a file to ``/v1/guard/media`` and return the decision.

        ``stage="tool_result"`` treats the file as retrieved content (RAG,
        web, email), which applies the indirect-injection prior; ``origin``
        defaults to "web" there.
        """
        data, name = _read(file, name)
        fields = {"stage": stage, "text": text, "origin": origin or "", "tool": tool or "", "tenant": tenant or ""}
        boundary = uuid.uuid4().hex
        body = bytearray()
        for key, value in fields.items():
            if value:
                body += f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode()
        mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
        safe_name = name.replace('"', "_")
        body += (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe_name}"\r\n'
                 f"Content-Type: {mime}\r\n\r\n").encode()
        body += data + f"\r\n--{boundary}--\r\n".encode()
        reply = self._request("POST", "/v1/guard/media", bytes(body),
                              content_type=f"multipart/form-data; boundary={boundary}")
        result = _result(reply)
        if result.blocked:
            raise Blocked(result.reason, result)
        return result

    def media_info(self) -> Dict[str, Any]:
        """What this gateway can read: formats, OCR, speech-to-text, image classifiers."""
        return self._request("GET", "/v1/media", None)

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
        result = _result(data)
        if result.blocked:
            raise Blocked(result.reason, result)
        return result

    def _request(self, method: str, path: str, body: Any, content_type: str = "application/json") -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        payload = None
        if isinstance(body, (bytes, bytearray)):
            payload = bytes(body)
            headers["Content-Type"] = content_type
        elif body is not None:
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

    async def scan_file(self, file: FileLike, **kwargs: Any) -> Result:
        return await asyncio.to_thread(self._client.scan_file, file, **kwargs)

    async def media_info(self) -> Dict[str, Any]:
        return await asyncio.to_thread(self._client.media_info)

    async def health(self) -> bool:
        return await asyncio.to_thread(self._client.health)


def _result(data: Dict[str, Any]) -> Result:
    return Result(
        decision=data.get("decision") or {},
        blocked=bool(data.get("blocked")),
        reason=data.get("reason", ""),
        system=data.get("system", ""),
        messages=data.get("messages") or [],
        completion=data.get("completion", ""),
        tool_results=data.get("tool_results") or [],
        vault_token=data.get("vault_token", ""),
        session=data.get("session"),
        semantic=data.get("semantic"),
    )


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
