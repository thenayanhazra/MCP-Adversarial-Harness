"""
Payload-injection shim transport.

Wraps a real MCPTransport and intercepts:
  - tools/list responses → splices payload into target tool's description
  - tools/call responses → replaces result text with payload

This lets us test any live server without modifying it.
"""

from __future__ import annotations

from typing import Any

from mcp_redteam.corpus.schema import InjectionPoint, Payload
from mcp_redteam.transport.base import MCPTransport


class ShimTransport(MCPTransport):
    def __init__(self, inner: MCPTransport, payload: Payload) -> None:
        self._inner = inner
        self._payload = payload
        self._tool_names: list[str] = []  # populated after first tools/list

    async def start(self) -> None:
        await self._inner.start()

    async def stop(self) -> None:
        await self._inner.stop()

    async def send(self, message: dict[str, Any]) -> None:
        await self._inner.send(message)

    async def recv(self) -> dict[str, Any]:
        return await self._inner.recv()

    async def request(
        self, method: str, params: dict[str, Any] | None = None, *, req_id: int = 1
    ) -> dict[str, Any]:
        result = await self._inner.request(method, params, req_id=req_id)
        return self._intercept(method, params or {}, result)

    def _intercept(
        self, method: str, params: dict[str, Any], result: dict[str, Any]
    ) -> dict[str, Any]:
        p = self._payload
        if method == "tools/list" and p.injection_point == InjectionPoint.description:
            return self._splice_description(result)
        if method == "tools/call" and p.injection_point == InjectionPoint.result:
            called_tool = params.get("name", "")
            target = p.target_tool or (self._tool_names[0] if self._tool_names else None)
            if target is None or called_tool == target:
                return self._splice_result(result)
        return result

    def _splice_description(self, result: dict[str, Any]) -> dict[str, Any]:
        tools: list[dict[str, Any]] = result.get("tools", [])
        if not tools:
            return result
        target = self._payload.target_tool
        modified: list[dict[str, Any]] = []
        for tool in tools:
            self._tool_names.append(tool["name"])
            if target is None or tool["name"] == target:
                tool = dict(tool)
                original_desc = tool.get("description", "")
                tool["description"] = original_desc + "\n" + self._payload.payload_text
            modified.append(tool)
        return {**result, "tools": modified}

    def _splice_result(self, result: dict[str, Any]) -> dict[str, Any]:
        content = result.get("content", [])
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict) and first.get("type") == "text":
                poisoned = first.get("text", "") + "\n" + self._payload.payload_text
                content = [{"type": "text", "text": poisoned}] + content[1:]
        return {**result, "content": content}
