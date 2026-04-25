"""Streamable-HTTP MCP transport (POST-based, single endpoint)."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx

from mcp_redteam.transport.base import MCPTransport


class StreamableHTTPTransport(MCPTransport):
    """MCP transport using the streamable-HTTP profile (RFC-style POST + GET stream)."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._client: httpx.AsyncClient | None = None
        self._recv_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._stream_task: asyncio.Task[None] | None = None
        self._session_id: str | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=60.0)
        # Initialize via POST; response contains session id in header
        init_msg = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "mcp-redteam", "version": "0.1.0"},
                "capabilities": {},
            },
        }
        resp = await self._client.post(
            self._url,
            json=init_msg,
            headers={"Accept": "application/json, text/event-stream"},
        )
        resp.raise_for_status()
        self._session_id = resp.headers.get("mcp-session-id")
        body = resp.json()
        await self._recv_queue.put(body)
        # Open long-poll GET stream for server-initiated messages
        self._stream_task = asyncio.create_task(self._stream_loop())
        await self.notify("initialized")

    async def stop(self) -> None:
        if self._stream_task:
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass
        if self._client:
            if self._session_id:
                with httpx.suppress(Exception):  # type: ignore[attr-defined]
                    await self._client.delete(
                        self._url,
                        headers={"mcp-session-id": self._session_id},
                    )
            await self._client.aclose()

    async def send(self, message: dict[str, Any]) -> None:
        if self._client is None:
            raise RuntimeError("Transport not started")
        headers: dict[str, str] = {"Accept": "application/json, text/event-stream"}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        resp = await self._client.post(self._url, json=message, headers=headers)
        resp.raise_for_status()
        ct = resp.headers.get("content-type", "")
        if "application/json" in ct and resp.content:
            body = resp.json()
            await self._recv_queue.put(body)
        elif "text/event-stream" in ct:
            for line in resp.text.splitlines():
                if line.startswith("data:"):
                    data = line[5:].strip()
                    try:
                        await self._recv_queue.put(json.loads(data))
                    except json.JSONDecodeError:
                        pass

    async def recv(self) -> dict[str, Any]:
        return await self._recv_queue.get()

    async def _stream_loop(self) -> None:
        assert self._client
        headers: dict[str, str] = {"Accept": "text/event-stream"}
        if self._session_id:
            headers["mcp-session-id"] = self._session_id
        try:
            async with self._client.stream("GET", self._url, headers=headers) as resp:
                async for line in resp.aiter_lines():
                    if line.startswith("data:"):
                        data = line[5:].strip()
                        try:
                            msg = json.loads(data)
                            await self._recv_queue.put(msg)
                        except json.JSONDecodeError:
                            continue
        except asyncio.CancelledError:
            pass
        except Exception:
            pass


def transport_from_spec(server_spec: str) -> MCPTransport:
    """Parse a server-spec string into the appropriate transport."""
    from mcp_redteam.transport.config import ConfigTransport

    if server_spec.startswith("stdio:"):
        from mcp_redteam.transport.stdio import StdioTransport
        return StdioTransport(server_spec[len("stdio:"):])
    elif server_spec.startswith("sse:"):
        from mcp_redteam.transport.sse import SSETransport
        return SSETransport(server_spec[len("sse:"):])
    elif server_spec.startswith("http:"):
        return StreamableHTTPTransport(server_spec[len("http:"):])
    elif server_spec.startswith("config:"):
        return ConfigTransport(server_spec[len("config:"):])
    else:
        raise ValueError(
            f"Unknown server spec format: {server_spec!r}. "
            "Expected stdio:<cmd>, sse:<url>, http:<url>, or config:<file>#<name>."
        )
