"""SSE MCP transport — connects to a server-sent events endpoint."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import httpx_sse

from mcp_redteam.transport.base import MCPTransport


class SSETransport(MCPTransport):
    """MCP transport over HTTP SSE (GET) + POST for client→server messages."""

    def __init__(self, url: str) -> None:
        # url is the SSE endpoint (GET), POST endpoint derived by convention
        self._sse_url = url
        # MCP SSE servers typically receive messages on the same base + /message
        base = url.rstrip("/")
        self._post_url = base.rsplit("/sse", 1)[0] + "/message"
        self._client: httpx.AsyncClient | None = None
        self._recv_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None
        self._session_id: str | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(timeout=30.0)
        self._reader_task = asyncio.create_task(self._sse_loop())
        # Wait briefly for session_id from endpoint event
        await asyncio.sleep(0.5)
        await self.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "mcp-redteam", "version": "0.1.0"},
                "capabilities": {},
            },
        )
        await self.notify("initialized")

    async def stop(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        if self._client:
            await self._client.aclose()

    async def send(self, message: dict[str, Any]) -> None:
        if self._client is None:
            raise RuntimeError("Transport not started")
        params = {}
        if self._session_id:
            params["sessionId"] = self._session_id
        await self._client.post(
            self._post_url,
            json=message,
            params=params,
            headers={"Content-Type": "application/json"},
        )

    async def recv(self) -> dict[str, Any]:
        return await self._recv_queue.get()

    async def _sse_loop(self) -> None:
        assert self._client
        try:
            async with httpx_sse.aconnect_sse(self._client, "GET", self._sse_url) as event_source:
                async for event in event_source.aiter_sse():
                    if event.event == "endpoint":
                        # Session ID is communicated via an endpoint event
                        data = event.data
                        if "sessionId=" in data:
                            self._session_id = data.split("sessionId=")[-1].split("&")[0]
                    elif event.event == "message":
                        try:
                            msg = json.loads(event.data)
                            await self._recv_queue.put(msg)
                        except json.JSONDecodeError:
                            continue
        except asyncio.CancelledError:
            pass
