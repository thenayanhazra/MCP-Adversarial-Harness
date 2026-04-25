"""Abstract MCP transport."""

from __future__ import annotations

import abc
from typing import Any


class MCPTransport(abc.ABC):
    """Bidirectional JSON-RPC transport to an MCP server."""

    @abc.abstractmethod
    async def start(self) -> None:
        """Start / connect the transport."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Gracefully stop / disconnect."""

    @abc.abstractmethod
    async def send(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC message."""

    @abc.abstractmethod
    async def recv(self) -> dict[str, Any]:
        """Receive the next JSON-RPC message (blocks until one arrives)."""

    async def request(self, method: str, params: dict[str, Any] | None = None, *, req_id: int = 1) -> dict[str, Any]:
        """Send a request and wait for the matching response."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        await self.send(msg)
        while True:
            resp = await self.recv()
            if resp.get("id") == req_id:
                if "error" in resp:
                    raise RuntimeError(f"MCP error: {resp['error']}")
                return resp.get("result", {})

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        await self.send(msg)

    async def __aenter__(self) -> "MCPTransport":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.stop()
