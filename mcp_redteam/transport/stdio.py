"""stdio MCP transport — spawns a subprocess and communicates over stdin/stdout."""

from __future__ import annotations

import asyncio
import json
import shlex
from typing import Any

from mcp_redteam.transport.base import MCPTransport


class StdioTransport(MCPTransport):
    """Launch a server process and speak JSON-RPC over its stdin/stdout."""

    def __init__(self, command: str) -> None:
        # command is the raw shell string after "stdio:" prefix
        self._command = command
        self._proc: asyncio.subprocess.Process | None = None
        self._recv_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        args = shlex.split(self._command)
        self._proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._reader_task = asyncio.create_task(self._read_loop())
        # MCP handshake
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
        if self._proc:
            try:
                self._proc.stdin.close()  # type: ignore[union-attr]
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except (asyncio.TimeoutError, Exception):
                self._proc.kill()

    async def send(self, message: dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("Transport not started")
        line = json.dumps(message).encode() + b"\n"
        self._proc.stdin.write(line)
        await self._proc.stdin.drain()

    async def recv(self) -> dict[str, Any]:
        return await self._recv_queue.get()

    async def _read_loop(self) -> None:
        assert self._proc and self._proc.stdout
        while True:
            try:
                line = await self._proc.stdout.readline()
            except asyncio.CancelledError:
                break
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
                await self._recv_queue.put(msg)
            except json.JSONDecodeError:
                continue
