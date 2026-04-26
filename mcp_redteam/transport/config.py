"""config: server-spec parser — reads Claude Desktop / MCP config JSON."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_redteam.transport.base import MCPTransport


class ConfigTransport(MCPTransport):
    """
    Reads a claude_desktop_config.json (or compatible) and delegates to
    StdioTransport using the named server's command + args.

    spec format:  config:/path/to/config.json#server-name
    """

    def __init__(self, spec: str) -> None:
        if "#" not in spec:
            raise ValueError("config: spec must be 'config:<file>#<server-name>'")
        file_part, server_name = spec.rsplit("#", 1)
        self._config_path = Path(file_part).expanduser()
        self._server_name = server_name
        self._delegate: MCPTransport | None = None

    def _build_delegate(self) -> MCPTransport:
        from mcp_redteam.transport.stdio import StdioTransport

        raw = json.loads(self._config_path.read_text())
        servers: dict[str, Any] = raw.get("mcpServers", {})
        if self._server_name not in servers:
            raise KeyError(
                f"Server {self._server_name!r} not found in {self._config_path}. "
                f"Available: {list(servers)}"
            )
        entry = servers[self._server_name]
        cmd = entry.get("command", "")
        args: list[str] = entry.get("args", [])
        env: dict[str, str] = entry.get("env", {})
        full_cmd = " ".join([cmd] + args)
        if env:
            env_prefix = " ".join(f"{k}={v}" for k, v in env.items())
            full_cmd = f"env {env_prefix} {full_cmd}"
        return StdioTransport(full_cmd)

    async def start(self) -> None:
        self._delegate = self._build_delegate()
        await self._delegate.start()

    async def stop(self) -> None:
        if self._delegate:
            await self._delegate.stop()

    async def send(self, message: dict[str, Any]) -> None:
        assert self._delegate
        await self._delegate.send(message)

    async def recv(self) -> dict[str, Any]:
        assert self._delegate
        return await self._delegate.recv()
