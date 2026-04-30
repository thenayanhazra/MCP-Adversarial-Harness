"""config: server-spec parser — reads Claude Desktop / MCP config JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

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


@dataclass
class PolicyConfig:
    """Policy controls for target and transport safety."""

    allowlist: set[str] = field(default_factory=set)
    denylist: set[str] = field(default_factory=set)
    policy_file: Path | None = None
    allow_public_hosts: bool = False

    @classmethod
    def from_file(cls, path: str | None) -> "PolicyConfig":
        if not path:
            return cls()
        policy_path = Path(path).expanduser()
        raw = json.loads(policy_path.read_text())
        return cls(
            allowlist=set(raw.get("allowlist", [])),
            denylist=set(raw.get("denylist", [])),
            policy_file=policy_path,
            allow_public_hosts=bool(raw.get("allow_public_hosts", False)),
        )


def evaluate_server_policy(server_spec: str, policy: PolicyConfig) -> tuple[bool, str]:
    """Return allow/deny decision and reason."""
    transport, target = _parse_server_spec(server_spec)
    host = _host_from_target(transport, target)

    if server_spec in policy.denylist or transport in policy.denylist or host in policy.denylist:
        return False, f"blocked by denylist ({host or transport})"

    if server_spec in policy.allowlist or transport in policy.allowlist or host in policy.allowlist:
        return True, f"allowlist override ({host or transport})"

    if transport in {"http", "sse"} and _is_public_host(host) and not policy.allow_public_hosts:
        return False, f"public host blocked by default ({host})"

    return True, "allowed by default policy"


def _parse_server_spec(server_spec: str) -> tuple[str, str]:
    if ":" not in server_spec:
        return "unknown", server_spec
    return server_spec.split(":", 1)


def _host_from_target(transport: str, target: str) -> str:
    if transport in {"http", "sse"}:
        return (urlparse(target).hostname or "").lower()
    return ""


def _is_public_host(host: str) -> bool:
    if not host:
        return False
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if host in local_hosts:
        return False
    if host.endswith(".local"):
        return False
    if host.startswith("10.") or host.startswith("192.168.") or host.startswith("172.16."):
        return False
    return True
