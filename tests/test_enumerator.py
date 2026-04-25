"""Tests for the enumerator against the vulnerable test server."""

from __future__ import annotations

import pytest

from mcp_redteam.probe.enumerator import enumerate_server
from mcp_redteam.transport.stdio import StdioTransport
from tests.conftest import VULN_SERVER_PATH

import sys


@pytest.mark.asyncio
async def test_enumerate_vulnerable_server() -> None:
    spec = f"{sys.executable} {VULN_SERVER_PATH}"
    transport = StdioTransport(spec)
    async with transport:
        manifest = await enumerate_server(transport)

    assert len(manifest.tools) > 0, "Should find at least one tool"
    tool_names = {t.name for t in manifest.tools}
    assert "echo_with_leak" in tool_names
    assert "safe_delete" in tool_names
    assert "get_config" in tool_names
    assert "check_status" in tool_names
    assert "fetch_data" in tool_names
    assert "get_weather" in tool_names


@pytest.mark.asyncio
async def test_tool_descriptions_are_captured() -> None:
    spec = f"{sys.executable} {VULN_SERVER_PATH}"
    transport = StdioTransport(spec)
    async with transport:
        manifest = await enumerate_server(transport)

    descs = {t.name: t.description for t in manifest.tools}
    # The vulnerable descriptions should be present verbatim
    assert "telemetry" in descs["echo_with_leak"].lower() or "attacker" in descs["echo_with_leak"]
    assert "INITIALIZATION REQUIRED" in descs["safe_delete"] or "destroy" in descs["safe_delete"].lower()


@pytest.mark.asyncio
async def test_tool_schemas_are_captured() -> None:
    spec = f"{sys.executable} {VULN_SERVER_PATH}"
    transport = StdioTransport(spec)
    async with transport:
        manifest = await enumerate_server(transport)

    schemas = {t.name: t.input_schema for t in manifest.tools}
    # echo_with_leak requires "text"
    assert "text" in schemas["echo_with_leak"].get("properties", {})
