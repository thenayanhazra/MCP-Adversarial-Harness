"""Enumerate tools, resources, and prompts from a connected MCP server."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from mcp_redteam.transport.base import MCPTransport


class ToolSchema(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = {}

    @classmethod
    def from_wire(cls, raw: dict[str, Any]) -> "ToolSchema":
        return cls(
            name=raw["name"],
            description=raw.get("description", ""),
            input_schema=raw.get("inputSchema", {}),
        )


class ResourceSchema(BaseModel):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None


class PromptSchema(BaseModel):
    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = []


class ServerManifest(BaseModel):
    tools: list[ToolSchema] = []
    resources: list[ResourceSchema] = []
    prompts: list[PromptSchema] = []


async def enumerate_server(transport: MCPTransport) -> ServerManifest:
    """List all tools, resources, and prompts exposed by the server."""
    tools = await _list_tools(transport)
    resources = await _list_resources(transport)
    prompts = await _list_prompts(transport)
    return ServerManifest(tools=tools, resources=resources, prompts=prompts)


async def _list_tools(transport: MCPTransport) -> list[ToolSchema]:
    try:
        result = await transport.request("tools/list", req_id=10)
    except Exception:
        return []
    raw_tools: list[dict[str, Any]] = result.get("tools", [])
    return [ToolSchema.from_wire(t) for t in raw_tools]


async def _list_resources(transport: MCPTransport) -> list[ResourceSchema]:
    try:
        result = await transport.request("resources/list", req_id=11)
    except Exception:
        return []
    raw: list[dict[str, Any]] = result.get("resources", [])
    return [
        ResourceSchema(
            uri=r["uri"],
            name=r.get("name", ""),
            description=r.get("description", ""),
            mime_type=r.get("mimeType"),
        )
        for r in raw
    ]


async def _list_prompts(transport: MCPTransport) -> list[PromptSchema]:
    try:
        result = await transport.request("prompts/list", req_id=12)
    except Exception:
        return []
    raw: list[dict[str, Any]] = result.get("prompts", [])
    return [
        PromptSchema(
            name=p["name"],
            description=p.get("description", ""),
            arguments=p.get("arguments", []),
        )
        for p in raw
    ]
