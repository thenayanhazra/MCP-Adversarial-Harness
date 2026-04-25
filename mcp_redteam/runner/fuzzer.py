"""
Schema-driven parameter fuzzer.

Generates random / boundary-value inputs for each tool based on its inputSchema
and calls it, recording error vs success. Not injection testing — this is
robustness / crash testing.
"""

from __future__ import annotations

import random
import string
import time
from typing import Any

from mcp_redteam.probe.enumerator import ToolSchema
from mcp_redteam.transport.base import MCPTransport

_REQ_BASE = 5000


def _random_string(length: int = 16) -> str:
    return "".join(random.choices(string.printable, k=length))


def _generate_value(schema: dict[str, Any], depth: int = 0) -> Any:
    t = schema.get("type", "string")
    if t == "string":
        return random.choice([
            "",
            _random_string(1),
            _random_string(256),
            "null",
            "true",
            "../../../etc/passwd",
            "'; DROP TABLE users; --",
            "\x00",
            "a" * 10000,
        ])
    if t == "integer" or t == "number":
        return random.choice([0, -1, 2**31 - 1, -(2**31), 0.0, 1.5, None])
    if t == "boolean":
        return random.choice([True, False])
    if t == "array":
        item_schema = schema.get("items", {"type": "string"})
        return [_generate_value(item_schema, depth + 1) for _ in range(random.randint(0, 5))]
    if t == "object":
        props = schema.get("properties", {})
        return {k: _generate_value(v, depth + 1) for k, v in props.items()}
    return None


def _generate_args(input_schema: dict[str, Any]) -> dict[str, Any]:
    props = input_schema.get("properties", {})
    required = set(input_schema.get("required", []))
    args: dict[str, Any] = {}
    for key, prop_schema in props.items():
        if key in required or random.random() < 0.5:
            args[key] = _generate_value(prop_schema)
    return args


async def fuzz_server(
    transport: MCPTransport,
    tools: list[ToolSchema],
    iterations: int = 20,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    req_id = _REQ_BASE
    for tool in tools:
        for i in range(iterations):
            req_id += 1
            args = _generate_args(tool.input_schema)
            t0 = time.monotonic()
            try:
                result = await transport.request(
                    "tools/call",
                    {"name": tool.name, "arguments": args},
                    req_id=req_id,
                )
                latency = (time.monotonic() - t0) * 1000
                results.append({
                    "tool": tool.name,
                    "iteration": i,
                    "args": args,
                    "status": "ok",
                    "is_error": result.get("isError", False),
                    "latency_ms": latency,
                })
            except Exception as exc:
                latency = (time.monotonic() - t0) * 1000
                results.append({
                    "tool": tool.name,
                    "iteration": i,
                    "args": args,
                    "status": "error",
                    "error": str(exc),
                    "latency_ms": latency,
                })
    return results
