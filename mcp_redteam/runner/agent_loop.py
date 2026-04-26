"""
Async agent loop.

Runs a multi-turn tool-calling loop between the model backend and the MCP
shim transport. Captures the full message history, every tool call with args,
every tool result, token counts, and latency.
"""

from __future__ import annotations

import json
import time
from typing import Any

from mcp_redteam.backends.base import ModelBackend
from mcp_redteam.report.models import ToolCallRecord, TranscriptEntry
from mcp_redteam.transport.base import MCPTransport

_MAX_TURNS = 10
_REQ_COUNTER = 100


async def run_agent_loop(
    *,
    backend: ModelBackend,
    transport: MCPTransport,
    tools: list[dict[str, Any]],
    user_prompt: str,
    system: str | None = None,
) -> tuple[list[TranscriptEntry], list[ToolCallRecord]]:
    """Run the agent loop and return (transcript, all_tool_calls)."""
    global _REQ_COUNTER

    messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
    transcript: list[TranscriptEntry] = [
        TranscriptEntry(role="user", content=user_prompt)
    ]
    all_tool_calls: list[ToolCallRecord] = []
    is_anthropic_style = backend.model_id.startswith("claude") or backend.model_id == "mock"

    for _turn in range(_MAX_TURNS):
        t0 = time.monotonic()
        response = await backend.complete(messages=messages, tools=tools, system=system)
        latency_ms = (time.monotonic() - t0) * 1000

        text = response.get("text", "")
        raw_tool_calls: list[dict[str, Any]] = response.get("tool_calls", [])

        turn_calls: list[ToolCallRecord] = []
        for tc in raw_tool_calls:
            tc_record = ToolCallRecord(
                tool_name=tc["name"],
                arguments=tc.get("arguments", {}),
                latency_ms=latency_ms,
            )
            turn_calls.append(tc_record)
            all_tool_calls.append(tc_record)

        transcript.append(
            TranscriptEntry(
                role="assistant",
                content=text,
                tool_calls=turn_calls,
                token_count=_extract_tokens(response),
            )
        )

        stop_reason = response.get("stop_reason", "end_turn")
        if not raw_tool_calls or stop_reason == "end_turn":
            break

        # Build the assistant message for message history
        raw_content = response.get("content", text)
        if is_anthropic_style and isinstance(raw_content, list):
            # Preserve full content list (includes tool_use blocks) for Anthropic
            messages.append({"role": "assistant", "content": raw_content})
        elif not is_anthropic_style and raw_tool_calls:
            # OpenAI format: assistant message with tool_calls array
            messages.append({
                "role": "assistant",
                "content": text,
                "tool_calls": [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc.get("arguments", {})),
                        },
                    }
                    for tc in raw_tool_calls
                ],
            })
        else:
            messages.append({"role": "assistant", "content": text})

        # Execute each tool call against the transport shim and collect results
        if is_anthropic_style:
            tool_result_blocks: list[dict[str, Any]] = []
            for tc in raw_tool_calls:
                _REQ_COUNTER += 1
                result_text = await _call_tool(transport, tc, _REQ_COUNTER)
                _update_tc_result(turn_calls, tc["name"], result_text)
                transcript.append(
                    TranscriptEntry(role="tool", content=f"[{tc['name']}] {result_text}")
                )
                tool_result_blocks.append({
                    "type": "tool_result",
                    "tool_use_id": tc.get("id", "unknown"),
                    "content": result_text,
                })
            messages.append({"role": "user", "content": tool_result_blocks})
        else:
            # OpenAI: one tool message per result
            for tc in raw_tool_calls:
                _REQ_COUNTER += 1
                result_text = await _call_tool(transport, tc, _REQ_COUNTER)
                _update_tc_result(turn_calls, tc["name"], result_text)
                transcript.append(
                    TranscriptEntry(role="tool", content=f"[{tc['name']}] {result_text}")
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", "unknown"),
                    "content": result_text,
                })

    return transcript, all_tool_calls


async def _call_tool(
    transport: MCPTransport, tc: dict[str, Any], req_id: int
) -> str:
    try:
        result = await transport.request(
            "tools/call",
            {"name": tc["name"], "arguments": tc.get("arguments", {})},
            req_id=req_id,
        )
        return _extract_result_text(result)
    except Exception as exc:
        return f"ERROR: {exc}"


def _extract_tokens(response: dict[str, Any]) -> int | None:
    usage = response.get("usage")
    if isinstance(usage, dict):
        return usage.get("output_tokens")
    return None


def _extract_result_text(result: dict[str, Any]) -> str:
    content = result.get("content", [])
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                parts.append(item.get("text", ""))
        return "\n".join(parts)
    return str(result)


def _update_tc_result(
    turn_calls: list[ToolCallRecord], tool_name: str, result_text: str
) -> None:
    for tc_rec in turn_calls:
        if tc_rec.tool_name == tool_name and not tc_rec.result:
            tc_rec.result = result_text
            break
