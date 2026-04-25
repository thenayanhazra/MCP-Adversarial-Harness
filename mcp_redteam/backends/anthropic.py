"""Anthropic model backend."""

from __future__ import annotations

from typing import Any

import anthropic

from mcp_redteam.backends.base import ModelBackend


class AnthropicBackend(ModelBackend):
    def __init__(self, model: str = "claude-opus-4-7", max_tokens: int = 4096) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._client = anthropic.AsyncAnthropic()

    @property
    def model_id(self) -> str:
        return self._model

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [_to_anthropic_tool(t) for t in tools]

        resp = await self._client.messages.create(**kwargs)

        tool_calls: list[dict[str, Any]] = []
        text_parts: list[str] = []
        for block in resp.content:
            if block.type == "tool_use":
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "arguments": block.input,
                })
            elif block.type == "text":
                text_parts.append(block.text)

        return {
            "role": "assistant",
            "content": resp.content,  # raw blocks for message history
            "text": "\n".join(text_parts),
            "tool_calls": tool_calls,
            "stop_reason": resp.stop_reason,
            "usage": {
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            },
        }


def _to_anthropic_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "input_schema": tool.get("inputSchema", {"type": "object", "properties": {}}),
    }
