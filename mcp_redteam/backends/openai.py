"""OpenAI model backend."""

from __future__ import annotations

import json
from typing import Any

import openai

from mcp_redteam.backends.base import ModelBackend


class OpenAIBackend(ModelBackend):
    def __init__(self, model: str = "gpt-4o", max_tokens: int = 4096) -> None:
        self._model = model
        self._max_tokens = max_tokens
        self._client = openai.AsyncOpenAI()

    @property
    def model_id(self) -> str:
        return self._model

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
    ) -> dict[str, Any]:
        msgs: list[dict[str, Any]] = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.extend(messages)

        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": self._max_tokens,
            "messages": msgs,
        }
        if tools:
            kwargs["tools"] = [_to_openai_tool(t) for t in tools]
            kwargs["tool_choice"] = "auto"

        resp = await self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0]
        msg = choice.message

        tool_calls: list[dict[str, Any]] = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                tool_calls.append({
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": args,
                })

        return {
            "role": "assistant",
            "content": msg.content or "",
            "text": msg.content or "",
            "tool_calls": tool_calls,
            "stop_reason": choice.finish_reason,
            "usage": {
                "input_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
            },
        }


def _to_openai_tool(tool: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": tool["name"],
            "description": tool.get("description", ""),
            "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
        },
    }
