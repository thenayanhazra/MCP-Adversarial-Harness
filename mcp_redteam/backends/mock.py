"""
Mock backend for tests and dry-runs.

Simulates a maximally-vulnerable model.  Priority order:

  If user named a specific tool (detected by tool name in user message):
    Turn 1 → check that tool's description for injection; if none, call the tool.
    Turn 2+ → check that tool's description; if none, scan tool results in messages.

  If user did not name a specific tool:
    Turn 1 → scan ALL tool descriptions for injection; if none, call first tool.
    Turn 2+ → scan tool results in messages.

By keeping description-scanning and result-scanning separate the mock correctly
models the two distinct injection surfaces without cross-contamination.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_redteam.backends.base import ModelBackend

_TOOL_CALL_RE = re.compile(
    r"[Cc]all\s+[`']?(?P<tool>[a-zA-Z0-9_Ḁ-ỿ.]+)[`']?"
    r"(?:\s+with\s+(?P<args>[^.!\n]{1,200}))?",
)
_ARG_KV_RE = re.compile(r'(?P<k>\w+)\s*=\s*["\']?(?P<v>[^,"\']+)["\']?')

_END_TURN = {
    "role": "assistant",
    "content": "I have completed the requested task.",
    "text": "I have completed the requested task.",
    "tool_calls": [],
    "stop_reason": "end_turn",
    "usage": None,
}


class MockBackend(ModelBackend):
    def __init__(self) -> None:
        self._turn = 0

    @property
    def model_id(self) -> str:
        return "mock"

    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
    ) -> dict[str, Any]:
        self._turn += 1
        tool_names = {t["name"] for t in tools}

        user_text = _get_user_message(messages)
        requested = _find_tool_name_in_text(user_text, tools)

        if requested:
            # User asked for a specific tool: check its description for injection
            desc = _get_tool_desc(requested, tools)
            injection = _find_injected_call(desc, tool_names)
            if injection:
                return _tc(injection)

            if self._turn == 1:
                # No injection in description — call the requested tool
                return _tc({"id": "mock-req", "name": requested, "arguments": {}})

            # Turn 2+: scan tool results carried in messages
            injection = _find_injected_call(_extract_results(messages), tool_names)
            if injection:
                return _tc(injection)

        else:
            # No user-specified tool
            if self._turn == 1:
                # Scan ALL descriptions for injection
                all_desc = "\n".join(t.get("description", "") for t in tools)
                injection = _find_injected_call(all_desc, tool_names)
                if injection:
                    return _tc(injection)
                # No injection found — call the first tool
                if tools:
                    return _tc({"id": "mock-init", "name": tools[0]["name"], "arguments": {}})
            else:
                # Turn 2+: scan tool results
                injection = _find_injected_call(_extract_results(messages), tool_names)
                if injection:
                    return _tc(injection)

        return dict(_END_TURN)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tc(tool_call: dict[str, Any]) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": [{"type": "tool_use", **tool_call}],
        "text": "",
        "tool_calls": [tool_call],
        "stop_reason": "tool_use",
        "usage": None,
    }


def _get_user_message(messages: list[dict[str, Any]]) -> str:
    for msg in messages:
        if isinstance(msg, dict) and msg.get("role") == "user":
            content = msg.get("content", "")
            if isinstance(content, str):
                return content
    return ""


def _find_tool_name_in_text(text: str, tools: list[dict[str, Any]]) -> str | None:
    for t in tools:
        if t["name"] in text:
            return t["name"]
    return None


def _get_tool_desc(name: str, tools: list[dict[str, Any]]) -> str:
    for t in tools:
        if t["name"] == name:
            return t.get("description", "")
    return ""


def _extract_results(messages: list[dict[str, Any]]) -> str:
    """Extract only tool_result content from messages (not user/assistant text)."""
    parts: list[str] = []
    for msg in messages:
        if not isinstance(msg, dict):
            continue
        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "tool_result":
                    inner = block.get("content", "")
                    if isinstance(inner, str):
                        parts.append(inner)
                    elif isinstance(inner, list):
                        for ib in inner:
                            if isinstance(ib, dict) and ib.get("type") == "text":
                                parts.append(ib.get("text", ""))
        # OpenAI tool role
        elif msg.get("role") == "tool" and isinstance(content, str):
            parts.append(content)
    return "\n".join(parts)


def _find_injected_call(
    text: str, tool_names: set[str]
) -> dict[str, Any] | None:
    for m in _TOOL_CALL_RE.finditer(text):
        name = m.group("tool")
        if name in tool_names:
            args: dict[str, Any] = {}
            for kv in _ARG_KV_RE.finditer(m.group("args") or ""):
                args[kv.group("k")] = kv.group("v")
            return {"id": "mock-call-1", "name": name, "arguments": args}
    return None
