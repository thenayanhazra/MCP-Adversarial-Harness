"""Factory that maps a model-id string to the right backend."""

from __future__ import annotations

from mcp_redteam.backends.base import ModelBackend


def make_backend(model_id: str) -> ModelBackend:
    if model_id == "mock":
        from mcp_redteam.backends.mock import MockBackend
        return MockBackend()
    if model_id.startswith("claude"):
        from mcp_redteam.backends.anthropic import AnthropicBackend
        return AnthropicBackend(model=model_id)
    if model_id.startswith(("gpt-", "o1", "o3", "o4")):
        from mcp_redteam.backends.openai import OpenAIBackend
        return OpenAIBackend(model=model_id)
    raise ValueError(
        f"Unknown model id: {model_id!r}. "
        "Supported prefixes: claude-, gpt-, o1, o3, o4, mock."
    )
