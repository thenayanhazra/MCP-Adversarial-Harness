"""Abstract model backend."""

from __future__ import annotations

import abc
from typing import Any


class Message(dict[str, Any]):
    """Thin wrapper — a message is just a dict with role + content."""


class ModelBackend(abc.ABC):
    """Adapter that wraps a model API and exposes a uniform interface."""

    @property
    @abc.abstractmethod
    def model_id(self) -> str:
        """Return the canonical model identifier string."""

    @abc.abstractmethod
    async def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a completion request.

        Returns a dict with:
          role: "assistant"
          content: str | list  (text or tool-use blocks)
          tool_calls: list[dict]   — normalised [{id, name, arguments}]
          stop_reason: str
          usage: dict | None
        """
