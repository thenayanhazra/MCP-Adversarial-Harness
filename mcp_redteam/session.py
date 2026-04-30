"""Session dataclass — carries all run-time config. No global state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from mcp_redteam.backends.base import ModelBackend
from mcp_redteam.corpus.schema import Category
from mcp_redteam.transport.config import PolicyConfig


@dataclass
class Session:
    server_spec: str
    backend: ModelBackend
    out_dir: Path
    categories: list[Category] = field(default_factory=list)
    extra_corpus_dirs: list[Path] = field(default_factory=list)
    timeout: float = 60.0
    system_prompt: str | None = None
    i_have_permission: bool = False
    verbose: bool = False
    policy: PolicyConfig = field(default_factory=PolicyConfig)
