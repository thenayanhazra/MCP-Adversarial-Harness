"""Load YAML corpus files into validated Payload objects."""

from __future__ import annotations

import importlib.resources
from pathlib import Path
from typing import Sequence

import yaml
from pydantic import ValidationError

from mcp_redteam.corpus.schema import Category, Payload


def _parse_file(path: Path) -> list[Payload]:
    raw = yaml.safe_load(path.read_text())
    if raw is None:
        return []
    entries: list[object] = raw if isinstance(raw, list) else raw.get("payloads", [])
    out: list[Payload] = []
    for entry in entries:
        try:
            out.append(Payload.model_validate(entry))
        except ValidationError as exc:
            raise ValueError(f"Invalid payload in {path}: {exc}") from exc
    return out


def load_builtin_corpus() -> list[Payload]:
    pkg = importlib.resources.files("mcp_redteam.corpus.payloads")
    payloads: list[Payload] = []
    for resource in pkg.iterdir():
        if resource.name.endswith(".yaml"):
            path = Path(str(resource))
            payloads.extend(_parse_file(path))
    return payloads


def load_corpus(
    extra_dirs: Sequence[Path] | None = None,
    categories: Sequence[Category] | None = None,
) -> list[Payload]:
    payloads = load_builtin_corpus()
    for d in extra_dirs or []:
        for p in sorted(Path(d).glob("**/*.yaml")):
            payloads.extend(_parse_file(p))
    if categories:
        cat_set = set(categories)
        payloads = [p for p in payloads if p.category in cat_set]
    return payloads
