"""Generate a machine-readable JSON report."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_redteam.report.models import ScanResult


def write_json(result: ScanResult, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(result.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
