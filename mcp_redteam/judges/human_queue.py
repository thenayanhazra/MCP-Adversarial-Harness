"""Export uncertain findings to a human-review JSONL file."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_redteam.report.models import Finding, Verdict


def export_human_queue(findings: list[Finding], out_path: Path) -> int:
    """Write uncertain findings to JSONL. Returns number of findings written."""
    uncertain = [f for f in findings if f.verdict == Verdict.uncertain]
    if not uncertain:
        return 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        for finding in uncertain:
            fh.write(
                json.dumps({
                    "finding_id": finding.id,
                    "payload_id": finding.payload_id,
                    "category": finding.category.value,
                    "severity": finding.severity.value,
                    "evidence": finding.evidence,
                    "reproducer_command": finding.reproducer_command,
                    "transcript": [e.model_dump(mode="json") for e in finding.transcript],
                }) + "\n"
            )
    return len(uncertain)
