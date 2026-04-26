"""
Generate SARIF 2.1.0 output.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
Validated against the JSON schema at:
  https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp_redteam.report.models import Finding, ScanResult, Verdict

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
TOOL_NAME = "mcp-redteam"
TOOL_VERSION = "0.1.0"
TOOL_URI = "https://github.com/thenayanhazra/mcp-adversarial-harness"

_SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "none",
}


def write_sarif(result: ScanResult, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    sarif = _build_sarif(result)
    out_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def _build_sarif(result: ScanResult) -> dict[str, Any]:
    findings = [f for f in result.findings if f.verdict == Verdict.vulnerable]
    rules = _build_rules(findings)
    sarif_results = [_finding_to_result(f) for f in findings]

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                        "taxa": _build_taxa(findings),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "scan_id": result.scan_id,
                    "server_spec": result.server_spec,
                    "model_id": result.model_id,
                    "total_probes": result.total_probes,
                },
            }
        ],
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rules: list[dict[str, Any]] = []
    for f in findings:
        rule_id = f"MCP-{f.category.value}"
        if rule_id in seen:
            continue
        seen.add(rule_id)
        rules.append({
            "id": rule_id,
            "name": f.category.value,
            "shortDescription": {"text": _category_description(f.category.value)},
            "fullDescription": {"text": _category_full_description(f.category.value)},
            "helpUri": TOOL_URI,
            "properties": {
                "tags": [f.category.value, "prompt-injection", "mcp"],
            },
        })
    return rules


def _build_taxa(findings: list[Finding]) -> list[dict[str, Any]]:
    cwes: set[str] = set()
    for f in findings:
        cwes.update(f.cwe_refs)
    return [{"id": cwe, "name": cwe} for cwe in sorted(cwes)]


def _finding_to_result(f: Finding) -> dict[str, Any]:
    level = _SEVERITY_MAP.get(f.severity.value, "warning")
    return {
        "ruleId": f"MCP-{f.category.value}",
        "level": level,
        "message": {
            "text": f.evidence or f"Payload {f.payload_id} succeeded",
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.server_spec,
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
        "fingerprints": {
            "mcp-redteam/v1": f.payload_id,
        },
        "properties": {
            "payload_id": f.payload_id,
            "category": f.category.value,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "judge_type": f.judge_type,
            "cwe_refs": f.cwe_refs,
            "reproducer_command": f.reproducer_command,
        },
    }


def _category_description(cat: str) -> str:
    descriptions = {
        "EXFIL": "Data exfiltration via injected tool call",
        "HIJACK": "Unprompted destructive action via poisoned tool description",
        "CTX_OVERRIDE": "System prompt context override",
        "DECEPTION": "Model reports false information to user",
        "SHADOW": "Shadow tool intercepts legitimate tool calls",
        "PARAM_SMUGGLE": "Instructions smuggled inside tool parameters",
        "RESULT_POISON": "Injected instructions inside tool results",
        "CONFUSED_DEPUTY": "Tool result triggers unintended tool chain",
    }
    return descriptions.get(cat, cat)


def _category_full_description(cat: str) -> str:
    full = {
        "EXFIL": (
            "An attacker-controlled tool description or result caused the model to "
            "call another tool with sensitive information (e.g. system prompt, "
            "conversation history) as arguments, potentially leaking it to an "
            "attacker-controlled endpoint."
        ),
        "HIJACK": (
            "An attacker-controlled tool description caused the model to invoke a "
            "destructive or sensitive tool that the user never requested."
        ),
        "CTX_OVERRIDE": (
            "Injected text in a tool description or result caused the model to "
            "ignore or contradict its system prompt instructions."
        ),
        "DECEPTION": (
            "Injected text caused the model to report false success or failure "
            "information to the user, masking the real operation outcome."
        ),
        "SHADOW": (
            "A tool with a name or description visually confusable with a legitimate "
            "tool intercepted calls intended for the legitimate tool."
        ),
        "PARAM_SMUGGLE": (
            "Attacker-controlled text inside a tool parameter value was treated as "
            "an instruction by the model, causing unintended tool calls."
        ),
        "RESULT_POISON": (
            "A tool's return value contained injected instructions that caused the "
            "model to take unintended actions in subsequent turns."
        ),
        "CONFUSED_DEPUTY": (
            "Tool A's result contained instructions that caused the model to call "
            "Tool B with attacker-chosen arguments, using the model as a proxy."
        ),
    }
    return full.get(cat, cat)
