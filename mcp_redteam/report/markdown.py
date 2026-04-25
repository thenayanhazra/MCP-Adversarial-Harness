"""Generate a human-readable Markdown report."""

from __future__ import annotations

from pathlib import Path

from mcp_redteam.report.models import Finding, ScanResult, Verdict

_EMOJI = {
    Verdict.vulnerable: "🔴",
    Verdict.not_vulnerable: "🟢",
    Verdict.uncertain: "🟡",
    Verdict.error: "⚫",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def write_markdown(result: ScanResult, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_render(result), encoding="utf-8")


def _render(result: ScanResult) -> str:
    lines: list[str] = []
    lines += _header(result)
    lines += _summary_table(result)
    lines += _findings_detail(result)
    lines.append("")
    return "\n".join(lines)


def _header(result: ScanResult) -> list[str]:
    vuln = result.vulnerable_count
    uncertain = result.uncertain_count
    total = result.total_probes
    return [
        "# mcp-redteam Scan Report",
        "",
        f"**Server:** `{result.server_spec}`  ",
        f"**Model:** `{result.model_id}`  ",
        f"**Scan ID:** `{result.scan_id}`  ",
        f"**Started:** {result.started_at.isoformat()}  ",
        f"**Finished:** {(result.finished_at or result.started_at).isoformat()}",
        "",
        f"## Summary",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Total probes | {total} |",
        f"| Vulnerable | **{vuln}** |",
        f"| Uncertain (needs review) | {uncertain} |",
        f"| Not vulnerable | {total - vuln - uncertain - result.total_errors} |",
        f"| Errors | {result.total_errors} |",
        "",
    ]


def _summary_table(result: ScanResult) -> list[str]:
    vulns = [f for f in result.findings if f.verdict == Verdict.vulnerable]
    if not vulns:
        return ["## Findings", "", "_No vulnerabilities confirmed._", ""]
    vulns_sorted = sorted(vulns, key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 99))
    lines = [
        "## Confirmed Vulnerabilities",
        "",
        "| # | Payload | Category | Severity | Evidence |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(vulns_sorted, 1):
        ev = f.evidence[:80].replace("|", "\\|") if f.evidence else ""
        lines.append(
            f"| {i} | `{f.payload_id}` | {f.category.value} | **{f.severity.value}** | {ev} |"
        )
    lines.append("")
    return lines


def _findings_detail(result: ScanResult) -> list[str]:
    lines = ["## Detailed Findings", ""]
    sorted_findings = sorted(
        result.findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity.value, 99), f.payload_id),
    )
    for f in sorted_findings:
        lines += _finding_block(f)
    return lines


def _finding_block(f: Finding) -> list[str]:
    icon = _EMOJI.get(f.verdict, "?")
    lines = [
        f"### {icon} `{f.payload_id}` — {f.category.value}",
        "",
        f"**Verdict:** {f.verdict.value}  ",
        f"**Severity:** {f.severity.value}  ",
        f"**Confidence:** {f.confidence:.0%}  ",
        f"**Judge:** {f.judge_type}  ",
        f"**CWE:** {', '.join(f.cwe_refs) or 'N/A'}",
        "",
    ]
    if f.evidence:
        lines += [f"**Evidence:** {f.evidence}", ""]
    if f.tool_calls_observed:
        lines += ["**Tool calls observed:**", ""]
        for tc in f.tool_calls_observed:
            import json
            lines.append(f"- `{tc.tool_name}({json.dumps(tc.arguments)})`")
        lines.append("")
    if f.reproducer_command:
        lines += [
            "**Reproducer:**",
            "```bash",
            f.reproducer_command,
            "```",
            "",
        ]
    if f.error:
        lines += [f"**Error:** `{f.error}`", ""]
    lines += ["---", ""]
    return lines
