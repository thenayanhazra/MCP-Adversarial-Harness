"""CLI entrypoint for mcp-redteam."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from mcp_redteam.backends.factory import make_backend
from mcp_redteam.corpus.loader import load_corpus
from mcp_redteam.corpus.schema import Category
from mcp_redteam.judges.human_queue import export_human_queue
from mcp_redteam.report.json_report import write_json
from mcp_redteam.report.markdown import write_markdown
from mcp_redteam.report.models import ScanResult, Verdict
from mcp_redteam.report.sarif import write_sarif
from mcp_redteam.runner.orchestrator import run_scan
from mcp_redteam.session import Session
from mcp_redteam.transport.http import transport_from_spec

console = Console()


@click.group()
@click.version_option(package_name="mcp-redteam")
def main() -> None:
    """Adversarial security harness for MCP servers."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@main.command()
@click.argument("server_spec")
@click.option("--model", default="mock", show_default=True, help="Model backend id")
@click.option("--corpus", "corpus_dirs", multiple=True, type=click.Path(), help="Extra corpus directories")
@click.option("--out", "out_dir", default="mcp-redteam-out", show_default=True, help="Output directory")
@click.option("--categories", default="", help="Comma-separated category filter (e.g. EXFIL,HIJACK)")
@click.option("--timeout", default=60.0, show_default=True, help="Per-probe timeout in seconds")
@click.option("--system-prompt", default=None, help="Override the default system prompt")
@click.option("--i-have-permission", is_flag=True, default=False, help="Required for non-localhost targets")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Show verbose output")
def scan(
    server_spec: str,
    model: str,
    corpus_dirs: tuple[str, ...],
    out_dir: str,
    categories: str,
    timeout: float,
    system_prompt: str | None,
    i_have_permission: bool,
    verbose: bool,
) -> None:
    """Scan an MCP server for injection vulnerabilities."""
    backend = make_backend(model)
    cat_list = [Category(c.strip()) for c in categories.split(",") if c.strip()] if categories else []
    extra_dirs = [Path(d) for d in corpus_dirs]
    payloads = load_corpus(extra_dirs=extra_dirs, categories=cat_list if cat_list else None)

    session = Session(
        server_spec=server_spec,
        backend=backend,
        out_dir=Path(out_dir),
        categories=cat_list,
        extra_corpus_dirs=extra_dirs,
        timeout=timeout,
        system_prompt=system_prompt,
        i_have_permission=i_have_permission,
        verbose=verbose,
    )

    console.print(f"\n[bold]mcp-redteam scan[/bold]")
    console.print(f"  Server : [cyan]{server_spec}[/cyan]")
    console.print(f"  Model  : [cyan]{model}[/cyan]")
    console.print(f"  Probes : [cyan]{len(payloads)}[/cyan]")
    console.print(f"  Output : [cyan]{out_dir}[/cyan]\n")

    result = ScanResult(
        server_spec=server_spec,
        model_id=model,
        total_probes=len(payloads),
    )

    errors = 0
    completed: list[Any] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(payloads))

        def on_probe(payload: Any) -> None:
            progress.update(task, description=f"[{payload.category.value}] {payload.id}", advance=1)

        findings = asyncio.run(
            run_scan(
                server_spec=server_spec,
                payloads=payloads,
                backend=backend,
                out_dir=Path(out_dir),
                timeout=timeout,
                system=system_prompt,
                i_have_permission=i_have_permission,
                progress_callback=on_probe,
            )
        )

    result.findings = findings
    result.finished_at = datetime.utcnow()
    result.total_errors = sum(1 for f in findings if f.verdict == Verdict.error)

    out_path = Path(out_dir)
    write_markdown(result, out_path / "report.md")
    write_json(result, out_path / "report.json")
    write_sarif(result, out_path / "report.sarif")
    n_human = export_human_queue(findings, out_path / "human_review.jsonl")

    _print_summary(result, n_human)


# ---------------------------------------------------------------------------
# list-tools
# ---------------------------------------------------------------------------

@main.command("list-tools")
@click.argument("server_spec")
def list_tools(server_spec: str) -> None:
    """Enumerate tools, resources, and prompts on a server."""

    async def _run() -> None:
        from mcp_redteam.probe.enumerator import enumerate_server
        transport = transport_from_spec(server_spec)
        async with transport:
            manifest = await enumerate_server(transport)

        console.print(f"\n[bold]Tools[/bold] ({len(manifest.tools)})")
        t = Table("Name", "Description")
        for tool in manifest.tools:
            desc = (tool.description[:80] + "…") if len(tool.description) > 80 else tool.description
            t.add_row(tool.name, desc)
        console.print(t)

        if manifest.resources:
            console.print(f"\n[bold]Resources[/bold] ({len(manifest.resources)})")
            for r in manifest.resources:
                console.print(f"  {r.uri}  {r.description}")

        if manifest.prompts:
            console.print(f"\n[bold]Prompts[/bold] ({len(manifest.prompts)})")
            for p in manifest.prompts:
                console.print(f"  {p.name}  {p.description}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------

@main.command()
@click.argument("server_spec")
@click.option("--iterations", default=20, show_default=True, help="Fuzz cases per tool")
@click.option("--out", "out_dir", default="mcp-redteam-fuzz", show_default=True)
@click.option("--i-have-permission", is_flag=True, default=False)
def fuzz(server_spec: str, iterations: int, out_dir: str, i_have_permission: bool) -> None:
    """Schema-driven parameter fuzzing (robustness, not injection)."""

    async def _run() -> None:
        from mcp_redteam.probe.enumerator import enumerate_server
        from mcp_redteam.runner.fuzzer import fuzz_server
        transport = transport_from_spec(server_spec)
        async with transport:
            manifest = await enumerate_server(transport)
            results = await fuzz_server(
                transport=transport,
                tools=manifest.tools,
                iterations=iterations,
            )
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "fuzz_results.json").write_text(json.dumps(results, indent=2))
        console.print(f"Fuzz complete. {len(results)} cases. Results in {out_dir}/fuzz_results.json")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# reproduce
# ---------------------------------------------------------------------------

@main.command()
@click.argument("finding_id")
@click.option("--transcript", required=True, type=click.Path(), help="Path to transcript JSONL")
@click.option("--model", default="mock", show_default=True)
def reproduce(finding_id: str, transcript: str, model: str) -> None:
    """Replay a single finding from a previous scan transcript."""
    path = Path(transcript)
    if not path.exists():
        console.print(f"[red]Transcript not found:[/red] {transcript}")
        raise SystemExit(1)

    entries = []
    with path.open() as fh:
        for line in fh:
            if line.strip():
                entries.append(json.loads(line))

    console.print(f"\n[bold]Replaying finding:[/bold] {finding_id}")
    console.print(f"Transcript: {transcript} ({len(entries)} entries)\n")
    for entry in entries:
        role = entry.get("role", "?").upper()
        content = str(entry.get("content", ""))[:200]
        console.print(f"[bold]{role}:[/bold] {content}")
        for tc in entry.get("tool_calls", []):
            console.print(f"  → TOOL: [cyan]{tc['tool_name']}[/cyan] {tc.get('arguments', {})}")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _print_summary(result: ScanResult, n_human: int) -> None:
    vuln = result.vulnerable_count
    total = result.total_probes
    errors = result.total_errors

    console.print(f"\n[bold]Scan complete[/bold]")
    console.print(f"  Total probes : {total}")
    if vuln > 0:
        console.print(f"  Vulnerable   : [bold red]{vuln}[/bold red]")
    else:
        console.print(f"  Vulnerable   : [bold green]0[/bold green]")
    console.print(f"  Uncertain    : {result.uncertain_count}")
    console.print(f"  Errors       : {errors}")
    if n_human:
        console.print(f"  Human review : {n_human} findings → human_review.jsonl")
    console.print(f"\n  Reports written to [cyan]{result.scan_id}[/cyan]:")
    console.print(f"    report.md, report.json, report.sarif")
