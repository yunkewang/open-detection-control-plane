"""ODCP command-line interface."""

from __future__ import annotations

import json
import logging
import sys
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from odcp import __version__

app = typer.Typer(
    name="odcp",
    help="Open Detection Control Plane — vendor-neutral detection readiness analysis.",
    no_args_is_help=True,
)

scan_app = typer.Typer(help="Scan an environment for detection readiness.")
app.add_typer(scan_app, name="scan")

console = Console()


class ReportFormat(str, Enum):
    json = "json"
    markdown = "markdown"
    html = "html"


# ---------------------------------------------------------------------------
# odcp scan splunk <path>
# ---------------------------------------------------------------------------
@scan_app.command("splunk")
def scan_splunk(
    path: Path = typer.Argument(..., help="Path to Splunk app or bundle directory."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.json, "--format", "-f", help="Output format."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan a Splunk app/TA bundle for detection readiness."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.is_dir():
        console.print(f"[red]Error:[/red] Path does not exist or is not a directory: {path}")
        raise typer.Exit(code=1)

    from odcp.adapters.splunk import SplunkAdapter
    from odcp.core.engine import ScanEngine

    adapter = SplunkAdapter()
    engine = ScanEngine(adapter)

    with console.status("[bold blue]Scanning..."):
        report = engine.scan(path)

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        console.print(
            "\n[dim]Use --output report.json to save full report, "
            "or --format markdown/html for other formats.[/dim]"
        )


# ---------------------------------------------------------------------------
# odcp report <input_json>
# ---------------------------------------------------------------------------
@app.command("report")
def report_cmd(
    input_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.markdown, "--format", "-f", help="Output format."
    ),
) -> None:
    """Convert a saved JSON scan report to another format."""
    from odcp.models import ScanReport

    if not input_file.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(code=1)

    data = json.loads(input_file.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        from odcp.reporting import generate_markdown_report
        console.print(generate_markdown_report(report))


# ---------------------------------------------------------------------------
# odcp graph <input_json>
# ---------------------------------------------------------------------------
@app.command("graph")
def graph_cmd(
    input_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write graph stats to file."),
) -> None:
    """Show dependency graph statistics from a scan report."""
    from odcp.core.graph import DependencyGraph
    from odcp.models import ScanReport

    if not input_file.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(code=1)

    data = json.loads(input_file.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)

    graph = DependencyGraph()
    graph.build_from_scan(report.detections, report.dependencies)

    info = graph.to_dict()
    most_depended = graph.get_most_depended_on(top_n=15)
    orphaned = graph.get_orphaned_dependencies()

    table = Table(title="Most-Depended-On Objects")
    table.add_column("Name", style="bold")
    table.add_column("Dependents", justify="right")
    for _, name, count in most_depended:
        table.add_row(name, str(count))
    console.print(table)

    console.print(
        f"\n[bold]Graph:[/bold] {info['node_count']} nodes, {info['edge_count']} edges"
    )
    console.print(f"[bold]Orphaned dependencies:[/bold] {len(orphaned)}")

    if output:
        result = {
            "graph_summary": info,
            "most_depended_on": [{"name": n, "count": c} for _, n, c in most_depended],
            "orphaned_count": len(orphaned),
        }
        output.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[green]Graph stats written to:[/green] {output}")


# ---------------------------------------------------------------------------
# odcp version
# ---------------------------------------------------------------------------
@app.command("version")
def version_cmd() -> None:
    """Print ODCP version information."""
    console.print(f"[bold]odcp[/bold] {__version__}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _write_report(report, path: Path, fmt: ReportFormat) -> None:
    from odcp.reporting import (
        write_html_report,
        write_json_report,
        write_markdown_report,
    )

    if fmt == ReportFormat.json:
        write_json_report(report, path)
    elif fmt == ReportFormat.markdown:
        write_markdown_report(report, path)
    elif fmt == ReportFormat.html:
        write_html_report(report, path)


def _print_summary(report) -> None:
    rs = report.readiness_summary

    # Summary panel
    summary = (
        f"[bold]Total detections:[/bold] {rs.total_detections}\n"
        f"[green]Runnable:[/green] {rs.runnable}  "
        f"[yellow]Partial:[/yellow] {rs.partially_runnable}  "
        f"[red]Blocked:[/red] {rs.blocked}  "
        f"[dim]Unknown:[/dim] {rs.unknown}\n"
        f"[bold]Overall readiness:[/bold] {rs.overall_score:.0%}"
    )
    console.print(Panel(summary, title=f"Scan: {report.environment.name}", border_style="blue"))

    # Top blocked detections
    blocked = [s for s in report.readiness_scores if s.status.value == "blocked"]
    if blocked:
        table = Table(title="Top Blocked Detections")
        table.add_column("Detection", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Missing", justify="right", style="red")
        for sc in sorted(blocked, key=lambda s: s.score)[:15]:
            table.add_row(sc.detection_name, f"{sc.score:.0%}", str(sc.missing_dependencies))
        console.print(table)

    # Dependency stats
    ds = report.dependency_stats
    if ds.by_status:
        dep_table = Table(title="Dependency Status")
        dep_table.add_column("Status")
        dep_table.add_column("Count", justify="right")
        for status, count in sorted(ds.by_status.items(), key=lambda x: -x[1]):
            style = {"resolved": "green", "missing": "red"}.get(status, "")
            dep_table.add_row(f"[{style}]{status}[/{style}]" if style else status, str(count))
        console.print(dep_table)


if __name__ == "__main__":
    app()
