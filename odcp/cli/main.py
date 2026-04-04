"""ODCP command-line interface."""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path
from typing import Optional

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
    api_url: Optional[str] = typer.Option(
        None, "--api-url",
        help="Splunk REST API URL (e.g. https://localhost:8089) for runtime health."
    ),
    token: Optional[str] = typer.Option(
        None, "--token", help="Splunk authentication token for runtime health."
    ),
    username: Optional[str] = typer.Option(
        None, "--username", help="Splunk username (alternative to token)."
    ),
    password: Optional[str] = typer.Option(
        None, "--password", help="Splunk password (used with --username)."
    ),
    verify_ssl: bool = typer.Option(
        False, "--verify-ssl", help="Verify SSL certificates for Splunk API."
    ),
    indexes: Optional[str] = typer.Option(
        None, "--indexes", help="Comma-separated index names to check health for."
    ),
    coverage: bool = typer.Option(
        False, "--coverage", help="Enable MITRE ATT&CK coverage and optimization analysis."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan a Splunk app/TA bundle for detection readiness.

    When --api-url is provided, also collects runtime health signals
    from the live Splunk instance and produces combined readiness scores.
    """
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

    runtime_enabled = api_url is not None
    index_list = [i.strip() for i in indexes.split(",")] if indexes else None

    if runtime_enabled:
        from odcp.adapters.splunk.api_client import SplunkAPIClient
        from odcp.collectors.api import APICollector

        client = SplunkAPIClient(
            base_url=api_url,
            token=token,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
        )
        collector = APICollector(client)

        with console.status("[bold blue]Scanning (static + runtime)..."):
            report = engine.scan_with_runtime(path, collector, index_names=index_list)
    else:
        with console.status("[bold blue]Scanning..."):
            report = engine.scan(path)

    if coverage:
        from odcp.core.graph import DependencyGraph

        with console.status("[bold blue]Analyzing coverage and optimization..."):
            graph = DependencyGraph()
            graph.build_from_scan(report.detections, report.dependencies)
            report = engine.enrich_with_coverage(
                report, graph,
                known_indexes=index_list,
            )

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        if runtime_enabled:
            _print_runtime_summary(report)
        if coverage:
            _print_coverage_summary(report)
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


def _print_runtime_summary(report) -> None:
    """Print runtime health summary when runtime data is available."""
    meta = report.metadata
    if not meta.get("runtime_enabled"):
        return

    rs = meta.get("runtime_summary", {})
    if not rs:
        return

    summary_lines = (
        f"[bold]Runtime detections checked:[/bold] {rs.get('total_detections', 0)}\n"
        f"[green]Healthy:[/green] {rs.get('healthy', 0)}  "
        f"[yellow]Degraded:[/yellow] {rs.get('degraded', 0)}  "
        f"[red]Unhealthy:[/red] {rs.get('unhealthy', 0)}  "
        f"[dim]Unknown:[/dim] {rs.get('unknown', 0)}\n"
        f"[bold]Runtime health score:[/bold] {rs.get('overall_runtime_score', 0):.0%}\n"
        f"[dim]Saved searches: {rs.get('saved_searches_checked', 0)} | "
        f"Lookups: {rs.get('lookups_checked', 0)} | "
        f"Data models: {rs.get('data_models_checked', 0)} | "
        f"Indexes: {rs.get('indexes_checked', 0)}[/dim]"
    )
    console.print(Panel(summary_lines, title="Runtime Health", border_style="magenta"))

    # Show combined scores for degraded/blocked detections
    combined = meta.get("combined_scores", [])
    problem_scores = [
        c for c in combined if c.get("combined_status") in ("blocked", "degraded")
    ]
    if problem_scores:
        table = Table(title="Detections with Runtime Issues")
        table.add_column("Detection", style="bold")
        table.add_column("Static", justify="right")
        table.add_column("Runtime", justify="right")
        table.add_column("Combined", justify="right")
        table.add_column("Status")

        for c in sorted(problem_scores, key=lambda x: x.get("combined_score", 0))[:15]:
            status_style = {"blocked": "red", "degraded": "yellow"}.get(
                c.get("combined_status", ""), ""
            )
            table.add_row(
                c.get("detection_name", ""),
                f"{c.get('static_score', 0):.0%}",
                f"{c.get('runtime_score', 0):.0%}",
                f"{c.get('combined_score', 0):.0%}",
                f"[{status_style}]{c.get('combined_status', '')}[/{status_style}]"
                if status_style
                else c.get("combined_status", ""),
            )
        console.print(table)

    # Show runtime errors if any
    errors = meta.get("runtime_errors", [])
    if errors:
        console.print(f"\n[yellow]Runtime collection warnings ({len(errors)}):[/yellow]")
        for err in errors[:5]:
            console.print(f"  [dim]{err}[/dim]")
        if len(errors) > 5:
            console.print(f"  [dim]... and {len(errors) - 5} more[/dim]")


def _print_coverage_summary(report) -> None:
    """Print MITRE ATT&CK coverage and optimization summary."""
    meta = report.metadata
    if not meta.get("coverage_enabled"):
        return

    # -- MITRE Coverage --
    cs = meta.get("coverage_summary", {})
    if cs:
        total = cs.get("total_techniques_in_scope", 0)
        covered = cs.get("covered", 0)
        partial = cs.get("partially_covered", 0)
        uncovered = cs.get("uncovered", 0)
        score = cs.get("coverage_score", 0)

        cov_text = (
            f"[bold]Techniques in scope:[/bold] {total}\n"
            f"[green]Covered:[/green] {covered}  "
            f"[yellow]Partial:[/yellow] {partial}  "
            f"[red]Uncovered:[/red] {uncovered}\n"
            f"[bold]Coverage score:[/bold] {score:.0%}"
        )
        console.print(Panel(cov_text, title="MITRE ATT&CK Coverage", border_style="cyan"))

        # Tactic breakdown
        by_tactic = cs.get("by_tactic", {})
        if by_tactic:
            tbl = Table(title="Coverage by Tactic")
            tbl.add_column("Tactic", style="bold")
            tbl.add_column("Covered", justify="right", style="green")
            tbl.add_column("Partial", justify="right", style="yellow")
            tbl.add_column("Uncovered", justify="right", style="red")
            for tactic, counts in sorted(by_tactic.items()):
                tbl.add_row(
                    tactic,
                    str(counts.get("covered", 0)),
                    str(counts.get("partial", 0)),
                    str(counts.get("uncovered", 0)),
                )
            console.print(tbl)

    # -- Data source gaps --
    ds = meta.get("data_source_inventory", {})
    gaps = [s for s in ds.get("sources", []) if s.get("expected") and not s.get("observed")]
    if gaps:
        console.print(f"\n[yellow]Data source gaps ({len(gaps)}):[/yellow]")
        for g in gaps[:10]:
            console.print(
                f"  [dim]{g.get('source_type', '?')}:[/dim] "
                f"{g.get('name', '?')} "
                f"[dim]({g.get('detection_count', 0)} detections)[/dim]"
            )

    # -- Optimization --
    opt = meta.get("optimization_summary", {})
    if opt:
        current = opt.get("current_score", 0)
        max_score = opt.get("max_achievable_score", 0)
        top_rems = opt.get("top_remediations", [])

        opt_text = (
            f"[bold]Current score:[/bold] {current:.0%}\n"
            f"[bold]Max achievable:[/bold] {max_score:.0%}\n"
            f"[bold]Blocked detections:[/bold] "
            f"{opt.get('total_blocked_detections', 0)}\n"
            f"[bold]Missing dependencies:[/bold] "
            f"{opt.get('total_missing_dependencies', 0)}"
        )
        console.print(Panel(opt_text, title="Optimization", border_style="green"))

        if top_rems:
            tbl = Table(title="Top Remediations (What-If)")
            tbl.add_column("#", justify="right")
            tbl.add_column("Dependency", style="bold")
            tbl.add_column("Kind")
            tbl.add_column("Unblocks", justify="right", style="green")
            tbl.add_column("Affects", justify="right")
            tbl.add_column("Effort")
            for r in top_rems[:10]:
                tbl.add_row(
                    str(r.get("rank", "")),
                    r.get("dependency_name", ""),
                    r.get("dependency_kind", ""),
                    str(r.get("blocked_detections_unblocked", 0)),
                    str(r.get("affected_detection_count", 0)),
                    r.get("effort", ""),
                )
            console.print(tbl)

        # What-if results
        what_ifs = opt.get("what_if_results", [])
        improving = [w for w in what_ifs if w.get("score_improvement", 0) > 0]
        if improving:
            tbl = Table(title="What-If Score Improvements")
            tbl.add_column("Fix", style="bold")
            tbl.add_column("New Score", justify="right")
            tbl.add_column("Improvement", justify="right", style="green")
            tbl.add_column("Unblocks", justify="right")
            for w in improving[:10]:
                tbl.add_row(
                    f"{w.get('fixed_dependency_kind', '')}: "
                    f"{w.get('fixed_dependency_name', '')}",
                    f"{w.get('new_overall_score', 0):.0%}",
                    f"+{w.get('score_improvement', 0):.0%}",
                    str(len(w.get("detections_unblocked", []))),
                )
            console.print(tbl)


if __name__ == "__main__":
    app()
