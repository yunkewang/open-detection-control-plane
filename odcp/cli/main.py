"""ODCP command-line interface."""

from __future__ import annotations

import json
import logging
import os
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

soc_app = typer.Typer(help="AI SOC automation workflows.")
app.add_typer(soc_app, name="ai-soc")

agent_app = typer.Typer(help="AI agent integration — LLM-callable tools and agentic queries.")
app.add_typer(agent_app, name="agent")

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
    cloud_check: bool = typer.Option(
        False, "--cloud-check", help="Run Splunk Cloud readiness checks (AppInspect/ACS-aligned)."
    ),
    stix_file: Optional[str] = typer.Option(
        None, "--stix-file", help="Path to a local ATT&CK STIX JSON bundle for catalog refresh."
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

            # Optional STIX catalog refresh
            stix_path = Path(stix_file) if stix_file else None
            report = engine.enrich_with_coverage(
                report, graph,
                known_indexes=index_list,
                stix_source=stix_path,
            )

    if cloud_check:
        from odcp.analyzers.splunk_cloud import SplunkCloudChecker

        with console.status("[bold blue]Running Splunk Cloud readiness checks..."):
            checker = SplunkCloudChecker()
            spl_pairs = [(d.name, d.search_query) for d in report.detections]
            cloud_findings = checker.check(path, detections_spl=spl_pairs)
            if cloud_findings:
                merged_findings = list(report.findings) + cloud_findings
                meta = dict(report.metadata)
                meta["cloud_check_enabled"] = True
                meta["cloud_check_issues"] = len(cloud_findings)
                report = report.model_copy(
                    update={"findings": merged_findings, "metadata": meta}
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
        if cloud_check:
            _print_cloud_check_summary(report)
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
# odcp ai-soc-prototype <input_json>
# ---------------------------------------------------------------------------
@app.command("ai-soc-prototype")
def ai_soc_prototype_cmd(
    input_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write prototype plan to file."
    ),
) -> None:
    """Build an environment-aware AI SOC prototype plan from a scan report."""
    from odcp.analyzers.ai_soc import AiSocPrototypeAnalyzer
    from odcp.models import ScanReport

    if not input_file.exists():
        console.print(f"[red]Error:[/red] File not found: {input_file}")
        raise typer.Exit(code=1)

    data = json.loads(input_file.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)
    summary = AiSocPrototypeAnalyzer().analyze(report)

    if output:
        output.write_text(
            json.dumps(summary.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Prototype plan written to:[/green] {output}")
        return

    panel = (
        f"[bold]Environment:[/bold] {summary.environment_name}\n"
        f"[bold]Detections:[/bold] {summary.total_detections}\n"
        f"[green]Detectable now:[/green] {summary.detectable_now}\n"
        f"[yellow]Blocked by data:[/yellow] {summary.blocked_by_data}\n"
        f"[red]Blocked by logic:[/red] {summary.blocked_by_logic}\n"
        f"[dim]Unknown:[/dim] {summary.unknown}"
    )
    console.print(Panel(panel, title="AI SOC Prototype", border_style="cyan"))

    if summary.next_actions:
        actions = Table(title="Next Action Items")
        actions.add_column("Phase", style="bold")
        actions.add_column("Priority")
        actions.add_column("Action")
        for item in summary.next_actions:
            actions.add_row(item.phase, item.priority, item.action)
        console.print(actions)


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


# ---------------------------------------------------------------------------
# odcp scan sigma <path>
# ---------------------------------------------------------------------------
@scan_app.command("sigma")
def scan_sigma(
    path: Path = typer.Argument(..., help="Path to Sigma rule directory or file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.json, "--format", "-f", help="Output format."
    ),
    ocsf: bool = typer.Option(
        False, "--ocsf", help="Enable OCSF normalization mapping."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan Sigma YAML rules for detection readiness."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(code=1)

    from odcp.adapters.sigma import SigmaAdapter
    from odcp.core.engine import ScanEngine

    adapter = SigmaAdapter()
    engine = ScanEngine(adapter)

    with console.status("[bold blue]Scanning Sigma rules..."):
        report = engine.scan(path)

    # Enrich with correlation/filter metadata
    meta = dict(report.metadata)
    if adapter.correlations:
        meta["correlations"] = [c.model_dump() for c in adapter.correlations]
    if adapter.filters:
        meta["filters"] = [f.model_dump() for f in adapter.filters]

    if ocsf:
        from odcp.analyzers.ocsf_mapper import OcsfMapper

        with console.status("[bold blue]Running OCSF normalization..."):
            mapper = OcsfMapper()
            ocsf_result = mapper.normalize(report.detections, report.dependencies, "sigma")
            meta["ocsf_normalization"] = ocsf_result.model_dump()

    if meta != report.metadata:
        report = report.model_copy(update={"metadata": meta})

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        _print_sigma_extras(adapter, report)
        console.print(
            "\n[dim]Use --output report.json to save full report.[/dim]"
        )


# ---------------------------------------------------------------------------
# odcp scan elastic <path>
# ---------------------------------------------------------------------------
@scan_app.command("elastic")
def scan_elastic(
    path: Path = typer.Argument(..., help="Path to Elastic rule directory or file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.json, "--format", "-f", help="Output format."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan Elastic Security detection rules for readiness."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(code=1)

    from odcp.adapters.elastic import ElasticAdapter
    from odcp.core.engine import ScanEngine

    adapter = ElasticAdapter()
    engine = ScanEngine(adapter)

    with console.status("[bold blue]Scanning Elastic rules..."):
        report = engine.scan(path)

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        console.print(
            "\n[dim]Use --output report.json to save full report.[/dim]"
        )


# ---------------------------------------------------------------------------
# odcp scan sentinel <path>
# ---------------------------------------------------------------------------
@scan_app.command("sentinel")
def scan_sentinel(
    path: Path = typer.Argument(..., help="Path to Sentinel analytics rule directory or file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.json, "--format", "-f", help="Output format."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan Microsoft Sentinel analytics rules for readiness."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(code=1)

    from odcp.adapters.sentinel import SentinelAdapter
    from odcp.core.engine import ScanEngine

    adapter = SentinelAdapter()
    engine = ScanEngine(adapter)

    with console.status("[bold blue]Scanning Sentinel rules..."):
        report = engine.scan(path)

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        console.print(
            "\n[dim]Use --output report.json to save full report.[/dim]"
        )


# ---------------------------------------------------------------------------
# odcp scan chronicle <path>
# ---------------------------------------------------------------------------
@scan_app.command("chronicle")
def scan_chronicle(
    path: Path = typer.Argument(..., help="Path to Chronicle YARA-L rule directory or file."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file."),
    fmt: ReportFormat = typer.Option(
        ReportFormat.json, "--format", "-f", help="Output format."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Scan Google Chronicle YARA-L detection rules for readiness."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(code=1)

    from odcp.adapters.chronicle import ChronicleAdapter
    from odcp.core.engine import ScanEngine

    adapter = ChronicleAdapter()
    engine = ScanEngine(adapter)

    with console.status("[bold blue]Scanning Chronicle YARA-L rules..."):
        report = engine.scan(path)

    if output:
        _write_report(report, output, fmt)
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        _print_summary(report)
        _print_chronicle_extras(report)
        console.print(
            "\n[dim]Use --output report.json to save full report.[/dim]"
        )


# ---------------------------------------------------------------------------
# odcp cross-platform <report_files...>
# ---------------------------------------------------------------------------
@app.command("cross-platform")
def cross_platform_cmd(
    report_files: list[Path] = typer.Argument(..., help="Two or more JSON scan report files."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write result to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Unified cross-platform readiness view across multiple scan reports."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    if len(report_files) < 2:
        console.print("[red]Error:[/red] Provide at least two scan report files.")
        raise typer.Exit(code=1)

    from odcp.analyzers.cross_platform import CrossPlatformReadinessAnalyzer
    from odcp.models import ScanReport

    reports: list[ScanReport] = []
    for rf in report_files:
        if not rf.exists():
            console.print(f"[red]Error:[/red] File not found: {rf}")
            raise typer.Exit(code=1)
        data = json.loads(rf.read_text(encoding="utf-8"))
        reports.append(ScanReport.model_validate(data))

    analyzer = CrossPlatformReadinessAnalyzer()
    with console.status("[bold blue]Analyzing cross-platform readiness..."):
        summary = analyzer.analyze(reports)

    if output:
        output.write_text(
            json.dumps(summary.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Cross-platform report written to:[/green] {output}")
    else:
        _print_cross_platform_summary(summary)


# ---------------------------------------------------------------------------
# odcp migrate <source_report> --target <platform>
# ---------------------------------------------------------------------------
@app.command("migrate")
def migrate_cmd(
    source_report: Path = typer.Argument(..., help="JSON scan report of the source platform."),
    target: str = typer.Option(..., "--target", "-t", help="Target platform (splunk, sigma, elastic, sentinel, chronicle)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write result to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Analyze detection migration feasibility from one platform to another."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s"
        )
    else:
        logging.basicConfig(level=logging.WARNING)

    valid_platforms = {"splunk", "sigma", "elastic", "sentinel", "chronicle"}
    if target not in valid_platforms:
        console.print(f"[red]Error:[/red] Invalid target platform: {target}. Choose from: {', '.join(sorted(valid_platforms))}")
        raise typer.Exit(code=1)

    if not source_report.exists():
        console.print(f"[red]Error:[/red] File not found: {source_report}")
        raise typer.Exit(code=1)

    from odcp.analyzers.cross_platform import MigrationAnalyzer
    from odcp.models import ScanReport

    data = json.loads(source_report.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)

    analyzer = MigrationAnalyzer()
    with console.status(f"[bold blue]Analyzing migration to {target}..."):
        migration = analyzer.analyze(report, target)

    if output:
        output.write_text(
            json.dumps(migration.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Migration report written to:[/green] {output}")
    else:
        _print_migration_summary(migration)


# ---------------------------------------------------------------------------
# Print helpers for new commands
# ---------------------------------------------------------------------------
def _print_chronicle_extras(report) -> None:
    """Print Chronicle-specific extras."""
    chronicle_dets = [d for d in report.detections if d.metadata.get("udm_entities")]
    if not chronicle_dets:
        return

    # Show UDM entity usage
    entity_counts: dict[str, int] = {}
    for d in chronicle_dets:
        for e in d.metadata.get("udm_entities", []):
            entity_counts[e] = entity_counts.get(e, 0) + 1

    table = Table(title="UDM Entity Usage")
    table.add_column("Entity", style="bold")
    table.add_column("Detections", justify="right")
    for entity, count in sorted(entity_counts.items(), key=lambda x: -x[1]):
        table.add_row(entity, str(count))
    console.print(table)

    # Show reference lists
    ref_list_dets = [d for d in report.detections if d.metadata.get("reference_lists")]
    if ref_list_dets:
        console.print(
            f"\n[bold]Reference lists used:[/bold] "
            + ", ".join(
                rl
                for d in ref_list_dets
                for rl in d.metadata.get("reference_lists", [])
            )
        )


def _print_cross_platform_summary(summary) -> None:
    """Print unified cross-platform readiness view."""
    # Per-platform table
    table = Table(title="Cross-Platform Readiness")
    table.add_column("Platform", style="bold")
    table.add_column("Vendor")
    table.add_column("Detections", justify="right")
    table.add_column("Runnable", justify="right", style="green")
    table.add_column("Blocked", justify="right", style="red")
    table.add_column("Score", justify="right")
    table.add_column("MITRE", justify="right")

    for p in summary.platforms:
        table.add_row(
            p.platform_name,
            p.vendor,
            str(p.total_detections),
            str(p.runnable),
            str(p.blocked),
            f"{p.overall_score:.0%}",
            str(len(p.mitre_technique_ids)),
        )
    console.print(table)

    # Aggregate
    agg_text = (
        f"[bold]Total platforms:[/bold] {summary.total_platforms}\n"
        f"[bold]Total detections:[/bold] {summary.total_detections}\n"
        f"[bold]Aggregate score:[/bold] {summary.aggregate_score:.0%}\n"
        f"[bold]Shared MITRE techniques:[/bold] {len(summary.shared_mitre_techniques)}"
    )
    console.print(Panel(agg_text, title="Aggregate", border_style="blue"))

    # Unique coverage
    if summary.unique_mitre_by_platform:
        table2 = Table(title="Unique MITRE Coverage by Platform")
        table2.add_column("Platform", style="bold")
        table2.add_column("Unique Techniques", justify="right")
        table2.add_column("IDs")
        for name, techs in summary.unique_mitre_by_platform.items():
            table2.add_row(name, str(len(techs)), ", ".join(techs[:10]))
        console.print(table2)

    # Recommendations
    if summary.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in summary.recommendations:
            console.print(f"  [dim]-[/dim] {rec}")


def _print_migration_summary(migration) -> None:
    """Print migration analysis results."""
    # Overview panel
    overview = (
        f"[bold]Source:[/bold] {migration.source_platform} -> "
        f"[bold]Target:[/bold] {migration.target_platform}\n"
        f"[bold]Total detections:[/bold] {migration.total_detections}\n"
        f"[bold]Overall feasibility:[/bold] {migration.overall_feasibility:.0%}\n"
        f"[bold]Estimated effort:[/bold] {migration.estimated_total_hours:.1f} hours"
    )
    console.print(Panel(overview, title="Migration Analysis", border_style="blue"))

    # Complexity breakdown
    table = Table(title="Migration Complexity Breakdown")
    table.add_column("Complexity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[green]Trivial[/green]", str(migration.trivial))
    table.add_row("[green]Low[/green]", str(migration.low_complexity))
    table.add_row("[yellow]Medium[/yellow]", str(migration.medium_complexity))
    table.add_row("[red]High[/red]", str(migration.high_complexity))
    table.add_row("[red bold]Infeasible[/red bold]", str(migration.infeasible))
    console.print(table)

    # Common blockers
    if migration.common_blockers:
        table2 = Table(title="Common Migration Blockers")
        table2.add_column("Category", style="bold")
        table2.add_column("Description")
        table2.add_column("Severity")
        for b in migration.common_blockers:
            sev_style = {"high": "red", "medium": "yellow", "low": "dim"}.get(b.severity, "")
            table2.add_row(
                b.category,
                b.description[:80],
                f"[{sev_style}]{b.severity}[/{sev_style}]" if sev_style else b.severity,
            )
        console.print(table2)

    # Top difficult detections
    hard = [
        r for r in migration.detection_results
        if r.complexity in ("high", "infeasible")
    ]
    if hard:
        table3 = Table(title="Detections Requiring Most Effort")
        table3.add_column("Detection", style="bold")
        table3.add_column("Complexity")
        table3.add_column("Feasibility", justify="right")
        table3.add_column("Blockers", justify="right")
        for r in hard[:15]:
            cstyle = {"high": "red", "infeasible": "red bold"}.get(r.complexity.value, "")
            table3.add_row(
                r.detection_name,
                f"[{cstyle}]{r.complexity.value}[/{cstyle}]" if cstyle else r.complexity.value,
                f"{r.feasibility_score:.0%}",
                str(len(r.blockers)),
            )
        console.print(table3)


def _print_cloud_check_summary(report) -> None:
    """Print Splunk Cloud readiness check results."""
    meta = report.metadata
    if not meta.get("cloud_check_enabled"):
        return

    issue_count = meta.get("cloud_check_issues", 0)
    cloud_findings = [
        f for f in report.findings
        if f.detection_id == "__cloud_readiness__"
    ]

    if not cloud_findings:
        console.print(
            Panel(
                "[green]No Splunk Cloud readiness issues found.[/green]",
                title="Splunk Cloud Readiness",
                border_style="green",
            )
        )
        return

    table = Table(title=f"Splunk Cloud Readiness Issues ({issue_count})")
    table.add_column("Severity", style="bold")
    table.add_column("Issue")
    table.add_column("Description")

    for f in cloud_findings:
        severity_style = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "dim",
        }.get(f.severity.value, "")
        table.add_row(
            f"[{severity_style}]{f.severity.value}[/{severity_style}]",
            f.title,
            f.description[:80] + "..." if len(f.description) > 80 else f.description,
        )

    console.print(table)


def _print_sigma_extras(adapter, report) -> None:
    """Print Sigma correlation and filter summaries."""
    from odcp.adapters.sigma import SigmaAdapter

    if not isinstance(adapter, SigmaAdapter):
        return

    if adapter.correlations:
        table = Table(title=f"Sigma Correlation Rules ({len(adapter.correlations)})")
        table.add_column("Name", style="bold")
        table.add_column("Type")
        table.add_column("Rules Referenced", justify="right")
        table.add_column("Timespan")
        table.add_column("Condition")

        for c in adapter.correlations:
            table.add_row(
                c.name,
                c.correlation_type.value,
                str(len(c.rule_references)),
                c.timespan or "-",
                c.condition or "-",
            )
        console.print(table)

    if adapter.filters:
        table = Table(title=f"Sigma Filters ({len(adapter.filters)})")
        table.add_column("Name", style="bold")
        table.add_column("Targets", justify="right")
        table.add_column("Logsource Filter")

        for f in adapter.filters:
            ls = ""
            if f.logsource_filter:
                ls = ", ".join(f"{k}={v}" for k, v in f.logsource_filter.items())
            table.add_row(
                f.name,
                str(len(f.target_rules)),
                ls or "-",
            )
        console.print(table)

    meta = report.metadata
    ocsf = meta.get("ocsf_normalization")
    if ocsf:
        mapped = ocsf.get("mapped_detections", 0)
        total = ocsf.get("total_detections", 0)
        unmapped = ocsf.get("unmapped_detections", 0)
        by_cat = ocsf.get("coverage_by_category", {})

        ocsf_text = (
            f"[bold]Total detections:[/bold] {total}\n"
            f"[green]OCSF-mapped:[/green] {mapped}  "
            f"[yellow]Unmapped:[/yellow] {unmapped}"
        )
        console.print(Panel(ocsf_text, title="OCSF Normalization", border_style="cyan"))

        if by_cat:
            tbl = Table(title="OCSF Coverage by Category")
            tbl.add_column("Category", style="bold")
            tbl.add_column("Mappings", justify="right")
            for cat, count in sorted(by_cat.items()):
                tbl.add_row(cat, str(count))
            console.print(tbl)


# ---------------------------------------------------------------------------
# odcp ci <report> [--baseline <baseline_report>]
# ---------------------------------------------------------------------------
@app.command("ci")
def ci_cmd(
    report_file: Path = typer.Argument(..., help="Path to current JSON scan report."),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b",
        help="Path to baseline JSON scan report for regression detection.",
    ),
    min_score: float = typer.Option(
        0.0, "--min-score",
        help="Minimum overall readiness score to pass (0.0-1.0).",
    ),
    max_blocked_ratio: float = typer.Option(
        1.0, "--max-blocked-ratio",
        help="Maximum ratio of blocked detections allowed (0.0-1.0).",
    ),
    fail_on_regression: bool = typer.Option(
        True, "--fail-on-regression/--allow-regression",
        help="Fail if any detection readiness score regresses.",
    ),
    fail_on_new_blocked: bool = typer.Option(
        True, "--fail-on-new-blocked/--allow-new-blocked",
        help="Fail if any detection becomes newly blocked.",
    ),
    max_critical: int = typer.Option(
        -1, "--max-critical",
        help="Maximum number of critical findings allowed (-1 = unlimited).",
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write CI result to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Run CI/CD gate checks on a scan report.

    When --baseline is provided, compares current vs. baseline to detect
    regressions and improvements.  Exit code 1 = policy violation.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not report_file.exists():
        console.print(f"[red]Error:[/red] File not found: {report_file}")
        raise typer.Exit(code=1)

    from odcp.analyzers.ci import CiAnalyzer, CiPolicy
    from odcp.models import ScanReport

    policy = CiPolicy(
        min_readiness_score=min_score,
        max_blocked_ratio=max_blocked_ratio,
        fail_on_regression=fail_on_regression,
        fail_on_new_blocked=fail_on_new_blocked,
        max_critical_findings=max_critical,
    )
    analyzer = CiAnalyzer(policy)

    current_data = json.loads(report_file.read_text(encoding="utf-8"))
    current_report = ScanReport.model_validate(current_data)

    if baseline:
        if not baseline.exists():
            console.print(f"[red]Error:[/red] Baseline file not found: {baseline}")
            raise typer.Exit(code=1)
        baseline_data = json.loads(baseline.read_text(encoding="utf-8"))
        baseline_report = ScanReport.model_validate(baseline_data)
        result = analyzer.compare(baseline_report, current_report)
    else:
        result = analyzer.analyze_single(current_report)

    if output:
        output.write_text(
            json.dumps(result.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]CI result written to:[/green] {output}")
    else:
        _print_ci_result(result)

    if result.exit_code != 0:
        raise typer.Exit(code=result.exit_code)


# ---------------------------------------------------------------------------
# odcp validate <path> --platform <platform>
# ---------------------------------------------------------------------------
@app.command("validate")
def validate_cmd(
    path: Path = typer.Argument(..., help="Path to detection rule directory or file."),
    platform: str = typer.Option(
        ..., "--platform", "-p",
        help="Detection platform (splunk, sigma, elastic, sentinel, chronicle).",
    ),
    require_description: bool = typer.Option(True, "--require-description/--no-require-description"),
    require_mitre: bool = typer.Option(False, "--require-mitre/--no-require-mitre"),
    naming_pattern: Optional[str] = typer.Option(None, "--naming-pattern"),
    max_query_length: int = typer.Option(0, "--max-query-length"),
    fail_on_warnings: bool = typer.Option(False, "--fail-on-warnings/--no-fail-on-warnings"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write result to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Validate detection rules for Detection-as-Code workflows.

    Checks naming conventions, required metadata, lifecycle states,
    and file structure.  Designed for pre-commit hooks and PR checks.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {path}")
        raise typer.Exit(code=1)

    from odcp.analyzers.dac import DacPolicy, DacValidator

    policy = DacPolicy(
        require_description=require_description,
        require_mitre_tags=require_mitre,
        naming_pattern=naming_pattern,
        max_query_length=max_query_length,
        fail_on_warnings=fail_on_warnings,
    )
    validator = DacValidator(policy)
    result = validator.validate_files(path, platform)

    if output:
        output.write_text(
            json.dumps(result.model_dump(), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Validation result written to:[/green] {output}")
    else:
        _print_validation_result(result)

    if not result.valid:
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Print helpers for CI and validation
# ---------------------------------------------------------------------------
def _print_ci_result(result) -> None:
    """Print CI/CD gate result."""
    verdict_style = {
        "passed": "green",
        "failed": "red",
        "warning": "yellow",
    }.get(result.verdict.value, "")

    overview = (
        f"[bold]Verdict:[/bold] [{verdict_style}]{result.verdict.value.upper()}[/{verdict_style}]\n"
        f"[bold]Detections:[/bold] {result.total_detections}\n"
        f"[bold]Findings:[/bold] {result.total_findings} "
        f"({result.critical_findings} critical)\n"
        f"{result.summary}"
    )
    console.print(Panel(overview, title="CI/CD Gate", border_style=verdict_style or "blue"))

    if result.score_changes:
        table = Table(title="Score Changes")
        table.add_column("Metric", style="bold")
        table.add_column("Baseline", justify="right")
        table.add_column("Current", justify="right")
        table.add_column("Delta", justify="right")
        for sc in result.score_changes:
            delta_style = "green" if sc.delta >= 0 else "red"
            table.add_row(
                sc.metric,
                f"{sc.baseline:.0%}",
                f"{sc.current:.0%}",
                f"[{delta_style}]{sc.delta:+.0%}[/{delta_style}]",
            )
        console.print(table)

    if result.regressions:
        table = Table(title=f"Regressions ({len(result.regressions)})")
        table.add_column("Detection", style="bold")
        table.add_column("Was", justify="right")
        table.add_column("Now", justify="right")
        table.add_column("Score", justify="right")
        for r in result.regressions[:15]:
            table.add_row(
                r.detection_name,
                r.baseline_status,
                f"[red]{r.current_status}[/red]",
                f"{r.baseline_score:.0%} -> {r.current_score:.0%}",
            )
        console.print(table)

    if result.improvements:
        table = Table(title=f"Improvements ({len(result.improvements)})")
        table.add_column("Detection", style="bold")
        table.add_column("Was", justify="right")
        table.add_column("Now", justify="right")
        table.add_column("Score", justify="right")
        for imp in result.improvements[:15]:
            table.add_row(
                imp.detection_name,
                imp.baseline_status,
                f"[green]{imp.current_status}[/green]",
                f"{imp.baseline_score:.0%} -> {imp.current_score:.0%}",
            )
        console.print(table)

    if result.policy_violations:
        table = Table(title="Policy Violations")
        table.add_column("Rule", style="bold")
        table.add_column("Severity")
        table.add_column("Message")
        for v in result.policy_violations:
            sev_style = "red" if v.severity == "error" else "yellow"
            table.add_row(
                v.rule,
                f"[{sev_style}]{v.severity}[/{sev_style}]",
                v.message,
            )
        console.print(table)


def _print_validation_result(result) -> None:
    """Print Detection-as-Code validation result."""
    valid_text = "[green]VALID[/green]" if result.valid else "[red]INVALID[/red]"
    overview = (
        f"[bold]Status:[/bold] {valid_text}\n"
        f"[bold]Files:[/bold] {result.total_files}\n"
        f"[bold]Detections:[/bold] {result.total_detections}\n"
        f"[red]Errors:[/red] {result.errors}  "
        f"[yellow]Warnings:[/yellow] {result.warnings}"
    )
    border = "green" if result.valid else "red"
    console.print(Panel(overview, title="Detection Validation", border_style=border))

    if result.lifecycle_summary:
        table = Table(title="Lifecycle Summary")
        table.add_column("State", style="bold")
        table.add_column("Count", justify="right")
        for state, count in sorted(result.lifecycle_summary.items()):
            table.add_row(state, str(count))
        console.print(table)

    if result.issues:
        table = Table(title=f"Issues ({len(result.issues)})")
        table.add_column("Severity")
        table.add_column("Rule", style="bold")
        table.add_column("File")
        table.add_column("Message")
        for issue in result.issues:
            sev_style = {
                "error": "red",
                "warning": "yellow",
                "info": "dim",
            }.get(issue.severity.value, "")
            table.add_row(
                f"[{sev_style}]{issue.severity.value}[/{sev_style}]",
                issue.rule,
                os.path.basename(issue.file),
                issue.message[:80],
            )
        console.print(table)


# ---------------------------------------------------------------------------
# odcp ai-soc inventory <report>
# ---------------------------------------------------------------------------
@soc_app.command("inventory")
def soc_inventory_cmd(
    report_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write catalog to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Build a unified data source catalog from a scan report."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not report_file.exists():
        console.print(f"[red]Error:[/red] File not found: {report_file}")
        raise typer.Exit(code=1)

    from odcp.analyzers.ai_soc import SourceInventoryBuilder
    from odcp.models import ScanReport

    data = json.loads(report_file.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)

    catalog = SourceInventoryBuilder().build_from_single(report)

    if output:
        output.write_text(
            json.dumps(catalog.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Source catalog written to:[/green] {output}")
        return

    _print_source_catalog(catalog)


# ---------------------------------------------------------------------------
# odcp ai-soc drift <baseline> <current>
# ---------------------------------------------------------------------------
@soc_app.command("drift")
def soc_drift_cmd(
    baseline_file: Path = typer.Argument(..., help="Baseline JSON scan report."),
    current_file: Path = typer.Argument(..., help="Current JSON scan report."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write drift report to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Detect environment drift between two scan snapshots."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    for f in (baseline_file, current_file):
        if not f.exists():
            console.print(f"[red]Error:[/red] File not found: {f}")
            raise typer.Exit(code=1)

    from odcp.analyzers.ai_soc import DriftDetector
    from odcp.models import ScanReport

    baseline = ScanReport.model_validate(json.loads(baseline_file.read_text(encoding="utf-8")))
    current = ScanReport.model_validate(json.loads(current_file.read_text(encoding="utf-8")))

    drift = DriftDetector().compare_reports(baseline, current)

    if output:
        output.write_text(
            json.dumps(drift.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Drift report written to:[/green] {output}")
        return

    _print_drift_summary(drift)


# ---------------------------------------------------------------------------
# odcp ai-soc feedback <report>
# ---------------------------------------------------------------------------
@soc_app.command("feedback")
def soc_feedback_cmd(
    report_file: Path = typer.Argument(..., help="Path to a JSON scan report."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write feedback to file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Analyze detection outcomes and propose tuning actions."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not report_file.exists():
        console.print(f"[red]Error:[/red] File not found: {report_file}")
        raise typer.Exit(code=1)

    from odcp.analyzers.ai_soc import FeedbackAnalyzer
    from odcp.models import ScanReport

    data = json.loads(report_file.read_text(encoding="utf-8"))
    report = ScanReport.model_validate(data)

    feedback = FeedbackAnalyzer().analyze(report)

    if output:
        output.write_text(
            json.dumps(feedback.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]Feedback report written to:[/green] {output}")
        return

    _print_feedback_summary(feedback)


# ---------------------------------------------------------------------------
# odcp ai-soc cycle <report> [--baseline <baseline>]
# ---------------------------------------------------------------------------
@soc_app.command("cycle")
def soc_cycle_cmd(
    report_file: Path = typer.Argument(..., help="Current JSON scan report."),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b", help="Baseline scan report for drift detection."
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write full cycle result."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging."),
) -> None:
    """Run a full AI SOC automation cycle.

    Builds source catalog, runs data-aware feasibility, detects drift
    (if baseline provided), analyzes detection feedback, and produces
    a prioritized action plan.
    """
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(name)s %(levelname)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not report_file.exists():
        console.print(f"[red]Error:[/red] File not found: {report_file}")
        raise typer.Exit(code=1)

    from odcp.analyzers.ai_soc import AiSocOrchestrator
    from odcp.models import ScanReport

    current = ScanReport.model_validate(json.loads(report_file.read_text(encoding="utf-8")))
    baseline_report = None
    if baseline:
        if not baseline.exists():
            console.print(f"[red]Error:[/red] Baseline file not found: {baseline}")
            raise typer.Exit(code=1)
        baseline_report = ScanReport.model_validate(
            json.loads(baseline.read_text(encoding="utf-8"))
        )

    with console.status("[bold blue]Running AI SOC cycle..."):
        result = AiSocOrchestrator().run_cycle(current, baseline_report)

    if output:
        output.write_text(
            json.dumps(result.model_dump(mode="json"), indent=2, default=str),
            encoding="utf-8",
        )
        console.print(f"[green]AI SOC cycle result written to:[/green] {output}")
        return

    _print_cycle_result(result)


# ---------------------------------------------------------------------------
# AI SOC print helpers
# ---------------------------------------------------------------------------
def _print_source_catalog(catalog) -> None:
    """Print unified source catalog."""
    overview = (
        f"[bold]Total sources:[/bold] {catalog.total_sources}\n"
        f"[bold]Platforms:[/bold] {', '.join(catalog.platforms_represented)}\n"
        f"[green]Healthy:[/green] {catalog.healthy_sources}  "
        f"[yellow]Degraded:[/yellow] {catalog.degraded_sources}  "
        f"[red]Unavailable:[/red] {catalog.unavailable_sources}"
    )
    console.print(Panel(overview, title="Source Catalog", border_style="cyan"))

    if catalog.sources:
        table = Table(title="Data Sources")
        table.add_column("Name", style="bold")
        table.add_column("Platform")
        table.add_column("Type")
        table.add_column("Observed")
        table.add_column("Detections", justify="right")
        table.add_column("Fields", justify="right")
        table.add_column("ATT&CK Sources", justify="right")
        for src in sorted(catalog.sources, key=lambda s: (-s.detection_count, s.name))[:25]:
            obs = "[green]yes[/green]" if src.observed else "[red]no[/red]"
            table.add_row(
                src.name,
                src.platform,
                src.source_type,
                obs,
                str(src.detection_count),
                str(len(src.fields)),
                str(len(src.attack_data_sources)),
            )
        console.print(table)

    if catalog.attack_data_source_coverage:
        table = Table(title="ATT&CK Data Source Coverage")
        table.add_column("Data Source", style="bold")
        table.add_column("Sources", justify="right")
        for ds, count in sorted(catalog.attack_data_source_coverage.items(), key=lambda x: -x[1]):
            table.add_row(ds, str(count))
        console.print(table)


def _print_drift_summary(drift) -> None:
    """Print environment drift summary."""
    risk_style = "green" if drift.risk_score < 0.3 else ("yellow" if drift.risk_score < 0.7 else "red")
    overview = (
        f"[bold]Risk score:[/bold] [{risk_style}]{drift.risk_score:.0%}[/{risk_style}]\n"
        f"[bold]Total events:[/bold] {drift.total_drift_events}\n"
        f"[green]Added:[/green] {drift.sources_added}  "
        f"[red]Removed:[/red] {drift.sources_removed}  "
        f"[yellow]Health changes:[/yellow] {drift.health_changes}"
    )
    console.print(Panel(overview, title="Environment Drift", border_style=risk_style))

    if drift.events:
        table = Table(title="Drift Events")
        table.add_column("Type", style="bold")
        table.add_column("Source")
        table.add_column("Platform")
        table.add_column("Severity")
        table.add_column("Description")
        for evt in drift.events[:20]:
            sev_style = {"critical": "red", "warning": "yellow", "info": "dim"}.get(evt.severity, "")
            table.add_row(
                evt.event_type,
                evt.source_name,
                evt.platform,
                f"[{sev_style}]{evt.severity}[/{sev_style}]" if sev_style else evt.severity,
                evt.description[:70],
            )
        console.print(table)

    if drift.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in drift.recommendations:
            console.print(f"  [dim]-[/dim] {rec}")


def _print_feedback_summary(feedback) -> None:
    """Print detection feedback analysis."""
    overview = (
        f"[bold]Analyzed:[/bold] {feedback.total_detections_analyzed}\n"
        f"[green]Healthy:[/green] {feedback.healthy_detections}  "
        f"[yellow]Noisy:[/yellow] {feedback.noisy_detections}  "
        f"[red]Stale:[/red] {feedback.stale_detections}\n"
        f"[bold]Tuning proposals:[/bold] {len(feedback.proposals)}"
    )
    console.print(Panel(overview, title="Detection Feedback", border_style="magenta"))

    if feedback.proposals:
        table = Table(title="Tuning Proposals")
        table.add_column("Detection", style="bold")
        table.add_column("Action")
        table.add_column("Priority")
        table.add_column("Rationale")
        for p in feedback.proposals[:15]:
            pstyle = {"high": "red", "medium": "yellow", "low": "dim"}.get(p.priority, "")
            table.add_row(
                p.detection_name,
                p.proposal_type,
                f"[{pstyle}]{p.priority}[/{pstyle}]" if pstyle else p.priority,
                p.rationale[:60],
            )
        console.print(table)

    if feedback.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in feedback.recommendations:
            console.print(f"  [dim]-[/dim] {rec}")


def _print_cycle_result(result) -> None:
    """Print full AI SOC cycle result."""
    overview = (
        f"[bold]Environment:[/bold] {result.environment_name}\n"
        f"[bold]Readiness:[/bold] {result.readiness_score:.0%}\n"
        f"[green]Detectable now:[/green] {result.detectable_now}  "
        f"[yellow]Blocked (data):[/yellow] {result.blocked_by_data}  "
        f"[red]Blocked (logic):[/red] {result.blocked_by_logic}\n"
        f"[bold]Coverage score:[/bold] {result.coverage_score:.0%}  "
        f"[bold]ATT&CK techniques:[/bold] {result.threat_intel_techniques}"
    )
    console.print(Panel(overview, title="AI SOC Cycle", border_style="cyan"))

    if result.source_catalog:
        console.print(
            f"\n[bold]Source catalog:[/bold] {result.source_catalog.total_sources} sources "
            f"across {', '.join(result.source_catalog.platforms_represented)}"
        )

    if result.drift_summary:
        _print_drift_summary(result.drift_summary)

    if result.feedback_summary:
        _print_feedback_summary(result.feedback_summary)

    if result.priority_actions:
        console.print(Panel(
            "\n".join(result.priority_actions),
            title="Priority Actions",
            border_style="red",
        ))


# ---------------------------------------------------------------------------
# odcp agent tools
# ---------------------------------------------------------------------------
@agent_app.command("tools")
def agent_tools(
    fmt: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table (default) or json.",
    ),
) -> None:
    """List all LLM-callable ODCP tools with descriptions."""
    from odcp.agent.tools import TOOL_REGISTRY

    if fmt == "json":
        import json as _json
        from odcp.agent.tools import get_tool_schemas
        print(_json.dumps(get_tool_schemas("anthropic"), indent=2))
        return

    table = Table(title="ODCP Agent Tools", show_header=True)
    table.add_column("Tool", style="bold cyan", min_width=30)
    table.add_column("Description")
    for tool in TOOL_REGISTRY.values():
        desc = tool.description
        if len(desc) > 90:
            desc = desc[:87] + "..."
        table.add_row(tool.name, desc)
    console.print(table)
    console.print(
        f"\n[dim]{len(TOOL_REGISTRY)} tools available. "
        "Use [bold]odcp agent schema[/bold] to export JSON schemas for LLM consumption.[/dim]"
    )


# ---------------------------------------------------------------------------
# odcp agent schema
# ---------------------------------------------------------------------------
@agent_app.command("schema")
def agent_schema(
    fmt: str = typer.Option(
        "anthropic",
        "--fmt",
        help="Schema format: anthropic (default) or openai.",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write schema to file."),
) -> None:
    """Export tool schemas in Anthropic or OpenAI format for LLM consumption."""
    import json as _json
    from odcp.agent.tools import get_tool_schemas

    schemas = get_tool_schemas(fmt=fmt)
    text = _json.dumps(schemas, indent=2)

    if output:
        output.write_text(text)
        console.print(f"[green]Schema written to {output}[/green] ({len(schemas)} tools, {fmt} format)")
    else:
        print(text)


# ---------------------------------------------------------------------------
# odcp agent run  "<prompt>"
# ---------------------------------------------------------------------------
@agent_app.command("run")
def agent_run(
    prompt: str = typer.Argument(..., help="Natural-language question or instruction."),
    report: Optional[Path] = typer.Option(
        None, "--report", "-r", help="Path to scan report JSON file."
    ),
    model: str = typer.Option(
        "claude-opus-4-6", "--model", "-m", help="Claude model ID."
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)."
    ),
    max_turns: int = typer.Option(10, "--max-turns", help="Maximum agentic turns."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print tool call details."),
) -> None:
    """Run a one-shot AI agent query against a scan report.

    Requires the 'anthropic' package: pip install 'odcp[agent]'

    Example:

        odcp agent run "Which detections are blocked?" --report scan.json
    """
    from odcp.agent.orchestrator import run_agent

    answer = run_agent(
        prompt,
        report_path=str(report) if report else None,
        model=model,
        api_key=api_key,
        max_turns=max_turns,
        verbose=verbose,
    )
    console.print(Panel(answer, title="Agent Response", border_style="cyan"))


# ---------------------------------------------------------------------------
# odcp agent chat
# ---------------------------------------------------------------------------
@agent_app.command("chat")
def agent_chat(
    report: Optional[Path] = typer.Option(
        None, "--report", "-r", help="Path to scan report JSON file (pre-loaded)."
    ),
    model: str = typer.Option(
        "claude-opus-4-6", "--model", "-m", help="Claude model ID."
    ),
    api_key: Optional[str] = typer.Option(
        None, "--api-key", help="Anthropic API key (defaults to ANTHROPIC_API_KEY env var)."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print tool call details."),
) -> None:
    """Start an interactive AI agent chat session.

    Requires the 'anthropic' package: pip install 'odcp[agent]'

    Example:

        odcp agent chat --report scan.json
    """
    from odcp.agent.orchestrator import interactive_session

    interactive_session(
        report_path=str(report) if report else None,
        model=model,
        api_key=api_key,
        verbose=verbose,
    )


# ---------------------------------------------------------------------------
# odcp serve [report.json]
# ---------------------------------------------------------------------------
@app.command("serve")
def serve(
    report: Optional[Path] = typer.Argument(
        None,
        help="Scan report JSON file to load on startup.",
    ),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind host."),
    port: int = typer.Option(8080, "--port", "-p", help="Bind port."),
    poll_interval: float = typer.Option(
        5.0, "--poll-interval",
        help="Seconds between report file checks (0 to disable).",
    ),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)."),
    open_browser: bool = typer.Option(False, "--open", "-o", help="Open browser on startup."),
) -> None:
    """Start the ODCP web dashboard.

    Requires the 'server' extra: pip install 'odcp[server]'

    Example:

        odcp serve report.json --port 8080
    """
    try:
        import uvicorn  # type: ignore[import]
    except ImportError:
        console.print(
            "[red]Error:[/red] 'uvicorn' is required. "
            "Install it with: [bold]pip install 'odcp[server]'[/bold]"
        )
        raise typer.Exit(code=1)

    from odcp.server.app import create_app
    from odcp.server.state import ReportStore

    report_path = str(report) if report else None
    store = ReportStore(report_path, poll_interval=poll_interval)
    app_instance = create_app(store)

    url = f"http://{host}:{port}"
    console.print(Panel(
        f"[bold]ODCP Dashboard[/bold]\n"
        f"[dim]URL:[/dim]     [cyan]{url}[/cyan]\n"
        f"[dim]Report:[/dim]  {report_path or 'none (load via /api/report/load)'}\n"
        f"[dim]API docs:[/dim] {url}/api/docs",
        border_style="cyan",
        title="Starting server",
    ))

    if open_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    uvicorn.run(
        app_instance,
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
    )


if __name__ == "__main__":
    app()
