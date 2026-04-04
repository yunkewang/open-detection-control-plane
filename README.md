# Open Detection Control Plane (ODCP)

**A vendor-neutral platform for understanding, validating, and optimizing security detection content.**

ODCP answers the questions every detection engineering team faces:

- What does this security environment actually look like?
- What detection content exists here?
- What dependencies do those detections have?
- Are those detections runnable in this environment?
- If not, what is missing or degraded?
- What should be optimized first?

## Why This Exists

Security teams deploy detection content (Splunk correlation searches, Sigma rules, Sentinel analytics) across complex environments. These detections depend on macros, lookups, data models, field extractions, and data sources — but there is no standard way to understand or validate those dependencies.

ODCP provides a **unified control plane** that models environments, detections, dependencies, and readiness — starting with Splunk and designed to support any platform.

## Architecture

| Layer | Components |
|-------|------------|
| **CLI / API** | `odcp scan`, `odcp report`, `odcp graph` |
| **Reporting** | JSON, Markdown, HTML |
| **Analyzers** | Readiness, Dependency, **Runtime Health**, *(Future: Semantic Gap, Optimization)* |
| **Core Engine** | Dependency Graph, Scoring, Findings |
| **Adapters** | **Splunk** (static + runtime), *(Future: Sigma, Sentinel, Elastic, Chronicle)* |
| **Collectors** | Local, **Splunk REST API**, *(Future: Remote)* |
| **Unified Models** | Environment, Detection, Dependency, Finding, ReadinessScore, RuntimeHealthScore, ScanReport |

## Current MVP (v0.1.0)

### What's implemented

**Phase 1 — Static Readiness:**
- **Core models** — Pydantic v2 models for Environment, Detection, Dependency, Finding, ReadinessScore, ScanReport
- **Splunk adapter** — Parses `savedsearches.conf`, `macros.conf`, `eventtypes.conf`, `transforms.conf` with default/local merge
- **SPL dependency extraction** — Extracts macro, eventtype, lookup, data model, and saved search references from SPL queries
- **Dependency graph** — NetworkX-based graph linking detections to dependencies
- **Readiness analyzer** — Classifies detections as `runnable`, `partially_runnable`, `blocked`, or `unknown`
- **Dependency analyzer** — Identifies orphaned objects and high-impact dependencies
- **Reporting** — JSON, Markdown, and HTML output formats
- **CLI** — `odcp scan splunk`, `odcp report`, `odcp graph`, `odcp version`

**Phase 2 — Runtime Signals and Health:**
- **Splunk REST API client** — Token and basic auth, SSL configurable, queries saved searches, lookups, data models, and indexes
- **API collector** — Gathers runtime signals from a live Splunk instance with graceful error handling
- **Runtime health models** — `SavedSearchHealth`, `LookupHealth`, `DataModelHealth`, `IndexHealth`, `RuntimeSignal`, `RuntimeHealthScore`, `CombinedReadinessScore`
- **Runtime health analyzer** — Scores detections based on live signals (scheduling, execution failures, lookup availability, data model acceleration)
- **Combined scoring** — Merges static readiness + runtime health into a single combined score with configurable weights
- **Runtime CLI flags** — `--api-url`, `--token`, `--username`, `--password`, `--verify-ssl`, `--indexes`

### What's placeholder / future

- Semantic gap analyzer (data source coverage analysis)
- Optimization analyzer (prioritized remediation)
- Additional adapters (Sigma, Sentinel, Elastic, Chronicle)

## Installation

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Quick Start

### Scan a Splunk app

```bash
# Console summary
odcp scan splunk /path/to/splunk_app

# Full JSON report
odcp scan splunk /path/to/splunk_app --output report.json

# Markdown report
odcp scan splunk /path/to/splunk_app --output report.md --format markdown

# HTML report
odcp scan splunk /path/to/splunk_app --output report.html --format html
```

### Scan with runtime health (requires live Splunk)

```bash
# Combined static + runtime scan with token auth
odcp scan splunk /path/to/splunk_app --api-url https://splunk:8089 --token YOUR_TOKEN

# With username/password and specific index checks
odcp scan splunk /path/to/splunk_app \
  --api-url https://splunk:8089 \
  --username admin --password changeme \
  --indexes main,security
```

### Convert report formats

```bash
odcp report report.json --format markdown --output report.md
```

### View dependency graph stats

```bash
odcp graph report.json
```

### Example output

```
╭──────────────── Scan: ACME Security Detections ──────────────────╮
│ Total detections: 5                                              │
│ Runnable: 3  Partial: 0  Blocked: 2  Unknown: 0                  │
│ Overall readiness: 67%                                           │
╰──────────────────────────────────────────────────────────────────╯
                 Top Blocked Detections
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━┓
┃ Detection                           ┃ Score ┃ Missing ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━┩
│ Detect Data Exfiltration via DNS    │    0% │       3 │
│ Detect Unauthorized Cloud API Calls │   33% │       2 │
└─────────────────────────────────────┴───────┴─────────┘
```

## Running Tests

```bash
pytest tests/ -v
```

## Project Structure

```
odcp/
├── models/          # Pydantic data models (unified schema + runtime health)
├── core/            # Engine, dependency graph
├── adapters/        # Vendor adapters (Splunk static + REST API client)
├── analyzers/       # Readiness, dependency, runtime health analyzers
├── collectors/      # Data collection (local filesystem, Splunk REST API)
├── reporting/       # JSON, Markdown, HTML report generation
└── cli/             # Typer CLI interface
```

## Roadmap

| Phase | Focus                                                 | Status           |
| ----- | ----------------------------------------------------- | ---------------- |
| 1     | Splunk static readiness analysis                      | **Complete** |
| 2     | Splunk runtime signals and health                     | **Complete** |
| 3     | Semantic gap analysis and optimization                | Planned          |
| 4     | Additional vendor adapters (Sigma, Sentinel, Elastic) | Planned          |

See [docs/mvp-roadmap.md](docs/mvp-roadmap.md) for detailed roadmap and [docs/architecture.md](docs/architecture.md) for architecture details.

## License

Apache 2.0
