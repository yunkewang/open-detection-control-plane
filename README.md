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
| **CLI / API** | `odcp scan`, `odcp report`, `odcp graph`, `odcp cross-platform`, `odcp migrate` |
| **Reporting** | JSON, Markdown, HTML |
| **Analyzers** | Readiness, Dependency, Runtime Health, Coverage, Optimization, **OCSF Mapper**, **Splunk Cloud CI**, **Cross-Platform Readiness**, **Migration Analysis** |
| **Core Engine** | Dependency Graph, Scoring, Findings, **STIX Refresh** |
| **Adapters** | Splunk (static + runtime), Sigma **(+ correlations/filters)**, Elastic, Sentinel, **Chronicle (YARA-L)** |
| **Collectors** | Local, Splunk REST API, *(Future: Remote)* |
| **Unified Models** | Environment, Detection, Dependency, Finding, ReadinessScore, RuntimeHealthScore, **CorrelationRule**, **SigmaFilter**, **OcsfMapping**, **CrossPlatformSummary**, **MigrationSummary**, ScanReport |

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

**Phase 3 — Semantic Gap and Optimization:**
- **MITRE ATT&CK coverage** — 25+ technique catalog, heuristic detection mapping, per-tactic coverage breakdown
- **Data source inventory** — Extracts index/sourcetype/data model references from SPL, identifies gaps vs. known sources
- **Coverage gap analysis** — Identifies uncovered MITRE techniques with remediation guidance
- **Optimization analyzer** — Ranks missing dependencies by unblock potential with effort-adjusted impact scores
- **What-if analysis** — Simulates fixing each dependency and predicts new readiness score
- **CLI `--coverage` flag** — Adds coverage and optimization panels to scan output

**Phase 4 — Additional Vendor Adapters:**
- **Sigma adapter** — Parses YAML rules, extracts logsource dependencies (category/product/service), builds pseudo-queries from detection blocks, maps MITRE ATT&CK tags
- **Elastic adapter** — Parses JSON detection rules (flat and nested Kibana export formats), extracts index patterns and required fields as dependencies, maps MITRE techniques from threat blocks
- **Sentinel adapter** — Parses YAML/JSON analytics rules, extracts KQL table references, data connector dependencies, and MITRE technique mappings
- **CLI commands** — `odcp scan sigma`, `odcp scan elastic`, `odcp scan sentinel`

**Phase 5 — Post-MVP Enhancements:**
- **Sigma correlation meta-rules** — Parses Sigma v2.1.0 correlation rules (`event_count`, `value_count`, `temporal`) with group-by, timespan, and threshold conditions; models cross-rule dependencies
- **Sigma filters** — Parses `filter` and `meta_filter` rule types for environment-specific exclusions without modifying original rules
- **ATT&CK STIX/TAXII catalog refresh** — Fetches the official MITRE ATT&CK Enterprise STIX bundle and merges with the curated catalog to reduce technique drift; supports local file or network fetch with automatic fallback
- **OCSF normalization** — Maps vendor data sources (Sigma logsources, Splunk sourcetypes, Elastic indexes, Sentinel tables) to OCSF v1.1 event classes for cross-platform normalization
- **Splunk Cloud CI checks** — Validates app bundles for cloud readiness: disallowed file types, app.conf metadata, app.manifest, restricted SPL commands, Python 3 compatibility
- **CLI flags** — `--ocsf`, `--cloud-check`, `--stix-file`

**Phase 6 — Chronicle, Cross-Platform, and Migration:**
- **Chronicle (Google) YARA-L adapter** — Parses YARA-L 2.0 detection rules (`.yaral`, `.yar`) with full section extraction (meta, events, match, outcome, condition); extracts UDM entity types, UDM field paths, reference list dependencies, match variables, and YARA-L functions
- **Unified cross-platform readiness** — Aggregates scan reports from multiple platforms into a single view with per-platform readiness scores, shared/unique MITRE technique analysis, and actionable recommendations
- **Detection migration analysis** — Evaluates feasibility and effort of migrating detections between any two platforms (Splunk, Sigma, Elastic, Sentinel, Chronicle); maps platform-specific features, identifies blockers, estimates effort in hours, and classifies complexity (trivial/low/medium/high/infeasible)
- **CLI commands** — `odcp scan chronicle`, `odcp cross-platform`, `odcp migrate`

### Future

- Web dashboard UI

## AI SOC Prototype Roadmap (Environment-Aware + Data-Aware)

This roadmap is focused on turning ODCP into an **AI SOC prototype loop** that can:
1) understand the environment,
2) reason over available data sources,
3) make data-aware detection decisions,
4) continuously ingest threat intel,
5) auto-update and validate detections.

### Phase A — Environment Awareness Baseline (in progress)
- Normalize and maintain a living **data source catalog** (indexes, sourcetypes, data models, connectors).
- Record what each source provides (event type, field richness, ATT&CK relevance).
- Track source health/availability as a first-class signal.

### Phase B — Data-Aware Detection Feasibility (in progress)
- Add per-detection **data support decisions**:
  - `detectable`
  - `blocked_data_gap`
  - `blocked_logic_gap`
  - `unknown`
- Require data support checks during detection generation/migration so we avoid producing content that cannot run.

### Phase C — Continuous AI SOC Automation Loop (next)
- Schedule recurring environment scans and runtime checks.
- Pull latest ATT&CK/STIX threat intel and map to onboarded data sources.
- Auto-prioritize detection updates based on drift (new TTPs, broken sources, runtime failures).
- Validate outcomes with post-deploy health checks (execution failures, volume anomalies, noisy detections).

### Immediate next action items
1. Wire real connector telemetry inventories from each adapter (Splunk/Elastic/Sentinel/Chronicle) into a unified source capability model.
2. Expand data capability mapping to include key fields/entities each source can satisfy.
3. Add data-aware gating into migration recommendations and generated detection content.
4. Add scheduled jobs (or CI workflow) for:
   - environment rescan,
   - threat intel refresh,
   - detection regression review.
5. Add a feedback loop that reads detection outcomes and automatically proposes tuning updates.

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

### Scan Sigma rules

```bash
odcp scan sigma /path/to/sigma_rules
odcp scan sigma /path/to/sigma_rules --output report.json

# With OCSF normalization (maps logsources to OCSF event classes)
odcp scan sigma /path/to/sigma_rules --ocsf
```

> Sigma scans automatically detect and parse **correlation meta-rules**
> (event_count, value_count, temporal) and **filter rules** alongside
> standard detections.

### Scan Elastic rules

```bash
odcp scan elastic /path/to/elastic_rules
odcp scan elastic /path/to/elastic_rules --output report.json
```

### Scan Sentinel analytics rules

```bash
odcp scan sentinel /path/to/sentinel_rules
odcp scan sentinel /path/to/sentinel_rules --output report.json
```

### Scan Chronicle YARA-L rules

```bash
odcp scan chronicle /path/to/chronicle_rules
odcp scan chronicle /path/to/chronicle_rules --output report.json
```

### Cross-platform readiness view

```bash
# Generate reports from multiple platforms, then compare
odcp scan sigma rules/ --output sigma.json
odcp scan elastic rules/ --output elastic.json
odcp scan chronicle rules/ --output chronicle.json

odcp cross-platform sigma.json elastic.json chronicle.json
odcp cross-platform sigma.json elastic.json --output cross-platform.json
```

### Detection migration analysis

```bash
# Analyze migration from one platform to another
odcp migrate sigma.json --target chronicle
odcp migrate splunk.json --target elastic --output migration.json
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

### Scan with MITRE ATT&CK coverage and optimization

```bash
# Add coverage analysis to any scan
odcp scan splunk /path/to/splunk_app --coverage

# Combined: static + runtime + coverage
odcp scan splunk /path/to/splunk_app \
  --api-url https://splunk:8089 --token YOUR_TOKEN \
  --coverage --indexes main,security
```

### Splunk Cloud readiness checks

```bash
# Validate an app for Splunk Cloud deployment
odcp scan splunk /path/to/splunk_app --cloud-check

# Use a local ATT&CK STIX bundle for coverage analysis
odcp scan splunk /path/to/splunk_app --coverage --stix-file enterprise-attack.json
```

### Convert report formats

```bash
odcp report report.json --format markdown --output report.md
```

### View dependency graph stats

```bash
odcp graph report.json
```

### Build an AI SOC prototype plan from a scan report

```bash
odcp ai-soc-prototype report.json
odcp ai-soc-prototype report.json --output ai_soc_plan.json
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
├── models/          # Pydantic data models (detection, dependency, coverage, correlation, OCSF, cross-platform, migration)
├── core/            # Engine, dependency graph
├── adapters/        # Vendor adapters (Splunk, Sigma + correlations/filters, Elastic, Sentinel, Chronicle)
├── analyzers/       # Readiness, dependency, runtime health, coverage, optimization, OCSF mapper, Splunk Cloud CI, cross-platform, migration
├── collectors/      # Data collection (local filesystem, Splunk REST API)
├── reporting/       # JSON, Markdown, HTML report generation
└── cli/             # Typer CLI interface
```

## Roadmap

| Phase | Focus | Status |
| ----- | ----- | ------ |
| 1 | Splunk static readiness analysis | **Complete** |
| 2 | Splunk runtime signals and health | **Complete** |
| 3 | Semantic gap analysis and optimization | **Complete** |
| 4 | Additional vendor adapters (Sigma, Sentinel, Elastic) | **Complete** |
| 5 | Sigma correlations/filters, STIX refresh, OCSF mapping, Splunk Cloud CI | **Complete** |
| 6 | Chronicle YARA-L adapter, cross-platform readiness, migration analysis | **Complete** |

See [docs/mvp-roadmap.md](docs/mvp-roadmap.md) for detailed roadmap and [docs/architecture.md](docs/architecture.md) for architecture details.

## License

Apache 2.0
