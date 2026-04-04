# ODCP Architecture

## Why a Control Plane?

Detection engineering today is fragmented. Teams write detections in vendor-specific formats, deploy them into complex environments, and have no unified way to answer:

- "Which of my detections can actually run?"
- "What dependencies are missing?"
- "What breaks if I remove this lookup table?"

ODCP is a **control plane** — not a SIEM, not a detection framework, not a deployment tool. It sits above vendor platforms and provides a unified model for understanding detection health.

## Core Design Principles

1. **Vendor-neutral unified model** — All concepts (detections, dependencies, findings) are modeled in a vendor-agnostic way. Adapters translate vendor specifics into this common model.

2. **Adapter pattern** — Each vendor platform (Splunk, Sentinel, Elastic) gets an adapter that implements a standard interface. The core engine doesn't know or care about vendor details.

3. **Separation of concerns** — Parsing, modeling, graph construction, analysis, and reporting are distinct phases with clean boundaries.

4. **Static-first, runtime-later** — The MVP analyzes config files on disk. Runtime health (API calls, live status) is a future layer that extends the same model.

## Architecture Layers

### 1. Unified Data Models (`odcp/models/`)

Pydantic v2 models that form the lingua franca of the platform:

- **Environment** — A security environment containing platforms
- **Platform** — A specific vendor platform (Splunk, Sentinel, etc.)
- **Detection** — A detection rule with its search query and metadata
- **Dependency** — Something a detection needs (macro, lookup, data model)
- **KnowledgeObject** — A defined object in the environment (the "supply" side)
- **Finding** — An analysis result (missing dependency, optimization opportunity)
- **ReadinessScore** — Per-detection readiness classification and score
- **ScanReport** — Complete scan output with all data and statistics

### 2. Adapters (`odcp/adapters/`)

Adapters translate vendor-specific artifacts into the unified model.

```python
class BaseAdapter(ABC):
    def parse_environment(self, path: Path) -> Environment: ...
    def parse_detections(self, path: Path) -> list[Detection]: ...
    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]: ...
    def resolve_dependencies(self, detections, knowledge_objects) -> list[Dependency]: ...
```

The Splunk adapter parses `.conf` files and extracts SPL references. Future adapters would parse Sigma YAML, Sentinel KQL, Elastic JSON, etc.

### 3. Core Engine (`odcp/core/`)

- **DependencyGraph** — NetworkX directed graph linking detections to dependencies. Supports queries like "what depends on this macro?" and "which dependencies are orphaned?"
- **ScanEngine** — Orchestrates the full pipeline: parse → resolve → graph → analyze → report.

### 4. Analyzers (`odcp/analyzers/`)

Analyzers consume the unified model and produce findings:

- **ReadinessAnalyzer** — Classifies each detection as runnable/blocked/partial/unknown based on dependency resolution status.
- **DependencyAnalyzer** — Identifies structural issues (orphaned objects, high fan-out dependencies).
- **(Future) RuntimeHealthAnalyzer** — Would check live API status.
- **(Future) SemanticGapAnalyzer** — Would identify missing data source coverage.
- **(Future) OptimizationAnalyzer** — Would prioritize remediation actions.

### 5. Collectors (`odcp/collectors/`)

Collectors gather raw data before adapter processing:

- **LocalCollector** — Reads from a local filesystem path.
- **(Future) APICollector** — Would pull from Splunk REST API, cloud APIs, etc.
- **(Future) RemoteCollector** — Would pull from S3, GCS, or remote hosts.

### 6. Reporting (`odcp/reporting/`)

Generates output in multiple formats from a ScanReport:

- JSON (machine-readable, round-trips perfectly)
- Markdown (human-readable, great for PRs and wikis)
- HTML (self-contained, shareable dashboards)

### 7. CLI (`odcp/cli/`)

Typer-based CLI with Rich output:

- `odcp scan splunk <path>` — Run a full scan
- `odcp report <json>` — Convert report formats
- `odcp graph <json>` — Dependency graph statistics

## Data Flow

```
Filesystem/API
      |
  Collector
      |
   Adapter
      |
 Unified Models
      |
 Dependency Graph
      |
  Analyzers
      |
  ScanReport
      |
  +---+---+
  |   |   |
JSON  MD HTML
```

## Adding a New Adapter

1. Create `odcp/adapters/your_vendor/`
2. Implement `BaseAdapter` — parse your vendor's format into the unified model
3. Register it in the CLI
4. All analyzers, graph, and reporting work automatically

This is the key architectural benefit: new vendors get the full analysis pipeline for free.
