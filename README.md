# Open Detection Control Plane (ODCP)

**The control plane for AI-driven Security Operations.**

ODCP is the structured intelligence layer that makes AI SOC possible. It gives AI agents, automation pipelines, and detection engineering teams a unified, vendor-neutral view of what detections exist, whether they work, what data feeds them, and what needs to change — continuously.

---

## The Problem AI SOC Solves (and What Blocks It)

AI-driven security operations promise autonomous triage, continuous tuning, and proactive threat hunting. But every AI SOC hits the same wall: **the detections it depends on are opaque, fragile, and siloed.**

Detection rules live across Splunk, Elastic, Sentinel, Sigma repositories, and Google Chronicle — each with its own dependency model, data source requirements, and health signals. Without a control plane that understands all of them, AI agents are flying blind:

- They can't know which detections are actually firing vs. broken
- They can't tell which data sources disappeared last night
- They can't identify noisy rules generating alert fatigue
- They can't safely migrate or retire detections across platforms
- They have no structured signal to act on — only raw logs and dashboards

ODCP solves this by providing the **structured, machine-readable foundation** an AI SOC requires.

---

## How ODCP Powers AI SOC

ODCP implements a continuous automation loop across five integrated stages:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI SOC Automation Loop                       │
│                                                                     │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐     │
│   │  SCAN    │───▶│INVENTORY │───▶│  DRIFT   │───▶│ FEEDBACK │     │
│   │          │    │          │    │          │    │          │     │
│   │ Parse &  │    │ Build    │    │ Detect   │    │ Analyze  │     │
│   │ analyze  │    │ unified  │    │ data     │    │ noisy,   │     │
│   │ detection│    │ source   │    │ source   │    │ stale &  │     │
│   │ content  │    │ catalog  │    │ changes  │    │ degraded │     │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘     │
│        ▲                                               │            │
│        │              ┌──────────┐                    │            │
│        └──────────────│  CYCLE   │◀───────────────────┘            │
│                       │          │                                  │
│                       │Orchestrat│                                  │
│                       │ priority │                                  │
│                       │ actions  │                                  │
│                       └──────────┘                                  │
└─────────────────────────────────────────────────────────────────────┘
```

At each stage, ODCP produces structured JSON that AI agents, SOAR platforms, and CI/CD pipelines can consume directly — no screen scraping, no brittle parsers, no vendor lock-in.

---

## Core Capabilities

### 1. Multi-Platform Detection Intelligence

ODCP understands detection content natively across five platforms through vendor-specific adapters that share a unified model:

| Platform | Input Format | Capabilities |
|----------|-------------|--------------|
| **Splunk** | `.conf` files + REST API | SPL dependency extraction, runtime health, Cloud readiness |
| **Sigma** | YAML rules | Correlations, filters, logsource dependencies, MITRE mapping |
| **Elastic** | JSON detection rules | Index pattern deps, threat block MITRE mapping |
| **Microsoft Sentinel** | YAML/JSON analytics | KQL table extraction, data connector mapping |
| **Google Chronicle** | YARA-L 2.0 | UDM entity/field extraction, reference list deps |

Every adapter outputs the same unified schema: `Environment → Detections → Dependencies → Findings → ReadinessScore`. AI agents work with one model regardless of which platforms are deployed.

### 2. Detection Readiness Analysis

Before AI can act on detections, it needs to know which ones actually work. ODCP builds a dependency graph for every detection rule and classifies it:

- **Runnable** — all dependencies present and healthy
- **Partially runnable** — degraded (missing lookup, unaccelerated data model)
- **Blocked** — critical dependency missing, detection cannot fire
- **Unknown** — insufficient data to assess

Combined with live runtime signals from Splunk REST APIs (scheduling health, execution failures, data model acceleration, index flow), ODCP produces a `CombinedReadinessScore` that reflects both static configuration and runtime reality.

### 3. Source Catalog and Drift Detection

An AI SOC needs to know what data it has access to — and when that changes. ODCP builds a **unified source catalog** from every scanned platform:

- Inventories all data sources (indexes, sourcetypes, log sources, UDM fields, Sentinel tables)
- Maps sources to MITRE ATT&CK data source categories
- Infers per-source health status
- Detects drift between snapshots: new sources, removed sources, health degradations, field changes

When a critical data source disappears overnight, ODCP surfaces it as a `DriftEvent` with severity classification and downstream detection impact — before any AI agent wastes cycles on detections that can never fire.

### 4. Detection Feedback and Tuning

Closed-loop AI SOC requires feedback on detection outcomes. ODCP's feedback analyzer processes runtime health signals and readiness data to identify:

- **Noisy detections** — high alert volume, candidates for threshold adjustment
- **Stale detections** — blocked or inactive, candidates for retirement
- **Degraded detections** — declining health scores over time

For each, it generates a `TuningProposal` with a specific action (`disable`, `adjust_threshold`, `update_query`, `escalate_severity`) and estimated effort — structured output an AI agent or SOAR playbook can execute directly.

### 5. AI SOC Cycle Orchestration

The `odcp ai-soc cycle` command chains the full loop into a single automation pass:

```
source catalog build → data-aware feasibility → drift detection
      → feedback analysis → priority action generation
```

The output is an `AiSocCycleResult` — a machine-readable action plan with unified metrics across all components. Run it on a schedule, trigger it from a SOAR webhook, or wire it into a CI/CD pipeline.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AI SOC Consumers                              │
│              AI Agents · SOAR Platforms · CI/CD Pipelines               │
└───────────────────────────────┬─────────────────────────────────────────┘
                                │  JSON / CLI exit codes
┌───────────────────────────────▼─────────────────────────────────────────┐
│                        ODCP Control Plane                               │
│                                                                         │
│  CLI: scan · report · graph · cross-platform · migrate · ci · validate  │
│       ai-soc inventory · ai-soc drift · ai-soc feedback · ai-soc cycle  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                         Analyzers                                │   │
│  │  Readiness · Dependency · Runtime Health · Coverage · MITRE      │   │
│  │  Optimization · OCSF Mapper · Cross-Platform · Migration         │   │
│  │  CI/CD Gate · DaC Validator · AI SOC Orchestrator                │   │
│  │  Source Inventory · Drift Detector · Feedback · Data Gate        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Vendor Adapters                               │   │
│  │  Splunk (static + REST API) · Sigma (+ correlations/filters)     │   │
│  │  Elastic · Microsoft Sentinel · Google Chronicle (YARA-L)        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    Unified Data Models                           │   │
│  │  Environment · Detection · Dependency · Finding · ReadinessScore │   │
│  │  RuntimeSignal · SourceCatalog · DriftEvent · TuningProposal     │   │
│  │  OcsfMapping · MigrationSummary · AiSocCycleResult               │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  Output: JSON · Markdown · HTML                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Install

```bash
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

### Run a full AI SOC automation cycle

```bash
# 1. Scan your detection content (any platform)
odcp scan splunk /path/to/splunk_app --output report.json
odcp scan sigma /path/to/sigma_rules --output report.json
odcp scan elastic /path/to/elastic_rules --output report.json
odcp scan sentinel /path/to/sentinel_rules --output report.json
odcp scan chronicle /path/to/chronicle_rules --output report.json

# 2. Run the full AI SOC cycle
odcp ai-soc cycle report.json

# 3. Compare against a previous baseline to detect drift and regressions
odcp ai-soc cycle report.json --baseline baseline.json --output cycle.json
```

The cycle output (`AiSocCycleResult`) is structured JSON with:
- Unified source catalog
- Drift events with severity and downstream impact
- Tuning proposals for noisy/stale/degraded detections
- Prioritized action list ready for AI agent or SOAR consumption

### Understand your detection posture

```bash
# Readiness breakdown across all platforms
odcp scan splunk /path/to/app --coverage --output report.json

# Combined static + runtime health (requires live Splunk)
odcp scan splunk /path/to/app \
  --api-url https://splunk:8089 --token YOUR_TOKEN \
  --coverage --indexes main,security

# Cross-platform readiness view
odcp scan sigma rules/ --output sigma.json
odcp scan elastic rules/ --output elastic.json
odcp scan chronicle rules/ --output chronicle.json
odcp cross-platform sigma.json elastic.json chronicle.json
```

### Detect data source drift

```bash
# Build a source catalog snapshot
odcp ai-soc inventory report.json --output catalog.json

# Compare snapshots to detect drift
odcp ai-soc drift baseline.json current.json

# Get structured drift events with risk scores
odcp ai-soc drift baseline.json current.json --output drift.json
```

### Analyze detection feedback for tuning

```bash
# Identify noisy, stale, and degraded detections
odcp ai-soc feedback report.json

# Get machine-readable tuning proposals
odcp ai-soc feedback report.json --output feedback.json
```

### Enforce quality in CI/CD

```bash
# Gate on detection quality policy
odcp ci report.json --min-score 0.5 --max-blocked-ratio 0.3 --max-critical 0

# Detect regressions against a baseline (non-zero exit on failure)
odcp ci current.json --baseline baseline.json --fail-on-regression

# Validate Detection-as-Code metadata and structure
odcp validate sigma_rules/ --platform sigma --require-mitre --require-description

# Validate naming conventions and lifecycle state
odcp validate elastic_rules/ --platform elastic --naming-pattern '^[a-z][a-z0-9_]+$'
```

### Plan detection migrations

```bash
# Analyze feasibility of migrating between platforms
odcp migrate splunk.json --target sentinel
odcp migrate sigma.json --target chronicle --output migration.json
```

### Example scan output

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

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Splunk static readiness analysis | **Complete** |
| 2 | Splunk runtime signals and health | **Complete** |
| 3 | MITRE ATT&CK coverage and optimization | **Complete** |
| 4 | Multi-vendor adapters (Sigma, Elastic, Sentinel) | **Complete** |
| 5 | Sigma correlations/filters, STIX refresh, OCSF, Splunk Cloud CI | **Complete** |
| 6 | Chronicle YARA-L adapter, cross-platform view, migration analysis | **Complete** |
| 7 | CI/CD integration and Detection-as-Code | **Complete** |
| 8 | AI SOC automation loop (catalog, drift, feedback, orchestration) | **Complete** |
| 9 | AI agent integration layer (LLM-callable tool interfaces, agentic orchestration) | Planned |
| 10 | Web dashboard and real-time SOC visibility UI | Planned |
| 11 | Distributed collection agents and enterprise-scale deployment | Planned |

### Phase 9 — AI Agent Integration (Next)

The next phase makes ODCP natively consumable by AI agents:

- **LLM tool interfaces** — Expose ODCP capabilities as structured tool calls for Claude, GPT, and open-source agents
- **Agentic orchestration** — Enable AI agents to plan and execute multi-step detection workflows (scan → analyze → tune → validate → commit)
- **Natural language querying** — Ask questions about detection posture in plain English; get answers backed by ODCP's structured data
- **Autonomous tuning loops** — AI agents that read feedback proposals, draft rule edits, validate them, and open pull requests

See [docs/mvp-roadmap.md](docs/mvp-roadmap.md) for full roadmap details and [docs/architecture.md](docs/architecture.md) for architecture details.

---

## Project Structure

```
odcp/
├── models/          # Pydantic v2 unified data models
│   ├── detection.py        # Environment, Detection, Dependency, Finding, ReadinessScore
│   ├── runtime.py          # RuntimeSignal, RuntimeHealthScore, CombinedReadinessScore
│   ├── coverage.py         # MITRE ATT&CK coverage models
│   ├── correlation.py      # Sigma correlation meta-rules
│   ├── ocsf.py             # OCSF normalization models
│   ├── cross_platform.py   # CrossPlatformSummary, MigrationSummary
│   └── source_catalog.py   # SourceCatalog, DriftEvent, TuningProposal, AiSocCycleResult
├── adapters/        # Vendor adapters (Splunk, Sigma, Elastic, Sentinel, Chronicle)
├── analyzers/       # Analysis engines
│   ├── readiness.py        # Readiness classification
│   ├── dependency.py       # Dependency graph analysis
│   ├── runtime/            # Runtime health scoring
│   ├── coverage/           # MITRE coverage + STIX refresh
│   ├── ocsf_mapper.py      # OCSF normalization
│   ├── cross_platform.py   # Cross-platform readiness
│   ├── migration.py        # Migration feasibility
│   ├── ci.py               # CI/CD gate analyzer
│   ├── dac.py              # Detection-as-Code validator
│   └── ai_soc/             # AI SOC automation loop
│       ├── source_inventory.py  # Unified source catalog
│       ├── drift_detector.py    # Environment drift detection
│       ├── feedback.py          # Detection feedback and tuning
│       ├── data_gate.py         # Data-aware migration gate
│       └── orchestrator.py      # AI SOC cycle orchestrator
├── collectors/      # Data collection (local filesystem, Splunk REST API)
├── core/            # Dependency graph engine, scoring
├── reporting/       # JSON, Markdown, HTML report generation
└── cli/             # Typer CLI interface
```

---

## Running Tests

```bash
pytest tests/ -v
```

452+ tests covering unit and integration scenarios across all components.

---

## License

Apache 2.0
