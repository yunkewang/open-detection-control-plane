# Open Detection Control Plane (ODCP)

**The control plane for AI-driven Security Operations.**

ODCP is the structured intelligence layer that makes AI SOC possible. It gives AI agents, automation pipelines, and detection engineering teams a unified, vendor-neutral view of what detections exist, whether they work, what data feeds them, and what needs to change — continuously, across every platform in the enterprise.

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

ODCP implements a continuous automation loop — from local scanning to fleet-wide visibility to AI-driven decision making:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          ODCP AI SOC Architecture                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐     │
│  │                         AI Consumers                                │     │
│  │   Claude · GPT · Open-Source Agents · SOAR · CI/CD · Dashboards    │     │
│  └─────────────────────────────┬───────────────────────────────────────┘     │
│                                │ tool calls / JSON / SSE                     │
│  ┌─────────────────────────────▼───────────────────────────────────────┐     │
│  │                       ODCP Central Server                           │     │
│  │                                                                     │     │
│  │   Web Dashboard (dark-theme)  ·  REST API  ·  AI Agent Chat        │     │
│  │   Fleet Management UI  ·  Server-Sent Events (live refresh)        │     │
│  │                                                                     │     │
│  │   ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐   │     │
│  │   │ AI Agent    │  │ Fleet        │  │ Automation Loop        │   │     │
│  │   │ Tool Layer  │  │ Registry     │  │ scan→inventory→drift   │   │     │
│  │   │ 15 tools    │  │ (all agents) │  │ →feedback→cycle        │   │     │
│  │   └─────────────┘  └──────────────┘  └────────────────────────┘   │     │
│  └────────────────────────────────────────────────────────────────────┘     │
│                                │                                             │
│                   ┌────────────┴────────────┐                               │
│                   │                         │                               │
│  ┌────────────────▼───────┐   ┌─────────────▼──────────────────────────┐   │
│  │ Remote Collector Agents│   │   Local CLI / Library                  │   │
│  │                        │   │                                        │   │
│  │  scan → push           │   │  odcp scan · odcp report · odcp graph  │   │
│  │  heartbeat             │   │  odcp ci · odcp validate · odcp serve  │   │
│  │  Splunk/Sigma/Elastic  │   │  odcp agent · odcp ai-soc cycle        │   │
│  │  Sentinel/Chronicle    │   │                                        │   │
│  └────────────────────────┘   └────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

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

Every adapter outputs the same unified schema: `Environment → Detections → Dependencies → Findings → ReadinessScore`.

### 2. Detection Readiness Analysis

ODCP builds a dependency graph for every detection rule and classifies it:

- **Runnable** — all dependencies present and healthy
- **Partially runnable** — degraded (missing lookup, unaccelerated data model)
- **Blocked** — critical dependency missing, detection cannot fire
- **Unknown** — insufficient data to assess

Combined with live runtime signals from Splunk REST APIs (scheduling health, execution failures, data model acceleration, index flow), ODCP produces a `CombinedReadinessScore` reflecting both static configuration and runtime reality.

### 3. Source Catalog and Drift Detection

ODCP builds a **unified source catalog** from every scanned platform, inventories all data sources, maps them to MITRE ATT&CK data source categories, and detects drift between snapshots. When a critical data source disappears overnight, ODCP surfaces it as a `DriftEvent` with severity classification and downstream detection impact.

### 4. AI Agent Integration Layer

ODCP exposes its full capability surface as **LLM-callable tools** — structured JSON-Schema interfaces compatible with both Anthropic tool-use and OpenAI function-calling formats:

- 15 tools: `load_report`, `get_detection_posture`, `list_detections`, `get_findings`, `get_coverage_gaps`, `get_dependency_issues`, `compare_reports`, `explain_detection`, and more
- `ToolExecutor` dispatches Anthropic/OpenAI tool-call blocks; all errors return `{"error": "..."}` for graceful LLM recovery
- `AgentSession` holds mutable context (loaded report, baseline) across multi-turn conversations
- Agentic orchestrator with Claude tool-use loop (`run_agent` one-shot, `interactive_session` terminal chat)
- Schema export: `get_tool_schemas("anthropic" | "openai")` — pass directly into any LLM API call

### 5. Real-Time Web Dashboard

A browser-based SOC dashboard with no build step required:

- **Dashboard** — readiness score gauge, runnable/blocked/unknown KPI cards, priority actions from AI SOC cycle
- **Detections** — filterable by status and severity, score bars, missing-deps count
- **ATT&CK Coverage** — tactic breakdown, technique coverage grid (green/yellow/grey)
- **Findings** — severity + category filters, expandable remediation steps
- **Data Sources** — health badges, detection count, field count per source
- **AI Agent Chat** — browser-based chat panel backed by ODCP agent API
- **Fleet** — live view of all collector agents with status, readiness, and last-seen
- Server-Sent Events push: browser reloads automatically when the report file changes on disk

### 6. Distributed Collection Agents

Deploy lightweight collector agents on any host with access to a security platform:

- Agents register with the central server, scan locally, push results, and send heartbeats
- `PushClient` uses only Python's built-in `urllib` (zero extra runtime dependencies)
- Thread-safe `AgentRegistry` with asyncio staleness checker marks agents offline automatically
- Fleet REST API for registration, report ingestion, heartbeats, and deregistration
- State persistence (save/load) for server restarts

---

## Quick Start

### Install

```bash
pip install -e .                      # core CLI
pip install -e ".[dev]"               # + tests
pip install -e ".[server]"            # + web dashboard (fastapi, uvicorn)
pip install -e ".[agent]"             # + AI agent (anthropic SDK)
pip install -e ".[server,agent,dev]"  # everything
```

### Scan detection content

```bash
# Any platform
odcp scan splunk  /path/to/splunk_app   --output report.json
odcp scan sigma   /path/to/sigma_rules  --output report.json
odcp scan elastic /path/to/rules        --output report.json
odcp scan sentinel /path/to/analytics  --output report.json
odcp scan chronicle /path/to/rules     --output report.json

# With MITRE ATT&CK coverage analysis
odcp scan splunk /path/to/app --coverage --output report.json

# With live runtime health (Splunk)
odcp scan splunk /path/to/app \
  --api-url https://splunk:8089 --token YOUR_TOKEN \
  --coverage --indexes main,security
```

### Run the AI SOC automation cycle

```bash
# Full cycle: catalog → drift → feedback → actions
odcp ai-soc cycle report.json

# Compare with baseline to detect regressions and drift
odcp ai-soc cycle report.json --baseline baseline.json --output cycle.json

# Individual steps
odcp ai-soc inventory report.json
odcp ai-soc drift   baseline.json current.json
odcp ai-soc feedback report.json
```

### Start the web dashboard

```bash
# Requires: pip install -e ".[server]"
odcp serve report.json --port 8080

# Custom host, open browser automatically
odcp serve report.json --host 0.0.0.0 --port 9000 --open
```

### AI agent — ask questions in natural language

```bash
# Requires: pip install -e ".[agent]"

# One-shot query
odcp agent run "Which detections are blocked and why?" --report report.json

# Interactive chat
odcp agent chat --report report.json

# Export tool schemas for integration with any LLM
odcp agent schema --fmt anthropic > tools.json
odcp agent schema --fmt openai    > tools.json
```

### Deploy collector agents

```bash
# On any remote host
odcp collector start \
  --platform splunk \
  --scan-path /opt/splunk/etc/apps/security \
  --central-url http://odcp-server:8080 \
  --environment "Production SIEM" \
  --interval 300

# Or from a YAML config file
odcp collector start --config agent.yaml

# Monitor the fleet
odcp collector status --central-url http://odcp-server:8080
odcp collector list   --central-url http://odcp-server:8080
```

### Enforce quality in CI/CD

```bash
# Gate on readiness policy
odcp ci report.json --min-score 0.5 --max-blocked-ratio 0.3 --max-critical 0

# Detect regressions against baseline (non-zero exit on failure)
odcp ci current.json --baseline baseline.json --fail-on-regression

# Validate Detection-as-Code structure and metadata
odcp validate sigma_rules/   --platform sigma   --require-mitre
odcp validate elastic_rules/ --platform elastic --naming-pattern '^[a-z][a-z0-9_]+$'
```

### Cross-platform and migration analysis

```bash
# Unified readiness view across all platforms
odcp cross-platform splunk.json sigma.json elastic.json

# Migration feasibility analysis
odcp migrate splunk.json --target sentinel
odcp migrate sigma.json  --target chronicle --output migration.json
```

### Python API

```python
# Direct tool use — no LLM needed
from odcp.agent import AgentSession, ToolExecutor, get_tool_schemas

session = AgentSession()
executor = ToolExecutor(session)
executor.execute("load_report", {"path": "report.json"})
posture = executor.execute("get_detection_posture", {})

# Export schemas for any LLM
anthropic_tools = get_tool_schemas("anthropic")   # → client.messages.create(tools=...)
openai_tools    = get_tool_schemas("openai")       # → openai.chat.completions.create(tools=...)

# Agentic one-shot (requires pip install odcp[agent])
from odcp.agent.orchestrator import run_agent
answer = run_agent("Which detections are blocked?", report_path="report.json")

# Web server with fleet registry
from odcp.server.app import create_app
from odcp.collector.registry import AgentRegistry

registry = AgentRegistry()
app = create_app(registry=registry)  # mount with uvicorn
```

---

## Architecture

```
odcp/
├── models/               # Pydantic v2 unified data models
│   ├── detection.py           Environment, Detection, Dependency, Finding, ReadinessScore
│   ├── runtime.py             RuntimeSignal, RuntimeHealthScore, CombinedReadinessScore
│   ├── coverage.py            MITRE ATT&CK coverage, optimization, what-if
│   ├── correlation.py         Sigma correlation meta-rules and filters
│   ├── ocsf.py                OCSF normalization models
│   ├── cross_platform.py      CrossPlatformSummary, MigrationSummary, MigrationBlocker
│   ├── source_catalog.py      SourceCatalog, DriftEvent, TuningProposal, AiSocCycleResult
│   └── collector.py           AgentConfig, AgentInfo, AgentStatus, FleetSummary
│
├── adapters/             # Vendor adapters
│   ├── splunk/                .conf parser + REST API client
│   ├── sigma/                 YAML rule parser + correlations + filters
│   ├── elastic/               JSON detection rule parser
│   ├── sentinel/              KQL analytics parser
│   └── chronicle/             YARA-L 2.0 parser
│
├── analyzers/            # Analysis engines
│   ├── readiness.py           Runnable / blocked / partial / unknown classification
│   ├── dependency.py          Dependency graph analysis
│   ├── runtime/               Runtime health scoring with Splunk API data
│   ├── coverage/              MITRE coverage, STIX refresh, optimization, what-if
│   ├── ocsf_mapper.py         OCSF event class normalization
│   ├── cross_platform.py      Cross-platform readiness view
│   ├── migration.py           Migration feasibility analysis
│   ├── ci.py                  CI/CD gate with regression detection
│   ├── dac.py                 Detection-as-Code validator
│   ├── splunk_cloud.py        Splunk Cloud AppInspect-aligned checks
│   └── ai_soc/
│       ├── source_inventory.py    Unified source catalog builder
│       ├── drift_detector.py      Environment drift detection
│       ├── feedback.py            Detection tuning proposal generator
│       ├── data_gate.py           Data-aware migration gate
│       └── orchestrator.py        AI SOC cycle orchestrator
│
├── agent/                # AI agent integration layer (Phase 9)
│   ├── session.py             AgentSession — report + baseline state
│   ├── tools.py               15 LLM-callable tools (Anthropic + OpenAI schema)
│   ├── executor.py            ToolExecutor — dispatches tool-call blocks
│   └── orchestrator.py        run_agent(), interactive_session() — Claude tool-use loop
│
├── server/               # Web dashboard and REST API (Phase 10)
│   ├── app.py                 FastAPI app factory with lifespan
│   ├── state.py               ReportStore — in-memory report + SSE + file watcher
│   ├── routes.py              UI pages + JSON API + SSE endpoint
│   ├── fleet_routes.py        Fleet management REST API + /fleet UI page
│   └── templates/
│       ├── base.html               Dark layout, sidebar nav, SSE reconnect loop
│       ├── dashboard.html          KPI cards, status bars, priority actions
│       ├── detections.html         Filterable detection table
│       ├── coverage.html           MITRE tactic breakdown + technique grid
│       ├── findings.html           Severity/category-filtered findings
│       ├── sources.html            Data source health table
│       ├── agent.html              AI agent chat + quick-query panel
│       └── fleet.html              Collector fleet status + agent table
│
├── collector/            # Distributed collection agents (Phase 11)
│   ├── agent.py               CollectionAgent — blocking scan loop
│   ├── push_client.py         PushClient — urllib HTTP client (zero extra deps)
│   └── registry.py            AgentRegistry — thread-safe store + staleness checker
│
├── core/                 # Dependency graph engine, scoring
├── collectors/           # Local data collectors (filesystem, Splunk API)
├── reporting/            # JSON, Markdown, HTML report generation
└── cli/                  # Typer CLI (odcp scan · serve · agent · collector · ai-soc · ci · …)
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
| 9 | AI agent integration (LLM-callable tools, agentic orchestration) | **Complete** |
| 10 | Web dashboard and real-time SOC visibility UI | **Complete** |
| 11 | Distributed collection agents and fleet management | **Complete** |
| 12 | Multi-tenant API, authentication, and role-based access control | **Planned** |
| 13 | Detection lifecycle management with Git-native workflows | **Planned** |
| 14 | Threat intelligence integration and gap analysis | **Planned** |
| 15 | Autonomous detection engineering (AI-generated rules, auto-PR) | **Planned** |
| 16 | Enterprise observability, alerting, and compliance reporting | **Planned** |

See [docs/mvp-roadmap.md](docs/mvp-roadmap.md) for full phase details and [docs/architecture.md](docs/architecture.md) for architecture details.

---

## Running Tests

```bash
pytest tests/ -v
```

646 tests covering unit and integration scenarios across all 11 phases.

---

## License

Apache 2.0
