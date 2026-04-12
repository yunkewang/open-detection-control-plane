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
           ┌──────────────────────────────────────┐
           │            AI Consumers              │
           │  Claude · GPT · SOAR · CI/CD · APIs  │
           └──────────────────┬───────────────────┘
                              │
                    tool calls / JSON / SSE
                              │
           ┌──────────────────▼───────────────────┐
           │        ODCP Central Server           │
           │                                      │
           │  · Web Dashboard  (7 pages)          │
           │  · Fleet Registry & API              │
           │  · AI Agent layer  (15 LLM tools)    │
           │  · REST API · Server-Sent Events     │
           └──────────────────┬───────────────────┘
                   ┌──────────┴──────────┐
                   │                     │
        ┌──────────▼──────┐   ┌──────────▼──────────────┐
        │ Collector Agents│   │   Local CLI / Library   │
        │                 │   │                         │
        │ scan → push     │   │ odcp scan · report      │
        │ heartbeat       │   │ odcp ci · validate      │
        │ 5 platforms     │   │ odcp serve · agent      │
        └─────────────────┘   └─────────────────────────┘
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
- **Lifecycle** — detection state pipeline funnel, promote/rollback controls, per-detection history
- **Threat Intel** — campaign gap analysis, IOC management, coverage KPIs
- Server-Sent Events push: browser reloads automatically when the report file changes on disk

### 6. Distributed Collection Agents

Deploy lightweight collector agents on any host with access to a security platform:

- Agents register with the central server, scan locally, push results, and send heartbeats
- `PushClient` uses only Python's built-in `urllib` (zero extra runtime dependencies)
- Thread-safe `AgentRegistry` with asyncio staleness checker marks agents offline automatically
- Fleet REST API for registration, report ingestion, heartbeats, and deregistration
- State persistence (save/load) for server restarts

### 7. Authentication, RBAC, and Audit Logging

Opt-in security layer for production deployments:

- Token-based authentication with SHA-256 hashed storage (tokens never stored in plaintext)
- Four roles: `admin`, `analyst`, `readonly`, `agent` — each with scoped permissions
- `AuditLogger` with a 10k-event ring buffer and optional JSONL file append
- `odcp serve --auth` bootstraps an admin token on startup; `odcp auth` subcommands manage tokens
- Fully opt-in: auth disabled by default so development and CI flows work without configuration

### 8. Detection Lifecycle Management

State-machine-driven promotion workflow from authoring to production:

- States: `draft → review → testing → production → deprecated` with controlled transitions and rollback
- `LifecycleManager` provides thread-safe state storage with optional JSON persistence (`--lifecycle-db`)
- Web dashboard page showing pipeline funnel, state-filtered table, and per-detection history
- `odcp detection` CLI: `list`, `status`, `promote`, `rollback`, `transition`, `summary`

### 9. Threat Intelligence Integration

Map active threat campaigns to detection coverage gaps:

- `IntelManager` stores campaigns, threat actors, IOC entries, and intel feeds with JSON persistence
- `analyze_coverage()` weights MITRE technique gaps by active campaign activity
- `/intel` dashboard: pipeline KPIs, gap analysis, campaigns, IOC management
- `odcp intel` CLI: `campaigns`, `add-campaign`, `add-ioc`, `gap-analysis`

### 10. AI Rule Generator

Claude-powered detection rule authoring:

- `RuleGenerator` calls the Claude API to generate Sigma, Splunk SPL, or KQL rules for a given MITRE technique and environment context
- `RuleQualityScore` evaluates specificity, false-positive risk, MITRE alignment, and data-source fit — works without an LLM via pure heuristics
- `POST /api/agent/generate-detection` REST endpoint; `odcp agent generate-detection` CLI

### 11. SLA Tracking and Compliance Reporting

Enterprise observability over the detection program:

- `SlaTracker` evaluates how long detections have spent in each lifecycle state against configurable `SlaPolicy` thresholds
- `ComplianceReportBuilder` generates SOC 2 and NIST CSF evidence packages (Markdown or JSON)
- `GET /api/sla/status`, `GET /api/compliance/report` REST endpoints
- `odcp sla status`, `odcp compliance report` CLI commands

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

### Authentication and access control

```bash
# Enable auth (prints bootstrap admin token on startup)
odcp serve report.json --auth --audit-log audit.jsonl

# Create tokens for team members
odcp auth create-token --name "alice" --role analyst --url http://odcp-server:8080 --token ADMIN_TOKEN
odcp auth list-tokens  --url http://odcp-server:8080 --token ADMIN_TOKEN
odcp auth revoke-token TOKEN_ID --url http://odcp-server:8080 --token ADMIN_TOKEN

# Inspect the audit trail
odcp auth audit --url http://odcp-server:8080 --token ADMIN_TOKEN
```

### Detection lifecycle management

```bash
# Promote a detection through the review pipeline
odcp detection list    --url http://odcp-server:8080
odcp detection status  det-001 --url http://odcp-server:8080
odcp detection promote det-001 --url http://odcp-server:8080
odcp detection rollback det-001 --url http://odcp-server:8080
odcp detection summary --url http://odcp-server:8080

# Persist lifecycle state across server restarts
odcp serve report.json --lifecycle-db lifecycle.json
```

### Threat intelligence

```bash
# Load active threat campaigns and check detection coverage
odcp intel add-campaign --name "APT29 Phishing" --techniques T1566,T1078 --active
odcp intel gap-analysis --url http://odcp-server:8080
odcp intel add-ioc --type ip --value 1.2.3.4 --campaign "APT29 Phishing"
odcp intel campaigns --url http://odcp-server:8080
```

### AI rule generator

```bash
# Generate a detection rule for a MITRE technique
odcp agent generate-detection T1059.001 --platform sigma --report report.json
odcp agent generate-detection T1078     --platform splunk --output new_rule.conf
```

### SLA tracking and compliance

```bash
# Check how long detections have been in each lifecycle state
odcp sla status --url http://odcp-server:8080 --draft 30 --review 14

# Generate a compliance evidence package
odcp compliance report soc2    --period 2025-Q1 --format markdown --output soc2.md
odcp compliance report nist_csf --period 2025-Q1 --format json    --output nist.json
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
├── models/auth.py        # UserRole, TokenRecord, AuditEvent (Phase 12)
├── server/auth.py        # TokenStore, get_current_token, require_role() (Phase 12)
├── server/audit.py       # AuditLogger — ring buffer + JSONL append (Phase 12)
│
├── models/lifecycle.py   # DetectionState, LifecycleEvent, VALID_TRANSITIONS (Phase 13)
├── lifecycle/
│   └── manager.py             LifecycleManager — promote/rollback + JSON persistence
│
├── models/intel.py       # ThreatCampaign, IocEntry, IntelGapReport (Phase 14)
├── intel/
│   └── manager.py             IntelManager — coverage analysis + JSON persistence
│
├── agent/rule_generator.py    RuleGenerator + RuleQualityScore (Phase 15)
│
├── sla/
│   └── tracker.py             SlaPolicy + SlaTracker (Phase 16)
├── compliance/
│   └── report_builder.py      ComplianceReportBuilder — SOC 2 / NIST CSF (Phase 16)
│
├── core/                 # Dependency graph engine, scoring
├── collectors/           # Local data collectors (filesystem, Splunk API)
├── reporting/            # JSON, Markdown, HTML report generation
└── cli/                  # Typer CLI (odcp scan · serve · agent · collector · ai-soc · ci
                          #            auth · detection · intel · sla · compliance · …)
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
| 12 | Multi-tenant API, authentication, and role-based access control | **Complete** |
| 13 | Detection lifecycle management (state machine, promote/rollback) | **Complete** |
| 14 | Threat intelligence integration and gap analysis | **Complete** |
| 15 | AI rule generator (Claude-powered Sigma/Splunk/KQL generation) | **Complete** |
| 16 | Enterprise observability — SLA tracking and compliance reporting | **Complete** |

See [docs/mvp-roadmap.md](docs/mvp-roadmap.md) for full phase details and [docs/architecture.md](docs/architecture.md) for architecture details.

---

## Running Tests

```bash
pytest tests/ -v
```

822 tests covering unit and integration scenarios across all 16 phases.

---

## License

Apache 2.0
