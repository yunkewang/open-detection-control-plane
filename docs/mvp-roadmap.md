# ODCP Roadmap

## Phase 1: Splunk Static Readiness (MVP) — Complete

**Goal:** Analyze Splunk app bundles on disk and produce detection readiness reports.

### Delivered

- Pydantic v2 unified data models
- Splunk .conf parser (savedsearches, macros, eventtypes, transforms)
- SPL dependency extraction (macros, lookups, eventtypes, data models, saved searches)
- Dependency graph (NetworkX)
- Readiness analyzer (runnable / blocked / partial / unknown classification)
- Dependency analyzer (orphaned objects, high-impact dependencies)
- Findings with remediation suggestions
- CLI with Rich output (`scan`, `report`, `graph`, `version`)
- JSON, Markdown, and HTML report generation
- Unit and integration tests
- Example Splunk app bundle

### Known Limitations (v0.1)

- Only parses local config files (no API/runtime data)
- Does not handle all Splunk edge cases (e.g., app inheritance chains, btool resolution)
- Data model field-level analysis not yet implemented

---

## Phase 2: Splunk Runtime Signals and Health — Complete

**Goal:** Extend analysis with live runtime data from Splunk APIs.

### Delivered

- Splunk REST API client (`odcp/adapters/splunk/api_client.py`) with token and basic auth
- API collector (`odcp/collectors/api.py`) for gathering runtime signals
- Saved search execution status (scheduling, dispatch history, failure detection)
- KV store and lookup table health checks (existence, type detection)
- Data model acceleration status (enabled, completion percentage)
- Index/sourcetype data flow health (event counts, receiving status)
- Runtime health models (`odcp/models/runtime.py`): signals, scores, summaries
- RuntimeHealthAnalyzer (`odcp/analyzers/runtime/`) with per-detection scoring
- Combined static + runtime readiness scoring with configurable weights
- New finding categories: `runtime_health`, `stale_execution`, `data_flow_issue`, `acceleration_issue`
- CLI integration: `odcp scan splunk --api-url --token` for combined scans
- Graceful degradation when API is unavailable or individual checks fail
- Unit and integration tests for all runtime components (97 tests total)

---

## Phase 3: Semantic Gap and Optimization — Complete

**Goal:** Identify coverage gaps and prioritize remediation.

### Delivered

- MITRE ATT&CK technique catalog (25+ curated techniques across all tactics)
- Heuristic detection-to-technique mapping (keyword + SPL pattern matching + tag support)
- Coverage gap analysis: covered / partial / uncovered classification per technique
- Per-tactic coverage breakdown
- Data source inventory: index, sourcetype, and data model extraction from SPL
- Data source gap detection (expected vs. observed)
- Optimization analyzer with ranked remediation recommendations
- Impact scoring: effort-adjusted priority ranking by unblock potential
- "What-if" analysis: simulates fixing each dependency and computes new readiness score
- Max achievable readiness score computation
- Coverage and optimization findings with remediation steps
- CLI `--coverage` flag for `odcp scan splunk`
- Rich CLI output: MITRE coverage panel, tactic breakdown, data source gaps, what-if table
- Unit and integration tests for all Phase 3 components (156 tests total)

---

## Phase 4: Additional Vendor Adapters — Complete

**Goal:** Extend ODCP beyond Splunk to other platforms.

### Delivered

- **Sigma adapter** (`odcp/adapters/sigma/`) — Parses YAML detection rules, extracts logsource dependencies (category/product/service), builds pseudo-queries from detection blocks, extracts MITRE ATT&CK tags
- **Elastic adapter** (`odcp/adapters/elastic/`) — Parses JSON detection rules (flat and nested Kibana export formats), extracts index patterns and required fields as dependencies, maps MITRE technique IDs from threat blocks
- **Sentinel adapter** (`odcp/adapters/sentinel/`) — Parses YAML/JSON analytics rules, extracts KQL table references via regex, extracts data connectors from requiredDataConnectors, supports relevantTechniques for MITRE mapping
- CLI commands: `odcp scan sigma`, `odcp scan elastic`, `odcp scan sentinel`
- Example rule sets for all three platforms (`examples/sigma_rules/`, `examples/elastic_rules/`, `examples/sentinel_rules/`)
- Unit and integration tests for all adapters (209 tests total)

### Adapter Status

| Adapter | Input Format | Status |
|---------|-------------|--------|
| Splunk | .conf files, REST API | **Phase 1 + 2 + 3 complete** |
| Sigma | YAML rules | **Complete** |
| Sentinel (Microsoft) | KQL analytics, YAML/JSON | **Complete** |
| Elastic | JSON detection rules | **Complete** |
| Chronicle (Google) | YARA-L rules | Planned |
| OCSF | Open Cybersecurity Schema Framework mapping | Planned |

### Cross-Platform Features (Future)

- Unified readiness view across multiple platforms
- Detection migration analysis (can this Splunk detection run in Sentinel?)
- Common dependency taxonomy across vendors
- Platform comparison reports

---

## Future Vision

- Web dashboard UI
- CI/CD integration (validate detections in PRs)
- Detection-as-code workflow support
- Distributed collection agents
- SaaS offering

---

## Phase 5: Post-MVP Enhancements — Complete

**Goal:** Address backlog items for cross-platform normalization, advanced Sigma support, and cloud readiness.

### Delivered

- **Sigma correlation meta-rules** (`odcp/models/correlation.py`, `odcp/adapters/sigma/adapter.py`) — Parses Sigma v2.1.0 correlation rules: event_count, value_count, and temporal types with group-by, timespan, and condition support
- **Sigma filter/meta-filter support** — Parses filter and meta_filter rule types for environment-specific exclusions; filters are accessible via `adapter.filters` and included in report metadata
- **ATT&CK STIX/TAXII catalog refresh** (`odcp/analyzers/coverage/stix_refresh.py`) — Fetches the official MITRE ATT&CK Enterprise STIX bundle, parses attack-pattern objects, and merges with curated catalog; supports local file or network fetch with fallback
- **OCSF-native dependency taxonomy mapping** (`odcp/models/ocsf.py`, `odcp/analyzers/ocsf_mapper.py`) — Maps vendor data sources (Sigma logsources, Splunk sourcetypes, Elastic indexes, Sentinel tables) to OCSF v1.1 event classes; CLI: `odcp scan sigma --ocsf`
- **Splunk Cloud CI integration checks** (`odcp/analyzers/splunk_cloud.py`) — Validates app bundles for cloud readiness: disallowed files, app.conf metadata, app.manifest, restricted SPL commands, Python 3 compatibility; CLI: `odcp scan splunk --cloud-check`
- Example Sigma correlation and filter rules in `examples/sigma_rules/`
- Unit and integration tests for all Phase 5 components (287 tests total)

### CLI Additions

- `odcp scan sigma --ocsf` — OCSF normalization mapping
- `odcp scan splunk --cloud-check` — Splunk Cloud readiness validation
- `odcp scan splunk --stix-file <path>` — Use local ATT&CK STIX bundle for catalog refresh

---

## Post-MVP Backlog

### Completed

- ✅ Lookup backing file verification for Splunk CSV lookups (transforms.conf + lookups/ checks)
- ✅ Tag-based dependency tracking from SPL (`tag=` and `tag::field=`) and `tags.conf`
- ✅ Sigma correlation meta-rule support (Sigma spec v2.1.0)
- ✅ Sigma filter/meta-filter support for environment-specific exclusions
- ✅ ATT&CK catalog auto-refresh from STIX/TAXII feeds
- ✅ OCSF-native dependency taxonomy mapping
- ✅ Splunk Cloud CI integration checks (AppInspect/ACS-aligned)

### Future Items

- ✅ Chronicle (Google) YARA-L adapter
- ✅ Unified cross-platform readiness view
- ✅ Detection migration analysis (e.g., Splunk → Sentinel feasibility)
- ✅ CI/CD integration (validate detections in PRs)
- ✅ Detection-as-code workflow support
- ✅ AI SOC automation loop (source catalog, drift detection, feedback, orchestration)
- Web dashboard UI

---

## Phase 7: CI/CD Integration and Detection-as-Code — Complete

**Goal:** Enable automated validation of detection content in CI/CD pipelines and support Detection-as-Code workflows.

### Delivered

- **CI/CD gate analyzer** (`odcp/analyzers/ci.py`) — Compares baseline vs. current scan reports to detect regressions, score drops, and newly blocked detections; enforces configurable policy thresholds (minimum readiness score, maximum blocked ratio, critical/high findings cap); produces pass/fail/warning verdicts with non-zero exit codes for pipeline gating
- **Detection-as-Code validator** (`odcp/analyzers/dac.py`) — Validates detection rule files for structural correctness, naming conventions (regex patterns), required metadata (description, severity, MITRE ATT&CK tags), lifecycle state enforcement (draft/review/testing/production/deprecated), query sanity checks, and file structure validation; supports all five platforms (Splunk, Sigma, Elastic, Sentinel, Chronicle)
- **GitHub Actions workflow template** (`examples/ci/github-actions-odcp.yml`) — Example CI workflow for PR-based detection validation with two jobs: single-report policy check and baseline regression comparison
- **Pre-commit hook** (`examples/ci/pre-commit-hook.sh`) — Shell script for local validation before commits, auto-detects changed detection directories
- CLI commands: `odcp ci`, `odcp validate`
- Unit and integration tests for all Phase 7 components (391 tests total)

### CLI Additions

- `odcp ci <report> [--baseline <baseline>]` — CI/CD gate check with configurable policy
- `odcp ci <report> --min-score 0.5 --max-blocked-ratio 0.3 --max-critical 0`
- `odcp validate <path> --platform <platform>` — Detection-as-Code validation
- `odcp validate <path> --platform sigma --require-mitre --naming-pattern '^[a-z_]+$'`

---

## Phase 8: AI SOC Automation Loop — Complete

**Goal:** Build a continuous AI SOC automation loop with unified source catalog, environment drift detection, detection feedback analysis, and data-aware migration gating.

### Delivered

- **Unified source catalog** (`odcp/analyzers/ai_soc/source_inventory.py`) — Extracts data sources from all 5 platform adapters (Splunk, Sigma, Elastic, Sentinel, Chronicle) into a vendor-neutral `SourceCatalog`; enriches with ATT&CK data source mapping via heuristic name matching; infers per-source health status; extracts common fields per source category
- **Environment drift detection** (`odcp/analyzers/ai_soc/drift_detector.py`) — Compares source catalog snapshots to detect source additions/removals, health changes, field changes, and detection count changes; classifies drift events by severity (info/warning/critical); computes aggregate risk score and generates actionable recommendations
- **Detection feedback analyzer** (`odcp/analyzers/ai_soc/feedback.py`) — Analyzes detection outcomes from runtime health data and readiness scores; identifies noisy (high alert volume), stale (blocked/inactive), and degraded detections; proposes tuning actions (disable, adjust_threshold, update_query, escalate_severity); generates summary recommendations
- **Data-aware migration gate** (`odcp/analyzers/ai_soc/data_gate.py`) — Enriches migration analysis with `data_availability` blockers by cross-referencing target catalog against mapped features; provides `check_detection_feasibility()` for pre-creation data support verification
- **AI SOC cycle orchestrator** (`odcp/analyzers/ai_soc/orchestrator.py`) — Chains all components into a single automation cycle: source catalog build → data-aware feasibility → drift detection → feedback analysis → priority action generation; produces `AiSocCycleResult` with unified metrics
- **Pydantic v2 data models** (`odcp/models/source_catalog.py`) — `UnifiedSource`, `SourceCatalog`, `SourceField`, `SourceHealth`, `DriftEvent`, `DriftSummary`, `TuningProposal`, `FeedbackSummary`, `AiSocCycleResult`
- CLI commands: `odcp ai-soc inventory`, `odcp ai-soc drift`, `odcp ai-soc feedback`, `odcp ai-soc cycle`
- Unit and integration tests for all Phase 8 components (452 tests total)

### CLI Additions

- `odcp ai-soc inventory <report>` — Build unified source catalog from a scan report
- `odcp ai-soc drift <baseline> <current>` — Detect environment drift between two reports
- `odcp ai-soc feedback <report>` — Analyze detection outcomes and propose tuning actions
- `odcp ai-soc cycle <report> [--baseline <baseline>]` — Run a full AI SOC automation cycle

---

## Phase 9: AI Agent Integration Layer — Complete

**Goal:** Expose all ODCP capabilities as LLM-callable tools with a structured JSON-Schema interface, and provide an agentic orchestration loop powered by Claude that can answer natural-language questions about detection posture without custom scripting.

### Delivered

- **LLM-callable tool registry** (`odcp/agent/tools.py`) — 15 tools covering the full ODCP capability surface: `load_report`, `load_baseline`, `get_detection_posture`, `list_detections`, `get_detection_detail`, `get_findings`, `get_coverage_gaps`, `get_dependency_issues`, `get_runtime_health`, `get_tuning_proposals`, `run_ai_soc_cycle`, `get_optimization_recommendations`, `get_data_sources`, `compare_reports`, `explain_detection`. Each tool has a JSON-Schema `input_schema` compatible with both Anthropic tool-use and OpenAI function-calling formats.
- **Tool executor** (`odcp/agent/executor.py`) — `ToolExecutor` dispatches LLM tool-call requests (Anthropic or OpenAI format) to Python implementations; wraps all errors into JSON-serialisable `{"error": "..."}` dicts so the LLM can recover gracefully.
- **Agent session** (`odcp/agent/session.py`) — `AgentSession` holds mutable context across tool calls: loaded report, optional baseline for drift comparison, and an in-session scratch cache for computed results.
- **Agentic orchestrator** (`odcp/agent/orchestrator.py`) — Multi-turn Claude tool-use loop (`run_agent` for one-shot queries; `interactive_session` for real-time terminal chat). Uses `claude-opus-4-6` by default; LLM-agnostic tool interface allows substitution. Ships with a SOC-analyst system prompt that routes queries to the right tools.
- **Schema export** — `get_tool_schemas(fmt="anthropic"|"openai")` returns all tool schemas as a list suitable for passing directly into an LLM API call.
- **Optional dependency** — `anthropic` SDK gated under `pip install 'odcp[agent]'`; core tools work without it (Python API only).
- CLI commands: `odcp agent tools`, `odcp agent schema`, `odcp agent run`, `odcp agent chat`
- Unit and integration tests for all Phase 9 components (527 tests total)

### Architecture

```
odcp/agent/
├── __init__.py        exports AgentSession, ToolExecutor, TOOL_REGISTRY, get_tool_schemas
├── session.py         AgentSession — report + baseline state
├── tools.py           15 tool definitions (JSON schema + implementation)
├── executor.py        ToolExecutor — dispatches Anthropic/OpenAI tool-call blocks
└── orchestrator.py    run_agent(), interactive_session() — Claude tool-use loop
```

### CLI Additions

- `odcp agent tools` — List all tools with descriptions (table or JSON output)
- `odcp agent schema [--fmt anthropic|openai]` — Export tool schemas for LLM consumption
- `odcp agent run "<prompt>" [--report <path>]` — One-shot agent query
- `odcp agent chat [--report <path>]` — Interactive SOC analyst chat session

### Python API Example

```python
from odcp.agent import AgentSession, ToolExecutor, get_tool_schemas

# Direct tool use (no LLM needed)
session = AgentSession()
executor = ToolExecutor(session)
executor.execute("load_report", {"path": "report.json"})
posture = executor.execute("get_detection_posture", {})

# Export schemas for any LLM
anthropic_tools = get_tool_schemas("anthropic")   # → pass to client.messages.create(tools=...)
openai_tools    = get_tool_schemas("openai")      # → pass to openai.chat.completions.create(tools=...)

# Agentic one-shot (requires pip install odcp[agent])
from odcp.agent.orchestrator import run_agent
answer = run_agent("Which detections are blocked and why?", report_path="report.json")
```

---

## Phase 10: Web Dashboard and Real-Time SOC Visibility UI — Complete

**Goal:** Provide a browser-based SOC dashboard that displays detection posture, MITRE ATT&CK coverage, findings, and data source health in real time — with automatic refresh when the underlying report file changes and an integrated AI agent chat panel.

### Delivered

- **FastAPI web server** (`odcp/server/app.py`) — production-ready FastAPI application with CORS middleware, automatic OpenAPI docs (`/api/docs`), and asyncio lifespan management.
- **Report store with live file watching** (`odcp/server/state.py`) — `ReportStore` holds the current `ScanReport` in memory; a background asyncio task polls the report JSON file's mtime every N seconds and reloads automatically on change, notifying all connected SSE clients.
- **Server-Sent Events (SSE)** (`GET /api/events`) — push-based real-time channel; the browser reloads the active page automatically when the report is refreshed (zero polling from the browser).
- **6 dashboard pages** (Jinja2 templates, dark theme, no build step):
  - `/` — **Dashboard**: KPI cards (readiness score gauge, runnable/blocked/unknown counts, findings by severity, detection status bars), priority actions from AI SOC cycle
  - `/detections` — **Detections table**: filterable by status and severity, score bar, missing-deps count, MITRE tags
  - `/coverage` — **ATT&CK Coverage**: tactic-by-tactic progress bars, technique coverage grid (green/yellow/grey), coverage score
  - `/findings` — **Findings**: severity filter, category filter, expandable remediation steps
  - `/sources` — **Data Sources**: health badges (healthy/degraded/unavailable), detection count, field count
  - `/agent` — **AI Agent Chat**: browser-based chat panel backed by the ODCP agent API; quick-query buttons; tool listing sidebar
- **JSON API** (`/api/*`): `GET /api/posture`, `GET /api/detections`, `GET /api/findings`, `GET /api/coverage`, `GET /api/sources`, `POST /api/report/load`, `POST /api/agent/query`, `GET /api/agent/tools`
- **Optional dependency**: `fastapi`, `uvicorn`, `python-multipart` gated under `pip install 'odcp[server]'`
- CLI command: `odcp serve [report.json] [--port 8080] [--host 0.0.0.0] [--open]`
- Unit and integration tests for all Phase 10 components (559 tests total)

### Architecture

```
odcp/server/
├── __init__.py          exports create_app, ReportStore
├── app.py               FastAPI app factory + lifespan
├── state.py             ReportStore — in-memory report + SSE subscribers + file watcher
├── routes.py            UI page routes + JSON API routes + SSE endpoint
└── templates/
    ├── base.html         dark layout, sidebar nav, SSE JS reconnect loop
    ├── dashboard.html    KPI cards, status bars, priority actions
    ├── detections.html   filterable detection table
    ├── coverage.html     MITRE tactic breakdown + technique grid
    ├── findings.html     severity/category-filtered findings with remediation
    ├── sources.html      data source health table
    └── agent.html        AI agent chat + quick-query panel
```

### CLI

```bash
# Minimal — load report, open on localhost:8080
odcp serve report.json

# Custom host/port and open browser immediately
odcp serve report.json --host 0.0.0.0 --port 9000 --open

# Dev mode with auto-reload
odcp serve report.json --reload --poll-interval 2
```

---

## Phase 11: Distributed Collection Agents and Enterprise-Scale Deployment — Complete

**Goal:** Enable any number of remote ODCP agents to scan their local platform environments and push results back to a central server; provide a Fleet dashboard for unified visibility across the entire agent fleet.

### Delivered

- **Collector agent** (`odcp/collector/agent.py`) — `CollectionAgent` runs a blocking scan loop on any host: registers with the central server on startup, runs an immediate scan, then repeats on a configurable interval; sends heartbeats between scans; dispatches to the correct platform adapter (Splunk, Sigma, Elastic, Sentinel, Chronicle); handles `SIGINT`/`SIGTERM` for clean shutdown; supports both YAML config files and inline `from_args()` construction.
- **HTTP push client** (`odcp/collector/push_client.py`) — `PushClient` sends scan reports, heartbeats, and registration calls to the central server using only Python's built-in `urllib` (zero extra runtime dependencies).
- **Thread-safe agent registry** (`odcp/collector/registry.py`) — `AgentRegistry` stores all registered agents and their latest reports in memory; all mutations hold a `threading.Lock`; a background asyncio task periodically marks agents offline when no heartbeat has been received within `scan_interval × threshold_multiplier` seconds; state can be saved/loaded to disk for persistence across server restarts.
- **Fleet data models** (`odcp/models/collector.py`) — Pydantic v2 models: `AgentConfig`, `AgentRegistration`, `AgentHeartbeat`, `AgentInfo`, `AgentStatus`, `FleetSummary`; `AgentInfo.is_stale()` computes staleness from `last_seen`; `FleetSummary.from_agents()` aggregates counts and average scores.
- **Fleet REST API** (`odcp/server/fleet_routes.py`) — 8 endpoints mounted on the FastAPI server:
  - `GET /api/fleet/health` — health check
  - `POST /api/fleet/agents/register` — register/re-register an agent
  - `POST /api/fleet/agents/{id}/report` — accept a full scan report
  - `POST /api/fleet/agents/{id}/heartbeat` — accept a liveness heartbeat
  - `DELETE /api/fleet/agents/{id}` — deregister on clean shutdown
  - `GET /api/fleet/agents` — list agents (filterable by status, environment, platform)
  - `GET /api/fleet/agents/{id}` — get single agent info
  - `GET /api/fleet/agents/{id}/report` — retrieve latest agent report
  - `GET /api/fleet/summary` — fleet-wide aggregated summary
- **Fleet dashboard page** (`/fleet`) — dark-theme web page with KPI cards (total/active/degraded/offline agents, total detections, average readiness), sortable agent table with status badges, readiness score progress bars, last-seen timestamps, and a Quick Start deployment snippet; auto-refreshes every 30 seconds.
- **Server integration** — `AgentRegistry` attached to `app.state.agent_registry`; staleness checker starts/stops with the FastAPI lifespan; `create_app()` accepts an optional `registry` parameter for testing.
- **CLI commands** (`odcp collector`):
  - `odcp collector start` — launch a blocking collector agent (YAML config or inline args)
  - `odcp collector status` — fetch fleet summary from the central server
  - `odcp collector list` — list all agents with status/platform/readiness table
- Unit and integration tests for all Phase 11 components (646 tests total)

### Architecture

```
odcp/
├── models/
│   └── collector.py          AgentConfig, AgentInfo, AgentStatus, FleetSummary, …
├── collector/
│   ├── __init__.py           exports CollectionAgent, PushClient, AgentRegistry
│   ├── agent.py              CollectionAgent — blocking scan loop with signal handlers
│   ├── push_client.py        PushClient — urllib-based HTTP client (zero extra deps)
│   └── registry.py           AgentRegistry — thread-safe in-memory store + staleness checker
└── server/
    ├── fleet_routes.py        Fleet API routes + /fleet UI page
    └── templates/fleet.html   Fleet dashboard (dark theme, KPI cards, agent table)
```

### CLI

```bash
# Deploy a collector on any remote host
odcp collector start \
  --platform splunk \
  --scan-path /opt/splunk/etc/apps/security \
  --central-url http://odcp-server:8080 \
  --environment "Production SIEM" \
  --interval 300

# Or from a YAML config file
odcp collector start --config agent.yaml

# Check fleet status from anywhere
odcp collector status --central-url http://odcp-server:8080

# List all agents
odcp collector list --central-url http://odcp-server:8080 --status active
```

### Python API Example

```python
from odcp.collector.agent import CollectionAgent
from odcp.collector.registry import AgentRegistry

# Start a collector agent (blocks until stopped)
agent = CollectionAgent.from_args(
    agent_id="my-agent",
    environment_name="Prod SIEM",
    platform="splunk",
    scan_path="/opt/apps/security",
    central_url="http://odcp-server:8080",
)
agent.start()

# Server side — registry is attached to the FastAPI app
from odcp.server.app import create_app
from odcp.collector.registry import AgentRegistry

registry = AgentRegistry()
app = create_app(registry=registry)
```

---

## Phase 12: Multi-Tenant API, Authentication, and Role-Based Access Control — Planned

**Goal:** Harden ODCP for multi-team and SaaS deployments by adding proper authentication, authorization, and tenant isolation so multiple organizations or teams can share a single ODCP server without data leakage.

### Planned Deliverables

- **JWT / API key authentication** — Bearer token auth on all API routes; token issuance and rotation endpoint; `ODCP_API_TOKEN` env var for agents and CLI
- **Role-based access control** — `admin`, `analyst`, `readonly`, `agent` roles; role enforcement on per-resource operations (agents can only push to their own `agent_id`; analysts can read but not delete)
- **Multi-tenancy** — Tenant namespace on all registry and report storage; tenant-scoped API keys; cross-tenant isolation enforced at the store layer
- **Auth middleware** — FastAPI dependency for all protected routes; clear 401/403 responses with `WWW-Authenticate` header
- **User management API** — `POST /api/auth/tokens`, `DELETE /api/auth/tokens/{id}`, `GET /api/auth/me`
- **Audit log** — Append-only log of authentication events, report pushes, config changes; structured JSON with actor, action, resource, timestamp
- **CLI auth support** — `--token` flag and `ODCP_API_TOKEN` env var threading through all CLI commands and collector agent

### Architecture Notes

```
odcp/server/auth.py        JWTAuth, ApiKeyAuth, require_role() FastAPI dependency
odcp/models/auth.py        TokenPayload, AuditEvent, UserRole
odcp/server/audit.py       AuditLogger — append-only structured log writer
```

---

## Phase 13: Detection Lifecycle Management and Git-Native Workflows — Planned

**Goal:** Give detection engineers a first-class lifecycle management system where every rule change is tracked, reviewable, and reversible — with native integration into Git-based collaboration workflows.

### Planned Deliverables

- **Detection lifecycle states** — Formal state machine: `draft → review → testing → production → deprecated`; state transition validation with role guards (only `senior_analyst` can promote to `production`)
- **Version history** — Per-detection change history stored alongside reports; diff computation between any two versions; `odcp detection history <id>` CLI command
- **Git integration** — `odcp detection commit` wraps `git add/commit` for detection files; `odcp detection pr` opens a GitHub/GitLab PR with ODCP scan summary as PR body; pre-receive hook that blocks merges when readiness score drops below policy
- **Detection scaffolding** — `odcp detection new --platform sigma --technique T1055` generates a rule template with correct metadata, lifecycle state, and MITRE tags pre-filled
- **Approval workflows** — Configurable approval chains (e.g., `draft → [review: 1 approver] → testing → [review: 2 approvers] → production`); review request notifications
- **Rollback** — `odcp detection rollback <id> --to <version>` restores a previous version and opens a PR; automatic rollback trigger on CI regression

### CLI Additions

```bash
odcp detection new    --platform sigma --technique T1055 --name "Proc Injection"
odcp detection status <id>           # current lifecycle state + history
odcp detection promote <id>          # advance to next state (role-gated)
odcp detection rollback <id> --to 3  # restore version 3
odcp detection pr                    # open PR with ODCP scan summary
```

---

## Phase 14: Threat Intelligence Integration and Active Gap Analysis — Planned

**Goal:** Connect ODCP's detection coverage model to live threat intelligence feeds so detection engineers can prioritize based on active campaigns rather than static ATT&CK coverage percentages.

### Planned Deliverables

- **STIX/TAXII 2.1 feed ingestion** — Subscribe to MISP, OpenCTI, ISAC feeds; parse attack-pattern, campaign, and indicator objects; map to ODCP detections via MITRE technique IDs
- **Active campaign coverage scoring** — Weight coverage scores by campaign activity: a technique actively used by a tracked threat actor scores higher than a theoretical gap
- **IOC-to-detection gap analysis** — Given a set of IOCs (hashes, IPs, domains), identify which ODCP detections would have fired, which wouldn't, and why; produces an `IocCoverageReport`
- **Threat-prioritized remediation** — Reorder `OptimizationSummary.top_remediations` by current threat relevance; surface "fix this dependency and you'd detect APT29's current campaign"
- **Intel feed management CLI** — `odcp intel add-feed`, `odcp intel sync`, `odcp intel gap-analysis`
- **Integration connectors** — VirusTotal (hash/domain context), MISP (event-based), OpenCTI (GraphQL), AlienVault OTX (pulse feed)

### Data Models

```python
class ThreatCampaign(BaseModel):
    name: str
    actor: str
    techniques: list[str]          # T-IDs
    confidence: float
    last_seen: datetime

class IocCoverageReport(BaseModel):
    ioc: str
    ioc_type: str                  # hash, ip, domain
    relevant_techniques: list[str]
    covered_by: list[str]          # detection IDs
    gaps: list[str]                # technique IDs with no coverage
    risk_score: float
```

---

## Phase 15: Autonomous Detection Engineering — Planned

**Goal:** Close the loop from gap identification to rule creation by letting AI agents draft new detection rules, test them in a staging environment, and open pull requests — all with human approval gates.

### Planned Deliverables

- **AI rule generation** — Given a MITRE technique and available data sources, an AI agent drafts a platform-appropriate detection rule (Sigma preferred for portability); uses Claude with ODCP's source catalog as context to ensure the generated rule matches available data
- **Rule quality scoring** — Automated quality score for generated rules: specificity, false-positive surface area, data source coverage, MITRE alignment; human-readable feedback with suggested improvements
- **Staging validation** — Generated rules are scanned through ODCP before any PR is opened; only rules that achieve `readiness_score >= 0.8` in the target environment are promoted
- **Automated PR workflow** — `odcp agent generate-detection --technique T1055 --platform sigma` generates a rule, validates it, and opens a PR with ODCP scan summary, quality score, and AI rationale as the PR body; waits for human approval before merging
- **Feedback loop** — Generated rules feed back into the AI SOC cycle; accepted rules update coverage; rejected rules train the generator (via preference data)
- **Tuning automation** — For existing noisy/degraded rules, agent drafts an updated version with tighter filter conditions; presents diff to engineer; opens PR on approval

### CLI Additions

```bash
odcp agent generate-detection \
  --technique T1055 \
  --platform sigma \
  --environment prod-siem-report.json \
  --open-pr

odcp agent tune-detection <id> \
  --reason "too noisy" \
  --open-pr
```

---

## Phase 16: Enterprise Observability, Alerting, and Compliance Reporting — Planned

**Goal:** Make ODCP a first-class enterprise component by exposing metrics, integrating with incident management tools, and producing compliance-grade reporting.

### Planned Deliverables

- **Prometheus / OpenTelemetry metrics** — Expose `/metrics` endpoint with gauges and counters: `odcp_detections_total`, `odcp_readiness_score`, `odcp_blocked_detections`, `odcp_agents_active`, `odcp_drift_events_total`; OTLP exporter for Grafana Cloud / Datadog / Honeycomb
- **Alerting integrations** — PagerDuty incidents on critical drift events (data source removal affecting >10 detections); Slack/Teams webhooks for readiness score drops, new blockers, and agent offline events; configurable thresholds and routing
- **SLA tracking** — Per-detection SLA: maximum allowed time in `blocked` state; SLA breach findings with escalation path; `odcp sla status` command showing at-risk detections
- **Compliance reports** — Pre-built report templates for SOC 2 Type II (detection coverage + change management), NIST CSF (identify/protect/detect functions), and custom frameworks; PDF/HTML output from `odcp compliance report --framework soc2`
- **Audit log API** — `GET /api/audit?from=&to=&actor=&action=` with pagination; exportable as JSONL or CSV for SIEM ingestion
- **Health checks and SLOs** — `/health/live`, `/health/ready` endpoints for Kubernetes probes; configurable SLOs for report freshness and agent fleet coverage percentage

### CLI Additions

```bash
odcp serve --metrics-port 9090       # Expose Prometheus metrics endpoint

odcp compliance report \
  --framework soc2 \
  --period 2024-Q4 \
  --output compliance-report.pdf

odcp sla status --central-url http://odcp-server:8080
```

---

## Summary Roadmap

| Phase | Focus | Status | Tests |
|-------|-------|--------|-------|
| 1 | Splunk static readiness analysis | **Complete** | — |
| 2 | Splunk runtime signals and health | **Complete** | 97 |
| 3 | MITRE ATT&CK coverage and optimization | **Complete** | 156 |
| 4 | Multi-vendor adapters (Sigma, Elastic, Sentinel) | **Complete** | 209 |
| 5 | Sigma correlations/filters, STIX, OCSF, Splunk Cloud CI | **Complete** | 287 |
| 6 | Chronicle YARA-L, cross-platform view, migration | **Complete** | 391 |
| 7 | CI/CD integration and Detection-as-Code | **Complete** | 452 |
| 8 | AI SOC automation loop | **Complete** | 527 |
| 9 | AI agent integration (LLM tools + agentic orchestration) | **Complete** | 559 |
| 10 | Web dashboard and real-time SSE UI | **Complete** | 559 |
| 11 | Distributed collection agents and fleet management | **Complete** | 646 |
| 12 | Multi-tenant API, auth, and RBAC | **Planned** | — |
| 13 | Detection lifecycle management + Git workflows | **Planned** | — |
| 14 | Threat intelligence integration + active gap analysis | **Planned** | — |
| 15 | Autonomous detection engineering (AI rule generation + PR) | **Planned** | — |
| 16 | Enterprise observability, alerting, compliance reporting | **Planned** | — |
