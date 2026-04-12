# CLAUDE.md — AI Assistant Guide for ODCP

This file gives AI assistants the context needed to work effectively in this codebase.

---

## What this project is

**Open Detection Control Plane (ODCP)** is a Python library and CLI that provides a unified, vendor-neutral control plane for AI-driven security operations. It scans detection content from five SIEM platforms (Splunk, Sigma, Elastic, Microsoft Sentinel, Google Chronicle), analyzes detection readiness and dependencies, surfaces drift and coverage gaps, and exposes everything to AI agents via LLM-callable tools.

The project is organized into 16 implementation phases, all complete. Key capabilities:
- Multi-platform detection parsing (5 platforms)
- Readiness analysis and dependency graph (runnable / partially-runnable / blocked / unknown)
- MITRE ATT&CK coverage and gap analysis
- AI SOC automation loop (source catalog, drift detection, tuning proposals)
- 15+ LLM-callable tools (Anthropic + OpenAI schema export)
- FastAPI web dashboard (10 pages, Server-Sent Events)
- Distributed collector agents (fleet management, heartbeats)
- Token-based auth and RBAC (opt-in)
- Detection lifecycle state machine (draft → review → testing → production → deprecated)
- Threat intelligence integration and coverage gap analysis
- AI-powered rule generation (Claude API)
- SLA tracking and compliance reporting (SOC 2, NIST CSF)

---

## Repository layout

```
open-detection-control-plane/
├── odcp/                    # Main Python package
│   ├── models/              # Pydantic v2 data models
│   ├── adapters/            # Vendor-specific parsers (splunk, sigma, elastic, sentinel, chronicle)
│   ├── analyzers/           # Analysis engines (readiness, runtime, coverage, ci, dac, migration…)
│   ├── agent/               # LLM tool layer (session, tools, executor, orchestrator, rule_generator)
│   ├── server/              # FastAPI app, routes, templates, auth, audit
│   ├── collector/           # Distributed collection agents and fleet registry
│   ├── lifecycle/           # Detection state machine manager
│   ├── intel/               # Threat intelligence manager
│   ├── compliance/          # SOC 2 / NIST CSF report builder
│   ├── sla/                 # SLA policy tracker
│   ├── core/                # Dependency graph engine (ScanEngine, DependencyGraph)
│   ├── collectors/          # Data collectors (filesystem, Splunk REST API)
│   ├── reporting/           # JSON / Markdown / HTML report generation
│   └── cli/main.py          # Typer CLI — all 50+ commands in one file
├── tests/
│   ├── unit/                # 40+ unit test files, one per module
│   └── integration/         # Integration scenarios
├── docs/
│   ├── architecture.md      # Design principles, layers, data flow
│   └── mvp-roadmap.md       # Phase-by-phase roadmap details
├── examples/                # Sample content for each platform
│   ├── splunk_app/          # .conf files (savedsearches, macros, transforms, lookups)
│   ├── sigma_rules/         # YAML rules including correlations
│   ├── elastic_rules/       # JSON rules
│   ├── sentinel_rules/      # KQL analytics
│   └── chronicle_rules/     # YARA-L 2.0 rules
├── schemas/                 # JSON schema exports
└── pyproject.toml           # Single source of truth for metadata and tooling config
```

---

## Technology stack

| Concern | Tool |
|---------|------|
| Language | Python 3.10+ |
| Data modeling | Pydantic v2 |
| CLI | Typer |
| Web framework | FastAPI + Uvicorn |
| Graph analysis | NetworkX |
| Terminal output | Rich |
| Templating | Jinja2 |
| YAML parsing | PyYAML |
| AI agent | Anthropic SDK (optional) |
| Linting | Ruff |
| Type checking | mypy |
| Testing | pytest + pytest-cov |

---

## Key architectural patterns

### Adapter pattern
All five vendors implement `BaseAdapter`. An adapter takes a filesystem path (or API config) and returns a `ScanReport` using the unified Pydantic model. When adding a new platform, extend `BaseAdapter` and register it in `cli/main.py`.

### Unified data model
`ScanReport → Environment → Detection[] → Dependency[] → Finding[] → ReadinessScore[]`

All analyzers consume and produce Pydantic models. Everything is JSON-serializable. There is no database — state is held in memory and optionally persisted to JSON files.

### LLM tool registry
`odcp/agent/tools.py` defines tool implementations. `odcp/agent/executor.py` dispatches Anthropic and OpenAI tool-call blocks. `AgentSession` holds mutable state (loaded report, baseline) across multi-turn conversations. Tools return plain dicts; errors return `{"error": "..."}` for graceful LLM recovery.

### FastAPI server
`odcp/server/app.py` is a factory function `create_app()` that wires all route routers and shares state via `app.state`. Report state and SSE broadcasting live in `ReportStore` (`server/state.py`). Auth is opt-in: pass `TokenStore(auth_enabled=True)` to enable it.

### CLI
All commands are in `odcp/cli/main.py` using Typer. Subapps are registered via `app.add_typer(sub_app, name="...")`. When adding a new subcommand, add a new `@sub_app.command(...)` function in the same file and, if needed, a new Typer sub-app.

---

## Data flow

```
Filesystem / REST API
    → Collector (odcp/collectors/)
    → Adapter (odcp/adapters/<vendor>/)
    → Unified Models (odcp/models/)
    → Core Engine (odcp/core/engine.py)
        → DependencyGraph (NetworkX)
        → Analyzers (readiness, runtime, coverage, …)
        → Findings + Scores
    → ScanReport (JSON)
    → [ReportStore → Web Dashboard / SSE]
    → [AgentSession → LLM Tool Calls → AI Agent]
    → [Reporting → JSON / Markdown / HTML]
```

---

## Development setup

```bash
# Install everything (required for tests)
pip install -e ".[server,agent,dev]"

# Run all tests
pytest tests/ -v

# Lint
ruff check odcp/ tests/

# Type check
mypy odcp/
```

No Makefile or Docker files exist — use `pip` and `pytest` directly.

---

## Testing conventions

- Test files live in `tests/unit/` and are named `test_<module>.py`
- One test file per major module (e.g., `test_readiness.py`, `test_sigma_adapter.py`)
- Tests use Pydantic model construction directly — no fixtures database
- Auth is disabled by default in all existing tests (`TokenStore(auth_enabled=False)`)
- 822 tests total across all 16 phases; all should pass

When adding a new module, add a corresponding `tests/unit/test_<module>.py` file.

---

## CLI command map

| Command group | Subcommands | Purpose |
|---------------|-------------|---------|
| `odcp scan` | `splunk`, `sigma`, `elastic`, `sentinel`, `chronicle` | Scan and produce a report |
| `odcp ai-soc` | `inventory`, `drift`, `feedback`, `cycle` | AI SOC automation loop |
| `odcp agent` | `run`, `chat`, `tools`, `schema`, `generate-detection` | LLM agent interface |
| `odcp collector` | `start`, `status`, `list` | Fleet management |
| `odcp auth` | `create-token`, `list-tokens`, `revoke-token`, `whoami`, `audit` | Token-based auth |
| `odcp detection` | `list`, `status`, `promote`, `rollback`, `transition`, `summary` | Lifecycle management |
| `odcp intel` | `campaigns`, `add-campaign`, `add-ioc`, `gap-analysis` | Threat intelligence |
| `odcp sla` | `status` | SLA policy evaluation |
| `odcp compliance` | `report` | SOC 2 / NIST CSF evidence |
| `odcp serve` | (flags: `--auth`, `--lifecycle-db`, `--audit-log`) | Start web dashboard |
| `odcp ci` | (flags: `--min-score`, `--baseline`, `--fail-on-regression`) | CI/CD gating |
| `odcp validate` | (flags: `--platform`, `--require-mitre`) | Detection-as-Code validation |
| `odcp cross-platform` | — | Multi-platform readiness view |
| `odcp migrate` | `--target` | Migration feasibility analysis |

---

## REST API summary

The FastAPI server exposes:

| Path prefix | Purpose |
|-------------|---------|
| `/` (GET) | Dashboard page |
| `/detections`, `/coverage`, `/findings`, `/sources`, `/fleet`, `/agent`, `/lifecycle`, `/intel` | Dashboard pages |
| `/api/posture`, `/api/detections`, `/api/findings`, `/api/sources`, `/api/coverage` | JSON data endpoints |
| `/api/stream` | Server-Sent Events (report-change push) |
| `/api/fleet/*` | Fleet agent registration, heartbeat, deregistration |
| `/api/auth/tokens`, `/api/auth/me`, `/api/auth/audit` | Token management + audit log |
| `/api/lifecycle/*` | Detection state machine (list, promote, rollback) |
| `/api/intel/*` | Threat campaigns, IOCs, gap analysis |
| `/api/agent/generate-detection` | AI rule generation |
| `/api/sla/status` | SLA policy evaluation |
| `/api/compliance/report` | SOC 2 / NIST CSF evidence |
| `/health`, `/metrics` | Observability |

---

## Model reference (most-used)

```python
from odcp.models.detection import Detection, DetectionSeverity
from odcp.models.environment import Environment, Platform
from odcp.models.dependency import Dependency, DependencyKind, DependencyStatus
from odcp.models.report import ScanReport
from odcp.models.scoring import ReadinessScore, ReadinessStatus
from odcp.models.finding import Finding, FindingCategory, FindingSeverity
from odcp.models.runtime import RuntimeSignal, CombinedReadinessScore
from odcp.models.coverage import CoverageSummary
from odcp.models.source_catalog import SourceCatalog, DriftEvent
from odcp.models.auth import UserRole, TokenRecord, AuditEvent
from odcp.models.lifecycle import DetectionState, DetectionLifecycle
from odcp.models.intel import ThreatCampaign, IocEntry, IntelGapReport
```

---

## Common extension points

### Add a new vendor adapter
1. Create `odcp/adapters/<vendor>/` with an `__init__.py` and adapter class extending `BaseAdapter`
2. Register the new `scan <vendor>` subcommand in `odcp/cli/main.py`
3. Add a test file at `tests/unit/test_<vendor>_adapter.py`

### Add a new LLM tool
1. Add the implementation function to `odcp/agent/tools.py`
2. Register it in the `TOOLS` dict with its JSON schema (Anthropic and OpenAI variants)
3. Add dispatch in `odcp/agent/executor.py`
4. Cover it in `tests/unit/test_agent_tools.py`

### Add a new dashboard page
1. Add a Jinja2 template to `odcp/server/templates/`
2. Add a route to `odcp/server/routes.py` (or a new `*_routes.py` module)
3. Register the router in `odcp/server/app.py`
4. Add a nav link to `odcp/server/templates/base.html`

### Add a new analyzer
1. Add the module to `odcp/analyzers/`
2. Wire it into `odcp/core/engine.py` if it should run as part of the scan pipeline
3. Expose any new CLI flags in `odcp/cli/main.py`
4. Cover it in `tests/unit/test_<analyzer>.py`

---

## Auth conventions

Auth is **opt-in**. Without `--auth`, the server accepts all requests. With `--auth`:
- Tokens are stored SHA-256 hashed; raw tokens are shown only once at creation time
- FastAPI dependencies: `get_current_token` (any auth), `require_role(UserRole.analyst)` (role guard)
- Agent-role tokens are for collector agents; analyst-role tokens are for human operators
- Audit events are logged to the in-memory ring buffer and optionally to a JSONL file

---

## Git branch

Active development branch: `claude/add-claude-documentation-5ppOT`

All commits and pushes should target this branch.

---

## Phases and status

All 16 phases are complete:

| Phase | Focus |
|-------|-------|
| 1–2 | Splunk static + runtime analysis |
| 3 | MITRE ATT&CK coverage |
| 4 | Sigma, Elastic, Sentinel adapters |
| 5 | Sigma correlations, STIX, OCSF, Splunk Cloud |
| 6 | Chronicle adapter, cross-platform, migration |
| 7 | CI/CD gating, Detection-as-Code |
| 8 | AI SOC automation loop |
| 9 | AI agent (LLM tools, orchestration) |
| 10 | Web dashboard (FastAPI, SSE) |
| 11 | Distributed collectors, fleet management |
| 12 | Token auth, RBAC, audit logging |
| 13 | Detection lifecycle state machine |
| 14 | Threat intelligence integration |
| 15 | AI rule generator (Claude API) |
| 16 | SLA tracking, SOC 2 / NIST CSF compliance |
