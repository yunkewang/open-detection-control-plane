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
