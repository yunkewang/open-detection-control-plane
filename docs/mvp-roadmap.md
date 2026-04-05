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

## Post-MVP Backlog (Updated April 5, 2026)

### Recently Completed

- ✅ Lookup backing file verification for Splunk CSV lookups (transforms.conf + lookups/ checks)
- ✅ Tag-based dependency tracking from SPL (`tag=` and `tag::field=`) and `tags.conf`

### Newly Added, Research-Informed Items

- Add Sigma correlation meta-rule support (Sigma spec v2.1.0, including temporal/value_count/event_count correlation blocks)
- Add Sigma filter/meta-filter support to better model environment-specific exclusions
- Add ATT&CK catalog auto-refresh from ATT&CK STIX/TAXII feeds to reduce manual technique curation drift
- Add OCSF-native dependency taxonomy mapping so detections can be normalized against common event classes
- Add Splunk Cloud CI integration checks for app readiness workflows (e.g., AppInspect/ACS-aligned validation steps)
