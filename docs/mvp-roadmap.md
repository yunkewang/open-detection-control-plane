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
- Lookup file existence is not verified on disk
- Data model field-level analysis not yet implemented
- No tag-based dependency tracking yet

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

## Phase 3: Semantic Gap and Optimization

**Goal:** Identify coverage gaps and prioritize remediation.

### Planned

- Data source inventory (what's logging vs. what's expected)
- MITRE ATT&CK mapping and coverage gap analysis
- Detection priority scoring based on risk and coverage
- Optimization analyzer with ranked remediation recommendations
- Estimated effort and impact for each remediation
- "What-if" analysis (if I fix X, how many detections unblock?)

---

## Phase 4: Additional Vendor Adapters

**Goal:** Extend ODCP beyond Splunk to other platforms.

### Planned Adapters

| Adapter | Input Format | Status |
|---------|-------------|--------|
| Splunk | .conf files, REST API | **Phase 1 + 2 complete** |
| Sigma | YAML rules | Planned |
| Sentinel (Microsoft) | KQL analytics, ARM templates | Planned |
| Elastic | JSON detection rules, Kibana exports | Planned |
| Chronicle (Google) | YARA-L rules | Planned |
| OCSF | Open Cybersecurity Schema Framework mapping | Planned |

### Cross-Platform Features

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
