# ODCP Architecture and Design

**Status:** Proposed target architecture (November 3, 2026); not a description of shipped agent-security controls.  
**Core primitive:** Vendor-neutral **agent identity and permission graph** with a policy-decision and enforcement interface.  
**Existing implementation:** Detection-readiness analysis; preserved in Appendix A and not represented as agent authorization enforcement.

## 1. Motivating example: the Binance $6.3B lateral movement (Oct 20, 2026)

### 1.1 Observed sequence, bounded by published facts

Binance's November 3 incident update reports approximately **$6.34 billion** in affected digital assets from the October 29 breach. Blockchain investigators attribute the theft to **TraderTraitor**, linked to the DPRK; this attribution is distinct from Binance's account of the intrusion mechanics. The publicly reported sequence is:

1. **Prior workstation compromise.** An attacker obtained access to an engineer's workstation using malicious code. The public post-mortem describes the compromised engineer device as the pivot point; it does not publish the internal AI tool's complete permission model.
2. **October 20: AI-tool-mediated lateral movement.** Using the compromised workstation, the attacker abused an **internal AI tool** to gain control of **two wallet engineers' machines**. This is a *confused-deputy* risk: an intermediary with authority may be induced to act beyond the actual requester's intended authorization. It does **not** establish that an autonomous model independently chose the attack.
3. **Credential discovery/theft.** The attacker found a **container deployment permission token** on a wallet DevOps engineer's machine. The token connected a workstation compromise to deployment authority.
4. **October 29: deployment and execution.** The attacker used stolen credentials to deploy a container and trigger malicious code that reached wallet signing operations. Unauthorized access to the signing service enabled illicit transactions.
5. **Response.** Binance reported rebuilding the affected internal AI tool **and its access controls**, rebuilding affected wallet systems, replacing affected devices, and decommissioning relevant credentials/tokens. These are reported actions, not proof that any specific proposed ODCP mechanism would have prevented the loss.

**MITRE ATT&CK reference mappings:** **T1078 Valid Accounts** for misuse of legitimately authorized identities; **T1528 Steal Application Access Token** for the stolen deployment token. Both are useful analytic mappings, not a full incident reconstruction.

### 1.2 Counterfactual ODCP control points

The following table describes where a **future, correctly deployed** ODCP could collect evidence or apply controls. It does not claim those controls existed at Binance or guarantee any would have stopped the attack.

| Stage | Permission-graph question | Pre-deploy evaluation | Runtime observability | Enforcement / kill action |
|---|---|---|---|---|
| Initial compromised workstation | Which human/workload identity and device can invoke the internal AI tool? | Review delegation scopes and workstation-to-agent trust; test malicious/compromised-caller scenarios | Correlate caller, device posture, tool invocation, and actual target | Require verified caller context; block invocation from an unauthorized or untrusted principal **if integrated with the entry point** |
| Oct 20 internal AI tool as pivot | Can this AI-tool identity administer or reach other engineers' endpoints, directly or through delegated tools? | Identify transitive `can_invoke → can_act_as → can_reach` paths; deny cross-user admin capabilities by default | Detect a new lateral action path, unusual target, or scope escalation at a tool-call boundary | Deny the tool call, require scoped approval, or revoke agent execution/session permissions **before privileged actions execute** |
| Two wallet engineers' devices accessed | Which target-device, tool, or remote-execution privileges were exercised? | Validate subject/target separation and purpose-bound grants | Correlate agent call chain to endpoint/identity alerts; detect deviation from approved paths | Quarantine the affected agent/tool session; trigger existing EDR containment through an integration |
| Deployment token exposed/stolen | What secrets or token issuers can the invoking identity reach, and which privileges do those tokens confer? | Flag reachable deployment credentials, long-lived token scope, and privilege-amplifying paths | Detect secret retrieval or credential use *where instrumented*; monitor anomalous new token usage | Deny secret retrieval, revoke/rotate tokens, remove deployment grants; tool-call denial **cannot undo an already stolen token** |
| Oct 29 malicious container deployed | Can a derived or stolen identity deploy workloads able to touch signing services? | Test graph reachability from developer → credential → deployment → signing workload; require separation of duties | Ingest deployment audit events and compare issuer, artifact, target, and declared purpose | Gate deployment using external CI/CD/cloud IAM enforcement; quarantine workload or revoke deployment identity before execution |
| Wallet signing abuse / asset transfers | Can a deployment path invoke or influence signing authority? | Identify critical transitive paths; require independent signing approval and workload isolation | Correlate signed transaction activity and policy drift from security/chain telemetry | Trigger downstream signing-service containment **only through integrated systems**; on-chain authorizations may require separate revocation and are not fixed by killing an AI agent |

**Key failure mode:** The October 20 pivot exposes a boundary question before it becomes an anomaly question: *What exactly could the internal AI tool, and every credential it could reach or delegate, do to other people and systems?* ODCP's first deliverable is a continuously updated, evidence-backed answer.

### 1.3 Detection is not prevention

A graph populated only from configuration is a **risk assessment**, not enforcement. An OTel span is **evidence**, not an authorization gate. A kill switch cannot retroactively invalidate exfiltrated credentials or blockchain authorizations. Prevention requires action at a real chokepoint (agent/tool runtime, credential broker, API gateway, CI/CD deploy gate, or cloud IAM); enforcement assurance depends on complete coverage and fail-closed behavior for protected actions.

## 2. Target architecture: permission graph at the center

### 2.1 Design principles

1. **Identity first.** Attribute every consequential action to an agent instance, executing workload, caller/delegator, and credential provenance. Avoid treating an LLM model name as a security principal.
2. **Graph over isolated permissions.** Model direct and transitive access, including delegated credentials and indirect execution. Evaluate *effective* reachability under conditions, not merely role names.
3. **Policy before privileged side effects.** Intercept tool/API calls where enforcement is possible; return explicit allow/deny/requires-approval with a stable reason and audit ID.
4. **Open interfaces.** Publish a vendor-neutral identity/permission/event schema, OTel-compatible action instrumentation, and pluggable policy/enforcement adapters. OPA/Rego-style decisions may be one backend, not a hard dependency.
5. **Complement existing tools.** Import traces, evaluations, endpoint detections and identity inventories from incumbent platforms. Do not recreate a general-purpose agent-observability console or EDR.
6. **Truthful capability boundaries.** Differentiate discovered access, inferred access, validated access and enforced restrictions; expose uninstrumented paths as unknown rather than safe.
7. **Least privilege by construction.** Prefer short-lived workload credentials, explicit resource/action grants, bounded delegation, owner attribution, change review and automated expiry.

### 2.2 System layout

```text
Agent frameworks / MCP hosts / agent runtimes / CI systems / cloud + SaaS APIs
         | identity inventory, permission metadata, action events
         v
  +------------------------------------------------------------+
  |  ODCP Agent Identity & Permission Graph  [CORE / TARGET]   |
  |  - normalized principals, tools, credentials, resources   |
  |  - direct/conditional/transitive permissions               |
  |  - delegation chain, ownership, blast-radius simulation    |
  |  - graph snapshots, diffs, confidence and evidence         |
  +----------------------------+-------------------------------+
                               |
                 query path / evaluate proposed action
                               v
           Policy decision engine (OPA/Rego or pluggable PDP)
                  | allow / deny / approval / audit
                  v
       Enforcement adapters / existing IAM, API, CI/CD, EDR
         (MCP proxy, tool wrapper, gateway, broker, hooks)

  Integrated inputs:                  Integrated outputs:
  pre-deploy evaluations              scoped approval + CI gates
  OTel/action traces                  SIEM / AI observability traces
  Falcon Observe / Galileo / etc.     EDR/identity incident response
  IAM / secrets / cloud inventory     targeted revoke / stop / quarantine
```

The **graph and policy semantics are the owned core**. Three surrounding operational layers remain part of the design but are **integration surfaces** rather than parallel product suites:

| Layer | ODCP responsibility | Expected partner / boundary |
|---|---|---|
| **Pre-deploy evaluation** | Compute risky reachable paths; test proposed grants, tool manifests, and agent task constraints in CI; emit machine-readable findings | Consume red-team/evaluation results (e.g., Dreadnode); ODCP is not a foundation-model red-team platform |
| **Runtime observability** | Standardize identity-aware agent action events and correlate intended principal, delegated privilege, policy decision, outcome, and graph snapshot | Export to OTel/SIEM and import from platforms such as Falcon Observe, Galileo/Splunk or Langfuse; ODCP is not another tracing dashboard |
| **Kill / containment** | Resolve the exact agent, session, token, tool, workload and downstream grants requiring containment; issue actions via adapters | Invoke existing gateway/EDR/IAM/credential systems; no claim of universal endpoint kill or independent host containment |

### 2.3 Minimal graph model

**Node types:** `HumanPrincipal`, `AgentDefinition`, `AgentInstance`, `WorkloadIdentity`, `Tool`, `CredentialRef` (metadata only; never store the secret), `API`, `Repository`, `Host`, `CloudRole`, `DeploymentTarget`, `Service`, `DataAsset`, and `Environment`.

**Edge types:** `invokes`, `runs_as`, `delegates_to`, `can_call`, `can_read`, `can_write`, `can_administer`, `holds_credential`, `credential_grants`, `can_assume_role`, `can_deploy_to`, `can_reach` and `belongs_to`. Every edge carries `source`, `observed_at`, `expires_at`, `conditions`, `confidence`, and whether it is `configured` / `observed` / `validated` / `enforced`.

**Identity separation:** An agent definition is not an agent instance. An agent instance is not the human requesting its action. A tool-server process is not the identity of the credential it uses. Explicit delegation chains prevent an agent from laundering a requester's insufficient privilege through a more privileged service account.

**Core queries:**
- `explain_access(agent_instance, resource, action, context)`: return ordered paths, effective scope, conditions and evidence.
- `blast_radius(principal_or_credential, depth, criticality)`: enumerate reachable hosts, repositories, APIs and sensitive services, including indirect paths.
- `least_privilege_diff(agent, observed_actions, granted_actions)`: identify unused, wildcard, stale and inherited grants; propose reductions for review.
- `simulate_policy_change(diff, test_cases)`: list allowed/blocked paths before rollout, including breakage risk.
- `trace_action(event_id)`: tie caller → agent → tool → credential → resource → actual execution outcome to a graph snapshot.
- `contain(principal_or_session, reason)`: enumerate actions and issue revocations through configured adapters with audited partial-failure states.

The graph must avoid treating arbitrary network reachability as sufficient authorization. Query execution combines identity, action, resource, environmental condition, delegated context and time. Transitive paths are **potential capability** unless end-to-end exercisability has been checked.

### 2.4 Policy interface and enforcement

Example request (illustrative target API, **not implemented**):

```json
{
  "request_id": "req-example",
  "agent_instance": "agent://prod/internal-assistant/run-123",
  "caller": "human://wallet/engineer-b",
  "delegation_chain": ["human://wallet/engineer-b"],
  "tool": "mcp://device-admin/execute",
  "action": "remote_execute",
  "resource": "host://wallet/engineer-a",
  "credential_ref": "secretref://broker/deploy-role",
  "environment": {"stage": "prod", "device_trust": "unknown"}
}
```

Decision: `allow | deny | requires_approval`, with `policy_version`, `reason_codes`, `decision_id`, and short TTL. The tool wrapper must bind the *actual* authenticated caller to this request; caller-supplied identity fields are not trusted. Privileged commands default to deny on policy-service failure, with separately defined break-glass workflows and audit. Read-only telemetry failures must not silently imply enforcement coverage.

**High-impact example policies** (conceptual):
- An internal AI assistant initiated by engineer B cannot administer engineer A or C's workstation without an independently authorized grant for that exact target and task.
- A development assistant cannot retrieve deployment-token material; deployment occurs through a scoped broker with short-lived credentials.
- An agent may deploy only approved artifacts to explicitly granted namespaces; signing-service reachability requires a separately approved trust boundary.
- New edges linking agent tools to sensitive wallet/deployment infrastructure fail a pre-deploy graph-policy gate until reviewed.

## 3. Telemetry and integration contract

The primary event is an **agent action**, not a chat transcript. Reuse OpenTelemetry traces/spans where possible, with a versioned security extension for missing identity and permission fields.

Minimum event envelope: `timestamp`, `trace_id`, `span_id`, `agent_instance_id`, `authenticated_caller_id`, `delegation_chain_ref`, `tool_id`, `action`, `resource_id`, `credential_ref`, `policy_decision_id`, `graph_snapshot_id`, `outcome`, `enforcement_point_id`, and `evidence_source`. Define cardinality limits and redaction; never export prompts, private data or raw secrets by default.

**Adapters:** MCP/tool-call wrappers, agent SDK interceptors, HTTP/API gateways, Git repository permissions, cloud IAM, secret brokers, CI/CD deployment systems, and existing OTel exporters. Optional integrations import CrowdStrike endpoint controls, Splunk/Galileo traces, Langfuse traces, and enterprise identity inventories. When a system cannot be instrumented or a downstream credential can bypass the tool boundary, report a coverage gap and residual risk.

**Consistency model:** Version graph snapshots and policy decisions independently; label stale or inferred edges. Events must carry correlation IDs to reconstruct a permitted/denied action even when policy and graph state later change. External revocation and kill actions are asynchronous and may partially fail; return per-adapter status and verify effects where possible.

## 4. Threat model, invariants and boundaries

**Threats in scope:** confused-deputy delegation, excessive agent/tool permissions, prompt-induced privilege misuse, stolen service/deployment tokens, dormant grants, insecure MCP/tool integration, cross-tenant access, and blind transitive paths from agents into production assets.

**Out of scope for the first release:** generic LLM quality monitoring, training-time model security, replacing full EDR, building a wallet-signing security system, universal downstream session termination, and attributing attacker identity from graph edges alone.

**Required invariants:** authenticated and independently verified caller identity; tenant isolation; policy checks *before* external side effects; no plaintext credential storage; audit events protected from tampering; per-adapter proof of coverage; no silent allow on enforcement failures for protected actions. False-positive and false-negative risk must be measured via replay and adversarial tests.

## 5. Competitive landscape (as of November 3, 2026)

| Company / transaction | Publicly described area | ODCP positioning |
|---|---|---|
| **CrowdStrike → Fiddler AI** (agreement announced Nov 3) | Agent observability and explainability, planned **Falcon Observe**. **~$400M is WSJ-reported**, not company-disclosed | Ingest or export events; do not compete for generic agent trace/quality dashboards |
| **CrowdStrike → Dreadnode** (agreement announced Nov 3) | Automated pre-deployment testing of models, apps and agents. **~$95M is WSJ-reported**, not company-disclosed | Import evaluation findings as proposed graph/policy changes |
| **CrowdStrike Falcon Guardian** | AI Kill Switch available at gateway as announced; endpoint termination capability described as coming later | Integrate with available controls; do not claim ODCP provides equivalent endpoint enforcement |
| **Cisco / Splunk → Galileo** | AI application and agent observability/evaluation | Complement traces with explicit agent-to-resource permission paths |
| **Dynatrace → Arize** (completed Oct 1, 2026) | End-to-end AI observability and evaluation | Integrate rather than duplicate tracing and evaluation |
| **ClickHouse → Langfuse** (Jan 2026) | Open-source LLM observability and evaluations | Interoperate; **open source alone is not unique differentiation** |
| **ServiceNow → Traceloop** (Mar 2026) | OTel-based agent observability integrated into AI Control Tower | Consume OpenLLMetry/OTel spans and apply graph-aware policy |
| **Mintlify → Helicone** (Mar 2026) | LLM gateway/observability joined knowledge infrastructure | Complement gateway telemetry with scoped authorization graph |

**Direct overlap / caution:** The permission space is **not** empty. ServiceNow's AI Control Tower describes Veza-backed access graphs and least-privilege governance across AI agents, while Cisco has announced agentic workforce security and identity-related acquisitions including Astrix and WideField. CrowdStrike also positions Falcon around AI agent identity and runtime controls. A vendor-neutral ODCP would compete on portable **graph schema, explainable transitive permissions, pluggable policy enforcement and multi-framework coverage**, not on a claim that incumbent stacks cannot govern identities. Falcon is a **Falcon-centered** integrated offering; cross-platform support is an empirical integration question, not an assertion that it literally works nowhere else.

**Defensibility hypothesis, not an established moat:** Open schemas + adapter coverage + verified authorization semantics can reduce lock-in. An open repository by itself is insufficient; the defensible asset would be interoperability, correct graph resolution, auditable enforcement contracts, and an active ecosystem of adapters/policies.

## 6. Product boundary and migration from current codebase

ODCP today is primarily a **detection engineering/readiness** implementation. Its existing `Detection → Dependency → Finding → ReadinessScore` model and NetworkX dependency graph analyze **detection content and data dependencies**. They are not agent identities, credential paths, runtime tool authorizations or policy enforcement points.

**Preserve/reuse:**
- Adapter design and vendor-normalized modeling as a software pattern, not the present SIEM schema.
- DependencyGraph graph-query approach and snapshot comparison techniques, while introducing a separate security-typed permission graph.
- Scan/collector pipelines, report format patterns, CLI, CI gates, auth/audit and web integration patterns where appropriate.
- Existing detection readiness, source catalog, MITRE coverage, drift, lifecycle and reporting functions as a **compatible legacy subsystem** and possible telemetry consumers.

**Do not conflate:**
- The `agent` in `odcp/agent/` currently refers to an LLM interface for querying detection reports, **not** a permission-managed enterprise AI agent identity.
- The `agent` token role in the existing server RBAC applies to ODCP collector clients; it is **not** an AI agent delegated-authorization graph.
- `odcp/core/DependencyGraph` links detection objects to macros/lookups/data models, not AI tools to credentials/repos/hosts.
- The existing web dashboards are for detection posture; they do not establish AI tool-call interception or endpoint kill capabilities.

### 6.1 Incremental implementation plan (proposed, unshipped)

1. **Graph schema + importer:** add namespaced agent, principal, tool, credential reference and resource node types; ingest static manifests/IAM exports; implement access explanation, blast-radius traversal and provenance tests.
2. **MCP/tool-call proof of enforcement:** instrument one local MCP server/tool wrapper; resolve the authenticated caller; run policy before side effects; demonstrate denied cross-user remote execution in an isolated test fixture.
3. **Credential/deployment graph:** ingest scoped secret-broker and CI/CD IAM metadata; flag reachable deployment tokens; simulate engineer → AI tool → deploy → sensitive workload path without connecting to production wallets.
4. **OTel event extension + runtime correlation:** correlate policy decision, graph version, tool action and cloud/endpoint results; export into existing observability platforms; quantify missing enforcement coverage.
5. **Containment orchestration:** integrate with one identity revocation mechanism and one existing runtime kill/EDR action; handle partial failure and verification.
6. **Pre-deploy regression gates:** block newly introduced privileged paths in PRs; compare production graph snapshots; adversarial tests for delegation, impersonation and confused-deputy paths.

**MVP acceptance tests:** (a) explain every reachable privilege from a sample agent to a sensitive deployment resource with provenance; (b) block a request from user B through an AI tool to administer user A's host; (c) show that removing a deploy grant breaks the transitive path; (d) replay events into OTel with decision/snapshot correlation; (e) mark uninstrumented bypass paths unknown, not blocked; (f) demonstrate scoped revocation and surface partial failures.

## 7. Repository contradictions and open decisions

**Explicit contradictions with the target positioning; intentionally not silently rewritten:**

1. `README.md` still presents ODCP as a **detection posture / AI SOC** control plane, with multi-SIEM detection scans and dashboards as its primary product. This contradicts the new agent-identity core narrative; the README and shipped CLI remain unchanged in this documentation-only revision.
2. `CLAUDE.md` describes 16 completed phases of a **detection engineering** product, including `odcp/agent/` as an LLM report interface. None of this substantiates agent permission enforcement. Do not relabel those phases as completed agent-security milestones.
3. `docs/mvp-roadmap.md` contains the detection-readiness roadmap and stale planned/completed labels, not the proposed permission-graph milestones. It has not been rewritten.
4. The previous `docs/architecture.md` calls runtime collection and non-Splunk adapters future work; this is stale relative to current README/CLAUDE implementation descriptions. Its historical text is preserved in Appendix A rather than promoted to current status.
5. `CLAUDE.md` references an older active development branch, while the repository default is `main`. This design revision is proposed on a dedicated branch for review.

**Open design decisions:** canonical principal URI scheme; evaluation semantics for conditional IAM policy; tenant-boundary graph traversal; freshness guarantees; authenticated delegation standard across MCP and other frameworks; exact fail-closed coverage; policy authoring/review UX; schema publication/versioning; integration licensing.

## References

- Binance, [29 October 2026 Binance Security Incident: Initial Findings and Response Update](https://www.binance.bh/en/blog/community/3229153443759566763), Nov 3, 2026.
- Chainalysis, [The $6.4 Billion Binance Hack: Tracing the North Korea Link](https://www.chainalysis.com/blog/binance-exploit-latest-findings-and-response/), Oct 30, 2026 (attribution).
- CrowdStrike, [To Acquire Fiddler](https://ir.crowdstrike.com/news-releases/news-release-details/crowdstrike-acquire-fiddler-deliver-agent-observability-ai-trust), Nov 3, 2026; [Dreadnode announcement](https://crowdstrike.gcs-web.com/news-releases/news-release-details/crowdstrike-acquire-dreadnode-advance-ai-trust-and-deliver), Nov 3, 2026; [AI Kill Switch announcement](https://crowdstrike.gcs-web.com/news-releases/news-release-details/crowdstrike-introduces-ai-kill-switch-ai-safety), Nov 3, 2026; [Falcon Observe planned branding](https://www.crowdstrike.com/en-us/blog/crowdstrike-to-acquire-fiddler/), Nov 3, 2026.
- The Wall Street Journal, [CrowdStrike to Buy Two AI Security Startups for $495 Million](https://www.wsj.com/pro/cybersecurity/crowdstrike-to-buy-two-ai-security-startups-for-495-million-b0ef6a9e), Nov 3, 2026 (reported, not disclosed, component prices).
- Cisco, [Corporate Strategy Office news](https://www.cisco.com/c/en/us/about/corporate-strategy-office/news.html), 2026 (Galileo, Astrix, WideField).
- Dynatrace, [Arize acquisition completed](https://www.dynatrace.com/news/press-release/dynatrace-completes-acquisition-of-arize/), Oct 1, 2026.
- ClickHouse, [Langfuse acquisition](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability), Jan 16, 2026.
- Traceloop, [Joining ServiceNow](https://traceloop.com/blog/traceloop-is-joining-servicenow), Mar 2026; ServiceNow, [AI Control Tower / Veza permissions](https://newsroom.servicenow.com/press-releases/details/2026/ServiceNow-expands-AI-Control-Tower-to-discover-observe-govern-secure-and-measure-AI-deployed-across-any-system-in-the-enterprise/default.aspx), May 2026.
- Mintlify, [Helicone acquisition](https://www.mintlify.com/blog/mintlify-acquires-helicone), Mar 3, 2026.

---

## Appendix A — Previous detection-readiness architecture (preserved)

> Historical implementation-oriented design retained to avoid losing earlier architecture details. Some 'future' labels below are stale; consult README.md and CLAUDE.md for the currently described detection feature set. This appendix is **not** an implemented agent-permission graph.

### Why a Control Plane?

Detection engineering today is fragmented. Teams write detections in vendor-specific formats, deploy them into complex environments, and have no unified way to answer:

- "Which of my detections can actually run?"
- "What dependencies are missing?"
- "What breaks if I remove this lookup table?"

ODCP is a **control plane** — not a SIEM, not a detection framework, not a deployment tool. It sits above vendor platforms and provides a unified model for understanding detection health.

### Core Design Principles

1. **Vendor-neutral unified model** — All concepts (detections, dependencies, findings) are modeled in a vendor-agnostic way. Adapters translate vendor specifics into this common model.

2. **Adapter pattern** — Each vendor platform (Splunk, Sentinel, Elastic) gets an adapter that implements a standard interface. The core engine doesn't know or care about vendor details.

3. **Separation of concerns** — Parsing, modeling, graph construction, analysis, and reporting are distinct phases with clean boundaries.

4. **Static-first, runtime-later** — The MVP analyzes config files on disk. Runtime health (API calls, live status) is a future layer that extends the same model.

### Architecture Layers

#### 1. Unified Data Models (`odcp/models/`)

Pydantic v2 models that form the lingua franca of the platform:

- **Environment** — A security environment containing platforms
- **Platform** — A specific vendor platform (Splunk, Sentinel, etc.)
- **Detection** — A detection rule with its search query and metadata
- **Dependency** — Something a detection needs (macro, lookup, data model)
- **KnowledgeObject** — A defined object in the environment (the "supply" side)
- **Finding** — An analysis result (missing dependency, optimization opportunity)
- **ReadinessScore** — Per-detection readiness classification and score
- **ScanReport** — Complete scan output with all data and statistics

#### 2. Adapters (`odcp/adapters/`)

Adapters translate vendor-specific artifacts into the unified model.

```python
class BaseAdapter(ABC):
    def parse_environment(self, path: Path) -> Environment: ...
    def parse_detections(self, path: Path) -> list[Detection]: ...
    def parse_knowledge_objects(self, path: Path) -> list[KnowledgeObject]: ...
    def resolve_dependencies(self, detections, knowledge_objects) -> list[Dependency]: ...
```

The Splunk adapter parses `.conf` files and extracts SPL references. Future adapters would parse Sigma YAML, Sentinel KQL, Elastic JSON, etc.

#### 3. Core Engine (`odcp/core/`)

- **DependencyGraph** — NetworkX directed graph linking detections to dependencies. Supports queries like "what depends on this macro?" and "which dependencies are orphaned?"
- **ScanEngine** — Orchestrates the full pipeline: parse → resolve → graph → analyze → report.

#### 4. Analyzers (`odcp/analyzers/`)

Analyzers consume the unified model and produce findings:

- **ReadinessAnalyzer** — Classifies each detection as runnable/blocked/partial/unknown based on dependency resolution status.
- **DependencyAnalyzer** — Identifies structural issues (orphaned objects, high fan-out dependencies).
- **(Future) RuntimeHealthAnalyzer** — Would check live API status.
- **(Future) SemanticGapAnalyzer** — Would identify missing data source coverage.
- **(Future) OptimizationAnalyzer** — Would prioritize remediation actions.

#### 5. Collectors (`odcp/collectors/`)

Collectors gather raw data before adapter processing:

- **LocalCollector** — Reads from a local filesystem path.
- **(Future) APICollector** — Would pull from Splunk REST API, cloud APIs, etc.
- **(Future) RemoteCollector** — Would pull from S3, GCS, or remote hosts.

#### 6. Reporting (`odcp/reporting/`)

Generates output in multiple formats from a ScanReport:

- JSON (machine-readable, round-trips perfectly)
- Markdown (human-readable, great for PRs and wikis)
- HTML (self-contained, shareable dashboards)

#### 7. CLI (`odcp/cli/`)

Typer-based CLI with Rich output:

- `odcp scan splunk <path>` — Run a full scan
- `odcp report <json>` — Convert report formats
- `odcp graph <json>` — Dependency graph statistics

### Data Flow

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

### Adding a New Adapter

1. Create `odcp/adapters/your_vendor/`
2. Implement `BaseAdapter` — parse your vendor's format into the unified model
3. Register it in the CLI
4. All analyzers, graph, and reporting work automatically

This is the key architectural benefit: new vendors get the full analysis pipeline for free.
