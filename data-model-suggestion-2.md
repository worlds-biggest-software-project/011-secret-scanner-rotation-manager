# Data Model Suggestion 2: Event-Sourced / Audit-First

> Project: Secret Scanner & Rotation Manager · Created: 2026-05-11

## Philosophy

The event-sourced model treats every state change as an immutable, append-only event. Instead of mutable rows that represent "current state," the system records a chronological stream of events: "secret detected," "verification attempted," "credential rotated," "incident resolved." Current state is derived by replaying the event stream through projection functions that build read-optimized materialized views.

This approach is used by financial systems, compliance platforms, and security audit tools where the complete history of every action is not optional but mandatory. Vault's audit log, AWS CloudTrail, and OCSF Detection Finding events all follow this pattern. For a secret scanner where SOC 2 auditors need to prove "when was this secret first detected, who was notified, what actions were taken, and when was it remediated," event sourcing provides the answer natively rather than through reconstructed audit logs.

The architecture follows CQRS (Command Query Responsibility Segregation): write operations append events to the event store; read operations query denormalized materialized views optimized for specific use cases (dashboard, incident list, compliance report). This separation allows the write path to be simple and fast while the read path can be shaped to any query pattern without modifying the source of truth.

**Best for:** Organizations with strict compliance requirements (SOC 2, PCI-DSS, FedRAMP) where complete, tamper-proof audit history is non-negotiable, and temporal queries ("what was the state at time T?") are common.

**Trade-offs:**
- Pro: Complete, immutable audit trail by design — no separate audit log needed
- Pro: Temporal queries are natural: replay events to any point in time
- Pro: Adding new read models (dashboards, reports) never requires schema migration on the write side
- Pro: Event replay enables AI training on historical incident patterns
- Pro: Natural alignment with OCSF event schema and CloudTrail audit patterns
- Con: Higher storage costs — events accumulate rapidly; requires partitioning and archival strategy
- Con: Eventual consistency between event store and materialized views
- Con: More complex to implement: requires event versioning, upcasting, and projection management
- Con: Simple queries like "show me all open incidents" require maintained materialized views
- Con: Debugging state issues requires replaying event streams

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF Detection Finding (class_uid 2004) | Each detection event directly maps to an OCSF Detection Finding event with matching attributes |
| OCSF Vulnerability Finding | Verification events map to OCSF Vulnerability Finding with validity assessment |
| SARIF v2.1.0 | SARIF export is a projection: replay scan events to build SARIF runs/results structure |
| Vault Audit Log Schema | Event format mirrors Vault's audit log: type, time, auth, request, response |
| AWS CloudTrail | Event structure follows CloudTrail conventions: eventTime, eventSource, eventName, requestParameters, responseElements |
| NIST SP 800-53 AU-2/AU-3 | Immutable event store satisfies audit record content and reviewability requirements |
| PCI DSS 4.0 Req. 10 | Event store natively satisfies "log and monitor all access to system components and cardholder data" |
| ISO/IEC 27001:2022 A.8.15 | Logging events satisfies "information security event logging" control |
| CWE-798 | Detection events carry CWE references in their payload for vulnerability classification |

---

## Event Store (Write Model)

```sql
-- =============================================================================
-- CORE EVENT STORE
-- =============================================================================

-- Aggregates represent the entities whose lifecycle is tracked via events.
-- Each aggregate has a type and a unique ID. The version provides optimistic
-- concurrency control.

CREATE TABLE aggregates (
    aggregate_id    UUID NOT NULL,
    aggregate_type  VARCHAR(50) NOT NULL,
    -- e.g.: 'Finding', 'Incident', 'Credential', 'ScanJob', 'RotationExecution'
    current_version BIGINT NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (aggregate_type, aggregate_id)
);

-- The event store. Every state change in the system is an immutable row here.
-- This table is append-only: no UPDATE or DELETE operations.

CREATE TABLE events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Which aggregate this event belongs to
    aggregate_type  VARCHAR(50) NOT NULL,
    aggregate_id    UUID NOT NULL,
    -- Monotonically increasing version per aggregate for ordering and concurrency
    version         BIGINT NOT NULL,
    -- Event classification
    event_type      VARCHAR(100) NOT NULL,
    -- e.g.: 'SecretDetected', 'SecretVerified', 'IncidentCreated',
    --        'IncidentAssigned', 'IncidentResolved', 'CredentialRotationStarted',
    --        'CredentialRotationStepCompleted', 'CredentialRotationCompleted',
    --        'CredentialRevoked', 'SuppressionCreated', 'HoneytokenTriggered',
    --        'ScanJobStarted', 'ScanJobCompleted', 'PolicyUpdated'
    -- Event payload: all data about what happened
    data            JSONB NOT NULL,
    -- Metadata: who, when, from where
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata example:
    -- {
    --   "actor_id": "uuid",
    --   "actor_type": "user|system|api_key",
    --   "organization_id": "uuid",
    --   "ip_address": "192.168.1.1",
    --   "correlation_id": "uuid",
    --   "causation_id": "uuid"  -- the event that caused this event
    -- }
    -- OCSF alignment
    ocsf_class_uid  INT,                  -- e.g.: 2004 for Detection Finding
    ocsf_category_uid INT,                -- e.g.: 2 for Findings
    ocsf_activity_id INT,                 -- e.g.: 1=Create, 2=Update, 3=Close
    -- Timestamp
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Schema version for event payload (enables upcasting old events)
    schema_version  INT NOT NULL DEFAULT 1,
    -- Unique constraint ensures optimistic concurrency control
    UNIQUE (aggregate_type, aggregate_id, version)
);

-- Partitioned by month for storage management and query performance
-- In production: PARTITION BY RANGE (occurred_at)

CREATE INDEX idx_events_aggregate ON events(aggregate_type, aggregate_id, version);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_occurred ON events(occurred_at DESC);
CREATE INDEX idx_events_org ON events USING GIN ((metadata->'organization_id'));
CREATE INDEX idx_events_correlation ON events USING GIN ((metadata->'correlation_id'));
```

## Event Payload Examples

```sql
-- =============================================================================
-- EVENT PAYLOAD EXAMPLES
-- =============================================================================

-- SecretDetected event:
-- {
--   "scan_job_id": "uuid",
--   "scan_source_id": "uuid",
--   "secret_type": "aws_access_key",
--   "secret_type_category": "api_key",
--   "secret_hash": "sha256:abc123...",
--   "secret_display": "AKIA****3F2Q",
--   "file_path": "config/settings.py",
--   "line_number": 42,
--   "column_number": 15,
--   "commit_hash": "a1b2c3d4...",
--   "commit_author": "dev@example.com",
--   "commit_date": "2026-05-10T14:30:00Z",
--   "branch": "main",
--   "detection_rule_id": "uuid",
--   "detection_method": "regex",
--   "confidence": "high",
--   "severity": "critical",
--   "fingerprint": "sha256:def456...",
--   "cwe_id": "CWE-798",
--   "provider": "aws"
-- }

-- SecretVerified event:
-- {
--   "finding_id": "uuid",
--   "verification_method": "api_call",
--   "provider": "aws",
--   "result": "verified_active",
--   "provider_response_code": 200,
--   "verification_duration_ms": 342,
--   "credential_metadata": {
--     "iam_user": "deploy-bot",
--     "account_id": "123456789012",
--     "last_used": "2026-05-09T22:15:00Z",
--     "permissions": ["s3:*", "ec2:*"]
--   }
-- }

-- IncidentCreated event:
-- {
--   "title": "AWS Access Key leaked in config/settings.py",
--   "severity": "critical",
--   "secret_type": "aws_access_key",
--   "secret_hash": "sha256:abc123...",
--   "finding_ids": ["uuid1", "uuid2"],
--   "locations_count": 2,
--   "sla_deadline": "2026-05-11T14:30:00Z"
-- }

-- CredentialRotationStarted event:
-- {
--   "credential_id": "uuid",
--   "provider_type": "aws",
--   "trigger": "incident",
--   "linked_incident_id": "uuid",
--   "rotation_policy_id": "uuid",
--   "planned_steps": [
--     {"step": 1, "type": "generate_credential", "description": "Generate new IAM access key"},
--     {"step": 2, "type": "update_consumers", "description": "Update ECS task definitions"},
--     {"step": 3, "type": "verify_new", "description": "Verify new key works"},
--     {"step": 4, "type": "revoke_old", "description": "Deactivate old access key"}
--   ]
-- }

-- CredentialRotationStepCompleted event:
-- {
--   "execution_id": "uuid",
--   "step_order": 1,
--   "step_type": "generate_credential",
--   "result": "success",
--   "duration_ms": 1523,
--   "output": {
--     "new_key_id": "AKIA...",
--     "new_vault_path": "secret/aws/deploy-bot/v3"
--   }
-- }
```

## Materialized Views (Read Models)

```sql
-- =============================================================================
-- MATERIALIZED VIEWS (READ MODELS)
-- =============================================================================
-- These tables are projections rebuilt from events. They can be dropped and
-- rebuilt at any time by replaying the event store. They should NEVER be
-- treated as the source of truth.

-- =====================
-- Organization read model (minimal; rarely changes)
-- =====================

CREATE TABLE mv_organizations (
    id              UUID PRIMARY KEY,
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL,
    member_count    INT NOT NULL DEFAULT 0,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL     -- Track which event built this state
);

CREATE TABLE mv_users (
    id              UUID PRIMARY KEY,
    email           VARCHAR(320) NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    organization_ids UUID[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

-- =====================
-- Findings read model (optimized for dashboard queries)
-- =====================

CREATE TABLE mv_findings (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    scan_job_id     UUID NOT NULL,
    scan_source_id  UUID NOT NULL,
    scan_source_name VARCHAR(255),
    secret_type     VARCHAR(100) NOT NULL,
    secret_type_category VARCHAR(100),
    secret_hash     VARCHAR(128) NOT NULL,
    secret_display  VARCHAR(50),
    provider        VARCHAR(100),
    cwe_id          VARCHAR(20),
    -- Location
    file_path       TEXT NOT NULL,
    line_number     INT,
    commit_hash     VARCHAR(40),
    commit_author   VARCHAR(255),
    commit_date     TIMESTAMPTZ,
    branch          VARCHAR(255),
    -- Classification
    confidence      VARCHAR(20) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    verification_status VARCHAR(30) NOT NULL DEFAULT 'unverified',
    verified_at     TIMESTAMPTZ,
    -- AI context
    risk_score      NUMERIC(5,2),
    risk_context    TEXT,
    -- Deduplication
    fingerprint     VARCHAR(128) NOT NULL,
    is_duplicate    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Incident linkage
    incident_id     UUID,
    -- Timestamps
    detected_at     TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

CREATE INDEX idx_mv_findings_org ON mv_findings(organization_id);
CREATE INDEX idx_mv_findings_severity ON mv_findings(severity);
CREATE INDEX idx_mv_findings_type ON mv_findings(secret_type);
CREATE INDEX idx_mv_findings_verification ON mv_findings(verification_status);
CREATE INDEX idx_mv_findings_detected ON mv_findings(detected_at DESC);
CREATE INDEX idx_mv_findings_fingerprint ON mv_findings(fingerprint);
CREATE INDEX idx_mv_findings_incident ON mv_findings(incident_id);

-- =====================
-- Incidents read model (optimized for team workflow)
-- =====================

CREATE TABLE mv_incidents (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    secret_type     VARCHAR(100) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(50) NOT NULL,
    -- Assignment
    assigned_to_id  UUID,
    assigned_to_name VARCHAR(255),
    assigned_team_id UUID,
    assigned_team_name VARCHAR(255),
    -- Resolution
    resolution      VARCHAR(50),
    resolution_notes TEXT,
    resolved_by_id  UUID,
    resolved_by_name VARCHAR(255),
    resolved_at     TIMESTAMPTZ,
    -- SLA
    sla_deadline    TIMESTAMPTZ,
    sla_breached    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Counts
    findings_count  INT NOT NULL DEFAULT 0,
    locations_count INT NOT NULL DEFAULT 0,
    comments_count  INT NOT NULL DEFAULT 0,
    -- Timeline
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_detected_at  TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

CREATE INDEX idx_mv_incidents_org ON mv_incidents(organization_id);
CREATE INDEX idx_mv_incidents_status ON mv_incidents(status);
CREATE INDEX idx_mv_incidents_severity ON mv_incidents(severity);
CREATE INDEX idx_mv_incidents_assigned ON mv_incidents(assigned_to_id);
CREATE INDEX idx_mv_incidents_sla ON mv_incidents(sla_deadline) WHERE sla_breached = FALSE;

-- =====================
-- Credentials & Rotation read model
-- =====================

CREATE TABLE mv_credentials (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    provider_type   VARCHAR(100) NOT NULL,
    secret_type     VARCHAR(100) NOT NULL,
    provider_identity TEXT,
    status          VARCHAR(50) NOT NULL,
    environment     VARCHAR(50) NOT NULL,
    risk_level      VARCHAR(20) NOT NULL,
    -- Rotation info
    rotation_policy_name VARCHAR(255),
    last_rotated_at TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ,
    rotation_count  INT NOT NULL DEFAULT 0,
    -- Current rotation execution (if in progress)
    active_rotation_id UUID,
    active_rotation_status VARCHAR(50),
    active_rotation_step VARCHAR(100),
    -- Ownership
    owner_user_name VARCHAR(255),
    owner_team_name VARCHAR(255),
    -- Linked incidents
    linked_incident_ids UUID[] DEFAULT '{}',
    -- Timeline
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

CREATE INDEX idx_mv_credentials_org ON mv_credentials(organization_id);
CREATE INDEX idx_mv_credentials_status ON mv_credentials(status);
CREATE INDEX idx_mv_credentials_next_rotation ON mv_credentials(next_rotation_at);
CREATE INDEX idx_mv_credentials_environment ON mv_credentials(environment);

-- =====================
-- Scan Jobs read model
-- =====================

CREATE TABLE mv_scan_jobs (
    id              UUID PRIMARY KEY,
    organization_id UUID NOT NULL,
    scan_source_id  UUID NOT NULL,
    scan_source_name VARCHAR(255),
    source_type     VARCHAR(50),
    trigger_type    VARCHAR(50) NOT NULL,
    triggered_by_name VARCHAR(255),
    status          VARCHAR(50) NOT NULL,
    scan_mode       VARCHAR(50) NOT NULL,
    branch          VARCHAR(255),
    -- Statistics
    files_scanned   INT DEFAULT 0,
    lines_scanned   BIGINT DEFAULT 0,
    findings_count  INT DEFAULT 0,
    new_findings    INT DEFAULT 0,
    duration_ms     INT,
    error_message   TEXT,
    -- Timeline
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

CREATE INDEX idx_mv_scan_jobs_org ON mv_scan_jobs(organization_id);
CREATE INDEX idx_mv_scan_jobs_source ON mv_scan_jobs(scan_source_id);
CREATE INDEX idx_mv_scan_jobs_status ON mv_scan_jobs(status);
CREATE INDEX idx_mv_scan_jobs_created ON mv_scan_jobs(created_at DESC);

-- =====================
-- Dashboard statistics read model (pre-aggregated metrics)
-- =====================

CREATE TABLE mv_dashboard_stats (
    organization_id UUID NOT NULL,
    stat_date       DATE NOT NULL,
    -- Finding metrics
    total_findings  INT NOT NULL DEFAULT 0,
    new_findings    INT NOT NULL DEFAULT 0,
    verified_active INT NOT NULL DEFAULT 0,
    critical_findings INT NOT NULL DEFAULT 0,
    high_findings   INT NOT NULL DEFAULT 0,
    -- Incident metrics
    open_incidents  INT NOT NULL DEFAULT 0,
    resolved_incidents INT NOT NULL DEFAULT 0,
    mean_time_to_resolve_hours NUMERIC(10,2),
    sla_breaches    INT NOT NULL DEFAULT 0,
    -- Rotation metrics
    rotations_completed INT NOT NULL DEFAULT 0,
    rotations_failed    INT NOT NULL DEFAULT 0,
    credentials_overdue INT NOT NULL DEFAULT 0,
    -- Scan metrics
    scans_completed INT NOT NULL DEFAULT 0,
    scans_failed    INT NOT NULL DEFAULT 0,
    total_files_scanned BIGINT DEFAULT 0,
    -- Suppression metrics
    false_positives INT NOT NULL DEFAULT 0,
    suppressions_created INT NOT NULL DEFAULT 0,
    -- Updated by projection
    last_event_version BIGINT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (organization_id, stat_date)
);

-- =====================
-- Compliance evidence read model
-- =====================

CREATE TABLE mv_compliance_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    framework       VARCHAR(50) NOT NULL,  -- 'soc2', 'pci_dss_4', 'fedramp'
    control_id      VARCHAR(50) NOT NULL,  -- 'CC6.1', 'Req.10.1'
    evidence_type   VARCHAR(50) NOT NULL,
    -- Evidence details
    description     TEXT NOT NULL,
    -- Reference to the events that provide this evidence
    event_ids       UUID[] NOT NULL,
    event_time_range TSTZRANGE NOT NULL,
    -- Assessment
    status          VARCHAR(50) NOT NULL DEFAULT 'passing'
                    CHECK (status IN ('passing', 'failing', 'needs_review')),
    last_assessed_at TIMESTAMPTZ NOT NULL,
    last_event_version BIGINT NOT NULL
);

CREATE INDEX idx_mv_compliance_org ON mv_compliance_evidence(organization_id);
CREATE INDEX idx_mv_compliance_framework ON mv_compliance_evidence(framework, control_id);
```

## Projection Infrastructure

```sql
-- =============================================================================
-- PROJECTION INFRASTRUCTURE
-- =============================================================================

-- Tracks the position of each projection in the event stream.
-- Projections read events sequentially and update their position after
-- processing each batch.

CREATE TABLE projection_checkpoints (
    projection_name VARCHAR(100) PRIMARY KEY,
    -- e.g.: 'mv_findings', 'mv_incidents', 'mv_dashboard_stats', 'mv_compliance'
    last_event_id   UUID,
    last_event_version BIGINT NOT NULL DEFAULT 0,
    last_processed_at TIMESTAMPTZ,
    status          VARCHAR(50) NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'paused', 'rebuilding', 'error')),
    error_message   TEXT,
    events_processed BIGINT NOT NULL DEFAULT 0,
    lag_seconds     INT,                  -- Estimated delay behind real-time
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Snapshots allow fast aggregate hydration without replaying all events.
-- Taken periodically (e.g., every 100 events per aggregate).

CREATE TABLE aggregate_snapshots (
    aggregate_type  VARCHAR(50) NOT NULL,
    aggregate_id    UUID NOT NULL,
    version         BIGINT NOT NULL,
    state           JSONB NOT NULL,       -- Serialized aggregate state at this version
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (aggregate_type, aggregate_id, version)
);

-- Dead letter queue for events that failed projection processing

CREATE TABLE projection_dead_letters (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    projection_name VARCHAR(100) NOT NULL,
    event_id        UUID NOT NULL REFERENCES events(event_id),
    error_message   TEXT NOT NULL,
    retry_count     INT NOT NULL DEFAULT 0,
    max_retries     INT NOT NULL DEFAULT 5,
    next_retry_at   TIMESTAMPTZ,
    resolved        BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Example Queries

```sql
-- =============================================================================
-- EXAMPLE QUERIES
-- =============================================================================

-- 1. Get the full history of an incident (event replay)
SELECT event_type, data, metadata, occurred_at
FROM events
WHERE aggregate_type = 'Incident'
  AND aggregate_id = '550e8400-e29b-41d4-a716-446655440000'
ORDER BY version ASC;

-- 2. What was the state of an incident at a specific point in time?
-- (temporal query — the killer feature of event sourcing)
SELECT event_type, data, occurred_at
FROM events
WHERE aggregate_type = 'Incident'
  AND aggregate_id = '550e8400-e29b-41d4-a716-446655440000'
  AND occurred_at <= '2026-05-10T12:00:00Z'
ORDER BY version ASC;
-- Application replays these events to reconstruct state at that moment.

-- 3. Dashboard query: open incidents by severity (uses materialized view)
SELECT severity, status, COUNT(*) as count
FROM mv_incidents
WHERE organization_id = '...'
  AND status NOT IN ('resolved', 'false_positive')
GROUP BY severity, status
ORDER BY
  CASE severity
    WHEN 'critical' THEN 1
    WHEN 'high' THEN 2
    WHEN 'medium' THEN 3
    WHEN 'low' THEN 4
  END;

-- 4. Mean time to resolution over last 30 days (from pre-aggregated stats)
SELECT stat_date, mean_time_to_resolve_hours
FROM mv_dashboard_stats
WHERE organization_id = '...'
  AND stat_date >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY stat_date;

-- 5. Compliance evidence: all rotation events for PCI DSS Req. 10
SELECT e.event_type, e.data, e.occurred_at
FROM events e
WHERE e.event_type IN ('CredentialRotationStarted', 'CredentialRotationCompleted',
                        'CredentialRotationFailed', 'CredentialRevoked')
  AND e.metadata->>'organization_id' = '...'
  AND e.occurred_at >= '2026-01-01'
  AND e.occurred_at < '2026-04-01'
ORDER BY e.occurred_at;

-- 6. Find all events correlated to a single scan job
SELECT event_type, aggregate_type, aggregate_id, data, occurred_at
FROM events
WHERE metadata->>'correlation_id' = '...'
ORDER BY occurred_at;

-- 7. Projection lag monitoring
SELECT projection_name, lag_seconds, events_processed, status
FROM projection_checkpoints
ORDER BY lag_seconds DESC;
```

## Reference Data Tables

```sql
-- =============================================================================
-- REFERENCE DATA (shared between write and read sides)
-- =============================================================================

-- These tables are NOT projections. They are reference data that both the
-- command handlers and projections use. Changes are rare and applied as
-- normal CRUD operations.

CREATE TABLE ref_secret_types (
    name            VARCHAR(100) PRIMARY KEY,
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(100) NOT NULL,
    provider        VARCHAR(100),
    cwe_id          VARCHAR(20),
    detection_pattern TEXT,
    prefix_pattern  VARCHAR(50),
    supports_verification BOOLEAN NOT NULL DEFAULT FALSE,
    supports_rotation     BOOLEAN NOT NULL DEFAULT FALSE,
    severity_default VARCHAR(20) NOT NULL DEFAULT 'high'
);

CREATE TABLE ref_provider_types (
    name            VARCHAR(100) PRIMARY KEY,
    display_name    VARCHAR(255) NOT NULL,
    supports_rotation    BOOLEAN NOT NULL DEFAULT FALSE,
    supports_verification BOOLEAN NOT NULL DEFAULT FALSE,
    api_docs_url    TEXT
);

CREATE TABLE ref_compliance_controls (
    framework       VARCHAR(50) NOT NULL,
    control_id      VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    evidence_type   VARCHAR(50) NOT NULL,
    PRIMARY KEY (framework, control_id)
);
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Event Store (Write Model) | 2 | aggregates, events |
| Projection Infrastructure | 3 | projection_checkpoints, aggregate_snapshots, projection_dead_letters |
| Materialized Views (Read Models) | 8 | mv_organizations, mv_users, mv_findings, mv_incidents, mv_credentials, mv_scan_jobs, mv_dashboard_stats, mv_compliance_evidence |
| Reference Data | 3 | ref_secret_types, ref_provider_types, ref_compliance_controls |
| **Total** | **16** | Write model is just 2 tables; complexity lives in projections |

---

## Key Design Decisions

1. **Single event store table for all aggregate types.** Rather than separate event tables per entity, all events live in one table partitioned by time. This simplifies cross-aggregate queries (e.g., "show me everything that happened in the last hour") and enables unified event streaming to projections.

2. **Events carry OCSF classification.** Each event includes optional `ocsf_class_uid`, `ocsf_category_uid`, and `ocsf_activity_id` fields, enabling direct export to SIEM systems that consume OCSF-formatted events without transformation.

3. **Metadata is separated from data.** The `data` field contains domain-specific event payload. The `metadata` field contains operational context (who, where, correlation). This separation enables consistent cross-cutting concerns (audit, tracing) without polluting domain events.

4. **Correlation and causation IDs enable distributed tracing.** Every event carries a `correlation_id` (linking all events from a single user action or scan) and `causation_id` (the specific event that triggered this one). This creates a causal graph for debugging and compliance evidence.

5. **Materialized views are explicitly labeled as projections.** The `mv_` prefix and `last_event_version` column make it clear these tables are derived, not authoritative. Any view can be dropped and rebuilt by replaying events from the checkpoint.

6. **Aggregate snapshots enable fast state hydration.** Rather than replaying thousands of events to load an incident's current state, the system periodically snapshots aggregate state. Loading = fetch latest snapshot + replay events since snapshot.

7. **Dashboard statistics are pre-aggregated daily.** Rather than querying the full findings/incidents tables for dashboard metrics, the `mv_dashboard_stats` table maintains daily rollups. This eliminates expensive COUNT/GROUP BY queries on large datasets.

8. **Dead letter queue prevents projection failures from losing events.** If a projection fails to process an event (bad data, bug in projection logic), the event goes to the dead letter queue rather than blocking the entire projection pipeline.

9. **Schema versioning enables event evolution.** The `schema_version` field on each event allows the system to evolve event payloads over time. Old events are upcasted (transformed to the current schema) during replay, avoiding the need to migrate historical data.

10. **Temporal queries are the primary advantage over Model 1.** Questions like "what secrets were exposed on March 15?" or "what was the incident severity when the SOC analyst first saw it?" are answered by replaying events to that timestamp — something impossible with a mutable relational model without separate audit logging.
