# Data Model Suggestion 1: Entity-Centric Normalized Relational

> Project: Secret Scanner & Rotation Manager · Created: 2026-05-11

## Philosophy

The entity-centric normalized relational model treats every domain concept as a first-class table with explicit foreign key relationships and strict referential integrity. Every secret finding, credential, rotation action, scan job, and policy gets its own table with well-defined columns and constraints. This is the approach used by enterprise security platforms like GitGuardian and CyberArk Conjur, where data integrity and cross-entity querying are paramount.

The design follows Third Normal Form (3NF) throughout, with junction tables for many-to-many relationships and explicit enum tables for classification taxonomies. Reference data (secret types, provider types, severity levels) is stored in lookup tables rather than application-level constants, making the schema self-documenting and enabling database-level constraint enforcement.

This approach prioritizes query flexibility and data integrity over write performance. Any question about the system state can be answered with standard SQL joins, and the database enforces business rules through constraints and foreign keys rather than relying on application logic.

**Best for:** Regulated environments (SOC 2, PCI-DSS, FedRAMP) where data integrity, auditability, and complex cross-entity reporting are essential.

**Trade-offs:**
- Pro: Strong referential integrity prevents orphaned records and inconsistent state
- Pro: Standard SQL queries can answer any business question without custom logic
- Pro: Well-understood by most development teams; extensive tooling support
- Pro: Schema is self-documenting; new developers can understand the domain from DDL alone
- Con: Higher table count increases migration complexity (40+ tables)
- Con: Schema changes require migrations for every new credential type or provider
- Con: Many JOIN operations required for common queries may impact read performance at scale
- Con: Provider-specific fields require either nullable columns or additional tables per provider

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF Detection Finding (class_uid 2004) | Finding table structure aligns with OCSF attributes: confidence_id, risk_level_id, severity_id, activity_id |
| SARIF v2.1.0 | Scan results export maps directly from finding/rule/scan tables to SARIF runs/results/rules structure |
| CWE-798 / CWE-522 | Secret type taxonomy includes CWE references for each detection pattern |
| OWASP Secrets Management Cheat Sheet | Credential lifecycle states (active/rotating/revoked/expired) follow OWASP recommendations |
| GitHub Secret Scanning API | Finding schema mirrors GitHub alert fields: secret_type, validity, state, resolution |
| ISO/IEC 27001:2022 | Audit log tables support evidence collection for ISMS certification |
| NIST SP 800-63B | Rotation policies support risk-based rotation (on compromise detection) rather than mandatory periodic rotation |
| PCI DSS 4.0 | Credential access logging and rotation evidence satisfy PCI credential management requirements |
| OAuth 2.0 (RFC 6749) | Credential type taxonomy includes OAuth token types; verification follows OAuth introspection patterns |

---

## Organization & Multi-Tenancy

```sql
-- =============================================================================
-- ORGANIZATION & MULTI-TENANCY
-- =============================================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free'
                    CHECK (plan IN ('free', 'team', 'business', 'enterprise')),
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(320) NOT NULL UNIQUE,  -- RFC 5321 max email length
    display_name    VARCHAR(255) NOT NULL,
    avatar_url      TEXT,
    auth_provider   VARCHAR(50) NOT NULL DEFAULT 'local'
                    CHECK (auth_provider IN ('local', 'github', 'gitlab', 'google', 'saml', 'oidc')),
    auth_provider_id VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(50) NOT NULL DEFAULT 'member'
                    CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    invited_by      UUID REFERENCES users(id),
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_org_members_org ON organization_members(organization_id);
CREATE INDEX idx_org_members_user ON organization_members(user_id);

CREATE TABLE teams (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, name)
);

CREATE TABLE team_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(50) NOT NULL DEFAULT 'member'
                    CHECK (role IN ('lead', 'member')),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, user_id)
);
```

## Scan Sources & Configuration

```sql
-- =============================================================================
-- SCAN SOURCES & CONFIGURATION
-- =============================================================================

CREATE TABLE source_types (
    id              SMALLINT PRIMARY KEY,
    name            VARCHAR(50) NOT NULL UNIQUE,
    -- e.g.: 'git_repository', 'docker_image', 's3_bucket', 'slack_workspace',
    --        'jira_project', 'confluence_space', 'ci_environment', 'filesystem'
    category        VARCHAR(50) NOT NULL
                    CHECK (category IN ('code', 'cloud_storage', 'collaboration', 'ci_cd', 'filesystem'))
);

CREATE TABLE scan_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_type_id  SMALLINT NOT NULL REFERENCES source_types(id),
    name            VARCHAR(255) NOT NULL,
    -- Canonical identifier: repo URL, bucket ARN, Slack workspace ID, etc.
    external_id     TEXT NOT NULL,
    connection_config JSONB NOT NULL DEFAULT '{}',
    -- Encrypted connection credentials stored separately
    credential_vault_ref VARCHAR(500),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_scanned_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, source_type_id, external_id)
);

CREATE INDEX idx_scan_sources_org ON scan_sources(organization_id);
CREATE INDEX idx_scan_sources_type ON scan_sources(source_type_id);

CREATE TABLE scan_source_teams (
    scan_source_id  UUID NOT NULL REFERENCES scan_sources(id) ON DELETE CASCADE,
    team_id         UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    PRIMARY KEY (scan_source_id, team_id)
);
```

## Detection Rules & Secret Types

```sql
-- =============================================================================
-- DETECTION RULES & SECRET TYPES
-- =============================================================================

CREATE TABLE secret_type_categories (
    id              SMALLINT PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE
    -- e.g.: 'api_key', 'oauth_token', 'password', 'private_key', 'certificate',
    --        'connection_string', 'webhook_url', 'encryption_key'
);

CREATE TABLE secret_types (
    id              SERIAL PRIMARY KEY,
    category_id     SMALLINT NOT NULL REFERENCES secret_type_categories(id),
    name            VARCHAR(100) NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL,
    -- e.g.: 'aws_access_key', 'github_pat', 'stripe_secret_key', 'slack_webhook'
    provider        VARCHAR(100),         -- e.g.: 'aws', 'github', 'stripe'
    cwe_id          VARCHAR(20),          -- e.g.: 'CWE-798'
    description     TEXT,
    -- Regex pattern for initial detection
    detection_pattern TEXT,
    -- Pattern for prefix matching (e.g., 'AKIA' for AWS access keys)
    prefix_pattern  VARCHAR(50),
    -- Whether this type supports live verification via provider API
    supports_verification BOOLEAN NOT NULL DEFAULT FALSE,
    -- Whether this type supports automated rotation
    supports_rotation     BOOLEAN NOT NULL DEFAULT FALSE,
    severity_default VARCHAR(20) NOT NULL DEFAULT 'high'
                    CHECK (severity_default IN ('critical', 'high', 'medium', 'low', 'info')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secret_types_category ON secret_types(category_id);
CREATE INDEX idx_secret_types_provider ON secret_types(provider);

CREATE TABLE detection_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL organization_id = built-in system rule
    secret_type_id  INT REFERENCES secret_types(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    rule_type       VARCHAR(50) NOT NULL
                    CHECK (rule_type IN ('regex', 'entropy', 'semantic', 'ml_classifier', 'composite')),
    -- Rule definition: regex pattern, entropy threshold, or ML model reference
    rule_definition JSONB NOT NULL,
    severity        VARCHAR(20) NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    false_positive_rate NUMERIC(5,4),     -- Tracked precision from production use
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detection_rules_org ON detection_rules(organization_id);
CREATE INDEX idx_detection_rules_type ON detection_rules(secret_type_id);

CREATE TABLE detection_rule_allowlist (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES detection_rules(id) ON DELETE CASCADE,
    -- Allowlist entry: file path pattern, content hash, or specific value hash
    allowlist_type  VARCHAR(50) NOT NULL
                    CHECK (allowlist_type IN ('file_path', 'content_hash', 'value_hash', 'line_pattern')),
    pattern         TEXT NOT NULL,
    reason          TEXT,
    created_by      UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## Scan Jobs & Execution

```sql
-- =============================================================================
-- SCAN JOBS & EXECUTION
-- =============================================================================

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_source_id  UUID NOT NULL REFERENCES scan_sources(id) ON DELETE CASCADE,
    -- What triggered this scan
    trigger_type    VARCHAR(50) NOT NULL
                    CHECK (trigger_type IN ('manual', 'scheduled', 'webhook', 'pre_commit', 'ci_pipeline')),
    triggered_by    UUID REFERENCES users(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    -- Scan scope
    scan_mode       VARCHAR(50) NOT NULL DEFAULT 'incremental'
                    CHECK (scan_mode IN ('full', 'incremental', 'commit_range', 'pr_diff')),
    -- For git sources: commit range
    start_commit    VARCHAR(40),
    end_commit      VARCHAR(40),
    branch          VARCHAR(255),
    -- Scan statistics
    files_scanned   INT DEFAULT 0,
    lines_scanned   BIGINT DEFAULT 0,
    findings_count  INT DEFAULT 0,
    duration_ms     INT,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_org ON scan_jobs(organization_id);
CREATE INDEX idx_scan_jobs_source ON scan_jobs(scan_source_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_created ON scan_jobs(created_at DESC);
```

## Findings & Incidents

```sql
-- =============================================================================
-- FINDINGS & INCIDENTS
-- =============================================================================

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_job_id     UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    scan_source_id  UUID NOT NULL REFERENCES scan_sources(id),
    secret_type_id  INT NOT NULL REFERENCES secret_types(id),
    detection_rule_id UUID REFERENCES detection_rules(id),
    -- Finding location
    file_path       TEXT NOT NULL,
    line_number     INT,
    column_number   INT,
    commit_hash     VARCHAR(40),
    commit_author   VARCHAR(255),
    commit_date     TIMESTAMPTZ,
    branch          VARCHAR(255),
    -- The detected secret (stored as a salted hash, NEVER plaintext)
    secret_hash     VARCHAR(128) NOT NULL,
    -- First and last N characters for display (e.g., "AKIA****3F2Q")
    secret_display  VARCHAR(50),
    -- Detection confidence
    confidence      VARCHAR(20) NOT NULL DEFAULT 'medium'
                    CHECK (confidence IN ('critical', 'high', 'medium', 'low')),
    -- OCSF-aligned severity
    severity        VARCHAR(20) NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    -- Verification status: did we confirm the credential is live?
    verification_status VARCHAR(30) NOT NULL DEFAULT 'unverified'
                    CHECK (verification_status IN ('unverified', 'verified_active', 'verified_inactive',
                                                    'verification_failed', 'verification_unsupported')),
    verified_at     TIMESTAMPTZ,
    -- AI-generated context assessment
    risk_context    TEXT,                 -- LLM explanation of risk level
    risk_score      NUMERIC(5,2),         -- 0.00-100.00 computed risk score
    -- Deduplication: same secret in same location
    fingerprint     VARCHAR(128) NOT NULL,
    is_duplicate    BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_of    UUID REFERENCES findings(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_org ON findings(organization_id);
CREATE INDEX idx_findings_scan ON findings(scan_job_id);
CREATE INDEX idx_findings_source ON findings(scan_source_id);
CREATE INDEX idx_findings_type ON findings(secret_type_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_verification ON findings(verification_status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_created ON findings(created_at DESC);

-- Incidents aggregate one or more findings of the same secret
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  INT NOT NULL REFERENCES secret_types(id),
    -- The shared secret hash that groups findings into this incident
    secret_hash     VARCHAR(128) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'high'
                    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    status          VARCHAR(50) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'ignored')),
    -- Assignment
    assigned_to     UUID REFERENCES users(id),
    assigned_team   UUID REFERENCES teams(id),
    -- Resolution details
    resolution      VARCHAR(50)
                    CHECK (resolution IN ('rotated', 'revoked', 'false_positive', 'accepted_risk', 'duplicate')),
    resolution_notes TEXT,
    resolved_by     UUID REFERENCES users(id),
    resolved_at     TIMESTAMPTZ,
    -- SLA tracking
    sla_deadline    TIMESTAMPTZ,
    sla_breached    BOOLEAN NOT NULL DEFAULT FALSE,
    -- Counts
    findings_count  INT NOT NULL DEFAULT 1,
    locations_count INT NOT NULL DEFAULT 1,
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_detected_at  TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_org ON incidents(organization_id);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_assigned ON incidents(assigned_to);
CREATE INDEX idx_incidents_secret_hash ON incidents(organization_id, secret_hash);

CREATE TABLE incident_findings (
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, finding_id)
);

CREATE TABLE incident_comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id       UUID NOT NULL REFERENCES users(id),
    body            TEXT NOT NULL,
    is_system       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incident_comments_incident ON incident_comments(incident_id);
```

## Credential Management & Rotation

```sql
-- =============================================================================
-- CREDENTIAL MANAGEMENT & ROTATION
-- =============================================================================

CREATE TABLE provider_types (
    id              SMALLINT PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE,
    -- e.g.: 'aws', 'azure', 'gcp', 'github', 'gitlab', 'stripe', 'slack',
    --        'postgresql', 'mysql', 'mongodb', 'redis', 'custom'
    display_name    VARCHAR(255) NOT NULL,
    supports_rotation    BOOLEAN NOT NULL DEFAULT FALSE,
    supports_verification BOOLEAN NOT NULL DEFAULT FALSE,
    api_docs_url    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE managed_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_type_id SMALLINT NOT NULL REFERENCES provider_types(id),
    secret_type_id  INT NOT NULL REFERENCES secret_types(id),
    -- Human-readable name for this credential
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    -- External identifier at the provider (IAM user ARN, service account email, etc.)
    provider_identity TEXT,
    -- Current lifecycle state
    status          VARCHAR(50) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'rotating', 'rotated', 'revoked', 'expired', 'pending_rotation')),
    -- Environment classification
    environment     VARCHAR(50) NOT NULL DEFAULT 'unknown'
                    CHECK (environment IN ('production', 'staging', 'development', 'test', 'unknown')),
    -- Risk metadata
    risk_level      VARCHAR(20) NOT NULL DEFAULT 'medium'
                    CHECK (risk_level IN ('critical', 'high', 'medium', 'low')),
    -- Vault reference for current credential value (never stored here)
    vault_path      VARCHAR(500),
    -- Rotation schedule
    rotation_policy_id UUID REFERENCES rotation_policies(id),
    last_rotated_at TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    -- Link to incident that triggered management
    linked_incident_id UUID REFERENCES incidents(id),
    -- Ownership
    owner_user_id   UUID REFERENCES users(id),
    owner_team_id   UUID REFERENCES teams(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_managed_creds_org ON managed_credentials(organization_id);
CREATE INDEX idx_managed_creds_provider ON managed_credentials(provider_type_id);
CREATE INDEX idx_managed_creds_status ON managed_credentials(status);
CREATE INDEX idx_managed_creds_next_rotation ON managed_credentials(next_rotation_at);
CREATE INDEX idx_managed_creds_environment ON managed_credentials(environment);

CREATE TABLE rotation_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    -- Rotation trigger: time-based, on-detection, or manual
    trigger_type    VARCHAR(50) NOT NULL
                    CHECK (trigger_type IN ('scheduled', 'on_detection', 'manual', 'on_expiry')),
    -- For scheduled: interval in hours
    rotation_interval_hours INT,
    -- Whether to auto-execute or require approval
    requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
    -- Number of approvers required
    approvers_required INT NOT NULL DEFAULT 1,
    -- Grace period after rotation before old credential is revoked (hours)
    grace_period_hours INT NOT NULL DEFAULT 24,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE rotation_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   UUID NOT NULL REFERENCES managed_credentials(id) ON DELETE CASCADE,
    policy_id       UUID REFERENCES rotation_policies(id),
    -- What triggered this rotation
    trigger         VARCHAR(50) NOT NULL
                    CHECK (trigger IN ('scheduled', 'incident', 'manual', 'policy', 'expiry')),
    triggered_by    UUID REFERENCES users(id),
    linked_incident_id UUID REFERENCES incidents(id),
    -- Execution state machine
    status          VARCHAR(50) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'awaiting_approval', 'approved', 'executing',
                                      'verifying', 'completed', 'failed', 'rolled_back', 'cancelled')),
    -- Step tracking
    current_step    VARCHAR(100),
    total_steps     INT,
    completed_steps INT DEFAULT 0,
    -- Provider interaction details
    provider_request_id VARCHAR(255),
    -- Old credential reference (for rollback)
    old_vault_path  VARCHAR(500),
    new_vault_path  VARCHAR(500),
    -- Timing
    approved_at     TIMESTAMPTZ,
    approved_by     UUID REFERENCES users(id),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    -- Error handling
    error_message   TEXT,
    retry_count     INT NOT NULL DEFAULT 0,
    max_retries     INT NOT NULL DEFAULT 3,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rotation_exec_credential ON rotation_executions(credential_id);
CREATE INDEX idx_rotation_exec_status ON rotation_executions(status);
CREATE INDEX idx_rotation_exec_created ON rotation_executions(created_at DESC);

CREATE TABLE rotation_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_id    UUID NOT NULL REFERENCES rotation_executions(id) ON DELETE CASCADE,
    step_order      INT NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    -- Step type: api_call, notification, verification, wait, approval
    step_type       VARCHAR(50) NOT NULL
                    CHECK (step_type IN ('generate_credential', 'update_provider', 'update_consumers',
                                         'verify_new', 'revoke_old', 'notify', 'wait', 'approval')),
    status          VARCHAR(50) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    -- Input/output for this step
    input_data      JSONB,
    output_data     JSONB,
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_ms     INT
);

CREATE INDEX idx_rotation_steps_execution ON rotation_steps(execution_id);
```

## Suppression & Allowlisting

```sql
-- =============================================================================
-- SUPPRESSION & ALLOWLISTING
-- =============================================================================

CREATE TABLE suppressions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- What to suppress: specific finding, file pattern, secret type, etc.
    suppression_type VARCHAR(50) NOT NULL
                    CHECK (suppression_type IN ('finding', 'file_pattern', 'secret_type',
                                                'repository', 'content_hash')),
    -- The target of suppression (fingerprint, glob pattern, secret_type name, etc.)
    target_value    TEXT NOT NULL,
    -- Scope: organization-wide or specific source
    scan_source_id  UUID REFERENCES scan_sources(id),
    reason          TEXT NOT NULL,
    classification  VARCHAR(50) NOT NULL DEFAULT 'false_positive'
                    CHECK (classification IN ('false_positive', 'test_credential', 'accepted_risk',
                                              'not_applicable', 'mitigated')),
    -- Expiration for time-limited suppressions
    expires_at      TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_suppressions_org ON suppressions(organization_id);
CREATE INDEX idx_suppressions_type ON suppressions(suppression_type);
CREATE INDEX idx_suppressions_active ON suppressions(is_active) WHERE is_active = TRUE;
```

## Honeytokens

```sql
-- =============================================================================
-- HONEYTOKENS / CANARY CREDENTIALS
-- =============================================================================

CREATE TABLE honeytokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  INT NOT NULL REFERENCES secret_types(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    -- Where the honeytoken is planted
    planted_location TEXT NOT NULL,
    planted_source_id UUID REFERENCES scan_sources(id),
    -- The honeytoken value (hashed)
    token_hash      VARCHAR(128) NOT NULL,
    -- Monitoring endpoint for detecting use
    callback_url    TEXT,
    -- Status
    status          VARCHAR(50) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'triggered', 'expired', 'disabled')),
    triggered_at    TIMESTAMPTZ,
    trigger_details JSONB,
    expires_at      TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_honeytokens_org ON honeytokens(organization_id);
CREATE INDEX idx_honeytokens_status ON honeytokens(status);
CREATE INDEX idx_honeytokens_hash ON honeytokens(token_hash);
```

## Audit Log

```sql
-- =============================================================================
-- AUDIT LOG
-- =============================================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    -- Who performed the action
    actor_id        UUID REFERENCES users(id),
    actor_type      VARCHAR(50) NOT NULL DEFAULT 'user'
                    CHECK (actor_type IN ('user', 'system', 'api_key', 'webhook')),
    -- What happened (OCSF activity_id alignment)
    action          VARCHAR(100) NOT NULL,
    -- e.g.: 'finding.created', 'incident.resolved', 'credential.rotated',
    --        'suppression.created', 'scan.started', 'policy.updated'
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     UUID NOT NULL,
    -- Change details
    changes         JSONB,               -- { field: { old: ..., new: ... } }
    metadata        JSONB,               -- Additional context (IP, user agent, etc.)
    -- Request context
    ip_address      INET,
    user_agent      TEXT,
    api_key_id      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partitioned by month for query performance and retention management
-- In production, use: PARTITION BY RANGE (created_at)

CREATE INDEX idx_audit_log_org ON audit_log(organization_id);
CREATE INDEX idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
```

## Notifications & Integrations

```sql
-- =============================================================================
-- NOTIFICATIONS & INTEGRATIONS
-- =============================================================================

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    channel_type    VARCHAR(50) NOT NULL
                    CHECK (channel_type IN ('email', 'slack', 'webhook', 'pagerduty', 'jira', 'teams')),
    name            VARCHAR(255) NOT NULL,
    config          JSONB NOT NULL,       -- Channel-specific config (webhook URL, Slack channel, etc.)
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notification_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    channel_id      UUID NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    -- Trigger conditions
    event_type      VARCHAR(100) NOT NULL,
    -- e.g.: 'finding.critical', 'incident.created', 'rotation.failed', 'honeytoken.triggered'
    min_severity    VARCHAR(20) DEFAULT 'medium'
                    CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    filter_conditions JSONB,              -- Additional filters (source, team, etc.)
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id),
    channel_id      UUID NOT NULL REFERENCES notification_channels(id),
    rule_id         UUID REFERENCES notification_rules(id),
    -- What triggered the notification
    event_type      VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     UUID NOT NULL,
    -- Delivery
    status          VARCHAR(50) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sent', 'delivered', 'failed', 'suppressed')),
    payload         JSONB NOT NULL,
    error_message   TEXT,
    sent_at         TIMESTAMPTZ,
    delivered_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_org ON notifications(organization_id);
CREATE INDEX idx_notifications_status ON notifications(status);
```

## Compliance Reporting

```sql
-- =============================================================================
-- COMPLIANCE REPORTING
-- =============================================================================

CREATE TABLE compliance_frameworks (
    id              SMALLINT PRIMARY KEY,
    name            VARCHAR(100) NOT NULL UNIQUE,
    -- e.g.: 'soc2', 'pci_dss_4', 'fedramp_moderate', 'iso_27001', 'hipaa'
    display_name    VARCHAR(255) NOT NULL,
    version         VARCHAR(50)
);

CREATE TABLE compliance_controls (
    id              SERIAL PRIMARY KEY,
    framework_id    SMALLINT NOT NULL REFERENCES compliance_frameworks(id),
    control_id      VARCHAR(50) NOT NULL,  -- e.g.: 'CC6.1' for SOC 2
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    -- How this platform provides evidence for this control
    evidence_type   VARCHAR(50) NOT NULL
                    CHECK (evidence_type IN ('scan_coverage', 'rotation_compliance', 'access_log',
                                             'incident_response', 'policy_enforcement')),
    UNIQUE (framework_id, control_id)
);

CREATE TABLE compliance_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    framework_id    SMALLINT NOT NULL REFERENCES compliance_frameworks(id),
    report_period_start DATE NOT NULL,
    report_period_end   DATE NOT NULL,
    -- Computed metrics
    total_controls  INT NOT NULL,
    passing_controls INT NOT NULL,
    failing_controls INT NOT NULL,
    compliance_score NUMERIC(5,2),        -- Percentage
    report_data     JSONB NOT NULL,       -- Full report content
    generated_by    UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_compliance_reports_org ON compliance_reports(organization_id);
```

## API Keys

```sql
-- =============================================================================
-- API KEYS (for platform access)
-- =============================================================================

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by      UUID NOT NULL REFERENCES users(id),
    name            VARCHAR(255) NOT NULL,
    -- Prefix for display (e.g., "sk_live_abc1")
    key_prefix      VARCHAR(20) NOT NULL,
    -- Hashed key value (bcrypt or argon2)
    key_hash        VARCHAR(255) NOT NULL,
    -- Scoped permissions
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    -- Rate limiting
    rate_limit_per_minute INT DEFAULT 60,
    -- Lifecycle
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_org ON api_keys(organization_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Organization & Multi-Tenancy | 5 | organizations, users, organization_members, teams, team_members |
| Scan Sources & Configuration | 3 | source_types, scan_sources, scan_source_teams |
| Detection Rules & Secret Types | 4 | secret_type_categories, secret_types, detection_rules, detection_rule_allowlist |
| Scan Jobs | 1 | scan_jobs |
| Findings & Incidents | 4 | findings, incidents, incident_findings, incident_comments |
| Credential Management & Rotation | 4 | managed_credentials, rotation_policies, rotation_executions, rotation_steps |
| Provider Types | 1 | provider_types |
| Suppression | 1 | suppressions |
| Honeytokens | 1 | honeytokens |
| Audit Log | 1 | audit_log |
| Notifications | 3 | notification_channels, notification_rules, notifications |
| Compliance | 3 | compliance_frameworks, compliance_controls, compliance_reports |
| API Keys | 1 | api_keys |
| **Total** | **32** | |

---

## Key Design Decisions

1. **Secret values are NEVER stored in the database.** The `secret_hash` column stores a one-way hash for deduplication and grouping; the `secret_display` column stores a masked prefix/suffix for UI display. Actual credential values are stored in an external vault (HashiCorp Vault, AWS Secrets Manager, or equivalent) referenced by `vault_path`.

2. **Findings and incidents are separate entities.** A finding is a single detection of a secret at a specific location. An incident groups multiple findings of the same secret across locations. This mirrors GitGuardian's model and aligns with OCSF's distinction between detection events and aggregated findings.

3. **Rotation is modeled as a state machine.** Each `rotation_execution` progresses through a defined set of states (pending -> approved -> executing -> verifying -> completed), with individual `rotation_steps` tracking each provider interaction. This supports both automated and approval-gated workflows.

4. **Secret type taxonomy is table-driven, not hardcoded.** The `secret_types` table with `secret_type_categories` enables adding new detection patterns without schema changes. Each type references its CWE identifier for compliance mapping.

5. **Multi-tenant isolation uses organization_id foreign keys.** Rather than schema-per-tenant or RLS, the model uses explicit foreign keys on every data table. This supports cross-tenant admin queries while keeping tenant isolation enforced at the application layer. PostgreSQL RLS can be layered on top for defense-in-depth.

6. **Audit log is designed for partitioning.** The `audit_log` table should be partitioned by `created_at` month in production to manage retention and query performance. The JSONB `changes` column captures before/after state for every mutation.

7. **Suppression is decoupled from detection rules.** Rather than modifying rules to exclude false positives, the `suppressions` table provides an auditable record of what was suppressed, why, and by whom. Suppressions can expire, requiring re-evaluation.

8. **Compliance mapping is built into the schema.** The `compliance_frameworks` / `compliance_controls` tables provide a direct mapping between platform capabilities and regulatory requirements, enabling automated compliance report generation.

9. **Provider types are separated from secret types.** A provider (AWS) can have multiple secret types (access key, session token, STS credential). A secret type (API key) can appear across multiple providers. This many-to-many semantic is captured through the separate tables without a junction table, since secret_types already reference their provider.

10. **Notification rules use event-type filtering.** Rather than hardcoded notification triggers, the `notification_rules` table allows organizations to configure which events generate alerts on which channels, with severity-based filtering and custom conditions via JSONB.
