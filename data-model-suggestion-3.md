# Data Model Suggestion 3: Hybrid Relational + JSONB

> Project: Secret Scanner & Rotation Manager · Created: 2026-05-11

## Philosophy

The hybrid model uses normalized relational tables for core entities that are queried frequently and have stable schemas, while leveraging PostgreSQL JSONB columns for data that varies by provider, secret type, or integration. This is the approach taken by modern SaaS platforms like Infisical, Doppler, and GitGuardian's backend, where the core workflow (detect, triage, rotate) is well-defined but the specifics vary enormously — an AWS access key rotation looks nothing like a Stripe API key rotation, and a Slack webhook scan produces different metadata than a git commit scan.

The key insight is that secret scanning and rotation is a domain where the "shape" of data varies across two dimensions: (1) the type of secret being detected (150+ types, each with different attributes), and (2) the provider where rotation happens (AWS, Azure, GCP, databases — each with different APIs, field names, and workflows). A fully normalized model would require either hundreds of type-specific tables or wide tables with mostly-NULL columns. The JSONB hybrid avoids both extremes by normalizing the workflow structure while keeping type-specific details flexible.

This approach enables rapid MVP development — new secret types and providers can be added by extending JSONB schemas without database migrations. It also naturally handles multi-region and jurisdiction-specific variations, where different deployments may need different metadata fields.

**Best for:** Teams prioritizing rapid iteration and feature velocity, deploying across multiple cloud providers where provider-specific metadata varies widely, or building an MVP that needs to support 100+ secret types without 100+ tables.

**Trade-offs:**
- Pro: New secret types and providers added without schema migrations
- Pro: Lower table count (18 vs. 32 in the normalized model) reduces migration complexity
- Pro: Provider-specific rotation steps stored as JSONB templates — no code changes for new providers
- Pro: JSONB GIN indexes enable fast filtering on variable attributes
- Pro: Natural fit for API responses — JSONB columns map directly to JSON API payloads
- Con: JSONB data lacks database-level type enforcement — validation must be in application code or JSON Schema
- Con: JSONB fields cannot have foreign key constraints — referential integrity for nested data is application-managed
- Con: Complex JSONB queries can be slower than equivalent normalized JOINs at scale
- Con: Schema documentation requires JSON Schema specs alongside DDL — two sources of truth
- Con: Harder to generate compliance reports that need to enumerate all possible field values

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF Detection Finding | Finding `detection_context` JSONB stores OCSF-aligned attributes; export maps directly to OCSF |
| SARIF v2.1.0 | Scan results stored with SARIF-compatible structure in `scan_results` JSONB; native export |
| JSON Schema (draft 2020-12) | Each JSONB column has a corresponding JSON Schema for application-level validation |
| CWE-798 / CWE-522 | Secret type definitions include CWE mappings in the `metadata` JSONB field |
| OpenAPI 3.2.0 | JSONB columns align with OpenAPI component schemas for API response generation |
| OAuth 2.0 (RFC 6749) | Provider connection configs store OAuth client credentials and token endpoints in JSONB |
| NIST SP 800-63B | Rotation policy configurations stored as JSONB support risk-based rotation parameters |
| PCI DSS 4.0 | Audit entries in JSONB format satisfy logging requirements with flexible field capture |

---

## Organization & Access Control

```sql
-- =============================================================================
-- ORGANIZATION & ACCESS CONTROL
-- =============================================================================

CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free',
    -- All org settings in one place: SSO config, notification defaults,
    -- scan schedules, retention policies, etc.
    settings        JSONB NOT NULL DEFAULT '{}',
    -- settings example:
    -- {
    --   "sso": { "provider": "okta", "domain": "example.com", "entity_id": "..." },
    --   "defaults": {
    --     "scan_schedule": "0 2 * * *",
    --     "sla_hours": { "critical": 4, "high": 24, "medium": 72 },
    --     "retention_days": 365
    --   },
    --   "features": { "ai_classification": true, "collaboration_scanning": true }
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(320) NOT NULL UNIQUE,
    display_name    VARCHAR(255) NOT NULL,
    auth            JSONB NOT NULL DEFAULT '{}',
    -- auth example:
    -- {
    --   "provider": "github",
    --   "provider_id": "12345",
    --   "avatar_url": "https://...",
    --   "mfa_enabled": true
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memberships (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            VARCHAR(50) NOT NULL DEFAULT 'member',
    -- Granular permissions beyond role (overrides)
    permissions     JSONB NOT NULL DEFAULT '{}',
    -- permissions example:
    -- {
    --   "can_manage_credentials": true,
    --   "can_approve_rotations": true,
    --   "can_suppress_findings": false,
    --   "restricted_sources": ["uuid1", "uuid2"]
    -- }
    team_ids        UUID[] NOT NULL DEFAULT '{}',
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

CREATE INDEX idx_memberships_org ON memberships(organization_id);
CREATE INDEX idx_memberships_user ON memberships(user_id);
```

## Scan Sources

```sql
-- =============================================================================
-- SCAN SOURCES
-- =============================================================================

CREATE TABLE scan_sources (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_type     VARCHAR(50) NOT NULL
                    CHECK (source_type IN ('git_repository', 'docker_image', 's3_bucket',
                                           'slack_workspace', 'jira_project', 'confluence_space',
                                           'ci_environment', 'gcs_bucket', 'azure_blob', 'filesystem')),
    name            VARCHAR(255) NOT NULL,
    external_id     TEXT NOT NULL,         -- repo URL, bucket ARN, workspace ID
    -- All source-specific configuration lives in JSONB
    config          JSONB NOT NULL DEFAULT '{}',
    -- config examples by source_type:
    --
    -- git_repository:
    -- {
    --   "url": "https://github.com/org/repo",
    --   "default_branch": "main",
    --   "scan_branches": ["main", "develop"],
    --   "exclude_paths": ["vendor/", "*.min.js"],
    --   "webhook_secret_hash": "sha256:...",
    --   "auth": { "type": "app_installation", "installation_id": 12345 }
    -- }
    --
    -- slack_workspace:
    -- {
    --   "workspace_id": "T012345",
    --   "workspace_name": "Example Corp",
    --   "channels": ["general", "engineering", "deployments"],
    --   "scan_dms": false,
    --   "auth": { "type": "bot_token", "vault_ref": "secret/slack/bot-token" }
    -- }
    --
    -- s3_bucket:
    -- {
    --   "bucket_name": "config-backup",
    --   "region": "us-east-1",
    --   "prefix_filter": "configs/",
    --   "auth": { "type": "iam_role", "role_arn": "arn:aws:iam::role/scanner" }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_scanned_at TIMESTAMPTZ,
    -- Cached scan statistics
    stats           JSONB NOT NULL DEFAULT '{}',
    -- { "total_scans": 42, "total_findings": 15, "last_finding_at": "..." }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, source_type, external_id)
);

CREATE INDEX idx_scan_sources_org ON scan_sources(organization_id);
CREATE INDEX idx_scan_sources_type ON scan_sources(source_type);
CREATE INDEX idx_scan_sources_config ON scan_sources USING GIN (config);
```

## Detection Configuration

```sql
-- =============================================================================
-- DETECTION CONFIGURATION
-- =============================================================================

-- Secret types are reference data stored as rows with JSONB for type-specific
-- attributes. This replaces the need for separate tables per secret category.

CREATE TABLE secret_types (
    id              VARCHAR(100) PRIMARY KEY,
    -- e.g.: 'aws_access_key', 'github_pat', 'stripe_secret_key', 'slack_webhook'
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(50) NOT NULL
                    CHECK (category IN ('api_key', 'oauth_token', 'password', 'private_key',
                                        'certificate', 'connection_string', 'webhook_url',
                                        'encryption_key', 'session_token', 'other')),
    provider        VARCHAR(100),
    severity_default VARCHAR(20) NOT NULL DEFAULT 'high',
    -- All detection and verification config in JSONB
    detection       JSONB NOT NULL DEFAULT '{}',
    -- detection example:
    -- {
    --   "patterns": [
    --     { "type": "regex", "pattern": "AKIA[0-9A-Z]{16}", "confidence": "high" },
    --     { "type": "entropy", "min_entropy": 4.5, "min_length": 20 }
    --   ],
    --   "prefix": "AKIA",
    --   "cwe_id": "CWE-798",
    --   "false_positive_hints": ["example", "test", "dummy", "placeholder"]
    -- }
    verification    JSONB NOT NULL DEFAULT '{}',
    -- verification example:
    -- {
    --   "supported": true,
    --   "method": "api_call",
    --   "endpoint": "https://sts.amazonaws.com/?Action=GetCallerIdentity",
    --   "auth_header": "AWS4-HMAC-SHA256",
    --   "success_indicators": ["GetCallerIdentityResponse"],
    --   "timeout_ms": 5000
    -- }
    rotation        JSONB NOT NULL DEFAULT '{}',
    -- rotation example:
    -- {
    --   "supported": true,
    --   "steps_template": [
    --     { "step": 1, "type": "generate_credential", "api": "iam:CreateAccessKey" },
    --     { "step": 2, "type": "update_consumers", "description": "Update services" },
    --     { "step": 3, "type": "verify_new", "api": "sts:GetCallerIdentity" },
    --     { "step": 4, "type": "revoke_old", "api": "iam:DeleteAccessKey" }
    --   ],
    --   "estimated_duration_minutes": 15,
    --   "rollback_supported": true
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_secret_types_category ON secret_types(category);
CREATE INDEX idx_secret_types_provider ON secret_types(provider);

-- Custom detection rules per organization (extends built-in secret_types)
CREATE TABLE detection_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  VARCHAR(100) REFERENCES secret_types(id),
    name            VARCHAR(255) NOT NULL,
    -- Full rule definition including detection logic, allowlists, and overrides
    rule_config     JSONB NOT NULL,
    -- rule_config example:
    -- {
    --   "type": "regex",
    --   "pattern": "MYCOMPANY-[A-Za-z0-9]{32}",
    --   "confidence": "high",
    --   "severity": "critical",
    --   "allowlist": {
    --     "file_patterns": ["*_test.go", "testdata/*"],
    --     "content_patterns": ["example", "placeholder"],
    --     "value_hashes": ["sha256:abc123"]
    --   },
    --   "verification": {
    --     "method": "http_get",
    --     "url": "https://api.mycompany.com/verify",
    --     "headers": { "Authorization": "Bearer {secret}" },
    --     "success_status": [200]
    --   }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_detection_rules_org ON detection_rules(organization_id);
```

## Scan Jobs & Findings

```sql
-- =============================================================================
-- SCAN JOBS & FINDINGS
-- =============================================================================

CREATE TABLE scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_source_id  UUID NOT NULL REFERENCES scan_sources(id),
    trigger_type    VARCHAR(50) NOT NULL
                    CHECK (trigger_type IN ('manual', 'scheduled', 'webhook', 'pre_commit', 'ci_pipeline')),
    triggered_by    UUID REFERENCES users(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    scan_mode       VARCHAR(50) NOT NULL DEFAULT 'incremental',
    -- Scan scope and results as JSONB (varies by source type)
    scope           JSONB NOT NULL DEFAULT '{}',
    -- scope example (git):
    -- {
    --   "start_commit": "a1b2c3d4",
    --   "end_commit": "e5f6g7h8",
    --   "branch": "main",
    --   "pr_number": 42
    -- }
    -- scope example (slack):
    -- {
    --   "channels": ["general", "engineering"],
    --   "since": "2026-05-01T00:00:00Z",
    --   "message_count": 15234
    -- }
    results         JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "files_scanned": 1234,
    --   "lines_scanned": 98765,
    --   "findings_count": 3,
    --   "new_findings": 2,
    --   "duplicate_findings": 1,
    --   "suppressed_findings": 0,
    --   "duration_ms": 4523,
    --   "rules_evaluated": 150
    -- }
    error_message   TEXT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_jobs_org ON scan_jobs(organization_id);
CREATE INDEX idx_scan_jobs_source ON scan_jobs(scan_source_id);
CREATE INDEX idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX idx_scan_jobs_created ON scan_jobs(created_at DESC);

CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_job_id     UUID NOT NULL REFERENCES scan_jobs(id),
    scan_source_id  UUID NOT NULL REFERENCES scan_sources(id),
    secret_type_id  VARCHAR(100) NOT NULL REFERENCES secret_types(id),
    -- Core finding fields (always present, always indexed)
    secret_hash     VARCHAR(128) NOT NULL,
    secret_display  VARCHAR(50),
    fingerprint     VARCHAR(128) NOT NULL,
    severity        VARCHAR(20) NOT NULL DEFAULT 'high',
    confidence      VARCHAR(20) NOT NULL DEFAULT 'medium',
    verification_status VARCHAR(30) NOT NULL DEFAULT 'unverified'
                    CHECK (verification_status IN ('unverified', 'verified_active', 'verified_inactive',
                                                    'verification_failed', 'verification_unsupported')),
    -- Location details in JSONB (varies by source type)
    location        JSONB NOT NULL,
    -- location example (git):
    -- {
    --   "file_path": "config/settings.py",
    --   "line_number": 42,
    --   "column_number": 15,
    --   "commit_hash": "a1b2c3d4",
    --   "commit_author": "dev@example.com",
    --   "commit_date": "2026-05-10T14:30:00Z",
    --   "branch": "main",
    --   "snippet": "AWS_KEY = 'AKIA****3F2Q'"
    -- }
    -- location example (slack):
    -- {
    --   "channel_id": "C012345",
    --   "channel_name": "engineering",
    --   "message_ts": "1715356200.000100",
    --   "author_id": "U012345",
    --   "author_name": "John Doe",
    --   "message_snippet": "Hey, use this key: AKIA****"
    -- }
    -- AI-generated context and risk assessment
    ai_analysis     JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "risk_score": 92.5,
    --   "risk_context": "Production AWS key with S3 and EC2 permissions",
    --   "environment_guess": "production",
    --   "false_positive_probability": 0.03,
    --   "recommended_action": "immediate_rotation",
    --   "similar_findings": ["uuid1", "uuid2"],
    --   "model_version": "v2.1",
    --   "inference_time_ms": 125
    -- }
    -- Verification details (populated after verification attempt)
    verification_details JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "verified_at": "2026-05-10T15:00:00Z",
    --   "method": "api_call",
    --   "provider_response": { "account_id": "123456789012", "iam_user": "deploy-bot" },
    --   "permissions_discovered": ["s3:*", "ec2:*"],
    --   "last_used": "2026-05-09T22:15:00Z"
    -- }
    -- Incident linkage
    incident_id     UUID,
    is_duplicate    BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_of    UUID REFERENCES findings(id),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_org ON findings(organization_id);
CREATE INDEX idx_findings_scan ON findings(scan_job_id);
CREATE INDEX idx_findings_source ON findings(scan_source_id);
CREATE INDEX idx_findings_type ON findings(secret_type_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_verification ON findings(verification_status);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX idx_findings_incident ON findings(incident_id);
CREATE INDEX idx_findings_detected ON findings(detected_at DESC);
-- GIN index on location for source-type-specific queries
CREATE INDEX idx_findings_location ON findings USING GIN (location);
-- GIN index on AI analysis for risk-score-based queries
CREATE INDEX idx_findings_ai ON findings USING GIN (ai_analysis);
```

## Incidents

```sql
-- =============================================================================
-- INCIDENTS
-- =============================================================================

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  VARCHAR(100) NOT NULL REFERENCES secret_types(id),
    secret_hash     VARCHAR(128) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged', 'in_progress', 'resolved',
                                      'false_positive', 'ignored')),
    -- Assignment and resolution details in JSONB (flexible workflow)
    workflow        JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "assigned_to": "uuid",
    --   "assigned_team": "uuid",
    --   "resolution": "rotated",
    --   "resolution_notes": "Rotated via automated workflow",
    --   "resolved_by": "uuid",
    --   "resolved_at": "2026-05-10T16:00:00Z",
    --   "sla_deadline": "2026-05-11T14:30:00Z",
    --   "sla_breached": false,
    --   "escalation_level": 1,
    --   "labels": ["production", "aws", "critical-path"]
    -- }
    -- Aggregated metrics
    findings_count  INT NOT NULL DEFAULT 0,
    locations_count INT NOT NULL DEFAULT 0,
    first_detected_at TIMESTAMPTZ NOT NULL,
    last_detected_at  TIMESTAMPTZ NOT NULL,
    -- Activity timeline as JSONB array (lightweight event log within the incident)
    timeline        JSONB NOT NULL DEFAULT '[]',
    -- [
    --   { "at": "2026-05-10T14:30:00Z", "type": "created", "actor": "system" },
    --   { "at": "2026-05-10T14:31:00Z", "type": "assigned", "actor": "uuid", "to": "uuid" },
    --   { "at": "2026-05-10T15:00:00Z", "type": "comment", "actor": "uuid", "body": "..." },
    --   { "at": "2026-05-10T16:00:00Z", "type": "resolved", "actor": "uuid", "resolution": "rotated" }
    -- ]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_incidents_org ON incidents(organization_id);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_incidents_secret_hash ON incidents(organization_id, secret_hash);
CREATE INDEX idx_incidents_workflow ON incidents USING GIN (workflow);
```

## Credential Management & Rotation

```sql
-- =============================================================================
-- CREDENTIAL MANAGEMENT & ROTATION
-- =============================================================================

CREATE TABLE managed_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  VARCHAR(100) NOT NULL REFERENCES secret_types(id),
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'rotating', 'rotated', 'revoked', 'expired',
                                      'pending_rotation')),
    environment     VARCHAR(50) NOT NULL DEFAULT 'unknown',
    risk_level      VARCHAR(20) NOT NULL DEFAULT 'medium',
    -- Provider-specific identity and configuration
    provider_config JSONB NOT NULL DEFAULT '{}',
    -- provider_config example (AWS):
    -- {
    --   "provider": "aws",
    --   "account_id": "123456789012",
    --   "iam_user": "deploy-bot",
    --   "iam_user_arn": "arn:aws:iam::123456789012:user/deploy-bot",
    --   "access_key_id": "AKIA****3F2Q",
    --   "region": "us-east-1",
    --   "consumer_services": ["ecs/web-api", "lambda/data-processor"]
    -- }
    -- provider_config example (database):
    -- {
    --   "provider": "postgresql",
    --   "host": "prod-db.internal",
    --   "port": 5432,
    --   "database": "appdb",
    --   "username": "app_user",
    --   "connection_vault_ref": "secret/db/prod/app_user"
    -- }
    -- Rotation configuration
    rotation_config JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "policy": "on_detection",
    --   "interval_hours": null,
    --   "requires_approval": true,
    --   "approvers": ["uuid1", "uuid2"],
    --   "grace_period_hours": 24,
    --   "notification_channels": ["uuid-slack-channel"]
    -- }
    -- Vault reference for current credential value
    vault_path      VARCHAR(500),
    -- Rotation tracking
    last_rotated_at TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ,
    rotation_count  INT NOT NULL DEFAULT 0,
    -- Ownership
    owner_user_id   UUID REFERENCES users(id),
    owner_team_ids  UUID[] DEFAULT '{}',
    -- Linked incidents
    linked_incident_ids UUID[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_managed_creds_org ON managed_credentials(organization_id);
CREATE INDEX idx_managed_creds_status ON managed_credentials(status);
CREATE INDEX idx_managed_creds_environment ON managed_credentials(environment);
CREATE INDEX idx_managed_creds_next_rotation ON managed_credentials(next_rotation_at);
CREATE INDEX idx_managed_creds_provider ON managed_credentials USING GIN (provider_config);

CREATE TABLE rotation_executions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id   UUID NOT NULL REFERENCES managed_credentials(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id),
    trigger         VARCHAR(50) NOT NULL
                    CHECK (trigger IN ('scheduled', 'incident', 'manual', 'policy', 'expiry')),
    triggered_by    UUID REFERENCES users(id),
    linked_incident_id UUID REFERENCES incidents(id),
    status          VARCHAR(50) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'awaiting_approval', 'approved', 'executing',
                                      'verifying', 'completed', 'failed', 'rolled_back', 'cancelled')),
    -- All step tracking in JSONB (replaces separate rotation_steps table)
    steps           JSONB NOT NULL DEFAULT '[]',
    -- [
    --   {
    --     "order": 1,
    --     "type": "generate_credential",
    --     "name": "Generate new IAM access key",
    --     "status": "completed",
    --     "started_at": "2026-05-10T15:01:00Z",
    --     "completed_at": "2026-05-10T15:01:02Z",
    --     "duration_ms": 1523,
    --     "output": { "new_key_id": "AKIA...", "vault_path": "secret/aws/v3" }
    --   },
    --   {
    --     "order": 2,
    --     "type": "update_consumers",
    --     "name": "Update ECS task definitions",
    --     "status": "running",
    --     "started_at": "2026-05-10T15:01:03Z"
    --   },
    --   {
    --     "order": 3,
    --     "type": "verify_new",
    --     "name": "Verify new key works",
    --     "status": "pending"
    --   },
    --   {
    --     "order": 4,
    --     "type": "revoke_old",
    --     "name": "Deactivate old access key",
    --     "status": "pending"
    --   }
    -- ]
    -- Approval details
    approval        JSONB NOT NULL DEFAULT '{}',
    -- { "required": true, "approvers_needed": 1, "approved_by": "uuid", "approved_at": "..." }
    -- Error handling
    error_message   TEXT,
    retry_count     INT NOT NULL DEFAULT 0,
    -- Timing
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rotation_exec_credential ON rotation_executions(credential_id);
CREATE INDEX idx_rotation_exec_org ON rotation_executions(organization_id);
CREATE INDEX idx_rotation_exec_status ON rotation_executions(status);
CREATE INDEX idx_rotation_exec_created ON rotation_executions(created_at DESC);
```

## Suppressions & Honeytokens

```sql
-- =============================================================================
-- SUPPRESSIONS & HONEYTOKENS
-- =============================================================================

CREATE TABLE suppressions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    suppression_type VARCHAR(50) NOT NULL
                    CHECK (suppression_type IN ('finding', 'file_pattern', 'secret_type',
                                                'repository', 'content_hash')),
    target_value    TEXT NOT NULL,
    scan_source_id  UUID REFERENCES scan_sources(id),
    reason          TEXT NOT NULL,
    classification  VARCHAR(50) NOT NULL DEFAULT 'false_positive',
    -- Flexible metadata for suppression context
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "classification": "test_credential",
    --   "expires_at": "2026-12-31T23:59:59Z",
    --   "approved_by": "uuid",
    --   "jira_ticket": "SEC-1234"
    -- }
    created_by      UUID NOT NULL REFERENCES users(id),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_suppressions_org ON suppressions(organization_id);
CREATE INDEX idx_suppressions_type ON suppressions(suppression_type);
CREATE INDEX idx_suppressions_active ON suppressions(is_active) WHERE is_active = TRUE;

CREATE TABLE honeytokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    secret_type_id  VARCHAR(100) NOT NULL REFERENCES secret_types(id),
    name            VARCHAR(255) NOT NULL,
    token_hash      VARCHAR(128) NOT NULL,
    status          VARCHAR(50) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'triggered', 'expired', 'disabled')),
    -- All honeytoken-specific config in JSONB
    config          JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "planted_location": "config/production.env",
    --   "planted_source_id": "uuid",
    --   "callback_url": "https://canary.example.com/t/abc123",
    --   "trigger_details": null,
    --   "triggered_at": null,
    --   "expires_at": "2027-05-10T00:00:00Z"
    -- }
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_honeytokens_org ON honeytokens(organization_id);
CREATE INDEX idx_honeytokens_hash ON honeytokens(token_hash);
```

## Audit Log & Notifications

```sql
-- =============================================================================
-- AUDIT LOG & NOTIFICATIONS
-- =============================================================================

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    actor_id        UUID,
    actor_type      VARCHAR(50) NOT NULL DEFAULT 'user',
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(100) NOT NULL,
    resource_id     UUID NOT NULL,
    -- All audit details in JSONB (flexible per action type)
    details         JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "changes": { "status": { "old": "open", "new": "resolved" } },
    --   "ip_address": "192.168.1.1",
    --   "user_agent": "Mozilla/5.0...",
    --   "api_key_id": "uuid",
    --   "request_id": "uuid"
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition by month in production
CREATE INDEX idx_audit_log_org ON audit_log(organization_id);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_log_details ON audit_log USING GIN (details);

CREATE TABLE notification_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    channel_type    VARCHAR(50) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    -- Channel config and rules combined in JSONB
    config          JSONB NOT NULL,
    -- {
    --   "type": "slack",
    --   "webhook_url": "https://hooks.slack.com/...",
    --   "channel": "#security-alerts",
    --   "rules": [
    --     { "event": "finding.critical", "min_severity": "critical" },
    --     { "event": "incident.created", "min_severity": "high" },
    --     { "event": "rotation.failed" },
    --     { "event": "honeytoken.triggered" }
    --   ],
    --   "rate_limit": { "max_per_hour": 20, "batch_window_seconds": 60 }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notification_channels_org ON notification_channels(organization_id);
```

## API Keys & Integrations

```sql
-- =============================================================================
-- API KEYS & INTEGRATIONS
-- =============================================================================

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by      UUID NOT NULL REFERENCES users(id),
    name            VARCHAR(255) NOT NULL,
    key_prefix      VARCHAR(20) NOT NULL,
    key_hash        VARCHAR(255) NOT NULL,
    -- Scopes and limits in JSONB
    config          JSONB NOT NULL DEFAULT '{}',
    -- {
    --   "scopes": ["scan:read", "scan:write", "findings:read", "incidents:read"],
    --   "rate_limit_per_minute": 60,
    --   "allowed_ips": ["192.168.1.0/24"],
    --   "expires_at": "2027-05-10T00:00:00Z"
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_org ON api_keys(organization_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

## Example Queries

```sql
-- =============================================================================
-- EXAMPLE QUERIES
-- =============================================================================

-- 1. Find all critical findings from Slack sources (JSONB location query)
SELECT f.id, f.secret_type_id, f.secret_display,
       f.location->>'channel_name' AS channel,
       f.location->>'author_name' AS author,
       f.ai_analysis->>'risk_score' AS risk_score
FROM findings f
WHERE f.organization_id = '...'
  AND f.severity = 'critical'
  AND f.location ? 'channel_name'  -- Has Slack-specific fields
ORDER BY f.detected_at DESC;

-- 2. Find findings with high AI risk scores
SELECT f.id, f.secret_type_id, f.severity,
       (f.ai_analysis->>'risk_score')::numeric AS risk_score,
       f.ai_analysis->>'risk_context' AS context
FROM findings f
WHERE f.organization_id = '...'
  AND (f.ai_analysis->>'risk_score')::numeric > 80
ORDER BY (f.ai_analysis->>'risk_score')::numeric DESC;

-- 3. Rotation execution with step details (no JOIN needed)
SELECT r.id, r.status, r.trigger,
       step->>'name' AS step_name,
       step->>'status' AS step_status,
       step->>'duration_ms' AS duration
FROM rotation_executions r,
     jsonb_array_elements(r.steps) AS step
WHERE r.credential_id = '...'
ORDER BY r.created_at DESC, (step->>'order')::int;

-- 4. Provider-specific credential query (AWS credentials needing rotation)
SELECT mc.id, mc.name, mc.status,
       mc.provider_config->>'iam_user' AS iam_user,
       mc.provider_config->>'account_id' AS account_id,
       mc.last_rotated_at
FROM managed_credentials mc
WHERE mc.organization_id = '...'
  AND mc.provider_config->>'provider' = 'aws'
  AND mc.next_rotation_at < NOW()
ORDER BY mc.next_rotation_at;

-- 5. Incident timeline (embedded in the incident row, no JOIN)
SELECT i.id, i.title, i.severity, i.status,
       entry->>'at' AS event_time,
       entry->>'type' AS event_type,
       entry->>'body' AS comment
FROM incidents i,
     jsonb_array_elements(i.timeline) AS entry
WHERE i.id = '...'
ORDER BY entry->>'at';

-- 6. Scan sources with their cached statistics
SELECT ss.name, ss.source_type,
       ss.stats->>'total_scans' AS total_scans,
       ss.stats->>'total_findings' AS total_findings,
       ss.last_scanned_at
FROM scan_sources ss
WHERE ss.organization_id = '...'
  AND ss.is_active = TRUE
ORDER BY ss.last_scanned_at DESC;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Organization & Access Control | 3 | organizations, users, memberships |
| Scan Sources | 1 | scan_sources (config in JSONB) |
| Detection Configuration | 2 | secret_types, detection_rules |
| Scan Jobs & Findings | 2 | scan_jobs, findings |
| Incidents | 1 | incidents (timeline embedded as JSONB array) |
| Credential Management | 2 | managed_credentials, rotation_executions (steps in JSONB) |
| Suppressions & Honeytokens | 2 | suppressions, honeytokens |
| Audit & Notifications | 2 | audit_log, notification_channels |
| API Keys | 1 | api_keys |
| **Total** | **16** | Half the table count of the normalized model |

---

## Key Design Decisions

1. **JSONB for provider-specific fields, relational for workflow fields.** The `status`, `severity`, `organization_id`, and `created_at` fields are always relational columns with proper types, indexes, and constraints. Provider-specific data (AWS IAM details, Slack channel info, rotation step details) lives in JSONB. This draws the line at "what we query across all records" (relational) vs. "what varies per record type" (JSONB).

2. **Rotation steps embedded as JSONB array, not a separate table.** In the normalized model, `rotation_steps` is a separate table requiring JOINs. Here, steps are an array within `rotation_executions.steps`. Since steps are always read together with their execution and never queried independently across executions, this eliminates a JOIN and simplifies the API.

3. **Incident timeline is an embedded JSONB array.** Rather than separate `incident_comments` and `incident_history` tables, the timeline is a chronological array within the incident. This trades independent comment querying for simpler incident loading. For a security incident with 5-50 timeline entries, the embedded approach is more practical than normalized comments.

4. **Secret types use VARCHAR primary keys instead of integer IDs.** Using `'aws_access_key'` as the primary key instead of an auto-incrementing integer makes queries and API responses self-documenting. Foreign key references read as `secret_type_id = 'github_pat'` rather than `secret_type_id = 47`.

5. **Detection, verification, and rotation configuration live on the secret type.** Rather than separate configuration tables, each `secret_type` row carries JSONB columns for detection patterns, verification endpoints, and rotation step templates. Adding a new secret type is a single INSERT with all its behavior defined inline.

6. **Finding location varies by source type.** A git finding has `file_path`, `line_number`, and `commit_hash`. A Slack finding has `channel_name`, `message_ts`, and `author_name`. Rather than nullable columns or per-source-type tables, the `location` JSONB column accommodates both with GIN indexing for filtered queries.

7. **AI analysis results stored alongside findings.** The `ai_analysis` JSONB column on findings stores risk scores, context explanations, and model metadata. This avoids a separate AI results table and keeps the finding self-contained for API responses.

8. **Membership permissions use JSONB for fine-grained overrides.** Rather than a full RBAC junction table structure, the `memberships` table uses a `permissions` JSONB column for granular overrides beyond the base role. This is simpler for teams that need quick "give this user credential approval rights" without a full permission model.

9. **Notification rules embedded in channel config.** Rather than separate `notification_rules` and `notification_channels` tables, rules are part of the channel's JSONB config. This reduces table count and keeps channel configuration self-contained, at the cost of not being able to query rules independently across channels.

10. **JSON Schema validation is required at the application layer.** Every JSONB column in this model should have a corresponding JSON Schema definition in application code. The database cannot enforce the structure of JSONB data, so validation must happen before writes. This is the primary trade-off of the hybrid approach: flexibility at the cost of application-managed constraints.
