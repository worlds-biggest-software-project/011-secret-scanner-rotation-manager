# Secret Scanner & Rotation Manager — Phased Development Plan

> Project: 011-secret-scanner-rotation-manager · Created: 2026-05-11
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Language | TypeScript (Node.js 22 LTS) | Type safety for complex domain model; broad ecosystem for cloud provider SDKs; strong JSONB/JSON Schema tooling |
| Runtime | Node.js 22 with native ESM | LTS stability; native fetch; performance improvements for streaming scan output |
| Framework | Fastify 5 | Faster than Express; native JSON Schema request/response validation aligns with JSONB validation strategy; OpenAPI 3.2 generation via @fastify/swagger |
| Database | PostgreSQL 16 | JSONB with GIN indexes for provider-specific fields; partitioning for audit_log; mature UUID and TIMESTAMPTZ support |
| ORM / Query | Drizzle ORM | Type-safe schema definitions; raw SQL escape hatch for JSONB queries; migration generation from schema |
| Cache / Queue | Redis 7 (via BullMQ) | Job queue for async scan jobs, rotation executions, and notification delivery; caching for verification results |
| AI / LLM | Ollama (llama3.1:8b) local; OpenAI API fallback | Fine-tuned LLaMA-3.1 8B achieves F1=0.985 per arXiv:2504.18784; local inference avoids sending secrets to external APIs; OpenAI fallback for risk context generation |
| Secret Storage | HashiCorp Vault (via API) or environment variable injection | Never store credential values in PostgreSQL; Vault API integration for managed credential lifecycle; OpenBao as MIT-licensed alternative |
| CLI Framework | Commander.js | Standard Node.js CLI library; subcommand pattern matches `scan`, `verify`, `rotate` UX |
| Testing | Vitest + Testcontainers | Vitest for unit/integration; Testcontainers for PostgreSQL and Redis in CI; Playwright for dashboard E2E |
| CI/CD | GitHub Actions | Pre-commit hook distribution; SARIF upload to GitHub Code Scanning; container image publishing |
| Container | Docker (multi-stage) | Single binary-like deployment; scanner runs as ephemeral container in CI; server runs as long-lived service |
| Monorepo | pnpm workspaces | Separate packages for CLI, server, scanner-engine, provider-plugins, shared types |
| API Docs | OpenAPI 3.2.0 | Generated from Fastify route schemas; aligns with standards.md recommendation |
| Auth | JWT + OAuth 2.0 (RFC 6749) | JWT for API access; OAuth 2.0 for GitHub/GitLab SSO; API key auth for CI/CD integration |
| Data Model | Hybrid Relational + JSONB (Suggestion 3) | 16 tables vs. 32 in normalized model; JSONB for provider-specific fields enables adding secret types without migrations; VARCHAR PKs on secret_types for self-documenting queries; rotation steps embedded as JSONB array eliminates unnecessary JOINs |

### Project Structure

```
secret-scanner/
├── package.json                    # pnpm workspace root
├── pnpm-workspace.yaml
├── docker-compose.yml              # PostgreSQL, Redis, Vault (dev)
├── Dockerfile                      # Multi-stage: build + runtime
├── .github/
│   └── workflows/
│       ├── ci.yml                  # Lint, test, build
│       └── release.yml             # Container publish, npm publish
├── packages/
│   ├── types/                      # Shared TypeScript types & JSON Schemas
│   │   ├── src/
│   │   │   ├── findings.ts
│   │   │   ├── incidents.ts
│   │   │   ├── credentials.ts
│   │   │   ├── scan-jobs.ts
│   │   │   ├── secret-types.ts
│   │   │   └── json-schemas/       # JSON Schema files for JSONB validation
│   │   └── package.json
│   ├── scanner-engine/             # Core detection logic
│   │   ├── src/
│   │   │   ├── detectors/
│   │   │   │   ├── regex-detector.ts
│   │   │   │   ├── entropy-detector.ts
│   │   │   │   ├── llm-detector.ts
│   │   │   │   └── composite-detector.ts
│   │   │   ├── sources/
│   │   │   │   ├── git-source.ts
│   │   │   │   ├── filesystem-source.ts
│   │   │   │   ├── docker-source.ts
│   │   │   │   └── slack-source.ts
│   │   │   ├── verifiers/
│   │   │   │   ├── aws-verifier.ts
│   │   │   │   ├── github-verifier.ts
│   │   │   │   ├── stripe-verifier.ts
│   │   │   │   └── verifier-registry.ts
│   │   │   ├── engine.ts
│   │   │   └── fingerprint.ts
│   │   └── package.json
│   ├── rotation-engine/            # Credential rotation orchestration
│   │   ├── src/
│   │   │   ├── providers/
│   │   │   │   ├── aws-rotator.ts
│   │   │   │   ├── github-rotator.ts
│   │   │   │   ├── database-rotator.ts
│   │   │   │   └── provider-registry.ts
│   │   │   ├── workflow.ts
│   │   │   ├── step-executor.ts
│   │   │   └── approval.ts
│   │   └── package.json
│   ├── server/                     # Fastify API server + dashboard
│   │   ├── src/
│   │   │   ├── routes/
│   │   │   │   ├── scans.ts
│   │   │   │   ├── findings.ts
│   │   │   │   ├── incidents.ts
│   │   │   │   ├── credentials.ts
│   │   │   │   ├── rotations.ts
│   │   │   │   ├── suppressions.ts
│   │   │   │   ├── honeytokens.ts
│   │   │   │   └── compliance.ts
│   │   │   ├── auth/
│   │   │   │   ├── jwt.ts
│   │   │   │   ├── oauth.ts
│   │   │   │   └── api-key.ts
│   │   │   ├── workers/
│   │   │   │   ├── scan-worker.ts
│   │   │   │   ├── rotation-worker.ts
│   │   │   │   └── notification-worker.ts
│   │   │   ├── db/
│   │   │   │   ├── schema.ts       # Drizzle schema
│   │   │   │   ├── migrations/
│   │   │   │   └── seed.ts
│   │   │   └── app.ts
│   │   └── package.json
│   └── cli/                        # Command-line interface
│       ├── src/
│       │   ├── commands/
│       │   │   ├── scan.ts
│       │   │   ├── verify.ts
│       │   │   ├── rotate.ts
│       │   │   └── config.ts
│       │   └── index.ts
│       └── package.json
├── rules/                          # Built-in detection rules (TOML/JSON)
│   ├── aws.json
│   ├── github.json
│   ├── stripe.json
│   ├── slack.json
│   └── generic.json
└── tests/
    ├── fixtures/                   # Test repositories with planted secrets
    ├── integration/
    └── e2e/
```

---

## Phase 1: Project Scaffold & Data Layer

### Purpose
Establish the monorepo structure, database schema, and development environment so all subsequent phases have a stable foundation to build on.

### Tasks

#### 1.1 — Monorepo Initialization
**What**: Set up pnpm workspace with all package directories, shared TypeScript config, and linting.
**Design**:
```typescript
// pnpm-workspace.yaml
packages:
  - 'packages/*'

// tsconfig.base.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "declaration": true,
    "outDir": "dist",
    "rootDir": "src",
    "esModuleInterop": true,
    "resolveJsonModule": true,
    "sourceMap": true
  }
}

// Each package extends tsconfig.base.json with:
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src"
  },
  "references": [
    { "path": "../types" }
  ]
}
```
**Testing**:
- `pnpm-workspace-builds`: All packages compile without errors after `pnpm build`
- `lint-passes`: ESLint + Prettier produce zero errors/warnings on scaffold code

#### 1.2 — Docker Compose Development Environment
**What**: Create docker-compose.yml providing PostgreSQL 16, Redis 7, and Vault dev server for local development.
**Design**:
```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: secretscanner
      POSTGRES_USER: scanner
      POSTGRES_PASSWORD: dev-only
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U scanner"]
      interval: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 5

  vault:
    image: hashicorp/vault:1.17
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: dev-root-token
    ports: ["8200:8200"]
    cap_add: [IPC_LOCK]

volumes:
  pgdata:
```
**Testing**:
- `docker-compose-starts`: `docker compose up -d` brings all three services to healthy state within 30 seconds
- `postgres-accepts-connections`: `psql` connects and runs `SELECT 1`

#### 1.3 — Database Schema Implementation
**What**: Implement the Hybrid Relational + JSONB schema (Data Model Suggestion 3) using Drizzle ORM with all 16 tables.
**Design**:
```typescript
// packages/server/src/db/schema.ts

import { pgTable, uuid, varchar, text, boolean, integer,
         timestamp, jsonb, uniqueIndex, index } from 'drizzle-orm/pg-core';

export const organizations = pgTable('organizations', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 255 }).notNull(),
  slug: varchar('slug', { length: 100 }).notNull().unique(),
  plan: varchar('plan', { length: 50 }).notNull().default('free'),
  settings: jsonb('settings').notNull().default({}),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 320 }).notNull().unique(),
  displayName: varchar('display_name', { length: 255 }).notNull(),
  auth: jsonb('auth').notNull().default({}),
  isActive: boolean('is_active').notNull().default(true),
  lastLoginAt: timestamp('last_login_at', { withTimezone: true }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const memberships = pgTable('memberships', {
  id: uuid('id').primaryKey().defaultRandom(),
  organizationId: uuid('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  userId: uuid('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  role: varchar('role', { length: 50 }).notNull().default('member'),
  permissions: jsonb('permissions').notNull().default({}),
  teamIds: uuid('team_ids').array().notNull().default([]),
  joinedAt: timestamp('joined_at', { withTimezone: true }).notNull().defaultNow(),
}, (t) => ({
  orgUserUnique: uniqueIndex('idx_memberships_org_user').on(t.organizationId, t.userId),
}));

export const secretTypes = pgTable('secret_types', {
  id: varchar('id', { length: 100 }).primaryKey(),
  displayName: varchar('display_name', { length: 255 }).notNull(),
  category: varchar('category', { length: 50 }).notNull(),
  provider: varchar('provider', { length: 100 }),
  severityDefault: varchar('severity_default', { length: 20 }).notNull().default('high'),
  detection: jsonb('detection').notNull().default({}),
  verification: jsonb('verification').notNull().default({}),
  rotation: jsonb('rotation').notNull().default({}),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// ... remaining 12 tables follow the same pattern from data-model-suggestion-3.md
```
**Testing**:
- `schema-migration-applies`: `drizzle-kit push` applies cleanly against empty PostgreSQL
- `schema-roundtrip`: Insert and read from all 16 tables with sample data
- `jsonb-gin-indexes-used`: EXPLAIN ANALYZE confirms GIN index usage on JSONB queries
- `foreign-key-cascades`: Deleting an organization cascades to memberships, scan_sources, findings, incidents

#### 1.4 — Shared Type Definitions & JSON Schema Validation
**What**: Define TypeScript types and corresponding JSON Schemas for all JSONB columns to enforce structure at the application layer.
**Design**:
```typescript
// packages/types/src/findings.ts

export interface FindingLocation {
  // Common fields
  sourceType: 'git_repository' | 'slack_workspace' | 's3_bucket' | 'docker_image' | 'filesystem';
}

export interface GitFindingLocation extends FindingLocation {
  sourceType: 'git_repository';
  filePath: string;
  lineNumber: number;
  columnNumber?: number;
  commitHash: string;
  commitAuthor: string;
  commitDate: string;  // ISO 8601
  branch: string;
  snippet?: string;
}

export interface SlackFindingLocation extends FindingLocation {
  sourceType: 'slack_workspace';
  channelId: string;
  channelName: string;
  messageTs: string;
  authorId: string;
  authorName: string;
  messageSnippet?: string;
}

export type AnyFindingLocation = GitFindingLocation | SlackFindingLocation;

export interface AIAnalysis {
  riskScore: number;        // 0-100
  riskContext: string;
  environmentGuess: 'production' | 'staging' | 'development' | 'test' | 'unknown';
  falsePositiveProbability: number;  // 0-1
  recommendedAction: 'immediate_rotation' | 'scheduled_rotation' | 'review' | 'suppress';
  modelVersion: string;
  inferenceTimeMs: number;
}

export interface VerificationDetails {
  verifiedAt: string;
  method: 'api_call' | 'dns_lookup' | 'http_probe';
  providerResponse: Record<string, unknown>;
  permissionsDiscovered?: string[];
  lastUsed?: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'critical' | 'high' | 'medium' | 'low';
export type VerificationStatus = 'unverified' | 'verified_active' | 'verified_inactive'
  | 'verification_failed' | 'verification_unsupported';

// packages/types/src/json-schemas/finding-location.json
// {
//   "$schema": "https://json-schema.org/draft/2020-12/schema",
//   "oneOf": [
//     { "$ref": "#/$defs/gitLocation" },
//     { "$ref": "#/$defs/slackLocation" }
//   ],
//   "$defs": {
//     "gitLocation": {
//       "type": "object",
//       "required": ["sourceType", "filePath", "lineNumber", "commitHash", "commitAuthor", "commitDate", "branch"],
//       "properties": {
//         "sourceType": { "const": "git_repository" },
//         "filePath": { "type": "string" },
//         "lineNumber": { "type": "integer", "minimum": 1 },
//         ...
//       }
//     }
//   }
// }
```
**Testing**:
- `type-exports-compile`: `packages/types` compiles and all types are importable from other packages
- `json-schema-validates-good-data`: AJV validates correct GitFindingLocation, SlackFindingLocation, AIAnalysis payloads
- `json-schema-rejects-bad-data`: AJV rejects locations missing required fields, invalid severity values, out-of-range risk scores

#### 1.5 — Seed Data for Detection Rules
**What**: Populate the `secret_types` table with the 20 most common secret types including regex patterns, verification endpoints, and rotation step templates.
**Design**:
```typescript
// packages/server/src/db/seed.ts

const SECRET_TYPES: SecretTypeInsert[] = [
  {
    id: 'aws_access_key',
    displayName: 'AWS Access Key ID',
    category: 'api_key',
    provider: 'aws',
    severityDefault: 'critical',
    detection: {
      patterns: [
        { type: 'regex', pattern: '(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}', confidence: 'high' }
      ],
      prefix: 'AKIA',
      cweId: 'CWE-798',
      falsePositiveHints: ['example', 'AKIAIOSFODNN7EXAMPLE']
    },
    verification: {
      supported: true,
      method: 'api_call',
      endpoint: 'https://sts.amazonaws.com/?Action=GetCallerIdentity',
      authHeader: 'AWS4-HMAC-SHA256',
      timeoutMs: 5000
    },
    rotation: {
      supported: true,
      stepsTemplate: [
        { step: 1, type: 'generate_credential', api: 'iam:CreateAccessKey', description: 'Generate new IAM access key' },
        { step: 2, type: 'update_consumers', description: 'Update services consuming this key' },
        { step: 3, type: 'verify_new', api: 'sts:GetCallerIdentity', description: 'Verify new key works' },
        { step: 4, type: 'revoke_old', api: 'iam:DeleteAccessKey', description: 'Deactivate old access key' }
      ],
      estimatedDurationMinutes: 15,
      rollbackSupported: true
    }
  },
  // github_pat, github_oauth, stripe_secret_key, stripe_publishable_key,
  // slack_bot_token, slack_webhook_url, google_api_key, azure_client_secret,
  // gcp_service_account_key, postgresql_connection_string, mysql_connection_string,
  // mongodb_connection_string, redis_url, sendgrid_api_key, twilio_api_key,
  // jwt_secret, rsa_private_key, npm_token, pypi_token, docker_hub_token
];
```
**Testing**:
- `seed-inserts-20-types`: Seed script inserts 20 secret types; `SELECT count(*) FROM secret_types` returns 20
- `seed-idempotent`: Running seed twice does not produce duplicate key errors (upsert pattern)
- `seed-regex-valid`: Every `detection.patterns[].pattern` compiles as a valid JavaScript RegExp

---

## Phase 2: Scanner Engine Core

### Purpose
Build the detection engine that scans source material for secrets using regex, entropy, and composite detection strategies. This is the foundation all scanning features depend on.

### Tasks

#### 2.1 — Regex Detector
**What**: Implement a regex-based detector that evaluates content against detection patterns loaded from the `secret_types` table.
**Design**:
```typescript
// packages/scanner-engine/src/detectors/regex-detector.ts

export interface DetectorMatch {
  secretTypeId: string;
  match: string;              // The matched secret value
  startIndex: number;
  endIndex: number;
  confidence: Confidence;
  detectionMethod: 'regex';
}

export interface DetectorConfig {
  patterns: Array<{
    type: 'regex';
    pattern: string;
    confidence: Confidence;
  }>;
  falsePositiveHints: string[];
}

export class RegexDetector {
  private compiledPatterns: Map<string, { regex: RegExp; confidence: Confidence; secretTypeId: string }[]>;

  constructor(secretTypes: SecretTypeDefinition[]) {
    this.compiledPatterns = this.compilePatterns(secretTypes);
  }

  detect(content: string, filePath: string): DetectorMatch[] {
    // 1. For each secret type, run all regex patterns against content
    // 2. Filter out matches that hit falsePositiveHints
    // 3. Filter out matches in allowlisted file paths
    // 4. Return deduplicated matches sorted by position
  }

  private compilePatterns(types: SecretTypeDefinition[]): Map<string, ...> {
    // Pre-compile all regex patterns at construction time
    // Throw on invalid patterns with the secret type ID in the error message
  }
}
```
**Testing**:
- `detects-aws-access-key`: Input `AKIAIOSFODNN7EXAMPLE` matched as `aws_access_key` with high confidence
- `detects-github-pat`: Input `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12` matched as `github_pat`
- `skips-false-positive-hints`: Input containing `AKIAIOSFODNN7EXAMPLE` (AWS example key) is filtered out
- `handles-multiple-matches`: Input with 3 different secret types returns 3 distinct matches
- `ignores-binary-content`: Binary file content produces zero matches
- `performance-1mb-under-100ms`: Scanning a 1MB text file completes in under 100ms

#### 2.2 — Entropy Detector
**What**: Implement Shannon entropy-based detection for high-entropy strings that may be secrets without known regex patterns.
**Design**:
```typescript
// packages/scanner-engine/src/detectors/entropy-detector.ts

export interface EntropyConfig {
  minEntropy: number;         // Default: 4.5 bits per character
  minLength: number;          // Default: 20 characters
  maxLength: number;          // Default: 500 characters
  charsetThresholds: {
    base64: number;           // Default: 4.5
    hex: number;              // Default: 3.5
    alphanumeric: number;     // Default: 4.0
  };
}

export class EntropyDetector {
  constructor(private config: EntropyConfig) {}

  detect(content: string, filePath: string): DetectorMatch[] {
    // 1. Tokenize content into candidate strings (split on whitespace, quotes, assignment operators)
    // 2. Filter by length constraints
    // 3. Detect character set (base64, hex, alphanumeric, mixed)
    // 4. Calculate Shannon entropy
    // 5. Compare against charset-specific threshold
    // 6. Return matches with 'medium' confidence (entropy alone is not definitive)
  }

  private shannonEntropy(s: string): number {
    const freq = new Map<string, number>();
    for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
    return -[...freq.values()]
      .map(f => f / s.length)
      .reduce((sum, p) => sum + p * Math.log2(p), 0);
  }
}
```
**Testing**:
- `high-entropy-string-detected`: A random 32-character base64 string exceeds the 4.5 threshold
- `low-entropy-string-ignored`: `aaaaaaaaaaaaaaaaaaaaaa` does not trigger detection
- `hex-string-uses-hex-threshold`: A 40-character hex string is evaluated against the 3.5 hex threshold
- `short-strings-skipped`: Strings under 20 characters are not evaluated
- `known-non-secrets-skipped`: Common high-entropy non-secrets (UUIDs, hashes in package-lock.json) are handled by the composite detector's filtering

#### 2.3 — Composite Detector
**What**: Orchestrate regex and entropy detectors, deduplicate overlapping matches, and apply allowlist filtering.
**Design**:
```typescript
// packages/scanner-engine/src/detectors/composite-detector.ts

export interface CompositeDetectorConfig {
  enableRegex: boolean;
  enableEntropy: boolean;
  enableLLM: boolean;         // Phase 5
  allowlistPatterns: string[]; // File path glob patterns to skip
  contentAllowlist: string[];  // Content hashes to skip
}

export class CompositeDetector {
  constructor(
    private regex: RegexDetector,
    private entropy: EntropyDetector,
    private config: CompositeDetectorConfig,
  ) {}

  detect(content: string, filePath: string): DetectorMatch[] {
    const matches: DetectorMatch[] = [];

    if (this.config.enableRegex) {
      matches.push(...this.regex.detect(content, filePath));
    }
    if (this.config.enableEntropy) {
      // Only run entropy on segments not already matched by regex
      const entropyMatches = this.entropy.detect(content, filePath);
      matches.push(...this.filterOverlapping(entropyMatches, matches));
    }

    return this.applyAllowlist(this.deduplicate(matches), filePath);
  }

  private deduplicate(matches: DetectorMatch[]): DetectorMatch[] {
    // Group by overlapping character ranges; keep highest-confidence match
  }

  private filterOverlapping(candidates: DetectorMatch[], existing: DetectorMatch[]): DetectorMatch[] {
    // Remove entropy matches that overlap with regex matches (regex is more specific)
  }

  private applyAllowlist(matches: DetectorMatch[], filePath: string): DetectorMatch[] {
    // Filter out matches in allowlisted file paths (glob matching)
    // Filter out matches with allowlisted content hashes
  }
}
```
**Testing**:
- `regex-takes-priority`: When regex and entropy match the same span, only the regex match is returned
- `entropy-fills-gaps`: Entropy detects a custom API key that no regex pattern matches
- `allowlist-file-path`: Matches in `test/fixtures/*.txt` are filtered when that glob is allowlisted
- `allowlist-content-hash`: A specific content hash in the allowlist suppresses its match
- `both-disabled-returns-empty`: Disabling both regex and entropy returns zero matches

#### 2.4 — Fingerprinting & Deduplication
**What**: Generate stable fingerprints for detected secrets so the same secret found in different scan runs is recognized as a duplicate.
**Design**:
```typescript
// packages/scanner-engine/src/fingerprint.ts

import { createHash } from 'node:crypto';

export interface Fingerprint {
  /** Hash of the secret value — groups findings of the same secret across locations */
  secretHash: string;
  /** Hash of secret + location — identifies the exact same finding */
  findingFingerprint: string;
  /** Masked display value, e.g. "AKIA****3F2Q" */
  secretDisplay: string;
}

export function generateFingerprint(
  secretValue: string,
  filePath: string,
  lineNumber: number,
): Fingerprint {
  const secretHash = createHash('sha256').update(secretValue).digest('hex');
  const findingFingerprint = createHash('sha256')
    .update(`${secretHash}:${filePath}:${lineNumber}`)
    .digest('hex');
  const secretDisplay = maskSecret(secretValue);

  return { secretHash, findingFingerprint, secretDisplay };
}

function maskSecret(value: string): string {
  if (value.length <= 8) return '****';
  const prefix = value.slice(0, 4);
  const suffix = value.slice(-4);
  return `${prefix}****${suffix}`;
}
```
**Testing**:
- `same-secret-same-hash`: The same secret value in two files produces the same `secretHash`
- `same-location-same-fingerprint`: The same secret at the same file:line produces the same `findingFingerprint`
- `different-location-different-fingerprint`: The same secret at different lines produces different fingerprints
- `mask-preserves-prefix-suffix`: `AKIAIOSFODNN7EXAMPLE` masks to `AKIA****MPLE`
- `short-secret-fully-masked`: A 6-character secret masks to `****`

#### 2.5 — Git Source Scanner
**What**: Scan git repositories by walking commit history and file trees, feeding content to the composite detector.
**Design**:
```typescript
// packages/scanner-engine/src/sources/git-source.ts

export interface GitScanOptions {
  repoPath: string;
  branch?: string;
  startCommit?: string;
  endCommit?: string;
  scanMode: 'full' | 'incremental' | 'commit_range' | 'pr_diff';
  excludePaths?: string[];
  maxFileSizeBytes?: number;  // Default: 1MB
}

export interface ScanResult {
  findings: Finding[];
  stats: {
    filesScanned: number;
    linesScanned: number;
    findingsCount: number;
    durationMs: number;
  };
}

export class GitSource {
  constructor(
    private detector: CompositeDetector,
    private options: GitScanOptions,
  ) {}

  async scan(): Promise<ScanResult> {
    // 1. Open git repo with isomorphic-git or simple-git
    // 2. Determine commit range based on scanMode
    // 3. For each commit in range:
    //    a. Get diff or full tree
    //    b. For each file: skip binary, skip excluded paths, skip oversized
    //    c. Run detector.detect(content, filePath)
    //    d. Generate fingerprints for each match
    //    e. Attach commit metadata (hash, author, date, branch)
    // 4. Deduplicate findings across commits (same fingerprint)
    // 5. Return findings with stats
  }
}
```
**Testing**:
- `scans-test-repo-finds-planted-secret`: Scan a fixture repo with a known planted AWS key; exactly 1 finding returned
- `incremental-skips-old-commits`: Incremental scan starting from HEAD~1 only processes the last commit
- `excludes-vendor-directory`: Files in `vendor/` are not scanned when excluded
- `skips-binary-files`: PNG/JPG files produce zero findings
- `commit-metadata-attached`: Finding includes correct commit hash, author email, and date
- `full-history-scan`: Scanning the full history of a repo with a secret added then removed finds the secret in the adding commit

#### 2.6 — Filesystem Source Scanner
**What**: Scan arbitrary filesystem directories (not git repos) for secrets.
**Design**:
```typescript
// packages/scanner-engine/src/sources/filesystem-source.ts

export interface FilesystemScanOptions {
  rootPath: string;
  includePatterns?: string[];  // Glob patterns to include
  excludePatterns?: string[];  // Glob patterns to exclude
  maxFileSizeBytes?: number;
  followSymlinks?: boolean;
  maxDepth?: number;
}

export class FilesystemSource {
  constructor(
    private detector: CompositeDetector,
    private options: FilesystemScanOptions,
  ) {}

  async scan(): Promise<ScanResult> {
    // 1. Walk directory tree respecting include/exclude globs, depth, symlinks
    // 2. For each file: read content, run detector, generate fingerprints
    // 3. Return findings with file path relative to rootPath
  }
}
```
**Testing**:
- `scans-directory-tree`: Scanning a test directory with 3 files containing secrets finds all 3
- `respects-exclude-globs`: `*.min.js` excluded produces zero findings from minified files
- `max-depth-limits-recursion`: Setting maxDepth=1 does not scan subdirectories
- `handles-permission-errors`: Unreadable files are skipped with a warning, not an error

---

## Phase 3: CLI & SARIF Output

### Purpose
Deliver a usable command-line tool that developers can run locally and in CI/CD pipelines, producing industry-standard SARIF output for integration with GitHub Code Scanning.

### Tasks

#### 3.1 — CLI Scaffold with `scan` Command
**What**: Build the CLI entry point with the `scan` subcommand that invokes the scanner engine.
**Design**:
```typescript
// packages/cli/src/commands/scan.ts

import { Command } from 'commander';

export const scanCommand = new Command('scan')
  .description('Scan for secrets in source code')
  .requiredOption('--repo <path>', 'Path to git repository or directory')
  .option('--branch <name>', 'Branch to scan', 'HEAD')
  .option('--mode <mode>', 'Scan mode: full, incremental, commit_range, pr_diff', 'full')
  .option('--start-commit <hash>', 'Start commit for commit_range mode')
  .option('--end-commit <hash>', 'End commit for commit_range mode')
  .option('--output <format>', 'Output format: json, sarif, table, csv', 'table')
  .option('--output-file <path>', 'Write output to file instead of stdout')
  .option('--severity <level>', 'Minimum severity to report: critical, high, medium, low', 'low')
  .option('--exclude <patterns...>', 'Glob patterns to exclude')
  .option('--no-entropy', 'Disable entropy-based detection')
  .option('--exit-code', 'Exit with code 1 if findings detected (for CI)')
  .action(async (options) => {
    // 1. Load secret types from bundled rules/ JSON files
    // 2. Construct CompositeDetector
    // 3. Construct GitSource or FilesystemSource based on path
    // 4. Run scan
    // 5. Format output (table, JSON, SARIF, CSV)
    // 6. Write to stdout or file
    // 7. Exit with code 1 if --exit-code and findings > 0
  });
```
**Testing**:
- `cli-scan-finds-secrets`: `secret-scanner scan --repo ./test-fixtures --output json` returns findings JSON
- `cli-exit-code-1-on-findings`: With `--exit-code`, exit code is 1 when secrets found, 0 when clean
- `cli-severity-filter`: `--severity high` excludes medium/low findings
- `cli-table-output-readable`: Table output includes columns: Type, Severity, File, Line, Display
- `cli-exclude-works`: `--exclude 'vendor/*'` suppresses findings from vendor directory
- `cli-help-text`: `--help` displays all options with descriptions

#### 3.2 — SARIF Output Formatter
**What**: Generate SARIF v2.1.0 compliant output from scan findings for upload to GitHub Code Scanning.
**Design**:
```typescript
// packages/scanner-engine/src/formatters/sarif.ts

import type { Log, Run, Result, ReportingDescriptor } from 'sarif';

export function toSarif(findings: Finding[], scanStats: ScanStats): Log {
  const rules: ReportingDescriptor[] = deduplicateSecretTypes(findings).map(st => ({
    id: st.secretTypeId,
    name: st.displayName,
    shortDescription: { text: `Detected ${st.displayName}` },
    defaultConfiguration: {
      level: severityToSarifLevel(st.severity),
    },
    properties: {
      'security-severity': severityToScore(st.severity),
      cwe: st.cweId,
    },
  }));

  const results: Result[] = findings.map(f => ({
    ruleId: f.secretTypeId,
    message: { text: `${f.secretTypeId} detected: ${f.secretDisplay}` },
    level: severityToSarifLevel(f.severity),
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.location.filePath },
        region: {
          startLine: f.location.lineNumber,
          startColumn: f.location.columnNumber,
        },
      },
    }],
    fingerprints: {
      'secret-scanner/v1': f.fingerprint,
    },
    partialFingerprints: {
      secretHash: f.secretHash,
    },
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'secret-scanner',
          version: '0.1.0',
          rules,
        },
      },
      results,
    }],
  };
}
```
**Testing**:
- `sarif-validates-against-schema`: Output validates against SARIF 2.1.0 JSON Schema
- `sarif-includes-all-findings`: 5 findings input produces 5 SARIF results
- `sarif-rules-deduplicated`: 3 findings of same type produce 1 rule entry
- `sarif-severity-mapping`: 'critical' maps to SARIF 'error'; 'low' maps to 'note'
- `sarif-fingerprints-present`: Each result has `fingerprints['secret-scanner/v1']` set
- `github-upload-compatible`: Output structure matches GitHub Code Scanning upload requirements

#### 3.3 — Pre-commit Hook Integration
**What**: Provide a pre-commit hook configuration that runs the scanner on staged files.
**Design**:
```yaml
# .pre-commit-hooks.yaml (in project root for pre-commit framework)
- id: secret-scanner
  name: Secret Scanner
  description: Scan staged files for secrets
  entry: npx secret-scanner scan --repo . --mode pr_diff --exit-code --output table
  language: node
  types: [text]
  stages: [commit]
```

```typescript
// packages/cli/src/commands/pre-commit.ts
// Lightweight mode: only scan staged files, not full repo

export const preCommitCommand = new Command('pre-commit')
  .description('Scan staged git files for secrets (pre-commit hook)')
  .action(async () => {
    // 1. Get list of staged files via `git diff --cached --name-only`
    // 2. Read content of each staged file
    // 3. Run composite detector on each file
    // 4. Output findings as table to stderr
    // 5. Exit 1 if findings found, blocking the commit
  });
```
**Testing**:
- `pre-commit-blocks-secret`: Staging a file with a secret and running pre-commit hook exits with code 1
- `pre-commit-allows-clean`: Staging a clean file exits with code 0
- `pre-commit-only-scans-staged`: Unstaged files with secrets do not trigger findings
- `pre-commit-performance-under-2s`: Hook completes in under 2 seconds for typical staged changeset (10 files)

#### 3.4 — JSON and CSV Output Formatters
**What**: Implement JSON and CSV formatters alongside the existing SARIF and table formatters.
**Design**:
```typescript
// packages/scanner-engine/src/formatters/json.ts
export function toJSON(findings: Finding[], stats: ScanStats): string {
  return JSON.stringify({
    version: '1.0',
    scanStats: stats,
    findings: findings.map(f => ({
      id: f.id,
      secretType: f.secretTypeId,
      severity: f.severity,
      confidence: f.confidence,
      secretDisplay: f.secretDisplay,
      location: f.location,
      fingerprint: f.fingerprint,
      detectedAt: f.detectedAt,
    })),
  }, null, 2);
}

// packages/scanner-engine/src/formatters/csv.ts
export function toCSV(findings: Finding[]): string {
  const header = 'id,secret_type,severity,confidence,file_path,line_number,secret_display,fingerprint\n';
  const rows = findings.map(f =>
    [f.id, f.secretTypeId, f.severity, f.confidence,
     f.location.filePath, f.location.lineNumber, f.secretDisplay, f.fingerprint
    ].map(csvEscape).join(',')
  ).join('\n');
  return header + rows;
}
```
**Testing**:
- `json-output-parseable`: `JSON.parse(output)` succeeds and has correct finding count
- `json-includes-scan-stats`: Output includes `scanStats.filesScanned`, `durationMs`
- `csv-header-correct`: First line matches expected column names
- `csv-escapes-commas`: Finding with comma in file path is properly quoted

---

## Phase 4: Credential Verification

### Purpose
Add live credential verification that calls provider APIs to confirm whether detected secrets are currently active, enabling accurate triage and prioritized remediation.

### Tasks

#### 4.1 — Verifier Interface & Registry
**What**: Define a plugin interface for credential verifiers and a registry to look up the correct verifier by secret type.
**Design**:
```typescript
// packages/scanner-engine/src/verifiers/verifier-registry.ts

export interface VerificationResult {
  status: VerificationStatus;
  verifiedAt: string;
  method: 'api_call' | 'dns_lookup' | 'http_probe';
  providerResponse?: Record<string, unknown>;
  permissionsDiscovered?: string[];
  lastUsed?: string;
  durationMs: number;
}

export interface SecretVerifier {
  readonly providerId: string;
  readonly supportedTypes: string[];

  verify(secretValue: string, secretType: string): Promise<VerificationResult>;
}

export class VerifierRegistry {
  private verifiers = new Map<string, SecretVerifier>();

  register(verifier: SecretVerifier): void {
    for (const type of verifier.supportedTypes) {
      this.verifiers.set(type, verifier);
    }
  }

  canVerify(secretTypeId: string): boolean {
    return this.verifiers.has(secretTypeId);
  }

  async verify(secretTypeId: string, secretValue: string): Promise<VerificationResult> {
    const verifier = this.verifiers.get(secretTypeId);
    if (!verifier) {
      return { status: 'verification_unsupported', verifiedAt: new Date().toISOString(),
               method: 'api_call', durationMs: 0 };
    }
    return verifier.verify(secretValue, secretTypeId);
  }
}
```
**Testing**:
- `registry-returns-correct-verifier`: Registering AWS verifier for `aws_access_key` returns it for that type
- `registry-returns-unsupported`: Unregistered type returns `verification_unsupported` status
- `registry-multiple-types`: A verifier supporting 3 types is found for all 3

#### 4.2 — AWS Credential Verifier
**What**: Verify AWS access keys by calling the STS GetCallerIdentity API.
**Design**:
```typescript
// packages/scanner-engine/src/verifiers/aws-verifier.ts

export class AWSVerifier implements SecretVerifier {
  readonly providerId = 'aws';
  readonly supportedTypes = ['aws_access_key'];

  async verify(secretValue: string, secretType: string): Promise<VerificationResult> {
    const startMs = Date.now();
    try {
      // 1. Parse the access key ID from the match context
      // 2. Sign a GetCallerIdentity request with AWS4-HMAC-SHA256
      // 3. Call https://sts.amazonaws.com/?Action=GetCallerIdentity
      // 4. If 200: verified_active, extract Account, Arn, UserId
      // 5. If 403: verified_inactive (key exists but is disabled)
      // 6. If other error: verification_failed
      return {
        status: 'verified_active',
        verifiedAt: new Date().toISOString(),
        method: 'api_call',
        providerResponse: { accountId, arn, userId },
        durationMs: Date.now() - startMs,
      };
    } catch (err) {
      return {
        status: 'verification_failed',
        verifiedAt: new Date().toISOString(),
        method: 'api_call',
        durationMs: Date.now() - startMs,
      };
    }
  }
}
```
**Testing**:
- `aws-active-key-verified`: Mock STS returns 200; status is `verified_active` with account ID
- `aws-inactive-key-detected`: Mock STS returns 403; status is `verified_inactive`
- `aws-timeout-handled`: Mock STS times out after 5s; status is `verification_failed`
- `aws-invalid-key-format`: Malformed key produces `verification_failed` without making API call

#### 4.3 — GitHub Token Verifier
**What**: Verify GitHub personal access tokens and app tokens by calling the GitHub API.
**Design**:
```typescript
// packages/scanner-engine/src/verifiers/github-verifier.ts

export class GitHubVerifier implements SecretVerifier {
  readonly providerId = 'github';
  readonly supportedTypes = ['github_pat', 'github_oauth', 'github_app_token'];

  async verify(secretValue: string, secretType: string): Promise<VerificationResult> {
    // 1. Call GET https://api.github.com/user with Authorization: Bearer {token}
    // 2. If 200: verified_active, extract login, scopes from response headers
    // 3. Parse X-OAuth-Scopes header for permission details
    // 4. If 401: verified_inactive
    // 5. If rate limited (403 with X-RateLimit-Remaining: 0): verification_failed
  }
}
```
**Testing**:
- `github-pat-active`: Mock API returns 200; status is `verified_active` with login and scopes
- `github-pat-revoked`: Mock API returns 401; status is `verified_inactive`
- `github-rate-limited`: Mock API returns 429; status is `verification_failed`, not misclassified as inactive

#### 4.4 — Stripe, Slack, and Generic HTTP Verifiers
**What**: Implement verifiers for Stripe API keys, Slack tokens, and a generic HTTP verifier for custom endpoints.
**Design**:
```typescript
// Stripe: POST https://api.stripe.com/v1/charges?limit=1 with Bearer auth
// Slack:  POST https://slack.com/api/auth.test with Bearer auth
// Generic: configurable endpoint, method, header, success indicators from secret_types.verification JSONB
```
**Testing**:
- `stripe-key-verified`: Mock Stripe API returns 200; status is `verified_active`
- `slack-token-verified`: Mock Slack returns `{"ok": true}`; status is `verified_active`
- `generic-verifier-uses-config`: Generic verifier reads endpoint/header from secret type config

#### 4.5 — CLI `verify` Command
**What**: Add a `verify` subcommand that takes scan output and verifies each finding's credential status.
**Design**:
```typescript
// packages/cli/src/commands/verify.ts

export const verifyCommand = new Command('verify')
  .description('Verify whether detected secrets are active')
  .requiredOption('--file <path>', 'Path to JSON findings file from scan output')
  .option('--providers <list>', 'Comma-separated provider filter: aws,github,stripe', 'all')
  .option('--concurrency <n>', 'Max concurrent verification requests', '5')
  .option('--timeout <ms>', 'Per-verification timeout in milliseconds', '10000')
  .option('--output <format>', 'Output format: json, table', 'table')
  .action(async (options) => {
    // 1. Load findings from JSON file
    // 2. Filter by requested providers
    // 3. Initialize verifier registry with selected verifiers
    // 4. Run verifications with concurrency limit (p-limit)
    // 5. Update findings with verification status
    // 6. Output updated findings
  });
```
**Testing**:
- `verify-updates-status`: Input with 3 unverified findings outputs 3 findings with verification status set
- `verify-concurrency-respected`: With `--concurrency 2`, max 2 verifications run simultaneously
- `verify-provider-filter`: `--providers aws` only verifies AWS findings, skips GitHub findings
- `verify-timeout-handled`: Slow verification times out and produces `verification_failed`

---

## Phase 5: LLM-Based Detection & Risk Scoring

### Purpose
Add AI-powered detection that achieves F1>0.985 (per arXiv:2504.18784), replacing regex-only detection for ambiguous cases, and generate context-aware risk scores for triage prioritization.

### Tasks

#### 5.1 — LLM Detector Integration
**What**: Integrate a local LLM (via Ollama) for secret classification, running as a secondary classifier on candidates identified by regex/entropy.
**Design**:
```typescript
// packages/scanner-engine/src/detectors/llm-detector.ts

export interface LLMDetectorConfig {
  endpoint: string;           // Default: http://localhost:11434
  model: string;              // Default: 'llama3.1:8b-secretscanner'
  batchSize: number;          // Default: 10 candidates per batch
  confidenceThreshold: number; // Default: 0.9
  timeoutMs: number;          // Default: 30000
  fallbackToRegexOnly: boolean; // Default: true (if LLM unavailable)
}

interface ClassificationRequest {
  candidates: Array<{
    value: string;            // The candidate secret (masked after first/last 4 chars)
    context: string;          // 5 lines of surrounding code
    filePath: string;
    variableName?: string;
  }>;
}

interface ClassificationResponse {
  results: Array<{
    isSecret: boolean;
    secretType: string | null;
    confidence: number;       // 0-1
    reasoning: string;        // Why the LLM classified it this way
  }>;
}

export class LLMDetector {
  constructor(private config: LLMDetectorConfig) {}

  async classify(candidates: DetectorMatch[], fileContent: string): Promise<DetectorMatch[]> {
    // 1. Extract surrounding context (5 lines) for each candidate
    // 2. Batch candidates into groups of batchSize
    // 3. Send classification request to Ollama API
    // 4. Filter candidates where isSecret=true and confidence >= threshold
    // 5. Upgrade confidence level based on LLM assessment
    // 6. If Ollama unavailable and fallbackToRegexOnly, return original candidates
  }
}
```
**Testing**:
- `llm-confirms-real-secret`: LLM classifies a real AWS key in production code as secret with >0.9 confidence
- `llm-rejects-test-fixture`: LLM classifies a key in `testdata/fixtures.go` as not-a-secret
- `llm-fallback-on-unavailable`: When Ollama is down, detector returns original regex matches without error
- `llm-batch-processing`: 25 candidates are processed in 3 batches (10, 10, 5)
- `llm-timeout-handled`: Request exceeding 30s times out gracefully

#### 5.2 — Context-Aware Risk Scoring
**What**: Use LLM analysis to generate risk scores (0-100) based on code context, distinguishing production credentials from test/development secrets.
**Design**:
```typescript
// packages/scanner-engine/src/risk-scorer.ts

export interface RiskFactors {
  secretType: string;
  filePath: string;
  branchName: string;
  variableName?: string;
  surroundingCode: string;    // 10 lines of context
  verificationStatus: VerificationStatus;
  commitAuthor: string;
}

export interface RiskAssessment {
  riskScore: number;          // 0-100
  riskContext: string;        // Human-readable explanation
  environmentGuess: 'production' | 'staging' | 'development' | 'test' | 'unknown';
  falsePositiveProbability: number;
  recommendedAction: 'immediate_rotation' | 'scheduled_rotation' | 'review' | 'suppress';
}

export class RiskScorer {
  constructor(private llmEndpoint: string, private model: string) {}

  async score(factors: RiskFactors): Promise<RiskAssessment> {
    // Heuristic base score:
    // - verified_active: +40 points
    // - production file path (deploy/, k8s/, prod): +20 points
    // - main/master branch: +10 points
    // - critical secret type (aws, stripe): +15 points
    // - test file path (*_test.*, testdata/): -30 points
    // - example variable name: -20 points
    //
    // LLM refinement:
    // - Send context to LLM for environment classification
    // - LLM adjusts score based on semantic understanding
    // - LLM generates riskContext explanation
  }

  heuristicScore(factors: RiskFactors): number {
    // Pure heuristic fallback when LLM is unavailable
    let score = 50; // base
    if (factors.verificationStatus === 'verified_active') score += 40;
    if (/\b(prod|production|deploy|k8s)\b/i.test(factors.filePath)) score += 20;
    if (/\b(test|spec|fixture|mock|example)\b/i.test(factors.filePath)) score -= 30;
    if (['aws_access_key', 'stripe_secret_key'].includes(factors.secretType)) score += 15;
    return Math.max(0, Math.min(100, score));
  }
}
```
**Testing**:
- `production-aws-key-scores-above-80`: Verified active AWS key in `deploy/config.yml` on `main` branch scores > 80
- `test-fixture-key-scores-below-30`: AWS key in `test/fixtures/aws_test.go` scores < 30
- `heuristic-fallback-works`: When LLM unavailable, heuristic score is returned without error
- `risk-context-explains-reasoning`: Risk context string mentions file path, verification status, and environment
- `recommended-action-follows-score`: Score > 80 recommends `immediate_rotation`; score < 20 recommends `suppress`

#### 5.3 — Integrate LLM Detector into Composite Detector
**What**: Wire the LLM detector into the composite detection pipeline as an optional third stage after regex and entropy.
**Design**:
```typescript
// Update CompositeDetector to accept LLMDetector

export class CompositeDetector {
  constructor(
    private regex: RegexDetector,
    private entropy: EntropyDetector,
    private llm: LLMDetector | null,   // null when LLM disabled
    private riskScorer: RiskScorer | null,
    private config: CompositeDetectorConfig,
  ) {}

  async detect(content: string, filePath: string, metadata?: ScanMetadata): Promise<DetectorMatch[]> {
    let matches = this.detectSync(content, filePath); // regex + entropy

    if (this.llm && this.config.enableLLM) {
      matches = await this.llm.classify(matches, content);
    }

    if (this.riskScorer && metadata) {
      for (const match of matches) {
        match.riskAssessment = await this.riskScorer.score({
          secretType: match.secretTypeId,
          filePath,
          branchName: metadata.branch || 'unknown',
          surroundingCode: this.extractContext(content, match.startIndex, 10),
          verificationStatus: match.verificationStatus || 'unverified',
          commitAuthor: metadata.commitAuthor || 'unknown',
        });
      }
    }

    return matches;
  }
}
```
**Testing**:
- `llm-reduces-false-positives`: Findings count decreases when LLM is enabled (filters out false positives from regex)
- `risk-scores-attached-to-findings`: Each finding has a `riskAssessment` object when risk scorer is enabled
- `pipeline-works-without-llm`: With LLM disabled, regex+entropy pipeline works exactly as in Phase 2

---

## Phase 6: API Server & Persistence

### Purpose
Build the REST API server that persists scan results, manages incidents, and provides the backend for team-based secret management workflows.

### Tasks

#### 6.1 — Fastify Server Setup
**What**: Initialize the Fastify server with plugins for auth, CORS, rate limiting, OpenAPI docs, and database connection.
**Design**:
```typescript
// packages/server/src/app.ts

import Fastify from 'fastify';
import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import fastifyJwt from '@fastify/jwt';
import fastifyRateLimit from '@fastify/rate-limit';
import fastifyCors from '@fastify/cors';

export async function buildApp() {
  const app = Fastify({ logger: true });

  await app.register(fastifyCors, { origin: process.env.CORS_ORIGIN || '*' });
  await app.register(fastifyRateLimit, { max: 100, timeWindow: '1 minute' });
  await app.register(fastifyJwt, { secret: process.env.JWT_SECRET! });
  await app.register(fastifySwagger, {
    openapi: {
      info: { title: 'Secret Scanner API', version: '0.1.0' },
      components: {
        securitySchemes: {
          bearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
          apiKey: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
        },
      },
    },
  });
  await app.register(fastifySwaggerUi, { routePrefix: '/docs' });

  // Register route modules
  await app.register(scanRoutes, { prefix: '/api/v1/scans' });
  await app.register(findingRoutes, { prefix: '/api/v1/findings' });
  await app.register(incidentRoutes, { prefix: '/api/v1/incidents' });
  await app.register(credentialRoutes, { prefix: '/api/v1/credentials' });
  await app.register(rotationRoutes, { prefix: '/api/v1/rotations' });

  return app;
}
```
**Testing**:
- `server-starts-on-port`: Server binds to configured port and responds to health check
- `swagger-ui-accessible`: GET `/docs` returns the Swagger UI HTML
- `openapi-spec-valid`: GET `/docs/json` returns valid OpenAPI 3.2.0 spec
- `rate-limit-enforced`: 101st request within 1 minute returns 429
- `unauthenticated-request-rejected`: Request without JWT or API key returns 401

#### 6.2 — Scan Job API & Worker
**What**: Implement scan job creation, execution via BullMQ worker, and status tracking.
**Design**:
```typescript
// packages/server/src/routes/scans.ts

// POST /api/v1/scans
// Request: { scanSourceId: string, mode: ScanMode, branch?: string, startCommit?: string, endCommit?: string }
// Response: { id: string, status: 'queued', createdAt: string }

// GET /api/v1/scans/:id
// Response: ScanJob with status, stats, and findings count

// GET /api/v1/scans
// Query: ?status=running&sourceId=uuid&page=1&limit=20
// Response: { data: ScanJob[], pagination: { page, limit, total } }

// packages/server/src/workers/scan-worker.ts
export class ScanWorker {
  constructor(private queue: Queue, private db: DrizzleDB) {}

  async process(job: Job<ScanJobPayload>): Promise<void> {
    // 1. Update scan_jobs.status = 'running'
    // 2. Load scan_source config from DB
    // 3. Construct scanner engine with loaded secret types and rules
    // 4. Execute scan
    // 5. For each finding:
    //    a. Generate fingerprint
    //    b. Check suppressions table
    //    c. Check for duplicates (same fingerprint already in findings)
    //    d. Insert into findings table
    //    e. Create or update incident (group by secret_hash)
    // 6. Update scan_jobs with results and status = 'completed'
    // 7. Enqueue notification jobs for new critical/high findings
  }
}
```
**Testing**:
- `create-scan-job-queued`: POST creates a scan job in `queued` status and returns its ID
- `worker-processes-job`: Queued job transitions through `running` to `completed`
- `findings-persisted`: After scan completion, findings are queryable via GET /api/v1/findings
- `duplicate-findings-marked`: Same secret scanned twice has `is_duplicate: true` on second finding
- `suppressed-findings-skipped`: Finding matching an active suppression is not persisted
- `failed-scan-recorded`: Scan that throws an error records `status: failed` with error message

#### 6.3 — Findings & Incidents API
**What**: Implement CRUD endpoints for findings and incidents, including incident auto-creation from findings.
**Design**:
```typescript
// GET /api/v1/findings
// Query: ?severity=critical&verification_status=verified_active&secretType=aws_access_key
//        &sourceId=uuid&page=1&limit=50&sort=detected_at:desc
// Response: { data: Finding[], pagination: {...} }

// GET /api/v1/findings/:id
// Response: Finding with full location, ai_analysis, verification_details

// POST /api/v1/incidents
// Auto-created by scan worker; also manually creatable
// Request: { title, severity, secretTypeId, findingIds }

// PATCH /api/v1/incidents/:id
// Request: { status?, assignedTo?, resolution?, resolutionNotes? }
// Response: Updated Incident

// POST /api/v1/incidents/:id/timeline
// Request: { type: 'comment', body: string }
// Response: Updated timeline array

// GET /api/v1/incidents
// Query: ?status=open&severity=critical&assignedTo=uuid&page=1&limit=20
```
**Testing**:
- `findings-filtered-by-severity`: Query with `severity=critical` returns only critical findings
- `findings-sorted-by-date`: Default sort returns most recent findings first
- `incident-auto-created`: New finding with new secret_hash creates a new incident
- `incident-updated-on-second-finding`: Second finding with same secret_hash increments incident findings_count
- `incident-status-transition`: PATCH from `open` to `in_progress` succeeds; from `resolved` to `open` succeeds
- `incident-timeline-appended`: POST comment adds entry to timeline JSONB array
- `incident-assignment-recorded`: PATCH with assignedTo updates workflow JSONB

#### 6.4 — Suppressions API
**What**: Implement CRUD for false-positive suppressions with audit trail.
**Design**:
```typescript
// POST /api/v1/suppressions
// Request: { type: 'file_pattern' | 'secret_type' | 'content_hash' | 'finding',
//            targetValue: string, reason: string, classification: string,
//            scanSourceId?: string, metadata?: { expiresAt?: string } }

// GET /api/v1/suppressions
// Query: ?active=true&type=file_pattern&page=1&limit=20

// DELETE /api/v1/suppressions/:id
// Soft-delete: sets is_active = false
```
**Testing**:
- `create-suppression-persists`: POST creates suppression; GET returns it
- `suppression-blocks-findings`: After creating file_pattern suppression, scan no longer reports matching findings
- `expired-suppression-ignored`: Suppression with past expires_at does not block findings
- `delete-suppression-soft`: DELETE sets is_active=false; suppression still queryable with `active=false`

#### 6.5 — Audit Log Middleware
**What**: Automatically log all mutation operations to the audit_log table.
**Design**:
```typescript
// packages/server/src/middleware/audit.ts

export function auditPlugin(app: FastifyInstance) {
  app.addHook('onResponse', async (request, reply) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) && reply.statusCode < 400) {
      await db.insert(auditLog).values({
        organizationId: request.organizationId,
        actorId: request.userId,
        actorType: request.apiKeyId ? 'api_key' : 'user',
        action: `${request.routeOptions.config?.resourceType}.${methodToAction(request.method)}`,
        resourceType: request.routeOptions.config?.resourceType,
        resourceId: request.params?.id || reply.payload?.id,
        details: {
          changes: request.body,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'],
          apiKeyId: request.apiKeyId,
        },
      });
    }
  });
}
```
**Testing**:
- `post-creates-audit-entry`: POST /api/v1/incidents creates an audit_log row with action `incident.created`
- `patch-creates-audit-entry`: PATCH creates audit_log with changes in details JSONB
- `get-no-audit`: GET requests do not create audit entries
- `failed-request-no-audit`: 4xx/5xx responses do not create audit entries
- `audit-includes-ip`: Audit entry includes request IP address

---

## Phase 7: Rotation Engine

### Purpose
Build the credential rotation orchestration engine that executes multi-step rotation workflows across cloud providers, closing the detection-to-remediation gap.

### Tasks

#### 7.1 — Rotation Provider Interface & Registry
**What**: Define a plugin interface for rotation providers and a registry for looking up the correct provider by credential type.
**Design**:
```typescript
// packages/rotation-engine/src/providers/provider-registry.ts

export interface RotationStep {
  order: number;
  type: 'generate_credential' | 'update_consumers' | 'verify_new' | 'revoke_old' | 'notify' | 'wait' | 'approval';
  name: string;
  description: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  errorMessage?: string;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
}

export interface RotationProvider {
  readonly providerId: string;
  readonly supportedTypes: string[];

  planRotation(credential: ManagedCredential): RotationStep[];
  executeStep(step: RotationStep, context: RotationContext): Promise<RotationStep>;
  rollback(completedSteps: RotationStep[], context: RotationContext): Promise<void>;
}

export interface RotationContext {
  credentialId: string;
  executionId: string;
  vaultClient: VaultClient;
  notifier: NotificationService;
}
```
**Testing**:
- `registry-returns-aws-provider`: AWS provider registered for `aws_access_key` and `aws_secret_key`
- `plan-generates-4-steps`: AWS rotation plan produces 4 steps: generate, update, verify, revoke
- `unknown-type-throws`: Requesting rotation for unregistered type throws descriptive error

#### 7.2 — AWS IAM Key Rotation Provider
**What**: Implement automated rotation of AWS IAM access keys.
**Design**:
```typescript
// packages/rotation-engine/src/providers/aws-rotator.ts

export class AWSIAMRotator implements RotationProvider {
  readonly providerId = 'aws';
  readonly supportedTypes = ['aws_access_key'];

  planRotation(credential: ManagedCredential): RotationStep[] {
    const config = credential.providerConfig as AWSProviderConfig;
    return [
      { order: 1, type: 'generate_credential', name: `Create new access key for ${config.iamUser}`,
        status: 'pending', description: 'Call IAM CreateAccessKey API' },
      { order: 2, type: 'update_consumers', name: 'Store new key in vault',
        status: 'pending', description: `Update ${credential.vaultPath}` },
      { order: 3, type: 'verify_new', name: 'Verify new key with GetCallerIdentity',
        status: 'pending', description: 'Confirm new key authenticates successfully' },
      { order: 4, type: 'revoke_old', name: `Deactivate old key ${config.accessKeyId}`,
        status: 'pending', description: 'Call IAM UpdateAccessKey with Status=Inactive' },
    ];
  }

  async executeStep(step: RotationStep, ctx: RotationContext): Promise<RotationStep> {
    switch (step.type) {
      case 'generate_credential':
        // IAM.createAccessKey({ UserName })
        // Store result in step.output
        break;
      case 'update_consumers':
        // Write new key to Vault at credential.vaultPath
        break;
      case 'verify_new':
        // STS.getCallerIdentity() with new key
        break;
      case 'revoke_old':
        // IAM.updateAccessKey({ Status: 'Inactive' }) then IAM.deleteAccessKey()
        break;
    }
    return { ...step, status: 'completed', completedAt: new Date().toISOString() };
  }

  async rollback(completedSteps: RotationStep[], ctx: RotationContext): Promise<void> {
    // Reverse completed steps: re-activate old key, delete new key, restore vault
  }
}
```
**Testing**:
- `aws-rotation-full-cycle`: Mock AWS APIs; all 4 steps complete successfully
- `aws-rotation-verify-failure-triggers-rollback`: Step 3 failure triggers rollback of steps 1-2
- `aws-rotation-vault-updated`: After rotation, vault contains new key values
- `aws-old-key-deactivated`: After rotation, old key is marked inactive via IAM API

#### 7.3 — GitHub Token Rotation Provider
**What**: Implement rotation for GitHub personal access tokens.
**Design**:
```typescript
// packages/rotation-engine/src/providers/github-rotator.ts

export class GitHubTokenRotator implements RotationProvider {
  readonly providerId = 'github';
  readonly supportedTypes = ['github_pat'];

  planRotation(credential: ManagedCredential): RotationStep[] {
    return [
      { order: 1, type: 'generate_credential', name: 'Create new GitHub PAT via API',
        status: 'pending', description: 'Generate new fine-grained PAT with same permissions' },
      { order: 2, type: 'update_consumers', name: 'Store new token in vault',
        status: 'pending', description: 'Update vault with new token value' },
      { order: 3, type: 'verify_new', name: 'Verify new token with GitHub API',
        status: 'pending', description: 'Confirm new token authenticates successfully' },
      { order: 4, type: 'revoke_old', name: 'Revoke old GitHub PAT',
        status: 'pending', description: 'Delete old token via GitHub API' },
    ];
  }
}
```
**Testing**:
- `github-rotation-completes`: All 4 steps complete with mocked GitHub API
- `github-rollback-deletes-new-token`: Rollback on step 3 failure deletes the newly created token

#### 7.4 — Database Credential Rotation Provider
**What**: Implement rotation for PostgreSQL and MySQL database passwords.
**Design**:
```typescript
// packages/rotation-engine/src/providers/database-rotator.ts

export class DatabaseRotator implements RotationProvider {
  readonly providerId = 'database';
  readonly supportedTypes = ['postgresql_connection_string', 'mysql_connection_string'];

  planRotation(credential: ManagedCredential): RotationStep[] {
    return [
      { order: 1, type: 'generate_credential', name: 'Generate new random password',
        status: 'pending', description: 'Generate 32-character random password' },
      { order: 2, type: 'update_consumers', name: 'ALTER USER with new password',
        status: 'pending', description: 'Execute ALTER USER ... PASSWORD on database' },
      { order: 3, type: 'verify_new', name: 'Test connection with new password',
        status: 'pending', description: 'Establish test connection to verify credentials' },
      { order: 4, type: 'update_consumers', name: 'Update vault with new connection string',
        status: 'pending', description: 'Write new credentials to vault' },
    ];
  }
}
```
**Testing**:
- `postgres-password-rotated`: Mock PG connection; ALTER USER succeeds; new password verified
- `mysql-password-rotated`: Mock MySQL connection; password change and verification pass
- `connection-test-fails-triggers-rollback`: Failed connection test triggers password revert

#### 7.5 — Rotation Workflow Orchestrator
**What**: Build the state machine that executes rotation steps sequentially, handling approvals, retries, and rollbacks.
**Design**:
```typescript
// packages/rotation-engine/src/workflow.ts

export class RotationWorkflow {
  constructor(
    private providerRegistry: RotationProviderRegistry,
    private db: DrizzleDB,
    private vaultClient: VaultClient,
    private notifier: NotificationService,
  ) {}

  async execute(executionId: string): Promise<void> {
    const execution = await this.db.select().from(rotationExecutions).where(eq(id, executionId));
    const credential = await this.db.select().from(managedCredentials).where(eq(id, execution.credentialId));
    const provider = this.providerRegistry.get(credential.secretTypeId);
    const context: RotationContext = { credentialId: credential.id, executionId, vaultClient: this.vaultClient, notifier: this.notifier };

    // State machine:
    // pending -> awaiting_approval (if policy requires) -> approved -> executing -> verifying -> completed
    //                                                                                        -> failed -> rolled_back

    try {
      if (execution.approval?.required && execution.status === 'pending') {
        await this.updateStatus(executionId, 'awaiting_approval');
        return; // Wait for approval webhook/API call
      }

      await this.updateStatus(executionId, 'executing');
      const steps: RotationStep[] = JSON.parse(execution.steps);

      for (const step of steps) {
        if (step.status === 'completed') continue;
        await this.updateStep(executionId, step.order, { status: 'running', startedAt: new Date().toISOString() });

        const result = await provider.executeStep(step, context);
        await this.updateStep(executionId, step.order, result);

        if (result.status === 'failed') {
          await this.handleFailure(executionId, steps, provider, context);
          return;
        }
      }

      await this.updateStatus(executionId, 'completed');
      await this.updateCredential(credential.id, { status: 'active', lastRotatedAt: new Date() });
    } catch (err) {
      await this.handleFailure(executionId, [], provider, context);
    }
  }

  private async handleFailure(executionId: string, steps: RotationStep[], provider: RotationProvider, context: RotationContext): Promise<void> {
    const completedSteps = steps.filter(s => s.status === 'completed');
    if (completedSteps.length > 0) {
      await provider.rollback(completedSteps, context);
      await this.updateStatus(executionId, 'rolled_back');
    } else {
      await this.updateStatus(executionId, 'failed');
    }
  }
}
```
**Testing**:
- `full-rotation-lifecycle`: Execution progresses pending -> executing -> completed; credential status updated
- `approval-required-pauses`: Execution with approval policy stops at `awaiting_approval`
- `approval-resumes-execution`: After approval, execution continues from where it paused
- `step-failure-triggers-rollback`: Failed step causes rollback of completed steps
- `retry-after-transient-failure`: Retry increments retry_count; re-executes from failed step

#### 7.6 — Rotation API & Worker
**What**: Implement API endpoints for triggering, approving, and monitoring rotations, with BullMQ worker for async execution.
**Design**:
```typescript
// POST /api/v1/rotations
// Request: { credentialId: string, trigger: 'manual' | 'incident', linkedIncidentId?: string }
// Response: { id: string, status: 'pending', steps: RotationStep[] }

// POST /api/v1/rotations/:id/approve
// Request: { approvedBy: string }
// Response: { id: string, status: 'approved' }

// GET /api/v1/rotations/:id
// Response: RotationExecution with steps, timing, status

// POST /api/v1/rotations/:id/cancel
// Response: { id: string, status: 'cancelled' }
```
**Testing**:
- `create-rotation-enqueues`: POST creates execution and enqueues BullMQ job
- `approve-rotation-triggers-execution`: POST approve transitions to `approved` and resumes worker
- `cancel-rotation-stops-execution`: POST cancel prevents further steps from executing
- `get-rotation-shows-step-progress`: GET returns current step status and timing

---

## Phase 8: Notification System

### Purpose
Deliver alerts through Slack, email, webhooks, and PagerDuty when critical events occur (new findings, rotation failures, honeytoken triggers), enabling real-time incident response.

### Tasks

#### 8.1 — Notification Channel Management
**What**: CRUD for notification channels with per-channel configuration and event rules.
**Design**:
```typescript
// POST /api/v1/notification-channels
// Request: {
//   channelType: 'slack' | 'email' | 'webhook' | 'pagerduty',
//   name: string,
//   config: {
//     // slack: { webhookUrl, channel }
//     // email: { recipients, fromAddress }
//     // webhook: { url, method, headers, secret }
//     // pagerduty: { integrationKey, severity_mapping }
//     rules: Array<{ event: string, minSeverity?: Severity }>
//   }
// }

// GET /api/v1/notification-channels
// PATCH /api/v1/notification-channels/:id
// DELETE /api/v1/notification-channels/:id
```
**Testing**:
- `create-slack-channel`: POST with Slack config persists channel
- `create-webhook-channel`: POST with webhook config persists with headers
- `update-channel-rules`: PATCH updates event rules in config JSONB
- `test-channel-sends-test-notification`: POST /notification-channels/:id/test sends a test message

#### 8.2 — Notification Dispatch Worker
**What**: BullMQ worker that processes notification jobs, formats messages per channel type, and tracks delivery.
**Design**:
```typescript
// packages/server/src/workers/notification-worker.ts

export interface NotificationPayload {
  organizationId: string;
  eventType: string;          // 'finding.critical', 'incident.created', 'rotation.failed'
  resourceType: string;
  resourceId: string;
  data: Record<string, unknown>;
}

export class NotificationWorker {
  async process(job: Job<NotificationPayload>): Promise<void> {
    // 1. Load notification channels for this organization
    // 2. For each channel, check if event matches any rule
    // 3. For matching channels:
    //    a. Format message per channel type (Slack blocks, email HTML, webhook JSON)
    //    b. Send message
    //    c. Record delivery status
    // 4. Rate limiting: respect per-channel rate limits from config
  }
}

// Slack message formatting:
function formatSlackFinding(finding: Finding): SlackBlock[] {
  return [
    { type: 'header', text: { type: 'plain_text', text: `Secret Detected: ${finding.secretTypeId}` } },
    { type: 'section', fields: [
      { type: 'mrkdwn', text: `*Severity:* ${finding.severity}` },
      { type: 'mrkdwn', text: `*File:* ${finding.location.filePath}:${finding.location.lineNumber}` },
      { type: 'mrkdwn', text: `*Secret:* ${finding.secretDisplay}` },
      { type: 'mrkdwn', text: `*Status:* ${finding.verificationStatus}` },
    ]},
    { type: 'actions', elements: [
      { type: 'button', text: { type: 'plain_text', text: 'View Incident' }, url: `${BASE_URL}/incidents/${finding.incidentId}` },
      { type: 'button', text: { type: 'plain_text', text: 'Rotate Now' }, style: 'danger', url: `${BASE_URL}/rotate/${finding.id}` },
    ]},
  ];
}
```
**Testing**:
- `slack-notification-sent`: Critical finding triggers Slack webhook call with formatted blocks
- `email-notification-sent`: High finding triggers email with HTML body
- `webhook-notification-sent`: Finding triggers outgoing webhook with JSON payload and HMAC signature
- `rule-filtering-works`: Channel with `minSeverity: high` does not fire for medium findings
- `rate-limiting-batches`: 20 findings in 1 second batched into fewer notifications per rate limit config
- `delivery-failure-recorded`: Failed webhook returns error status in notification record

#### 8.3 — Incident-to-Notification Pipeline
**What**: Wire incident lifecycle events (created, assigned, resolved, SLA breached) to the notification system.
**Design**:
```typescript
// Event types emitted by incident operations:
// - incident.created: new incident auto-generated from finding
// - incident.assigned: incident assigned to user/team
// - incident.resolved: incident resolved (rotated, false_positive, etc.)
// - incident.sla_breached: SLA deadline passed without resolution
// - rotation.started: credential rotation initiated
// - rotation.completed: rotation finished successfully
// - rotation.failed: rotation step failed
// - honeytoken.triggered: honeytoken usage detected
```
**Testing**:
- `new-incident-notifies`: Creating an incident enqueues notifications to matching channels
- `sla-breach-notifies`: Scheduled SLA check finds overdue incident and sends alert
- `rotation-failure-notifies`: Failed rotation step sends notification to configured channels

---

## Phase 9: Web Dashboard

### Purpose
Provide a web-based dashboard for team incident management, finding triage, and rotation monitoring, replacing CLI-only workflows for team scenarios.

### Tasks

#### 9.1 — Dashboard Frontend Setup
**What**: Initialize a React SPA (within the server package or separate) with routing, auth state, and API client.
**Design**:
```typescript
// Technology: React 19 + Vite + TanStack Router + TanStack Query + Tailwind CSS 4

// Route structure:
// /                       -> Dashboard overview
// /findings               -> Findings list with filters
// /findings/:id           -> Finding detail
// /incidents              -> Incidents list with Kanban/table view
// /incidents/:id          -> Incident detail with timeline
// /credentials            -> Managed credentials list
// /credentials/:id        -> Credential detail with rotation history
// /rotations/:id          -> Rotation execution detail with step progress
// /sources                -> Scan source management
// /settings               -> Organization settings
// /settings/rules         -> Detection rule management
// /settings/notifications -> Notification channel configuration
// /settings/suppressions  -> Suppression management
```
**Testing**:
- `dashboard-renders`: Main page loads without errors
- `auth-redirect`: Unauthenticated user redirected to login
- `api-client-sends-jwt`: All API requests include Authorization header

#### 9.2 — Findings & Incidents Views
**What**: Build the findings list with severity/verification filtering and incident detail view with timeline and assignment.
**Design**:
```
Findings List:
┌──────────────────────────────────────────────────────────────────────────┐
│ Findings                                         [Filters] [Export CSV] │
│                                                                        │
│ Severity: [All ▼]  Status: [All ▼]  Type: [All ▼]  Source: [All ▼]    │
│                                                                        │
│ ┌─────────┬──────────┬──────────┬──────────────────┬──────┬───────────┐ │
│ │Severity │ Type     │ Status   │ Location         │ Risk │ Detected  │ │
│ ├─────────┼──────────┼──────────┼──────────────────┼──────┼───────────┤ │
│ │CRITICAL │ aws_key  │ ● Active │ config/prod.yml  │ 92.5 │ 2m ago    │ │
│ │HIGH     │ ghp_*    │ ○ Unver  │ src/deploy.ts:42 │ 71.0 │ 1h ago    │ │
│ │MEDIUM   │ slack_wh │ ● Active │ #engineering     │ 55.0 │ 3h ago    │ │
│ └─────────┴──────────┴──────────┴──────────────────┴──────┴───────────┘ │
└──────────────────────────────────────────────────────────────────────────┘

Incident Detail:
┌──────────────────────────────────────────────────────────────────────────┐
│ Incident #42: AWS Access Key leaked in config/prod.yml                 │
│ Status: [In Progress ▼]  Assigned: [@alice ▼]  SLA: 2h remaining      │
│                                                                        │
│ ┌──────────────────────────────────┬─────────────────────────────────┐  │
│ │ Timeline                        │ Findings (3)                     │  │
│ │                                 │                                  │  │
│ │ 14:30 ● Created (auto)          │ config/prod.yml:42 ● Active     │  │
│ │ 14:31 ● Assigned to @alice      │ deploy/k8s/secret.yaml:15       │  │
│ │ 15:00 ● Comment: "Rotating..."  │ .env.production:8               │  │
│ │ 15:15 ● Rotation started        │                                  │  │
│ │                                 │                                  │  │
│ │ [Add Comment]                    │ [Rotate All] [Mark FP]          │  │
│ └──────────────────────────────────┴─────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
```
**Testing**:
- `findings-list-renders`: Page displays findings from API with correct columns
- `findings-filter-by-severity`: Selecting "Critical" filter updates URL params and re-fetches
- `incident-timeline-displays`: Timeline entries rendered in chronological order
- `incident-status-update`: Changing status dropdown triggers PATCH and updates UI
- `incident-comment-adds`: Submitting comment appends to timeline

#### 9.3 — Credential & Rotation Views
**What**: Build credential management list and rotation execution detail view with step-by-step progress.
**Design**:
```
Rotation Execution Detail:
┌──────────────────────────────────────────────────────────────────────────┐
│ Rotation #7 — AWS IAM Key for deploy-bot                               │
│ Status: Executing  Trigger: Incident #42  Started: 15:15               │
│                                                                        │
│ Step 1: Generate new IAM access key     [✓ Completed]    1.5s          │
│ Step 2: Store new key in vault          [✓ Completed]    0.3s          │
│ Step 3: Verify new key (GetCallerIdentity)  [● Running]  ...           │
│ Step 4: Deactivate old access key       [○ Pending]                    │
│                                                                        │
│ [Cancel Rotation]                                                      │
└──────────────────────────────────────────────────────────────────────────┘
```
**Testing**:
- `credential-list-shows-status`: Credentials displayed with status badges (active, rotating, expired)
- `rotation-steps-show-progress`: Running rotation shows completed/running/pending steps
- `rotation-step-updates-realtime`: Step status updates via polling or SSE without page reload

#### 9.4 — Dashboard Overview & Metrics
**What**: Build the overview page with key metrics: open incidents, findings by severity, rotation status, SLA compliance.
**Design**:
```typescript
// Dashboard queries (server-side):
// 1. Open incidents by severity: SELECT severity, count(*) FROM incidents WHERE status NOT IN ('resolved', 'false_positive') GROUP BY severity
// 2. Findings trend (30 days): SELECT date_trunc('day', detected_at) as day, count(*) FROM findings WHERE detected_at > now() - '30 days' GROUP BY day
// 3. Verification breakdown: SELECT verification_status, count(*) FROM findings GROUP BY verification_status
// 4. Rotation success rate: SELECT status, count(*) FROM rotation_executions WHERE created_at > now() - '30 days' GROUP BY status
// 5. SLA compliance: SELECT count(*) FILTER (WHERE NOT sla_breached), count(*) FROM incidents WHERE resolved_at > now() - '30 days'
```
**Testing**:
- `dashboard-displays-metrics`: Overview page shows incident count, finding trend chart, verification breakdown
- `dashboard-loads-under-2s`: Dashboard API queries complete in under 2 seconds with 10K findings
- `empty-state-handled`: Dashboard with zero data displays "No findings yet" message

---

## Phase 10: Collaboration Tool Scanning

### Purpose
Extend scanning to Slack, Jira, and Confluence where 28% of secrets leak (per Snyk/GitGuardian 2025 report), covering the gap that no open-source tool addresses.

### Tasks

#### 10.1 — Slack Workspace Scanner
**What**: Scan Slack messages for secrets using the Slack Web API, feeding messages through the composite detector.
**Design**:
```typescript
// packages/scanner-engine/src/sources/slack-source.ts

export interface SlackScanOptions {
  workspaceId: string;
  botToken: string;           // Retrieved from vault, not stored in DB
  channels: string[];         // Channel IDs to scan
  scanDMs: boolean;
  since?: Date;               // Only messages after this timestamp
  batchSize: number;          // Default: 200 messages per API call
}

export class SlackSource {
  constructor(
    private detector: CompositeDetector,
    private options: SlackScanOptions,
  ) {}

  async scan(): Promise<ScanResult> {
    // 1. For each channel:
    //    a. Call conversations.history with pagination
    //    b. For each message, run detector on message text
    //    c. Handle threaded replies via conversations.replies
    //    d. Generate SlackFindingLocation for matches
    // 2. Rate limit API calls per Slack's Tier 3 limits (50+ RPM)
    // 3. Handle pagination tokens for large channels
  }
}
```
**Testing**:
- `slack-finds-secret-in-message`: Mock Slack API returns message with AWS key; detected as finding
- `slack-handles-threads`: Secret in thread reply is detected with correct message_ts
- `slack-rate-limiting`: Scanner respects Slack API rate limits (mock 429 response)
- `slack-pagination`: Large channel with 1000+ messages fully scanned across multiple pages
- `slack-location-populated`: Finding location includes channelName, authorName, messageSnippet

#### 10.2 — Docker Image Scanner
**What**: Scan Docker image layers for secrets in environment variables, config files, and embedded credentials.
**Design**:
```typescript
// packages/scanner-engine/src/sources/docker-source.ts

export interface DockerScanOptions {
  imageRef: string;           // e.g., 'myapp:latest' or 'registry.example.com/myapp:v1.2'
  extractLayers: boolean;     // Default: true
  scanEnvVars: boolean;       // Default: true
  excludePaths?: string[];
}

export class DockerSource {
  constructor(
    private detector: CompositeDetector,
    private options: DockerScanOptions,
  ) {}

  async scan(): Promise<ScanResult> {
    // 1. Pull image manifest and config
    // 2. Extract ENV variables from image config — scan each value
    // 3. For each layer: extract tar, scan file contents
    // 4. Skip binary files, node_modules, etc.
    // 5. Return findings with Docker-specific location metadata
  }
}
```
**Testing**:
- `docker-finds-env-secret`: Image with `ENV AWS_SECRET_KEY=AKIA...` detected
- `docker-finds-file-secret`: Secret in a config file within a layer detected
- `docker-excludes-node-modules`: node_modules directory in layers is skipped
- `docker-handles-multi-layer`: Secrets found across multiple layers all reported

#### 10.3 — S3 Bucket Scanner
**What**: Scan S3 bucket objects for secrets, supporting prefix filtering and file type selection.
**Design**:
```typescript
// packages/scanner-engine/src/sources/s3-source.ts

export interface S3ScanOptions {
  bucketName: string;
  region: string;
  prefixFilter?: string;
  includeExtensions?: string[];  // e.g., ['.env', '.yml', '.json', '.conf']
  maxObjectSizeBytes?: number;
  credentials: { roleArn: string } | { accessKeyId: string; secretAccessKey: string };
}

export class S3Source {
  constructor(
    private detector: CompositeDetector,
    private options: S3ScanOptions,
  ) {}

  async scan(): Promise<ScanResult> {
    // 1. ListObjectsV2 with prefix filter
    // 2. For each object matching extension filter and size limit:
    //    a. GetObject to retrieve content
    //    b. Run detector on content
    //    c. Generate S3-specific location metadata
    // 3. Handle pagination for buckets with 1000+ objects
  }
}
```
**Testing**:
- `s3-finds-secret-in-env-file`: `.env` file in S3 bucket with secret detected
- `s3-prefix-filter`: Only objects under specified prefix are scanned
- `s3-extension-filter`: Only `.env` and `.yml` files scanned when filter specified
- `s3-oversized-skipped`: Object exceeding maxObjectSizeBytes is skipped

---

## Phase 11: Compliance Reporting & Honeytokens

### Purpose
Add compliance report generation mapped to SOC 2, PCI-DSS, and FedRAMP controls, and implement honeytoken generation for proactive intrusion detection.

### Tasks

#### 11.1 — Compliance Framework Seed Data
**What**: Populate compliance control mappings for SOC 2 Type II, PCI DSS 4.0, and FedRAMP Moderate.
**Design**:
```typescript
// Seed data mapping platform capabilities to compliance controls

const SOC2_CONTROLS = [
  { framework: 'soc2', controlId: 'CC6.1', title: 'Logical Access Security',
    evidenceType: 'access_log', description: 'Restrict logical access to information assets' },
  { framework: 'soc2', controlId: 'CC6.3', title: 'Role-Based Access',
    evidenceType: 'policy_enforcement', description: 'Role-based access and least privilege' },
  { framework: 'soc2', controlId: 'CC7.2', title: 'Security Event Monitoring',
    evidenceType: 'scan_coverage', description: 'Monitor system components for anomalies' },
  // ...
];

const PCI_DSS_CONTROLS = [
  { framework: 'pci_dss_4', controlId: 'Req.3.6', title: 'Cryptographic Key Management',
    evidenceType: 'rotation_compliance', description: 'Key management procedures documented and implemented' },
  { framework: 'pci_dss_4', controlId: 'Req.10.1', title: 'Audit Trails',
    evidenceType: 'access_log', description: 'Implement audit trails linking access to individual users' },
  // ...
];
```
**Testing**:
- `seed-soc2-controls`: SOC 2 controls inserted; count matches expected
- `seed-pci-controls`: PCI DSS 4.0 controls inserted correctly

#### 11.2 — Compliance Report Generator
**What**: Generate compliance reports by querying audit logs, scan coverage, and rotation history against control requirements.
**Design**:
```typescript
// POST /api/v1/compliance/reports
// Request: { framework: 'soc2', periodStart: '2026-01-01', periodEnd: '2026-03-31' }
// Response: ComplianceReport with per-control pass/fail and evidence references

export class ComplianceReportGenerator {
  async generate(orgId: string, framework: string, start: Date, end: Date): Promise<ComplianceReport> {
    const controls = await this.db.select().from(complianceControls).where(eq(framework, framework));
    const results = [];

    for (const control of controls) {
      const evidence = await this.gatherEvidence(orgId, control, start, end);
      results.push({
        controlId: control.controlId,
        title: control.title,
        status: evidence.passing ? 'passing' : 'failing',
        evidence: evidence.items,
        gaps: evidence.gaps,
      });
    }

    return {
      framework, periodStart: start, periodEnd: end,
      totalControls: results.length,
      passingControls: results.filter(r => r.status === 'passing').length,
      failingControls: results.filter(r => r.status === 'failing').length,
      complianceScore: (passingCount / totalCount) * 100,
      controls: results,
    };
  }

  private async gatherEvidence(orgId: string, control: ComplianceControl, start: Date, end: Date) {
    switch (control.evidenceType) {
      case 'scan_coverage':
        // Query scan_jobs for scan frequency and coverage metrics
        break;
      case 'rotation_compliance':
        // Query rotation_executions for rotation frequency and success rate
        break;
      case 'access_log':
        // Query audit_log for access patterns and anomalies
        break;
      case 'incident_response':
        // Query incidents for mean time to resolution
        break;
    }
  }
}
```
**Testing**:
- `soc2-report-generated`: Report includes all SOC 2 controls with pass/fail status
- `pci-report-includes-rotation-evidence`: Rotation metrics satisfy PCI Req.3.6
- `report-period-filtering`: Only data within specified date range is included
- `failing-control-shows-gap`: Control without sufficient evidence shows `failing` with gap description

#### 11.3 — Honeytoken Generation & Monitoring
**What**: Generate fake credentials (honeytokens) that can be planted in repositories or config files to detect unauthorized access.
**Design**:
```typescript
// POST /api/v1/honeytokens
// Request: { secretTypeId: 'aws_access_key', name: string, plantedLocation: string }
// Response: { id, tokenValue (shown once), callbackUrl, status: 'active' }

// Honeytoken types:
// - AWS: Create a real IAM user with no permissions but CloudTrail logging
// - GitHub: Create a PAT with no scopes but audit log monitoring
// - Generic: Generate a unique token with a callback URL that triggers on HTTP request

// POST /api/v1/honeytokens/:id/trigger  (webhook endpoint for callback)
// Called when honeytoken is used; updates status to 'triggered', sends alerts

export class HoneytokenService {
  async create(orgId: string, request: CreateHoneytokenRequest): Promise<Honeytoken> {
    // 1. Generate a realistic-looking credential for the specified type
    // 2. Set up monitoring (CloudTrail, callback URL, or audit polling)
    // 3. Hash and store the token
    // 4. Return the plaintext value (shown to user once for planting)
  }

  async checkTrigger(tokenHash: string, triggerDetails: TriggerDetails): Promise<void> {
    // 1. Look up honeytoken by hash
    // 2. Update status to 'triggered'
    // 3. Record trigger details (source IP, user agent, timestamp)
    // 4. Send high-priority notifications to all configured channels
  }
}
```
**Testing**:
- `honeytoken-created`: POST creates honeytoken; response includes plaintext value
- `honeytoken-value-hashed`: Stored token_hash does not equal plaintext value
- `honeytoken-trigger-detected`: Callback to trigger endpoint updates status and sends notification
- `honeytoken-expiry-respected`: Expired honeytoken trigger is logged but not alerted

---

## Phase 12: CI/CD Integration & GitHub Actions

### Purpose
Deliver production-ready CI/CD integration including a GitHub Action, GitLab CI template, and webhook-driven scanning for push events.

### Tasks

#### 12.1 — GitHub Action
**What**: Build a GitHub Action that runs secret scanning on push/PR events with SARIF upload to GitHub Code Scanning.
**Design**:
```yaml
# action.yml
name: 'Secret Scanner'
description: 'Scan for leaked secrets in your codebase'
inputs:
  scan-mode:
    description: 'Scan mode: full, incremental, pr_diff'
    default: 'pr_diff'
  severity:
    description: 'Minimum severity to report'
    default: 'medium'
  verify:
    description: 'Enable live credential verification'
    default: 'false'
  fail-on-findings:
    description: 'Fail the check if secrets found'
    default: 'true'
  sarif-upload:
    description: 'Upload SARIF to GitHub Code Scanning'
    default: 'true'
runs:
  using: 'composite'
  steps:
    - run: npx secret-scanner scan --repo ${{ github.workspace }} --mode ${{ inputs.scan-mode }} --severity ${{ inputs.severity }} --output sarif --output-file results.sarif --exit-code
    - uses: github/codeql-action/upload-sarif@v3
      if: inputs.sarif-upload == 'true'
      with:
        sarif_file: results.sarif
```
**Testing**:
- `action-scans-repo`: Action runs in test workflow and produces SARIF output
- `action-uploads-sarif`: SARIF file uploaded to GitHub Code Scanning API
- `action-fails-on-findings`: Workflow step fails when secrets detected and fail-on-findings is true
- `action-passes-clean-repo`: Workflow step passes on repo with no secrets
- `pr-diff-mode-only-scans-changes`: In PR context, only changed files are scanned

#### 12.2 — Webhook Receiver for Push Events
**What**: Accept GitHub/GitLab webhook events to trigger scans on push, enabling real-time monitoring of repository changes.
**Design**:
```typescript
// POST /api/v1/webhooks/github
// Verifies webhook signature (HMAC-SHA256), extracts push event data,
// enqueues scan job for the affected repository and commit range.

// POST /api/v1/webhooks/gitlab
// Verifies webhook token, extracts push event data, enqueues scan job.

export async function handleGitHubWebhook(request: FastifyRequest): Promise<void> {
  // 1. Verify X-Hub-Signature-256 header against webhook secret
  // 2. Parse push event: extract repo URL, before/after commits, branch
  // 3. Find matching scan_source by external_id
  // 4. Enqueue scan job with mode='commit_range', startCommit=before, endCommit=after
}
```
**Testing**:
- `webhook-valid-signature-accepted`: Valid HMAC signature passes verification
- `webhook-invalid-signature-rejected`: Invalid signature returns 401
- `webhook-enqueues-scan`: Valid push event creates scan job with correct commit range
- `webhook-unknown-repo-ignored`: Push from unregistered repo returns 200 but no scan enqueued

#### 12.3 — GitLab CI Template
**What**: Provide a `.gitlab-ci.yml` template for GitLab CI/CD integration.
**Design**:
```yaml
# .gitlab-ci-template.yml
secret-scan:
  image: ghcr.io/secret-scanner/scanner:latest
  stage: test
  script:
    - secret-scanner scan --repo $CI_PROJECT_DIR --mode incremental --output sarif --output-file gl-secret-detection-report.json --exit-code
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```
**Testing**:
- `gitlab-template-valid-yaml`: Template parses as valid YAML
- `gitlab-artifact-path-correct`: Report path matches GitLab's expected secret_detection artifact location

#### 12.4 — Container Image Build & Publishing
**What**: Build and publish the multi-stage Docker image for scanner and server components.
**Design**:
```dockerfile
# Dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/ packages/
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

FROM node:22-alpine AS scanner
WORKDIR /app
COPY --from=builder /app/packages/cli/dist ./cli/
COPY --from=builder /app/packages/scanner-engine/dist ./scanner-engine/
COPY --from=builder /app/packages/types/dist ./types/
COPY --from=builder /app/rules/ ./rules/
ENTRYPOINT ["node", "cli/index.js"]

FROM node:22-alpine AS server
WORKDIR /app
COPY --from=builder /app/packages/server/dist ./
COPY --from=builder /app/packages/types/dist ./types/
EXPOSE 3000
CMD ["node", "app.js"]
```
**Testing**:
- `scanner-image-runs`: `docker run scanner scan --help` displays help text
- `server-image-starts`: `docker run server` starts Fastify and responds to health check
- `image-size-under-200mb`: Final scanner image is under 200MB

---

## Phase Summary & Dependencies

```
Phase 1: Project Scaffold & Data Layer
  └─> Phase 2: Scanner Engine Core
       ├─> Phase 3: CLI & SARIF Output
       │    └─> Phase 12: CI/CD Integration & GitHub Actions
       └─> Phase 4: Credential Verification
            └─> Phase 5: LLM-Based Detection & Risk Scoring
                 └─> Phase 6: API Server & Persistence
                      ├─> Phase 7: Rotation Engine
                      │    └─> Phase 8: Notification System
                      │         └─> Phase 11: Compliance Reporting & Honeytokens
                      ├─> Phase 9: Web Dashboard
                      └─> Phase 10: Collaboration Tool Scanning
```

| Phase | Depends On | Produces | Estimated Effort |
|-------|-----------|----------|-----------------|
| 1. Scaffold & Data Layer | None | Monorepo, DB schema, dev environment | 3-4 days |
| 2. Scanner Engine Core | Phase 1 | Regex/entropy detectors, git/filesystem sources | 5-7 days |
| 3. CLI & SARIF Output | Phase 2 | Working CLI tool, SARIF/JSON/CSV output | 3-4 days |
| 4. Credential Verification | Phase 2 | AWS/GitHub/Stripe verifiers, verify command | 4-5 days |
| 5. LLM Detection & Scoring | Phase 4 | LLM detector, risk scorer, heuristic fallback | 5-7 days |
| 6. API Server & Persistence | Phase 5 | REST API, scan/finding/incident CRUD, audit log | 7-10 days |
| 7. Rotation Engine | Phase 6 | AWS/GitHub/DB rotation, workflow orchestrator | 7-10 days |
| 8. Notification System | Phase 7 | Slack/email/webhook/PagerDuty notifications | 3-4 days |
| 9. Web Dashboard | Phase 6 | React dashboard for findings/incidents/rotations | 7-10 days |
| 10. Collaboration Scanning | Phase 6 | Slack/Docker/S3 source scanners | 5-7 days |
| 11. Compliance & Honeytokens | Phase 8 | SOC 2/PCI reports, honeytoken generation | 4-5 days |
| 12. CI/CD Integration | Phase 3 | GitHub Action, GitLab template, Docker images | 3-4 days |

---

## Definition of Done (per phase)

1. **All tasks implemented**: Every task in the phase has working code committed to the repository.
2. **All named tests pass**: Every test scenario listed in the Testing section passes in CI. Unit tests via Vitest; integration tests via Testcontainers.
3. **Type safety enforced**: Zero TypeScript errors with `strict: true`. All JSONB columns have corresponding JSON Schema validation.
4. **API documentation current**: Any new API endpoints are reflected in the generated OpenAPI spec and verified via `fastify.swagger()`.
5. **No regression**: All tests from prior phases continue to pass.
6. **Linting clean**: ESLint and Prettier produce zero errors or warnings.
7. **Security review**: No secrets hardcoded in code. No credential values stored in PostgreSQL (hash only). Vault references used for all sensitive data.
8. **Docker builds**: `docker compose up` brings up the full development environment. Container images build successfully.
