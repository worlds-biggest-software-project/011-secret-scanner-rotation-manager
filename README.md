# Secret Scanner & Rotation Manager

Unified secret detection and rotation platform that closes the gap between discovering leaked credentials and safely remediating them. Combines LLM-powered detection with automated credential lifecycle management across cloud providers.

## The Problem

Secrets leak constantly. The Snyk & GitGuardian 2025 State of Secrets Sprawl Report found **28.65 million new hardcoded secrets pushed to public GitHub in 2025 alone** — a 34% year-over-year increase. Yet the industry's best-of-breed tools remain siloed:

- **Detection tools** (Gitleaks, TruffleHog) flag secrets but leave remediation to manual steps
- **Rotation platforms** (HashiCorp Vault, AWS Secrets Manager) manage credentials but have no integrated scanning
- **The median gap from discovery to removal is 2+ weeks**, creating a window for exploitation

Current solutions treat secret management as two separate problems. Organizations run both a scanner (to find leaks) and a rotation tool (to manage credentials), then manually bridge the gap with tribal knowledge.

## What This Does

This platform closes the detection-to-remediation loop with:

### Detection (AI-Native)
- **LLM-based pattern recognition** replacing regex-only matching — achieves F1>0.985 on production datasets (vs. ~46% precision for Gitleaks)
- **Multi-source scanning** covering code repositories, collaboration tools (Slack, Jira, Confluence — where 28% of leaks originate), and CI/CD environment variables
- **Live credential verification** confirming whether found secrets are actually active vs. expired test keys
- **Collaboration tool coverage** — the 28% of leaks from Slack, Jira, Confluence are invisible to every open-source scanner

### Rotation (Context-Aware)
- **Automatic rotation workflow generation** — given a leaked credential type and provider, generate the specific rotation steps
- **Provider-agnostic orchestration** — unified interface for AWS, Azure, GCP, and self-hosted databases
- **Risk-aware prioritization** — distinguish production API keys (critical) from development test tokens (low priority)

### Unified Detection → Rotation
- **Bridging the 2-week gap** — convert a finding directly into a rotation action without manual context-switching
- **Rotation guidance with justification** — LLM explains *why* a secret should be rotated and what risk it poses in the specific deployment context

## Key Differentiators

| Feature | This Platform | Gitleaks | TruffleHog | HashiCorp Vault | Snyk Secrets |
|---------|---|---|---|---|---|
| **LLM-based detection** | ✓ (F1>0.985) | — | — | — | — |
| **Collaboration tool scanning** | ✓ (Slack, Jira) | — | — | — | — |
| **Automated rotation** | ✓ | — | — | ✓ | — |
| **Live credential verification** | ✓ | — | ✓ | — | ✓ |
| **Unified detection + rotation** | ✓ | — | — | — | — |
| **Risk scoring & prioritization** | ✓ | — | — | — | ✓ |

## Market & Opportunity

- **Market size**: $4.22B (2025) → $8.05B (2030) at 13.8% CAGR
- **Buyers**: DevSecOps teams (primary), security operations centers, compliance officers, AI/ML companies
- **Open-source gap**: No single open-source tool combines detection + rotation + collaboration tools + AI context

## Research Foundation

- **28.65M secrets leaked to public GitHub in 2025** (Snyk & GitGuardian 2025)
- **53% of all data breaches involve credential compromise** (IBM Cost of a Breach 2025)
- **LLM-based detection achieves F1=0.985** vs. 46% precision for regex tools (arXiv:2504.18784, 2025)
- **18% overlap between existing tool true positives** — multi-detector ensemble strongly recommended (SecretBench, 2023)

## Quick Start

```bash
# Scan a repository
scan --repo /path/to/repo --output json

# Verify credentials (check which are actually active)
verify --file findings.json --providers aws,github,stripe

# Generate rotation workflow
rotate --credential-id <id> --destination vault
```

## Target Users

1. **DevSecOps Engineers** — integrate into pre-commit and CI/CD pipelines
2. **Security Operations Centers** — enterprise credential lifecycle management
3. **Compliance / Governance Teams** — SOC 2, PCI-DSS credential compliance
4. **Cloud Platform Teams** — multi-cloud secret rotation orchestration
5. **AI/ML Companies** — managing rapidly deployed API keys and credentials

## Related Standards

- OWASP Secrets Management Cheat Sheet
- NIST SP 800-63B Digital Identity Guidelines
- CWE-798: Use of Hard-coded Credentials
- PCI-DSS, SOC 2 Type II, FedRAMP credential management requirements

---

Built on open-source, production-validated research. [Read the full research analysis](./research.md) | [Feature roadmap](./features.md)
