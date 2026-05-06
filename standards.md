# Standards & API Reference

> Project: Secret Scanner & Rotation Manager · Generated: 2026-05-03

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022** — Information security management system standard that emphasizes secure handling of authentication information and credential lifecycle management. Essential for organizations managing sensitive secrets across multiple systems. [https://www.iso.org/standard/27001](https://www.iso.org/standard/27001)

- **ISO/IEC 27002:2022** — Information security code of practice providing guidelines for secrets management, including secure storage, rotation, and access control. Complements ISO 27001 with practical implementation guidance.

### W3C & IETF Standards

- **RFC 7231 (HTTP/1.1 Semantics and Content)** — Defines HTTP semantics and authentication mechanisms used in API credential transmission. Critical for understanding secure API design patterns. [https://tools.ietf.org/html/rfc7231](https://tools.ietf.org/html/rfc7231)

- **RFC 6749 (OAuth 2.0 Authorization Framework)** — Industry-standard protocol for delegated authorization, providing secure token-based authentication patterns that replace hardcoded credentials. [https://tools.ietf.org/html/rfc6749](https://tools.ietf.org/html/rfc6749)

- **RFC 6750 (OAuth 2.0 Bearer Token Usage)** — Defines bearer token usage in HTTP requests, a primary mechanism for API credential transmission and a key target for secret scanning.

- **OpenID Connect 1.0** — Adds authentication layer on top of OAuth 2.0, enabling identity verification while managing credential lifecycle.

### Data Model & API Specifications

- **OpenAPI 3.2.0** — The industry standard for describing RESTful API interfaces, enabling machine-readable documentation of API endpoints, authentication methods, request/response schemas, and security requirements. Latest version released September 2025 with enhanced security and streaming support. [https://spec.openapis.org/oas/v3.2.0.html](https://spec.openapis.org/oas/v3.2.0.html)

- **JSON Schema** — Standard for validating credential structures, API request/response bodies, and configuration data. Essential for enforcing credential format validation in rotation workflows.

- **Arazzo (API Orchestration Specification)** — Emerging standard for describing multi-step API workflows, complementing OpenAPI by enabling orchestration of credential rotation across dependent services.

### Security & Authentication Standards

- **OWASP Secrets Management Cheat Sheet** — Comprehensive guidance on storing, rotating, and managing secrets in applications. Directly relevant for implementing detection and rotation best practices. [https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

- **NIST SP 800-63B (Digital Identity Guidelines - Authentication and Lifecycle Management)** — Defines authenticator lifecycle management, credential rotation requirements, and multi-factor authentication standards. Mandates credential rotation only when compromise is suspected, moving away from periodic forced rotation. [https://pages.nist.gov/800-63-3/sp800-63b.html](https://pages.nist.gov/800-63-3/sp800-63b.html)

- **NIST SP 800-53 (Security and Privacy Controls)** — Comprehensive control framework covering credential management, access logging, and compliance requirements for federal and government systems.

- **CWE-798: Use of Hard-coded Credentials** — MITRE weakness classification identifying hardcoded secrets as a critical vulnerability. This is the primary vulnerability category this platform detects and remediates. [https://cwe.mitre.org/data/definitions/798.html](https://cwe.mitre.org/data/definitions/798.html)

- **OWASP Top 10 2025 (A07: Identification and Authentication Failures)** — Identifies hardcoded credentials and weak credential management as top security risks. [https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)

- **PCI DSS 4.0** — Payment Card Industry standard requiring secure credential storage, automated rotation, and audit logging for payment systems. Explicitly addresses CWE-798 hardcoded credentials as a non-compliance violation.

- **SOC 2 Type II** — Security audit standard requiring evidence of credential lifecycle management, including rotation policies and access logs.

- **GDPR (General Data Protection Regulation)** — EU regulation treating authentication credentials as personal data, requiring encryption, access controls, and breach notification procedures.

### MCP Server Specifications

- **Model Context Protocol (MCP) 2025-11-25** — Open protocol for integrating LLM applications with external data sources and tools, enabling AI-driven secret scanning, credential verification, and rotation workflow generation. Supports stdio, HTTP, and WebSocket transports for flexible deployment. [https://modelcontextprotocol.io/specification/2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)

## Similar Products — Developer Documentation & APIs

### Gitleaks

- **Description:** Open-source secret detection tool that scans git repositories for hardcoded secrets using regex and entropy-based patterns. Lightweight and fast, ideal for pre-commit and CI/CD integration.
- **API Documentation:** [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
- **SDKs/Libraries:** Available as CLI tool; integrates with pre-commit, GitHub Actions, GitLab CI/CD
- **Developer Guide:** [https://gitleaks.io/](https://gitleaks.io/)
- **Standards:** REST API-style JSON output, SARIF reporting format for SAST compliance
- **Authentication:** None required (standalone tool)
- **Key Differentiator:** Fast, easy to use, but limited to code repositories; no built-in rotation or verification

### TruffleHog

- **Description:** Advanced secret detection tool with multi-source scanning including S3 buckets, Docker images, and cloud storage. Features two-phase detection (entropy/regex + verification) with live credential validation API calls.
- **API Documentation:** [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog)
- **SDKs/Libraries:** Python, Go, JavaScript; Docker images available
- **Developer Guide:** [https://docs.trufflesecurity.com/](https://docs.trufflesecurity.com/)
- **Standards:** REST API, JSON output, webhook integrations
- **Authentication:** API key-based authentication for cloud integrations
- **Key Differentiator:** Most comprehensive multi-source scanning; can verify active credentials via API calls; resource-intensive compared to Gitleaks

### GitGuardian

- **Description:** Commercial secret scanning platform with enterprise-grade incident management, historical analysis, and collaboration tool scanning (Slack, Jira, Confluence). Strong focus on enterprise remediation workflows.
- **API Documentation:** [https://docs.gitguardian.com/](https://docs.gitguardian.com/)
- **SDKs/Libraries:** Python (ggshield), JavaScript, REST API clients available
- **Developer Guide:** [https://www.gitguardian.com/documentation](https://www.gitguardian.com/documentation)
- **Standards:** OpenAPI-documented REST API, SARIF output, SCIM provisioning for enterprise SSO
- **Authentication:** OAuth 2.0, API tokens, JWT for workspace access
- **Key Differentiator:** Collaboration tool scanning (28% of leaks originate from Slack/Jira); SaaS platform with managed incident tracking; no open-source alternative for collaboration tools

### HashiCorp Vault

- **Description:** Industry-leading secrets management and credential rotation platform with support for dynamic secrets, encryption-as-a-service, and multi-cloud credential rotation. Enterprise-grade with extensive audit logging.
- **API Documentation:** [https://www.vaultproject.io/api-docs](https://www.vaultproject.io/api-docs)
- **SDKs/Libraries:** Go, Python, Ruby, JavaScript, Java, .NET, and more
- **Developer Guide:** [https://learn.hashicorp.com/vault](https://learn.hashicorp.com/vault)
- **Standards:** RESTful API (OpenAPI 3.0 compatible), supports OAuth 2.0, mTLS, JWT authentication
- **Authentication:** Token-based, OAuth 2.0, multi-cloud IAM integrations
- **Key Differentiator:** Most mature rotation platform; dynamic secrets generation; enterprise-grade access control; no integrated detection

### AWS Secrets Manager

- **Description:** AWS-native secrets management service with automatic rotation for AWS resources, RDS databases, and third-party services. Tight integration with IAM and Lambda for serverless credential management.
- **API Documentation:** [https://docs.aws.amazon.com/secretsmanager/](https://docs.aws.amazon.com/secretsmanager/)
- **SDKs/Libraries:** AWS SDKs for Python (boto3), JavaScript, Java, Go, .NET, Ruby
- **Developer Guide:** [https://docs.aws.amazon.com/secretsmanager/latest/userguide/](https://docs.aws.amazon.com/secretsmanager/latest/userguide/)
- **Standards:** AWS API Gateway patterns, JSON credential format, CloudTrail audit logging
- **Authentication:** IAM roles, access keys, STS temporary credentials
- **Key Differentiator:** AWS-native with Lambda-based rotation; vendor lock-in; no multi-cloud support

### Akeyless

- **Description:** Cloud-agnostic secrets management platform automating rotation for AWS, Azure, GCP, and self-hosted databases. Emphasizes simplified workflows and cost efficiency compared to traditional vaults.
- **API Documentation:** [https://docs.akeyless.io/](https://docs.akeyless.io/)
- **SDKs/Libraries:** Python, Go, JavaScript, REST API clients
- **Developer Guide:** [https://docs.akeyless.io/getting-started](https://docs.akeyless.io/getting-started)
- **Standards:** RESTful API, OpenAPI 3.0 compliant, OAuth 2.0 authentication
- **Authentication:** API keys, OIDC, OAuth 2.0
- **Key Differentiator:** Zero-trust architecture; cloud-agnostic; simplified admin experience; emerging alternative to Vault

### CyberArk Conjur

- **Description:** Enterprise-grade secrets management solution for securing secrets sprawled across applications, tools, and cloud environments. Strong focus on access control and compliance audit trails.
- **API Documentation:** [https://docs.cyberark.com/conjur/latest/](https://docs.cyberark.com/conjur/latest/)
- **SDKs/Libraries:** Ruby, Python, Java, Go, JavaScript
- **Developer Guide:** [https://cyberark.github.io/conjur/](https://cyberark.github.io/conjur/)
- **Standards:** RESTful API, RBAC, SAML/OIDC integration
- **Authentication:** Certificate-based, OIDC, JWT tokens
- **Key Differentiator:** Enterprise access control; DevOps-focused; strong compliance audit trails

### Doppler

- **Description:** Modern secrets management platform built for development teams with emphasis on environment variable management, version control, and real-time synchronization across platforms. Strong CI/CD integration.
- **API Documentation:** [https://docs.doppler.com/](https://docs.doppler.com/)
- **SDKs/Libraries:** CLI tool, Python, Node.js, Go, Ruby packages
- **Developer Guide:** [https://docs.doppler.com/docs](https://docs.doppler.com/docs)
- **Standards:** RESTful API (OpenAPI documented), Kubernetes integration, Git sync capabilities
- **Authentication:** OAuth 2.0, Service tokens
- **Key Differentiator:** Developer-friendly UX; version control integration; real-time environment variable sync; lightweight alternative to enterprise vaults

### Infisical

- **Description:** Open-source secrets management platform with secret referencing across projects, ephemeral access controls, approval workflows, and automated rotation templates for common services.
- **API Documentation:** [https://infisical.com/docs/integrations/overview](https://infisical.com/docs/integrations/overview)
- **SDKs/Libraries:** Python, JavaScript, Go, Java, available on GitHub
- **Developer Guide:** [https://infisical.com/docs/getting-started/quickstart](https://infisical.com/docs/getting-started/quickstart)
- **Standards:** RESTful API, OpenAPI 3.0, Kubernetes native integration
- **Authentication:** API tokens, OAuth 2.0, OIDC
- **Key Differentiator:** Open-source alternative to commercial vaults; automated rotation templates; ephemeral credentials; multi-cloud support

## Notes

### Standards Landscape Evolution

1. **Shift from Mandatory Rotation to Risk-Based Rotation**: NIST SP 800-63B Rev. 4 (2023) moved away from periodic forced credential rotation, recommending rotation only upon compromise detection. This platform aligns with modern risk-based practices.

2. **Emerging Multi-Source Scanning Need**: While Gitleaks and TruffleHog scan code repositories, 28% of secrets leak from collaboration tools (Slack, Jira, Confluence). Only GitGuardian and this platform address this gap, representing an underserved market segment.

3. **Unified Detection + Rotation Gap**: No open-source tool currently combines LLM-based detection with automated context-aware rotation. This platform fills a critical gap in the DevSecOps toolkit.

4. **MCP Integration Opportunity**: The Model Context Protocol (2025) creates new opportunities for AI-driven secret detection and rotation orchestration, enabling LLM-powered decision-making about credential risk and remediation.

5. **Compliance Consolidation**: PCI DSS 4.0, SOC 2, and HIPAA increasingly require automated credential rotation and audit logging. An integrated platform reduces compliance verification overhead compared to point solutions.

### Key Standards for Architecture Alignment

1. **Detection**: Align with OpenAPI 3.2.0 for API documentation and OWASP Secrets Management Cheat Sheet for detection rules
2. **Verification**: Follow OAuth 2.0 (RFC 6749) patterns for credential validation workflows
3. **Rotation**: Implement NIST SP 800-63B lifecycle management principles and PCI DSS 4.0 requirements
4. **Audit**: Use CloudTrail / audit logs for SOC 2 Type II compliance evidence
5. **Integration**: Consider MCP server specification for AI-driven rotation decision workflows

### Competitive Advantages vs. Similar Products

- **vs. Gitleaks + Vault**: This platform provides unified workflow; no context-switching between detection and rotation
- **vs. GitGuardian**: Open-source + community-driven; collaboration tool scanning + LLM-powered rotation logic
- **vs. TruffleHog**: Adds automated rotation and context-aware remediation; TruffleHog excels at detection, not remediation
- **vs. Vault/Secrets Manager**: Adds integrated detection layer; vault platforms excel at storage/rotation, not finding secrets
