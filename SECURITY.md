# Security Policy

## Supported Versions

| Version       | Supported |
| ------------- | --------- |
| 0.9.x (beta) | Yes       |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Report security vulnerabilities privately using either channel:

- Email: [security.aegaeon@codetakt.com](mailto:security.aegaeon@codetakt.com),
  handled by the **Aegaeon Security Reports** group.
- [GitHub private vulnerability reporting](https://github.com/codetakt/aegaeon/security/advisories/new).

Private vulnerability reporting is enabled for this repository. GitHub reports
are visible to the reporter and the repository's security advisory collaborators
until disclosure.

### What to include

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof of concept
- Affected version(s) and configuration
- Any suggested mitigation or fix

### Response timeline

| Stage                        | Target    |
| ---------------------------- | --------- |
| Acknowledgement              | 72 hours  |
| Initial assessment           | 7 days    |
| Patch for critical issues    | 30 days   |
| Patch for non-critical issues| 90 days   |
| Public disclosure             | After fix is released, or 90 days (whichever comes first) |

We follow coordinated disclosure. We will credit reporters in the advisory
unless they prefer to remain anonymous.

## Scope

The following are considered security issues:

- Authentication or authorization bypass
- Token leakage, replay, or injection
- Cryptographic weaknesses (algorithm downgrade, key exposure, timing attacks)
- SSRF, CSRF, XSS, or injection vulnerabilities
- Privilege escalation across tenants or environments
- Bypasses of sender-constrained token mechanisms (DPoP, mTLS)

The following are **not** security issues (please use regular issues):

- Feature requests or usability improvements
- Non-security bugs or test failures
- Performance issues without security impact
- Documentation errors

## Security Posture

Aegaeon maintains formal-verification assets and security-test tooling. Its
[server assurance contract](docs/verification/claims/assurance-case/assurance-contract.md)
fixes requirements for an assumption-qualified formally verified and security-tested
foundation. The [foundation claim is inactive](docs/verification/claims/assurance-case/contract-status.md)
until the obligations are closed for an identified release artifact/configuration.

The separate SDK contract also remains pending. The
[public assurance statement specification](docs/verification/claims/assurance-statement.md)
defines the four distinct claims (specification, implementation/state, symbolic
security, and security testing), required release disclosures, and correction or
withdrawal rules. Finalized wording does not activate either release guarantee.

Matrix `verified` rows are component/model evidence, not a release attestation.
The contract requires implementation correspondence, adversarial model adequacy,
durable state semantics, and release-specific test results. External cryptography,
entropy, toolchain, OS/network/storage contracts must be disclosed; own-code
validation, configuration and orchestration remain verification obligations.

Existing F*/Low*/HACL*, EverParse, Tamarin and Kani assets have distinct evidence
meanings and bounds. See [evidence interpretation](docs/verification/claims/assurance-case/claim-definition.md)
and the [assumption inventory](docs/verification/claims/assumptions/current-register.md).
Dependency review, audit, fuzzing, sanitizers and SBOM tooling provide empirical
evidence when actually run for the identified target; their presence alone does
not mean a release passed security review or is free of vulnerabilities.

## Security-Related Configuration

Operators can tune security behaviour through environment variables and policy
gates documented in [`docs/`](docs/). Key controls include DPoP enforcement,
PKCE requirements, token lifetimes, and allowed signing algorithms.

## Contact

For security matters, use the channels in [Reporting a Vulnerability](#reporting-a-vulnerability).
For Code of Conduct concerns, use
[conduct.aegaeon@codetakt.com](mailto:conduct.aegaeon@codetakt.com), as described in
the [Code of Conduct](CODE_OF_CONDUCT.md#enforcement).
For general questions and non-security bugs, use
[GitHub Issues](https://github.com/codetakt/aegaeon/issues).
