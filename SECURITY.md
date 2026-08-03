# Security Policy

## Supported Versions

| Version       | Supported |
| ------------- | --------- |
| 0.9.x (beta) | Yes       |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Please report security vulnerabilities through
[GitHub Security Advisories](https://github.com/conceptual-systems/aegaeon/security/advisories/new).
This provides a private channel for responsible disclosure.

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

Aegaeon employs multi-layer formal verification to minimize the attack surface
(modulo the 12 documented proof assumptions and the runtime contracts — see the
[Assumption Register](docs/verification/claims/assumptions/current-register.md)
and the
[Runtime Contract Register](docs/verification/claims/assumptions/runtime-contract-register.md)):
the official verification claim and boundary conditions are defined in
[`docs/verification/claims/assurance-case.md`](docs/verification/claims/assurance-case.md).

The claim covers **VerifiedReqs** — the subset of compliance matrix entries with `status: verified`
and a formal proof reference (F\*/Low\*/HACL\*, Tamarin, Kani, or EverParse) — and applies
only to artifacts built with the pinned Nix toolchain; misconfiguration and out-of-scope
requirements are explicitly excluded.
See [Assurance Case §0.2](docs/verification/claims/assurance-case/claim-definition.md#02-claim-scope) for the full definition.

**Formal boundary note:** In realistic von Neumann systems with I/O, the
following cannot be proven inside the project’s formal system and are treated
as explicit assumptions outside the formal claim:

1. computational hardness (EUF‑CMA, collision resistance) stated as theorem
   premises
2. OS/device entropy sources modeled as external contracts (for example,
   min‑entropy)
3. external host/storage behaviour modeled as explicit interface contracts or
   TCB boundaries

- **F\*** -- 155 specification modules with 0 `admit()` calls and 12
  `assume val` declarations across 8 files (6 crypto hardness, 2 HACL\*
  linkage, 1 EverParse linkage, 2 OIDC hash runtime linkage, 1 WASM host --
  see [Assumption Register](docs/verification/claims/assumptions/current-register.md))
- **Tamarin Prover** -- 54 protocol models with 247 verified lemmas (symbolic Dolev-Yao model)
- **Kani** -- 139 bounded model-checking harnesses for Rust code
- **Supply chain** -- `cargo deny`, `cargo audit`, `cargo vet`, SBOM generation,
  and Trivy container scanning in CI

All dependencies are policy-gated, and CI enforces `clippy -D warnings` plus
the full verification suite on every pull request.

## Security-Related Configuration

Operators can tune security behaviour through environment variables and policy
gates documented in [`docs/`](docs/). Key controls include DPoP enforcement,
PKCE requirements, token lifetimes, and allowed signing algorithms.

## Contact

For security matters, use
[GitHub Security Advisories](https://github.com/conceptual-systems/aegaeon/security/advisories/new).
For general questions, use [GitHub Discussions](https://github.com/conceptual-systems/aegaeon/discussions).
