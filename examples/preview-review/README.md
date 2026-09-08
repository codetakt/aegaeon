# Review a prebuilt Aegaeon server

This Linux x86_64 example starts an isolated local PostgreSQL/Redis environment
and exercises a real Authorization Code + PKCE S256 login with a prebuilt server.
It verifies the ID token signature, issuer, audience, nonce and time claims,
compares the UserInfo subject, and requires reuse of the code to fail.
The optional browser RP displays only validated ID token claims.

The RP uses Python libraries. Packaging and testing the separate Aegaeon SDK
remain subsequent distribution work. This experiment does not activate a
server, SDK or combined assurance claim.

## Run with a published preview

First complete the [private preview publication](../../docs/automation/flakehub-preview.md)
and its separate consumer check. Obtain `manifest.json` from that trusted
successful run's `server-preview-publication` artifact; retain its run URL with
your review record.
Authenticate to FlakeHub on the workstation as described in that runbook.

From this directory:

```sh
nix develop
python3 review.py \
  --manifest /absolute/path/to/manifest.json \
  --state-dir .review/session-001 \
  --serve
```

Use a new state directory for every invocation. The runner retrieves the exact
FlakeHub reference in the manifest, compares the executable digest and the entire
Nix runtime closure, then starts the reviewed binary. A failed fetch or identity
check stops execution. It never invokes Cargo or builds an alternative server.
The Nix shell supplies PostgreSQL, Redis, Atlas, Caddy and the Python dependencies;
Nix may realize these helpers separately.

All listeners bind to `127.0.0.1` on dynamically allocated ports. The runner prints
the HTTPS RP URL, the root certificate path and the path to the generated login
details. Trust `review-ca.pem` in a temporary browser profile, then open the
printed RP URL and select **Login with Aegaeon**. The root signs a separate server
certificate for `localhost` and `127.0.0.1`; both expire after two days. The root
signing key is not saved, and the server key cannot sign certificates. The runner
does not install certificates into the system trust store. Both the issuer and RP
use HTTPS and Secure cookies. Automated HTTP checks verify the certificate chain
against the same root without disabling TLS verification.

The generated account is `reviewer@example.com`; its fresh password is in
`login.txt` inside the private state directory. Press Ctrl-C to stop the RP,
server, proxy, Redis and PostgreSQL. Omitting `--serve` performs the automated flow
and shuts everything down immediately. Neither mode attaches to existing DB or
Redis services. A cancelled or failed check is not recorded as passed.

## Configuration and identity

The flake pins migration source to server commit
`4f22252f8f0f1320d20c8ce90d6476cc670a3e45`, matching the initial distribution lock.
It treats that input as source data, without evaluating the server's flake or
loading its proof toolchain. `AEGAEON_REVIEW_MIGRATIONS` and
`AEGAEON_REVIEW_SOURCE_REVISION` are inputs to the review helper, not server runtime
configuration. A preview from another source revision is rejected until this
kit's source pin, fixture compatibility and tests are updated together.

The private FlakeHub reference uses `codetakt-inc/aegaeon`. The manifest's
`repository` and `server_source` still identify the GitHub repository
`codetakt/aegaeon`; the publication namespace does not replace that source identity.

Atlas applies the source migrations with revision records in `public`. The
isolated `review` database role uses `aegaeon, public` as its search path because
the migration installs pgcrypto in `aegaeon`. The fixture creates a control-plane
policy, team, tenant, active environment/configuration, a downstream OAuth
profile, an encrypted RS256 runtime key and a local password user. The private
key and password are generated per run. The RP registers through the real DCR
endpoint with `pkce_required=true`.

The selected scenario uses a public Code + PKCE client, requires state and the
profile's issuer parameter, enables OIDC discovery/UserInfo, and uses bearer
access tokens. DPoP, PAR, refresh, federation and management-console setup are not
exercised by this scenario. The fixture is written directly into a newly created
database before startup; it does not demonstrate a management onboarding flow.
Server preflight checks and the mandatory DB/Redis runtime stores remain active.

## Evidence and local preparation

`evidence.json` records the source/publication identities, manifest and migration
inventory digests, executable/closure comparison, configuration digest and actual
flow results. `configuration.json` contains the public fixture configuration.
The surrounding state directory also contains database files, credentials,
private TLS material and diagnostic logs. It is created with owner-only access.
Share the evidence JSON and reviewed configuration as appropriate, not the entire
state directory. After stopping the runner, delete only that experiment's state
directory when its local data is no longer needed. `.review/` is Git ignored.

Before FlakeHub publication, maintainers can exercise an already built output
using an authentic build manifest from the preview helper:

```sh
python3 review.py \
  --manifest /absolute/path/to/local-build-manifest.json \
  --local-output /nix/store/REPLACE_WITH_RECORDED_OUTPUT \
  --state-dir .review/prepublication-001
```

This explicit mode still compares the output, binary and closure against the
manifest. Its evidence says `local preparation`; it cannot establish publication,
private-account access or fresh-consumer retrieval. The default published mode
requires `flakeref_exact` and always runs `fh fetch`.

## Regression checks

```sh
nix flake check -L
```

This example's check exercises manifest rejection, actual RSA token verification,
forged/missing/expired/wrong-issuer token rejection, callback state/expiry checks
and single-use browser transactions. The repository's Linux flake checks also
enforce it as `preview-review-contract`. Those small regressions do not start a
database or fetch a private preview; use the real runner for integration evidence.
