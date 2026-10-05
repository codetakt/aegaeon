# AWS EC2 performance nodes

This module creates a server node, a load-generator node, role-specific secret
access and an S3 report path. PostgreSQL, TLS Redis, an activated Aegaeon issuer,
its clients and runtime keys, HTTPS ingress/DNS and tested OCI artifacts are
required external supplies. Creating these nodes alone does not produce a
working issuer or establish a successful benchmark.

## Required supplies

Apply the exact source-managed Atlas migration inventory before provisioning
an active management environment and runtime keys. The selected server checks
that schema revision at startup. Its issuer host selects that active database
configuration; it does not set issuer policy or keys.

Supply these required OpenTofu inputs through your normal private configuration:

- `issuer_host` and matching `issuer_url` (`https://` plus the canonical DNS host).
  The HTTPS origin is the load-generator target. Supply actual ingress, DNS,
  certificate validation and narrow `server_trusted_proxies` CIDRs. These are
  the TLS proxy source addresses actually observed by the backend, including
  any source translation, and are shared by its TCP ingress and header trust.
  Supply canonical IPv4 networks with prefixes 1 through 32; IPv6, host bits,
  leading-zero aliases, empty entries and unrestricted `/0` are rejected.
  Spaces around entries and duplicates are removed consistently for both uses.
- `server_image` and `loadgen_image`, each pinned with `@sha256:` and the actual
  artifact digest; `server_entrypoint` and `loadgen_entrypoint` are explicit
  absolute paths verified in those images. No sibling executable is inferred.
  Use nonempty ASCII filename components containing letters, digits, dots,
  underscores or hyphens. Root, repeated or trailing slashes, and `.`/`..`
  components are rejected by both planning and load-generator admission.
- `server_secret_arn`/`server_secret_version` and
  `client_secret_arn`/`client_secret_version`: exact Secrets Manager ARN and
  version ID. Bundle contents are managed externally. OpenTofu never reads them.
- `runtime_kms_key_arns`: actual active signing key resources. If bundles use
  customer-managed encryption keys, supply the corresponding
  `server_secret_kms_key_arns`, `client_secret_kms_key_arns`, and optional
  `metrics_secret_kms_key_arns`. Confirm resource policies and actual container
  instance-role credentials independently.

Image references use lowercase registry labels and repository components, with
an optional numeric registry port and an exact `@sha256:` digest of 64 lowercase
hexadecimal characters. Repository components allow alphanumeric runs separated
by a single dot, one or two underscores, or one or more hyphens. The repository
path is limited to 255 characters, excluding the registry and digest. Tags,
empty path components and uppercase names are rejected; update invalid image
inputs before regenerating node userdata.

Existing network, node sizing, registry-token identifier and report-bucket
inputs remain available. The two roles share registry access only when enabled;
server supply/signing permissions and load-generator client/metrics/report
permissions remain separate. Migration DDL and management bootstrap privileges
are external and are not granted to these node roles.

The server admits its backend TCP port only from those explicit proxy CIDRs.
The load generator reaches the canonical HTTPS issuer through that proxy;
it has no separate direct backend ingress grant. The generated VPC, routes and
server listener support IPv4. A provided subnet still requires IPv4 backend
connectivity. Configure the external proxy's routing, ACLs and backend target
registration separately; an ingress rule alone does not establish reachability.
When upgrading, replace unsupported proxy CIDR forms and verify the actual
proxy source addresses before applying the changed ingress.

Registry identifiers are rendered as quoted JSON data in root-owned mode-0600
`/etc/aegaeon/registry.json`. The login helper validates the exact six string
fields before using them; it never sources their values. Each field is limited
to 4 KiB of UTF-8 data and the file to 16 KiB; control characters, duplicate
fields, unsafe file permissions and changed files are rejected. Recreate node
userdata from these templates when upgrading from the former `registry.env`
format; the helper requires the JSON file.

The only writable host bind mount is the dedicated `workload/` report directory,
mounted at `/results`. Configuration, artifact/source receipts, logs and driver
results remain in the protected parent directory. After Docker exits, the driver
accepts only a regular, singly linked report of at most 16 MiB and copies its exact bytes
to the protected `report.json` before checking identity and configuration.
Symlinks and special files are rejected before report contents are read or
uploaded. Invalid JSON remains available in the protected copy; oversized or
unsafe outputs remain in the workload directory and make collection fail.
Regenerate node userdata when
upgrading, and ensure the selected OCI consumer respects this report limit.

## Server bundle

The JSON object must contain exactly `AEGAEON_DATABASE_URL`,
`AEGAEON_KEY_ENCRYPTION_KEY` and all twenty supported Redis surface names below.
Every value is a nonempty single-line string. Unknown, removed, duplicate and
control-character fields are rejected. The KEK is the canonical unpadded
base64url encoding of the same 32-byte key used to encrypt managed key handles.

```text
AEGAEON_PAR_REDIS_URL
AEGAEON_AUTH_CODE_REDIS_URL
AEGAEON_TOKEN_STORE_REDIS_URL
AEGAEON_DPOP_REDIS_URL
AEGAEON_JWKS_REDIS_URL
AEGAEON_REQUEST_OBJECT_JTI_REDIS_URL
AEGAEON_AUTH_SESSION_REDIS_URL
AEGAEON_DEVICE_CODE_REDIS_URL
AEGAEON_DEVICE_CSRF_REDIS_URL
AEGAEON_DEVICE_RATE_LIMIT_REDIS_URL
AEGAEON_LOCAL_AUTH_CSRF_REDIS_URL
AEGAEON_LOCAL_LOGIN_RATE_LIMIT_REDIS_URL
AEGAEON_STEPUP_REDIS_URL
AEGAEON_MANAGEMENT_SESSION_REDIS_URL
AEGAEON_MANAGEMENT_LOGIN_RATE_LIMIT_REDIS_URL
AEGAEON_UPSTREAM_AUTH_REDIS_URL
AEGAEON_UPSTREAM_LOGOUT_RELAY_REDIS_URL
AEGAEON_DPOP_NONCE_REDIS_URL
AEGAEON_CLIENT_ASSERTION_REPLAY_REDIS_URL
AEGAEON_OIDC_LOGOUT_SESSION_REDIS_URL
```

Use actual `rediss://` supplier URLs without query/fragment and with a numeric
Redis database path. PAR, authorization-code, token, request-object-JTI and OIDC
logout/session surfaces must use the same scheme, host, port and database for
atomic transactions. Supplying separate database indexes for that group fails.
The PostgreSQL URL requires an explicit supported TLS mode. The server's own
validation, actual policy requirements and live supplier checks still apply.

## Load-generator bundle

The client bundle uses schema version 2 and exactly five fields:

```text
schema_version                 integer 2
client_secret                  nonempty single-line string
profile_manifest_base64        canonical standard base64 of raw profile JSON
session_cookie                 aegaeon_auth_session=<base64url token>, without LF
session_provenance_base64       canonical standard base64 of raw provenance JSON
```

The decoded profile is the consumer's activated managed-profile manifest. It
binds the canonical issuer, environment/configuration/profile IDs, `ACTIVE`
activation, client ID, registered HTTPS redirect, scopes, subject,
`client_secret_basic` or `client_secret_post` authentication, `none` or `dpop`
sender policy and `optional` or `required` PAR policy. Optional OIDC/resource
fields retain the consumer's schema; an OpenID scope requires `RS256`.
The provenance has exactly `issuer`, `subject`, `method`, `producer`,
`profile_sha256` and `session_sha256`. Its method is `public-login`; issuer,
subject and both raw-byte digests must match the profile and session. The
producer obtains activation and a genuine public-login session externally.
Delivery preserves the decoded profile/provenance bytes without reserializing.

The previous seven environment-variable bundle and mixed old/new schemas are
rejected. Migrate the externally managed secret to this bundle, adopt its new
version ID, and supply compatible reviewed consumer/artifact versions together.
No default client, fabricated activation, local cookie or owner password
substitutes for the actual protocol supplies.

## Artifact and invocation configuration

The infrastructure check validates static delivery wiring against the external
consumer interface below. The separately selected, digest-pinned OCI artifact
and explicit entrypoint are the deployment consumer; local loadtest sources are
not that artifact's authority. A passed static check leaves actual artifact,
interface, build/OCI, supply, runtime and performance acceptance required and
not observed. Before execution, independently review the supplied complete
source inventory, build and OCI closure, and consumer interface evidence.
An independently trusted producer remains a premise: matching metadata does
not authenticate the relation between source and executable.

The consumer requires and permits exactly five delivered process inputs:
`AEG_LOADTEST_CLIENT_SECRET`, `AEG_LOADTEST_PROFILE_MANIFEST`,
`AEG_LOADTEST_SESSION_FILE`, `AEG_LOADTEST_SESSION_PROVENANCE` and
`AEG_LOADTEST_SOURCE_SHA256`. The validator binds this interface to the exact
reviewed delivery helper, templates, configuration and actual invocation.

The trusted build/supply owner installs two nonsecret JSON files on the loadgen
host: an artifact receipt and the complete independently preserved source
manifest. Supply their absolute paths as `loadgen_artifact_receipt_path` and
`loadgen_source_manifest_path`, their independently adopted raw SHA256 pins as
`loadgen_artifact_receipt_sha256` and `loadgen_source_manifest_sha256`, and the
actual load-generator executable digest as `loadgen_executable_sha256`.
Every path component must be root-owned, with no group/other write permissions;
files must be regular, distinct, and reached without symlinks. The module does
not retrieve or manufacture these files. The `loadgen_artifact` output exposes
only their paths and pins for the sweep.

Receipt version 1 has exactly `schema_version`, `source_manifest_sha256`,
`executable_sha256`, `image`, `entrypoint` and `build_binding`. The build binding
has exactly `recipe_sha256`, `Cargo_lock_sha256`, `flake_lock_sha256`,
`toolchain_sha256`, `target`, `features` and `native_closure_sha256`. Digests are
lowercase SHA256; supported targets are x86_64/aarch64 Linux GNU. Features are
an ordered unique list; an empty list asserts the trusted build used no optional
features. The image and entrypoint match the deployed loadgen pins. Cargo/flake
lock and toolchain hashes match corresponding manifest entries. Establish the
actual recipe, source/build relation and native library/interpreter/CA closure
with the supply owner; metadata consistency alone cannot establish them.

The manifest has exactly `candidate_tree`, `files`, `patch_sha256` and
`source_base_commit`. Each canonical tracked-path entry has exactly `bytes`,
`filesystem_mode`, `git_blob`, `git_mode`, `sha256` and `symlink`; ordinary files
use null `symlink`, links retain their literal bytes. Mode pairs are
`100644`/33188, `100755`/33261, and `120000`/41471.
Filesystem modes are exact integers; octal strings and booleans are rejected. Link length,
SHA256 and Git blob framing are checked as data, including dangling links.
The complete inventory must be independently preserved and reviewed. Checking
mandatory build/loadtest entries is a minimum, not a full-inventory proof.

The immutable boot default is root-owned mode-0600
`/etc/aegaeon/loadtest.json`. Its exact ten string fields are `SERVER_URL`,
`SERVER_IMAGE`, `ARTIFACT_BUCKET`, `ARTIFACT_PREFIX`, `WORKERS`, `RPS`,
`RUN_TIME`, `WARMUP`, `SCENARIO` and `LOADTEST_BIN`, plus `artifact` with
`receipt_path`, `receipt_sha256`, `source_manifest_path`,
`source_manifest_sha256` and `executable_sha256`. The existing `SERVER_IMAGE`
identifier carries `loadgen_image`. Workers are positive bounded integers;
RPS accepts positive finite f64 values, including fractional/scientific values.
Run/warmup durations accept integer seconds or `s`/`m`/`h`, bounded to one day;
main duration is positive and warmup may be zero.

Invoke `/usr/local/bin/aegaeon-run-loadtest --config-file /protected/run.json`
with an independently protected regular nonsecret config to override that run.
The sweep creates a fresh mode-0600 invocation file and removes it on exit.
Neither path evaluates or sources config data, or rewrites the shared boot
configuration. Host `flock` covers configuration/input reads, workload, metrics,
every upload attempt and generation cleanup. Each invocation has an exclusive
mode-0700 output directory and an unused report path.

## Delivery and restart behavior

Before launching a workload, the node retrieves the exact pinned bundle version
and checks its returned ARN/version ID. Validation precedes publishing a complete
root-owned mode-0700 client generation by directory rename. Each file is written
atomically with mode 0600; refresh failures publish no partial generation and
never reuse stale supplies. The driver removes its private generation and Docker
credentials on exit. The load-generator container runs as UID 0 with all
capabilities dropped and `no-new-privileges`, and receives separate read-only
profile/session/provenance mounts. The independent metrics supply remains outside
those mounts. The server retains its existing UID 1000 and restart refresh rules.
Rotate by explicitly selecting and reviewing new version identifiers; an existing
running server container does not refresh itself.

Secret values must stay out of OpenTofu variables, data sources, state, outputs,
userdata and logs. Only identifiers enter configuration. Userdata is gzip encoded
for EC2's size limit and processed by cloud-init. Runtime files and Docker process
configuration contain actual secret values and require the node's normal trusted
administrator boundary. Do not attach Docker inspection or credential-bearing
runtime files to public logs.

## Reports and authenticated metrics

The existing SSM convenience outputs identify both nodes. With externally supplied
services and artifacts verified, start `aegaeon-loadtest.service` on the loadgen
node, or use `scripts/perf/aws_sweep.sh`. The sweep uses deployed digest/entrypoint
outputs rather than selecting a floating replacement image. Automatic execution
is off by default. The driver attempts to preserve every available report, stdout/stderr log, exit-code
and metrics-status file before returning the actual nonzero load-generator status.
Missing required outputs, failed enabled metrics or failed required uploads return
failure. The sweep records workload and driver exit codes separately. A failed
driver still permits the SSM wrapper to return its run ID so that available
logs, exit code, metrics and receipts can be downloaded, including when the
report is missing. Any failed or ambiguous outcome keeps the sweep's final
status unsuccessful; SSM transport failures and missing run IDs also fail. Checks parse both outer userdata and each embedded Bash executable;
outer heredoc syntax alone does not validate the driver.

Reports live under exclusive run directories in `/opt/aegaeon/results` and the
selected S3 prefix. The driver binds schema-2 `scenario_invocations` accounting
and `load_generator_process` memory identity to the selected scenario, source
manifest, executable, canonical UUIDv4, `/results/report.json` and profile/session
provenance. It hashes the producer's exact UTF-8 `config_json` witness and compares
all eight producer configuration values to actual CLI values/defaults without
reserializing: `target_url`, `discovery_expected_issuer`, `workers`, `duration`,
`target_rps`, `warmup_duration`, `scenario` and `debug`.
`discovery_expected_issuer` is required and must be null for this driver; it
cannot be omitted or defaulted. Duplicate, missing, unknown and incorrectly
typed fields and nonfinite rates are rejected. The raw driver configuration
has a separate digest.

Preserved/uploaded artifacts include report, stdout/stderr, exit code,
metrics status, `run-receipt.json`, nonsecret `client.version.json`, raw
`driver-config.json`, `artifact-receipt.json` and `SOURCE-MANIFEST.json`, plus
metrics when available. The outer receipt establishes identity/config wiring;
actual supply/build/runtime and performance acceptance remain external. Failed
workloads/reports retain their own identities and nonzero status.

Selections remain `smoke`, `auth-code`, `introspection`, `revocation`, `dpop`,
`userinfo`, `discovery`, `jwks`, `par`, `mixed`, `policy-mixed` and `key-rotation`.
The last selection explicitly reports unsupported key-rotation lifecycle; it
does not establish AWS key rotation. Compatibility and successful protocol runs
require the reviewed consumer source/artifact composition and genuine supplies.

For metrics, optionally supply `metrics_secret_arn` and `metrics_secret_version`
for an independent JSON bundle containing exactly `api_key`, a valid management
Bearer API key with sufficient operational metrics capability. Collection uses
HTTPS `/api/v1/operations/metrics`, verifies TLS and refuses redirects. Absent
metrics produce `metrics-status.json` with `absent`; a failed enabled collection
stops the driver and records `incomplete`. Successful bounded collection records
`complete` and its pinned version. The sweep leaves endpoint counts empty when
metrics are absent. A status file alone does not prove valid measured counters.

## Upgrade and validation limits

`expose_metrics_on_main` has been removed. Remove it from existing variable files;
there is no replacement public-metrics server switch. `BASE_URL` and the removed
metrics environment variable are no longer delivered. Required supplier,
entrypoint and digest inputs replace the former two-node default startup.
Explicit proxy CIDRs replace automatic subnet trust. Existing node IAM roles and
instance profiles split by role; review replacement and policy changes before
any separately authorized application of this module.

Both userdata templates read the same module-local `delivery_helper.py` facade
and all eight fixed `runtime_delivery/` sources through explicit `file()` bindings.
They install the package under `/usr/local/lib/aegaeon/runtime_delivery` with
directory mode `0700` and source mode `0400`, then install the executable facade
at `/usr/local/bin/aegaeon-deliver-supplies`. Every invocation uses
`/usr/bin/python3 -I -B`. Before importing, the facade checks the complete fixed
inventory, source hashes and root-owned non-writable paths; it rejects symlinks
and preloaded package modules. Current-directory and `PYTHONPATH` code cannot
replace that implementation. Import and dispatch errors emit only the generic
delivery failure line and exit 1.

Bootstrap retains `dnf` installation of `python3` and `awscli`, requires the fixed
`/usr/bin/aws` route, and runs its secure resolution preflight. The helper follows
at most 40 root-owned symlinks, checks every intermediate directory and the final
root-owned executable, and rejects group/other-writable paths before subprocess
execution. It uses the resolved absolute executable with the existing pinned
secret identity and version arguments; there is no `PATH` fallback. The exact
route supplied by a live guest still requires observation before runtime acceptance.

The infrastructure validator hashes the whole facade/package closure and checks
the exact sources emitted by both roles. Changes require an explicit
delivery-contract review; the guest does not download a replacement implementation.
Git SHA-1 identifiers use `usedforsecurity=False` alongside independent SHA-256
and length checks. Availability still depends on the guest Python/FIPS policy;
failure remains a delivery failure and is never treated as successful validation.

Provider/schema, rendered Bash and synthetic delivery-mechanics checks establish
source properties only. Actual OCI feature/entrypoint/schema probes, supplier
startup, supported authorization/rotation flows and nonempty successful measured
runs remain required before calling this stack a working benchmark. No cloud
application or full benchmark assurance follows from local source validation.
