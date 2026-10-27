# Dudect CI evidence admission

Last updated: 2026-10-23

Status: draft

Status note: tested admission components; production identities, dispatch and commissioning are deferred until the next release. Ordinary CI uses the explicit migration exception; release remains blocked.

Owner: Engineering

Audience: CI maintainers, verification reviewers

## Scope and execution order

The current work closes Dudect qualification and connects its result to ordinary
CI. It does not require completion of Auth0, performance or full product assurance.
The owner confirmed this sequencing: Dudect qualification and ordinary CI first,
reviewed PR integration and functional completeness next, full assurance later.
Existing unrelated functional checks remain required. Task3 remains paused.

The owner subsequently authorized a pre-release exception on 2026-10-23:
production authentication and commissioning are deferred until the next release,
and the completed bare-metal measurement is accepted as the migration basis.
The [exception record](../../ci/evidence/dudect-ci-transition-20261023.json) binds
the retained checkpoint and adoption record without changing their bytes. Ordinary
PR/merge-group CI now reports selected-check success independently of external
admission. The release hold remains until commissioning and the release's actual
qualification obligations are satisfied. This exception accepts the current
revision's physical-coverage gap; it does not fill that gap with an old receipt.

The limited measurement contract and its review remain closed. Historical
observations retain their original identities and dates. A successful import or
functional CI run does not turn those observations into a fresh measurement of a
rebuilt ELF or a new revision.

## Admission boundary to commission before the next release

The protected controller owns a durable request ledger, immutable request bytes,
the expected repository/event/revision and complete case/compiler inventory. It
registers each request once before execution. PR-supplied code cannot write the
ledger or supply its authentication policy. A successful measurement is insufficient
without the separately authenticated replay and complete lifecycle/recovery record.

Producer and verifier sign distinct, domain-separated statements over the exact
document bytes. The initial adapter uses detached OpenPGP signatures, a pinned
`gpgv` executable, an explicit pinned public keyring and distinct authorized primary
fingerprints. No default keyring, downloaded key or replacement production identity
is accepted. Key ownership and separate verifier execution are commissioning
conditions; two signatures alone do not prove independent operation.

The controller authenticates both documents before applying the existing receipt
correspondence checks. It then rechecks cancellation, expiry, policy identity and
the exact target while holding a bounded transaction. Successful validation consumes
the request once and stores the result in the same transaction. A durable outbox
allows publication to resume after a crash without a new statistical opportunity.
Invalid packets do not consume an open request. Cancellation and admission are
serialized; a cancelled request cannot subsequently succeed. Cancellation after
admission prevents unpublished delivery and requires withdrawing an already
published result through the owning GitHub adapter.

The ledger directory is local, controller-owned, mode 0700. It is not a shared
untrusted filesystem or an authorization substitute. The HTTP/GitHub controller
must authenticate requests, derive event targets from trusted CI state and enforce
current target/expiry again when publishing. No public CLI here grants arbitrary
callers those privileges.

## Retained evidence projection

The existing ordinary replay report supplies raw-prefix verification, the exact
native/analysis identities, original and effective result bindings, and preserved
detection differences. Projection verifies the expected report digest, internal
receipt digest, case order and every expected identity. It produces an explicitly
historical projection for retained observations, not a fresh producer attestation.
Historical evidence without a pre-existing CI request stays outside fresh admission.

## Verification and activation

Functional verification covers real detached-signature verification, byte and role
substitution, expiry, cancellation, concurrent consumers, restart/outbox handling,
policy changes, wrong targets and retained-evidence projection. Test-only keys are
not production trust anchors. No physical timing is required for these tests.

Before activation, bind the actual producer/verifier credentials, protected runtime,
request issuer and GitHub publication owner. Verify the concrete lifecycle path and
failure recovery. Missing configuration remains an explicit admission failure.
Ordinary functional CI can run while activation is pending; its success is reported
as functional success, not external measurement success. Release/periodic and other
qualification responsibilities are separate from this Dudect PR boundary.

The signature interface follows the [GnuPG status format](https://github.com/gpg/gnupg/blob/master/doc/DETAILS)
and [gpgv's explicit keyring interface](https://gnupg.org/documentation/manuals/gnupg-devel/gpgv.html).

## Proposed operational configuration

No existing producer or independent verifier service/key is available. The first
deployment will use separate protected GitHub workflows as the two authenticated
principals, with short-lived AWS access and GitHub artifact attestations. This
section fixes the proposed responsibility boundaries; it does not activate them.
The OpenPGP/local-SQLite implementation above remains a tested controller component.
It does not implement the keyless verifier or distributed ledger described below.

The repository was public when inspected on 2026-10-23 (repository ID 957961616,
owner ID 12448272). Only the unrelated `copilot` environment existed. The default
OIDC subject policy was enabled; no Dudect environment or commissioning receipt
was present. These observations are prerequisites to recheck, not lasting policy.
GitHub supports attestations for public repositories on current Free, Pro and Team
plans; private repository availability has different requirements
([GitHub attestation availability](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)).

### Principals and resources

The workflow/environment names below are reserved design names, not deployed
resources. The commissioning record must replace every unresolved account, ARN,
workflow commit, action digest, runtime digest and trust-root digest with reviewed
values. Missing values reject activation; test identities are never defaults.

| Principal | Protected environment | Authority and execution boundary |
| --- | --- | --- |
| Request issuer / result publisher | `dudect-admission` | Derive current repository event and target, issue/cancel requests, consume once, publish the exact-target check. No native execution. |
| Measurement manager / producer | `dudect-producer` | Launch only the finite reviewed plan, verify artifact/environment/lifecycle, recover evidence and attest its producer statement. No admission or verifier authority. |
| Independent replay verifier | `dudect-verifier` | Read the recovered evidence, execute the pinned adopted replay/qualification implementation in a fresh allocation, attest its verifier statement. No native execution or measurement launch authority. |
| Deadline/recovery guard | Dedicated AWS role | Stop and recover only the request's owned resources after its registered deadline, independently of GitHub job survival. No success publication. |
| Measurement instance | Request-specific restricted identity | Execute the supplied ELF unprivileged and upload only its own evidence. No attestation, request-ledger or GitHub-check authority. |

Each GitHub principal has a different workflow file and an allowlisted immutable
workflow commit: `dudect-external-admission.yml`, `dudect-external-producer.yml`
and `dudect-external-replay.yml`, respectively, under `.github/workflows/`.
These files have not been installed. Environment protection permits only reviewed controller refs and
requires owner approval for the initial commissioning. PR code cannot change these
workflows, protection rules or policy. A privileged workflow never checks out or
executes the candidate PR's scripts. Candidate builds run separately without cloud,
attestation or publication credentials; their outputs are untrusted until the
controller binds the actual bytes to the request. Changes to the adopted analysis
implementation require their own review rather than automatic PR checkout.

AWS roles use the GitHub OIDC issuer, `aud=sts.amazonaws.com` and an exact
environment subject, such as
`repo:codetakt/aegaeon:environment:dudect-producer`. The three subjects are distinct;
neither a repository-wide wildcard nor an arbitrary caller-provided subject is
accepted. Environment/ref protection is necessary because this AWS subject alone
does not identify the workflow file. IAM is not assumed to evaluate unsupported
custom GitHub claims
([GitHub OIDC configuration for AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)).

The deployment inventory is one private versioned evidence bucket, one durable
request/outbox table, encryption-key and recovery-secret references, the four
limited management roles above, and a deadline scheduler/stop handler. Measurement
instances and disks are ephemeral. No permanent runner or personal signing key is
required. Evidence retention and its recurring cost are separate from the finite
measurement budget. Native code must not inherit management tokens, recovery keys
or access to instance metadata; verify that separation before running an ELF.

### Authentication and durable admission

Producer and verifier attest the existing domain-separated statement bytes, which
include the role and exact document digest. Publish only the minimal statement and
attestation; raw inputs, operational identifiers and private evidence remain in
the restricted store. The final verifier checks the artifact digest, certificate
issuer/identity, exact signer workflow and signer commit, trust roots and signed
time evidence against protected policy. Predicate fields alone are not identity
proof. Pin the verifier executable and bundle bytes; do not select a public key or
workflow from the received receipt. The CLI exposes signer-workflow/digest and
certificate constraints, which require explicit configuration
([GitHub CLI attestation verification](https://cli.github.com/manual/gh_attestation_verify)).

Use distinct fresh GitHub jobs for production and replay. Separate signatures do
not establish independent checking when both jobs merely copy the same verdict.
The verifier must reconstruct every required case from the recovered raw evidence
with the pinned analysis runtime. It signs its own replay digest and references the
producer/evidence digests. Its permissions cannot create a producer attestation or
alter the acquired object versions.

GitHub runner disks are not a durable cross-run request ledger. The deployment
adapter will preserve the local ledger's invariants using conditional transactions
in DynamoDB: immutable issuance, `open` to `admitted` at most once, serialized
cancellation, and result plus pending publication in one transaction. TTL deletion
is housekeeping, not a deadline mechanism. Retain consumed/cancelled tombstones
for the policy's replay horizon; do not make an old nonce reusable after expiry.
Store request/policy digests and exact evidence object versions, not mutable URLs.

Before publishing, recheck the current target, cancellation and expiry. Bind the
check to the exact commit and request ID and use an idempotent external ID. Re-read
the result and target after publication; a cancellation or superseding event must
invalidate the old result, never copy success to a new revision. A crash after
publication resumes delivery reconciliation without another physical trial.

### Commissioning order and acceptance

1. Freeze a deployment manifest containing repository IDs, environment rules,
   workflow/action/runtime digests, AWS account/region and resource policies,
   encryption recipients, evidence retention, finite inventory, absolute deadlines
   and cost limit. Recheck permissions and public/private repository status.
2. Implement the attestation and durable-store adapters behind the tested receipt
   checks. Exercise unauthorized signer/workflow, role swaps, stale evidence,
   concurrent admission/cancellation, delayed publication, duplicate deliveries
   and process death. A successful local OpenPGP fixture is not this check.
3. Validate the actual protected workflows with non-timing fixtures, full planned
   storage/recovery volume, credential separation, independent stop, orphan
   recovery and revoked requests. Do not let the fixture publisher grant real PR
   admission. Every owned resource must be accounted for after completion.
4. Freeze a new finite physical plan for the exact candidate ELF/analysis and
   current event. Run the adopted complete inventory with the commissioned
   producer/verifier path. All required roles, numerical/collection conditions,
   authenticated recovery and teardown must pass. Preserve every failure and
   unfinished case; no replacement run is implicit.
5. Publish the authenticated result for that target and exercise required-check
   consumption before replacing the temporary migration exception with the
   commissioned path. Release qualification remains blocked until its requirements
   are met. Historical physical receipts, functional CI success and a signed commit
   cannot perform this step. Merge remains a separate owner action.

Initial controller publication is a reviewed bootstrap change on a protected ref;
it cannot authorize itself by citing an attestation from the same unreviewed PR.
Activation therefore needs a concrete infrastructure/protection review and a new
finite cost approval after the plan and estimate exist. The completed measurement
contract review is not reopened, and consumed campaigns/budgets are not resumed.
This sequence makes no new operational failure-rate or full-product assurance
claim.

The deployment sequence above is deferred work, not a prerequisite for the current
ordinary-CI rerun. No new physical campaign is launched for that rerun: the owner
accepts the recorded measurement within its limited scope. Any later measurement
needed to qualify the release artifact receives a separate fixed plan and budget;
the old campaigns are not resumed or relabelled as current observations.
