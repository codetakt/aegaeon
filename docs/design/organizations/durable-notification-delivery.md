# Durable notification delivery

Last updated: 2026-11-19

Status: current implementation baseline

Owner: Engineering

Audience: implementers and operators

This extends the invitation delivery contract
for explicitly configured durable delivery; it does not qualify a mail provider
or complete account recovery or public registration.

## Message and attempt identity

A business transaction creates one logical message, one purpose-bound proof and
one encrypted outbox row together with its ordinary audit event. Its random
message UUID, exact payload, recipient, purpose, template version, authority and
contact revisions, original deadline and runtime generation remain fixed.
Retries use that message UUID as the adapter idempotency key and never regenerate
the proof. An explicit authorized resend creates a different logical message and
retires the preceding proof and pending message in the same transaction.

Each claim has a distinct attempt UUID and monotonically increasing fencing
number. PostgreSQL selects bounded batches with `FOR UPDATE SKIP LOCKED`, finite
leases and a finite total attempt count. Claiming is bookkeeping, not permission
to send. After a known successful claim commit, a purpose handler obtains its
normal authority locks and rechecks current issuer, account, Organization,
membership or grant ancestry, contact, configuration, deadline, runtime
generation and the exact live attempt. Only then may the worker decrypt and
send. No database transaction spans HTTP. Revocation after send admission cannot
recall an in-flight request; the recipient action still requires current
authority.

Completion changes only the exact current attempt while its lease is live.
An expired owner cannot acknowledge a newer attempt or revive retired work.
Lost replies, timeouts, process loss and lease expiry retain an uncertain
transport observation. Exhaustion and expiry remain separate terminal reasons;
they never assert that an uncertain request was not delivered.

A definite current-authority refusal completes the unadmitted attempt as
`not_admitted` and retires its message as `authority_changed`, clearing ciphertext
and releasing active capacity in the same transaction. Earlier uncertain transport
observations remain unchanged. The worker continues the batch without sending
HTTP or reporting this expected refusal as unavailable. Database/supplier errors,
failed commits and unknown results retain the finite lease/retry path instead.

## Custody and transport

The existing internal notification JWE profile seals the full secret payload
with an explicitly selected public key and exact authenticated context. Producer
configuration contains public SPKI, fingerprint, version, scope and bounded
validity only. Worker private PKCS#8 bytes are separately provisioned and erased
on drop. A small exact-version key ring can open retained ciphertext under its
original context. Send admission also requires the current delivery configuration
revision. Changing the configured public key fences preceding messages; explicitly
reissue still-authorized work under the new configuration. Retain old private keys
only for the declared recovery window. Retiring a required key prevents decryption.
Automatic wrapping-key replacement is not implemented.

The [version 2 adapter contract](notification-adapter-v2.md) defines a fixed schema
and template, exact destination,
message UUID, expiry and purpose payload. Its documented deduplication window
must cover the message retry lifetime. Aegaeon cannot promise exactly-once
delivery if the adapter lacks durable deduplication. HTTP 204 with an empty body
means adapter acceptance, not inbox delivery.

The configured HTTPS origin and actual connection address remain checked with
the existing non-routable DNS resolver, certificate validation, disabled proxies
and redirects, and bounded request, response and time budgets. Only configured
origins are eligible; message contents never select an endpoint. Retry-After is
a lower bound, combined with persisted bounded jitter, the attempt limit and
the original expiry. Provider bodies, addresses, proofs, credentials and private
keys are excluded from operational logs.

## Lifecycle and upgrade

The selected runtime generation fences new claims and every send admission.
Before restoring a database, stop the workers, disable supervisor restarts and
block the old workers' access to the restored database before selecting a new
generation. If the adapter spool was also restored, complete the
[spool reconciliation](../../../examples/notification-adapter/README.md#restoring-an-older-spool)
before resuming delivery.
Old-generation actionable messages cannot be delivered or accepted.

Pending and leased messages consume a separate bounded queue allowance. Retiring
work frees active capacity without deleting audit facts or changing authority
receipt retention. Expired payload ciphertext is removed while bounded minimal
delivery facts remain available for diagnosis. Restrictive operations do not
depend on acquiring new delivery capacity.

Drain and stop all affected servers and workers for the migration and runtime
grants. Resume them after the catalog and grant checks succeed. Additive
migrations preserve populated installations. Existing hash-only
invitation records have no recoverable plaintext proof. While their channel is
legacy, its one-shot interface remains available. Enabling channel encryption
disables that interface and does not synthesize pending ciphertext. Explicitly
reissue eligible legacy work to create a durable message and invalidate the old
proof. Durable retries never call the legacy proof-rotation function.

## Explicit reissue

The separate `aegaeon-notification-reissue` command requires the independently
selected Environment runtime and the current private delivery credential. It is
an operator-controlled service action; the initiating invitation principal and
the service executor are both retained in its audit provenance. Current inviter,
recipient or identity-policy authority is checked again. A delivery credential
cannot extend that authority, select another recipient or extend the original
expiry. The existing five-proof limit and 60-second interval still apply.

Supply `--key-file`, `--domain-id`, `--invitation-id`,
`--expected-delivery-revision` and a fresh `--operation-id` UUID. For a child
purpose, supply either `--challenge-id` or `--identity-request-id`. The command
atomically replaces the proof, retires the predecessor's encrypted payload,
queues a different message UUID and records its audit/idempotency receipt. It
sends no HTTP itself. The ordinary worker handles the new message.

Keep the operation UUID and exact command arguments when reconciling an uncertain
result. Operation UUIDs are unique across all principals and domains within an
Environment. A transaction lock serializes the operation, and a unique database
index enforces that namespace independently of the invitation's original actor.
Repeating the arguments returns the recorded result while the purpose remains
authorized; changing them with the same operation UUID is refused. Output contains
only the new message UUID, proof revision and original expiry. Authorization
receipts remain separate from transport-record retention. A restored generation
requires new issuance under the selected authority when the original purpose's
generation no longer applies.

## Worker operation and observations

Configure the selected Environment runtime with
`AEGAEON_ORGANIZATION_RUNTIME_CONFIG` and `AEGAEON_RUNTIME_ISSUER_HOST`, using the
same version 2 runtime profile and restricted database credential as the serving
runtime. Configure an HTTPS delivery channel and its public `encryption` key
before issuing durable work. The private worker key file is separate from the
server's public configuration. Its version 1 JSON document contains `credential`
and one to sixteen `keys`; each key declares `version`, `deployment_id`, explicit
Environment/Domain/Organization `scope`, `not_before`, `seal_until`, `open_until`,
canonical base64url `spki_sha256` and private DER PKCS#8 `pkcs8`. Load it from an
absolute owner-only regular file with no final symlink or hard links. Key version,
scope, deployment and fingerprint must match the public configuration.
Claims are restricted to domains whose current delivery credential matches the
worker, before consuming an attempt. Run a worker for each distinct credential;
workers sharing one credential must carry all required keys for its domains.
Provision and verify every required private key on all workers sharing a credential
before enabling its public key for issuance or starting those workers. Claims do
not filter by locally held key versions: a worker with the right credential but a
missing key consumes attempts, and exhaustion removes the ciphertext. Recovery
then requires explicit reissue for each still-authorized message. Stop or drain
workers during key/configuration changes and restart them with the complete ring.
The send admission still rechecks current purpose and configuration authority.

### Preparing the worker RSA private key

The `pkcs8` field contains the unencrypted PKCS#8 DER wrapper around an RSA
private key, encoded as canonical unpadded base64url. Raw PKCS#1 RSA DER and
PEM text are rejected. In a new owner-only directory, generate a key and
explicitly select the PKCS#8 output format:

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out delivery.pem
openssl pkcs8 -topk8 -nocrypt -inform PEM -in delivery.pem -outform DER -out delivery.pk8
```

For an existing raw RSA DER key, use `-inform DER -in existing-rsa.der` in the
second command. Encode the DER into a private file for the secret store:

```sh
python3 -c 'import base64, pathlib; print(base64.urlsafe_b64encode(pathlib.Path("delivery.pk8").read_bytes()).decode().rstrip("="), end="")' > delivery.pkcs8.b64url
```

A startup refusal names only the failing check. `rsa_pkcs8` identifies an
unsupported RSA key or DER container, `key_base64url` the private-key encoding,
and `spki_sha256` the public fingerprint format or pin mismatch. `key_file`
covers path, access, file type, permissions and size. `key_document`,
`credential`, `key_scope` and `key_metadata` cover the remaining file checks.

### Checking keys before activation or rotation

1. List every delivery domain served by a given credential and every worker
   that can claim with it, including standby replicas. For each domain use the
   intended public delivery configuration and its Environment and domain IDs.
2. On **each** worker, compare the domain's public `encryption` settings with
   one entry in the private file's `keys[]`. Compare `version` to the entry's
   `version` (the outer file version is the format version), `spkiSha256` to
   `spki_sha256`, and `deploymentId` to `deployment_id`. The pin is unpadded
   base64url SHA-256 of the DER public SPKI. Check `scope.kind = domain` and
   both scope IDs against the selected domain. Match `notBefore`, `sealUntil`
   and `openUntil` to their snake_case counterparts. Check on the worker or
   inside its secret store and record only public key metadata and coverage.
   Keep `pkcs8` and the delivery credential out of shell arguments and logs.
3. Keep the pool stopped if any worker lacks a required entry, its pin differs
   or the key is outside its intended validity window. Complete distribution
   before enabling issuance or restarting the pool. At load time the worker
   derives the public pin from each private key and checks it against the file.
   The inventory comparison supplies the separate check for domain coverage.

### Running and observing workers

Lease and proof deadlines use worker wall-clock seconds. Maintain synchronized
clocks and the documented [runtime-generation clock bounds](runtime-generation.md)
on old workers, replacement workers and the database. Clock faults are not detected
or repaired by the notification queue; skew may expire a lease early and permit a
duplicate transport attempt. Fencing still prevents an old owner from completing a
replacement attempt, and proof use independently checks current authority.

Run `aegaeon-notification-worker --key-file /run/credentials/notification-keys`
under a supervisor. Add `--once` to finish when idle or after at most sixteen
claims. Each process polls once per second and processes one claim at a time.
SIGINT/SIGTERM requests finish the current bounded cycle before closing owned
connections. A configuration or generation change requires an explicit restart.
Use the [adapter example](../../../examples/notification-adapter/README.md) or an
implementation of the same versioned acceptance contract.

Operational events use fixed names and bounded values. A
`notification_attempt_claimed` event follows a confirmed claim commit and contains
only attempt ordinal and whether an expired lease was recovered.
`notification_transport_observed` records an HTTP outcome; it does not imply a
successful completion commit. `notification_cycle_completed` records that
commit's outcome (including `not_admitted`) and retry status (including
`authority_changed`), retirement counts by expiry/exhaustion/generation,
collection count, pending/leased backlog and
oldest age in seconds. Backlog is an observation from before the cycle's claim,
so concurrent workers and later completion may already have changed it. Idle
observations appear every thirty polling cycles; activity produces an observation
immediately. An incomplete cycle logs `unavailable` and a fixed processing-stage
name; it never logs the source error.

Collect these structured events into bounded counter/gauge series. Keep process
restart identity in the collector's deployment metadata, never in message labels.
Alert on missing observations, growing oldest age, repeated unavailable outcomes,
retry exhaustion and recovered leases. Claim, transport and committed-completion
counts intentionally describe different events; process loss can separate them.
No event contains message UUIDs, addresses, URLs, proofs, credentials or key bytes.

### Stopping a pool during an outage

Five attempts include the initial claim. Without a longer `Retry-After`, four
scheduled waits starting at 60, 120, 240 and 480 seconds total 15–29 minutes
with jitter. A message already partway through this budget or near expiry can
have much less time left. [Issue #365](https://github.com/codetakt/aegaeon/issues/365)
tracks the retry policy for unattended outages.

1. Use the deployment's monitoring to evaluate each credential-sharing worker
   pool at least once a minute. As initial stop thresholds, trigger on **one**
   `notification_cycle_refused` with `stage=open`, a confirmed adapter outage,
   or **two** `notification_cycle_completed` events with `outcome=retryable` or
   `outcome=uncertain` within five minutes. An open-stage failure warrants a
   key check even if the adapter saw no HTTP request. Connect the alert to the
   supervisor's stop action for unattended periods and notify the operator.
2. Suspend restarts and scheduled one-shot launches, send SIGTERM to every
   affected worker and wait for the supervisor to report that all have exited.
   A bounded cycle already in flight may finish. Stopping prevents further
   claims by the drained pool. Attempts already consumed stay consumed, and
   the original expiry continues to run.
3. Resolve the fault, verify the keys on every replica and confirm adapter
   readiness and deduplication continuity. Start one worker. If work is
   pending, confirm a successful completion before scaling back up. For an
   empty queue, confirm healthy idle observations and monitor the first new
   delivery when it arrives. For exhausted messages, check eligibility
   per target and use [explicit reissue](#explicit-reissue) within its limits.

One-batch and supervised continuous workers use the same admission and attempt
state machine, bounded concurrency and graceful cancellation. Purpose handlers
for contact verification, account recovery and public registration own their
identity and proof contracts independently. Enabling delivery does not enable
any of those flows or grant Organization membership.
