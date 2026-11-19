# Durable notification acceptance example

This Python example implements the [version 2 HTTPS adapter contract](../../docs/design/organizations/notification-adapter-v2.md).
It validates the fixed payload, renders one RFC 5322 message and atomically stores
that message with its deduplication receipt. Repeated identical requests return
204 without creating another message, including after restarting the process.
The same UUID with different bytes returns 409.

The example stops at a durable mail spool. Connect an operator-controlled mail
submission service to that spool before using it for real recipients. That
service must preserve the stored message, original expiry and declared retry
policy. Its downstream SMTP/provider acceptance and inbox delivery are separate
observations. The example does not qualify a mail provider or implement a
recipient web application.

## Run

Use Python 3.13 or later with SQLite 3.51.3 or later. Run under a dedicated account
with a local encrypted filesystem and an owner-only directory. Database, journal,
backup and submission-service access all contain actionable mail secrets and
must stay inside that custody boundary. Configure durable storage that honors
SQLite's synchronization requests. SQLite's [WAL requirements](https://www.sqlite.org/wal.html)
exclude sharing this database over a network filesystem. The minimum version
includes its WAL-reset fix.

Provision a private regular credential file containing the same canonical
base64url 32-byte bearer credential as the Aegaeon worker, without padding. The
file may have a single final newline. Set its permissions to `0600`; do not place
the credential in command arguments. Provision an ordinary trusted TLS
certificate for the configured adapter DNS name. The test certificate and key
in this repository are public fixtures and are unsuitable for deployment.

```sh
python3 examples/notification-adapter/adapter.py \
  --database /srv/aegaeon-mail/spool.sqlite \
  --credential-file /run/credentials/mail-adapter \
  --certificate /run/credentials/mail-adapter.crt \
  --private-key /run/credentials/mail-adapter.key \
  --issuer https://accounts.example.org \
  --recipient-ui https://accounts.example.org/continue \
  --sender no-reply@example.org \
  --bind 0.0.0.0 --port 443
```

The listener accepts `POST /envelopes`. Isolate it with the deployment's network
policy; port binding privileges are an operator decision. Supervise the process
and bound restarts. No per-message scheduling loop is required at Aegaeon.

The recipient UI is a fixed operator-provisioned HTTPS page. The message places
its purpose metadata and proof in a base64url JSON URL fragment. The UI must
remove that fragment before loading third-party content and must use the
purpose-specific POST protocol to continue. Opening a link never accepts an
invitation, resets a password or grants membership.

## Storage and retention

The `accepted` table contains message UUID, digest of the exact request bytes,
original expiry, retention deadline and rendered mail bytes. Acceptance uses one
SQLite transaction with WAL and `synchronous=FULL`; each connection verifies the
synchronous setting. Concurrent repeats serialize at the database write lock.
Storage errors produce no successful acknowledgment.

Receipts remain for at least 24 hours after first acceptance, covering the
contract's maximum message lifetime. Capacity is 10,000 retained messages. When
full, requests return 503 with `Retry-After: 60`; operators must size or replace
this example for their workload. Each authenticated request purges at most 32
expired retention records. No expired new message is accepted, and the
submission service must also refuse mail past its original expiry. Keep the
deduplication receipt through its retention deadline even after submitting mail.

Row deletion is logical cleanup. It does not establish erasure from SQLite
pages, journals, filesystem snapshots or backups; those follow the deployment's
encrypted-storage retention policy. A stopped adapter performs no cleanup until
restarted. The example records no headers, bodies, recipients or provider replies
in operational logs.

### Restoring an older spool

A backup can predate a successful HTTP 204 or a downstream mail submission.
Rolling it back can erase a deduplication receipt or make a submitted mail
appear pending. The `accepted` table records adapter acceptance. Downstream
submission needs its own durable record.

1. Isolate the adapter and stop the submission service and its restarts.
   [Drain the affected workers](../../docs/design/organizations/durable-notification-delivery.md#stopping-a-pool-during-an-outage).
   Fence old instances and preserve the newest available spool and submission
   records. Restore a consistent SQLite backup, including any matching WAL
   data required by the backup method, into an isolated location.
2. Cover the interval from the backup through isolation. Compare message IDs,
   exact request digests, original expiries, retention deadlines and stored
   mail against an authoritative acceptance record or a newer intact spool.
   Recover missing unexpired acceptances and receipts still within retention
   from that evidence. Reconcile each candidate for submission against the
   downstream ledger by message ID so previously submitted mail stays suppressed.
3. Quarantine discrepancies and unknown submission outcomes. A missing row
   leaves prior acceptance unknown. If the missing IDs cannot be enumerated,
   keep the affected endpoint and submission service paused. Resume once the
   records cover the gap, or after all potentially affected messages and
   retention windows have elapsed and stale restored mail has been excluded
   from submission. Bound that wait from the last possible acceptance before
   isolation using the configured retention (at least 24 hours). Account
   separately for accepted mail lost in the rollback.
   Use the original expiry for every submission and recheck current authority
   before any explicit reissue. Retain the reconciliation record under the
   spool's access and retention controls.

## Validation

The single-connection server applies one three-second absolute receive deadline
from TCP acceptance through TLS, the request line, headers and the complete body.
Sending occasional bytes cannot renew that deadline or indefinitely block the
next request. This bounds request receipt; SQLite commit and downstream mail
submission have separate storage and operational constraints.

```sh
python3 -m unittest discover -s tests/ci -p test_notification_adapter.py -v
```

The tests exercise actual SQLite commits, concurrent duplicate requests,
transaction rollback, restart, expiry/retention boundaries, conflicting payloads,
private-file requirements and a real local HTTPS listener with certificate
verification. They do not simulate a physical storage power failure or establish
downstream mail-provider behavior.
