# Read-only Hosted service inspection

This entry records existing CPU configuration and two bounded membership
censuses. It neither starts Dudect/native tests nor writes service properties,
affinities or cgroup membership. It is not a CI admission gate.

At the verified cgroup2 root, four legitimately absent interfaces are recorded
as not applicable. Non-root missing interfaces, permission errors and missing
required effective CPU/memory masks remain failures. Available partial records
are retained separately from completed censuses.

The fixed workflow uses one job/allocation, a 600 second job limit, a 60 second
collector limit, commands bounded to 5 seconds, and no replacement or automatic
measurement transition. An unset policy rejects the existing placement method;
an explicit consistent policy establishes read compatibility only.

The plan hashes the collector, its unchanged `state.py` dependency, runner,
workflow and encryption certificate. Checkout must equal the event commit.
Host Python/systemd/OpenSSL and their linked libraries are bound immediately
before collection and rechecked afterwards; the actual isolated Python module
closure is recorded. These runtime identities are allocation-specific, not
asserted equal to local validation dependencies.

Receipts contain allowlisted metadata, hashed command lines and no full
environment or credentials. The public artifact contains only AES-256-GCM CMS
encrypted evidence for the fixed RSA-OAEP recipient. Its private key stays with
the local investigator. There is no plaintext upload fallback. A successful
workflow means collection completed; UNKNOWN or unset classifications do not
permit measurement. Encryption is evidence transport, not a product primitive.

Run the collector regression checks locally with:

```sh
python3 -B -m unittest discover -s scripts/diagnostics/dudect_placement -p 'test_inspection.py'
```

`state.py` is copied unchanged from the owned local diagnostic prototype. Only
its CPU-mask parser is used by this collector; no mutation or service-runner
entry point is invoked. Recovery and timing code are not included here.
