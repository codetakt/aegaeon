# Read-only RT preflight with pinned kernel correspondence

This successor adds kernel correspondence to the previously published collector.
The new bounded read-only plan uses `test/dudect-kernel-readonly-20261018` and
`.github/workflows/dudect-kernel-readonly.yml`. The old workflow/plan and old
trigger branches are retained as history and must not be reused. The new
plan is `rt-kernel-inspection-plan.json`, with a new public recipient certificate
`rt-kernel-recipient.pem`; its private key is kept outside the repository.

The CLI reads an existing service, PID 1, the collector and the supplied job
PID. It performs two censuses, preserving missing information and disagreement.
It never creates a unit, sets affinity, changes a scheduling policy or resource
limit, modifies cgroups, or launches native measurement. Its only subprocess
commands are allowlisted `systemctl --version` and `systemctl show` reads. A
timeout kills only the read command child that this invocation created.

The limits are 60 seconds overall, 5 seconds per command, 1 MiB per metadata
file/command, 4 MiB per expanded config, 128 background cgroups, 128 combined
processes, 1,024 threads per census, and CPU IDs below 4,096. Runtime binding
allows 256 files, 64 MiB per file and 384 MiB total per snapshot. A deadline or
bound failure is recorded as unknown; no replacement census is scheduled.
These userspace limits cannot guarantee termination of a kernel-stuck task.

At the verified cgroup2 root, absent `cgroup.type`, `cpuset.cpus`, and `cpu.max`
are explicitly not applicable. This collector does not require `cgroup.events`.
Missing non-root interfaces, permission errors and missing/empty effective CPU
information remain failures. Only relevant boot options and the command-line
digest are saved, not the entire command line or environment.

The classifier is a model of the reviewed upstream Linux 6.17 conditions.
Kernel versions outside that model are unknown. This successor additionally
requires the reviewed archive reference: Ubuntu Azure 6.17.0-1022.22 amd64.
A release-named `/boot/config` file or `/proc/config.gz` alone no longer satisfies
this candidate's archive correspondence check. Different builds are UNKNOWN
until a separate reference is reviewed. Existing config sources must all match
the full reference digest and size; neither version nor config alone establishes
Ubuntu patch equivalence.

All four outcomes set `execution_admitted=false`. Even the compatible outcome
means only that no rejection was identified in the read-only model: service
creation permission, RT admission, bounded stopping and physical timing remain
unproved. Missing required facts take priority over model classification.
The census is a bounded sequence of observations, not an atomic process or
scheduler snapshot and not proof that future interference is absent.

Run the functional checks locally:

```sh
python3 -B -m unittest discover \
  -s scripts/diagnostics/dudect_placement -p 'test_rt_preflight.py' -v
```

A local acquisition needs a fixed existing service, parent job PID and new
output pathname. The output is reserved with `O_EXCL` and mode 0600. CLI success
means a report was written, not that its classification permits execution.

Python modules, mapped parent libraries, source, interpreter and systemctl
bytes are recorded before/after. `rt_runtime.py` also queries the ELF loader's
fixed dependency set and checks each actual systemctl command's `LD_DEBUG=files`
objects against that set. This is child loader logging, not scheduler tracing.
Unexpected libraries, incomplete logging or persistent file changes fail the
binding. File hashes and loader diagnostics are not in-memory attestation or
protection against adversarial transient replacement.

`hosted_rt_preflight.py` binds the new plan, checkout/event/workflow commit,
source inventory, system Python, systemctl, OpenSSL and Git dependencies. The
new workflow uses only the creation of `test/dudect-kernel-readonly-20261018`,
workflow run number 1 and attempt 1. Repeated pushes/reruns are rejected at the
job condition, before runner allocation, and again in the runner. Do not delete
or recreate this branch or rename the workflow to get another opportunity.
The job is capped at 600 seconds, the operation at 170 seconds, the collector at
60 seconds (65 second outer guard), with no replacements or native launch.

The candidate collector keeps `hosted_execution_ready=false`: it never grants
execution permission. The outer lifecycle can finish with an UNKNOWN report;
that is successful evidence recovery, not RT availability. A kernel config
identified only by its boot filename still yields UNKNOWN. Archive/build
correspondence is a separate receipt and never implies RT rights.

Only AES-256-GCM CMS evidence and an allowlisted public summary are uploaded.
The new RSA-OAEP recipient public certificate is in the frozen inventory; its
private key stays outside the checkout. Encryption failure never publishes
plaintext. `recover_rt_preflight.py` checks ciphertext hash, CMS authentication,
archive names, manifest hashes and plan/commit identities before creating a new
local plaintext destination. Failure and partial reports remain failures.

Local transport checks use generated fixture keys and mock collection where
appropriate; they do not allocate a runner or prove Hosted permissions:

```sh
python3 -B -m unittest discover \
  -s scripts/diagnostics/dudect_placement -p 'test_rt_*.py' -v
```

This plan allows one read-only allocation, run number 1 and attempt 1 only.
Neither old trigger branch nor the stopped reliability campaign is reusable.
Do not replenish an UNKNOWN, failed or incomplete allocation. No outcome automatically admits RT
probing, native measurement, CI use, a retry, or the excluded PID 1 extension.

The future scheduling launcher remains unimplemented: SCHED_OTHER bootstrap,
verified finite limits/affinity and independent guards, self-transition to
FIFO/1, same-PID native exec, and actual process readback. Direct systemd FIFO
startup is excluded because the reviewed v255 application order sets the RT
policy before affinity and resource limits. The custom-image/PID 1 extension
remains outside the current Hosted repair route.


## Kernel identity successor

`rt_kernel_identity.py` reads `/sys/kernel/notes` with a 1 MiB/1,024-note limit.
Every path component is opened without following symlinks. The open FD's mount
ID and device must match the unique root sysfs mount at `/sys`; covering bind
mounts or provenance changes are rejected. Raw bytes, hash, unique GNU build ID
and provenance are retained in both censuses. Malformed bytes remain evidence;
failed acquisition does not manufacture an identity. Boot ID, uname, config,
notes and the correspondence receipt must be stable across the two censuses.

`rt-kernel-reference.json` is pinned by SHA256 in the implementation and included
in both the source inventory and before/after runtime binding. It contains the
offline-reviewed Ubuntu archive signature/package/config/build-ID chain, linked
to the immutable review manifest. The collector performs no network access,
package unpacking or kernel execution. Missing/altered reference bytes fail
closed. `/proc/version_signature` is supporting only: absence is explicit;
a present mismatch or read error prevents correspondence.

A matched receipt means linked build/config identity under the stated trusted
Ubuntu archive/provider model. GNU build ID is not a running-memory checksum;
runtime patch absence, distribution scheduler equivalence, RT authorization,
bounded stopping and Dudect stability remain unproven. Non-ID note bytes are
saved and compared between censuses, not assumed to equal link-time addresses.

The collector schema is v2. The wrapper requires that schema and the plan's
pinned reference digest; v1 or a different reference cannot be silently accepted.
Authenticated encrypted recovery preserves the separate receipt and raw notes.
Local fixtures cover the two maximum-size note streams. Their private fixture
keys are temporary and are not saved in the source or evidence packet.
