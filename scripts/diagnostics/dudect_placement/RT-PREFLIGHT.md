# Local read-only RT preflight candidate

`rt_preflight.py` implements the read-only acquisition portion of the
2026-10-18 owned-scheduling review. It is a separate private candidate, not the
collector frozen into the existing Hosted inspection workflow. That workflow,
its plan, and the old trigger branch must not be reused for this candidate.

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
Kernel versions outside that model are unknown. A release-named `/boot/config`
file alone is not accepted as a build binding. `/proc/config.gz` provides a
running-kernel correspondence; mismatched existing sources are rejected.
Neither configuration nor version alone establishes Ubuntu patch equivalence.

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
separate workflow uses only the creation of `test/dudect-rt-readonly-20261018`,
workflow run number 1 and attempt 1. Repeated pushes/reruns are rejected at the
job condition, before runner allocation, and again in the runner. Do not delete
or recreate this branch or rename the workflow to get another opportunity.
The job is capped at 600 seconds, the operation at 170 seconds, the collector at
60 seconds (65 second outer guard), with no replacements or native launch.

The standalone collector keeps `hosted_execution_ready=false`: it never grants
execution permission. The outer lifecycle can finish with an UNKNOWN report;
that is successful evidence recovery, not RT availability. A kernel config
identified only by its boot filename still yields UNKNOWN. No package/image
equivalence or RT rights are invented to turn it into a compatible result.

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

Any actual publication uses this new workflow only, never the old inspection
trigger branch or stopped reliability campaign. It stops after one read-only
opportunity irrespective of classification. No outcome automatically admits RT
probing, native measurement, CI use, a retry, or the excluded PID 1 extension.

The future scheduling launcher remains unimplemented: SCHED_OTHER bootstrap,
verified finite limits/affinity and independent guards, self-transition to
FIFO/1, same-PID native exec, and actual process readback. Direct systemd FIFO
startup is excluded because the reviewed v255 application order sets the RT
policy before affinity and resource limits. The custom-image/PID 1 extension
remains outside the current Hosted repair route.
