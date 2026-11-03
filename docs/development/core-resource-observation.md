# Fixed core resource observation

Last updated: 2026-11-03

Status: active plan

Owner: Engineering

Audience: maintainers

This diagnostic investigates runner shutdown during the core build of LTI
PR #284. It is not an ordinary CI result, an assurance result, or a repair.
The candidate checkout, check inventory, and eight Rust build derivations are
fixed in `scripts/ci/core_resource_observation.json`. All recipes and concurrency settings stay unchanged.

The two retained interruptions started 14 distinct build derivations. Successful
retries started five, so cache effects confound any claim of recovery. This
observation exercises the eight compilation derivations from the failed run.
It substitutes only their dependencies with local builds disabled, refuses any
already realized target output, then builds those exact outputs with substitution
disabled. No cache paths are deleted. This exposes the compilation load but does
not reproduce every historical scheduling, cache, image, or provider condition.

The workflow permits one run and its first attempt on the dedicated branch.
Its job limit is 70 minutes; dependency substitution is limited to 10 minutes,
and compilation to 50 minutes. There is no automatic retry. It changes no
ordinary workflow, required check, product source, test, or proof.

The observer flushes memory, VM OOM counters, selected process classes and RSS,
cgroup limits/events, sanitized kernel OOM events, and runner lifecycle event
categories to the job log every five seconds. Missing readings remain unknown.
The final artifact is supplementary: runner shutdown may prevent its upload.
Buffered log delivery, process censuses, cgroup membership, and the bounded
kernel/runner tails are not complete or atomic observations.

Resource exhaustion requires counter/event evidence and correlation with the
process and stop timeline. Exit 137 alone is insufficient. A successful run
without the shutdown leaves the historical cause unresolved; it must not be
reported as a flakiness fix or used to admit the PR.

Run local helper validation with:

```sh
python3 -m pytest tests/ci/test_core_resource_observation.py tests/ci/test_runner_resource_sampler.py
```
