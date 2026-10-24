# Workflow time analysis

Last updated: 2026-10-24

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, reviewers, repository administrators

Use retained GitHub REST responses to compare CI elapsed time with individual
job and step intervals. This diagnostic does not execute or approve checks.

```bash
gh api repos/codetakt/aegaeon/actions/runs/RUN_ID > run.json
# Use run_attempt from run.json, not a mixture of retries.
gh api --paginate --slurp \
  'repos/codetakt/aegaeon/actions/runs/RUN_ID/attempts/ATTEMPT/jobs?per_page=100' \
  > jobs.json
python3 scripts/ci/report_workflow_times.py \
  --run-json run.json --jobs-json jobs.json --output times.json
```

The report binds both input digests and retains the event, attempt, event head,
referenced workflow revisions, outcomes, runner labels and original step names.
All pages must agree on the inventory size and contain unique jobs from that
run, attempt and head. Missing timestamps for completed work, reversed intervals
and overlapping steps leave the affected job unaccounted with an explicit error.
Failed and cancelled jobs stay in the report. Incomplete or invalid snapshots
have `complete: false` and no final elapsed time; their job totals include only
completed jobs with valid timestamps. Retain the inputs and earlier snapshots
when collecting a later state.

An all-skipped completed run has zero occupied job time and no elapsed measurement.
Malformed job metadata or mixed/incomplete pagination fail the command. The output
must be distinct from both inputs, including symbolic and hard links.

`attempt_elapsed_seconds` runs from the attempt start to its last completed job,
so it excludes time between earlier attempts. `completed_job_seconds` sums job
wall intervals, including parallel work. It is neither CPU consumption nor a
billable-minute estimate. `created_to_start_seconds` is the observed interval
after GitHub created a job; it does not include all dependency waiting or isolate
runner allocation. Job time outside completed step intervals remains explicitly
unattributed.

The longest job or last-finishing job does not, by itself, identify the causal
dependency critical path. A step that builds and tests cannot be split into
compile, test, transfer and cache costs from its timestamps alone. Use its retained
logs and the exact workflow dependency graph for those questions. Likewise,
`head_sha` identifies the event, not necessarily the checkout or tested artifact.

Historical comparisons remain descriptive until source, selected obligations,
event, runner, tools and cache conditions are accounted for. Never drop failed
attempts or interpret a single shorter run as a guaranteed improvement.
