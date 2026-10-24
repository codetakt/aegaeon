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

Run ID, attempt, full 40-digit hexadecimal head SHA and event are required even
when there are no jobs. Run and job identity integers must be positive integers;
booleans and floating-point values cannot stand in for IDs or attempts. Page
counts and job arrays are validated before identity matching.

The optional job `steps` field may be omitted for pre-start or explicitly skipped
work; the report treats that omission as an empty step list without modifying the
retained input. Started work must include its step observations. A malformed
supplied list remains an error. Pre-start timestamp placeholders do not establish
job or attempt start-delay measurements.

Any job timestamp error or nonskipped job with an unknown start also makes the
attempt-to-first-job delay unavailable: discarding an earlier invalid or unstarted
job must not make a later job appear to start first. In-progress jobs and steps
must have a valid start; queued steps may omit their optional timestamps.

The reporter recognizes the GitHub lifecycle states, including `requested`.
The API may omit the attempt start before work begins. Missing or invalid run
timestamps remain visible in `run_timestamp_error`, with `complete: false` and
both attempt time metrics unavailable. Valid individual job intervals remain in
the partial total. These distinctions follow the [GitHub REST schemas](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json).

An all-skipped completed run has zero occupied job time and no elapsed measurement.
Skipped timestamp placeholders are retained but never used as measured intervals.
Zero-job snapshots also preserve the run status and conclusion with zero occupied
job time and no elapsed measurement, including cancellation before any job starts.
Malformed job metadata or mixed/incomplete pagination fail the command. The output
must be distinct from both inputs, including symbolic and hard links.

`attempt_elapsed_seconds` runs from the attempt start to its last completed job,
so it excludes time between earlier attempts. `completed_job_seconds` sums job
wall intervals, including parallel work. It is neither CPU consumption nor a
billable-minute estimate. `created_to_start_seconds` is the observed interval
after GitHub created a job; it does not include all dependency waiting or isolate
runner allocation. Job time outside completed step intervals remains explicitly
unattributed.

`last_completed_job_id` is available only when the run is complete, all timing is
valid, and one job has the unique maximum completion timestamp. Incomplete or
invalid timing cannot identify the last job. Tied completion timestamps also
leave the ID unavailable, while preserving the valid elapsed measurement.

The longest job or last-finishing job does not, by itself, identify the causal
dependency critical path. A step that builds and tests cannot be split into
compile, test, transfer and cache costs from its timestamps alone. Use its retained
logs and the exact workflow dependency graph for those questions. Likewise,
`head_sha` identifies the event, not necessarily the checkout or tested artifact.

Historical comparisons remain descriptive until source, selected obligations,
event, runner, tools and cache conditions are accounted for. Never drop failed
attempts or interpret a single shorter run as a guaranteed improvement.
