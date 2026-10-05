#!/usr/bin/env bash
#
# Run an AWS-backed performance sweep against the OpenTofu perf-aws-ec2 environment.
# - Restarts the server between runs to avoid state accumulation.
# - Runs aegaeon-loadtest on the load generator instance via SSM.
# - Downloads S3 artifacts locally and produces a CSV summary.
#
# Prereqs:
# - AWS CLI v2 authenticated for the target account/region.
# - OpenTofu state present at TOFU_DIR (defaults to infra/tofu/perf-aws-ec2).
# - The environment deployed via `tofu apply`.
#
# Usage:
#   AWS_PROFILE=... AWS_REGION=ap-northeast-1 ./scripts/perf/aws_sweep.sh
#
# Optional:
#   RPS_LIST="200,500,1000" WORKERS=50 RUN_TIME=60s WARMUP=10 SCENARIO=mixed ./scripts/perf/aws_sweep.sh

set -euo pipefail
umask 077

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

AWS_PROFILE="${AWS_PROFILE:-}"
AWS_REGION="${AWS_REGION:-}"
if [[ -z $AWS_PROFILE ]]; then
	echo "[perf/aws] AWS_PROFILE is required" >&2
	exit 2
fi
if [[ -z $AWS_REGION ]]; then
	echo "[perf/aws] AWS_REGION is required" >&2
	exit 2
fi

TOFU_DIR="${TOFU_DIR:-infra/tofu/perf-aws-ec2}"
WORKERS="${WORKERS:-50}"
RUN_TIME="${RUN_TIME:-60s}"
WARMUP="${WARMUP:-10}"
SCENARIO="${SCENARIO:-mixed}"
RPS_LIST="${RPS_LIST:-200,500,1000,2000,4000,8000}"

TS="${TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-artifacts/perf/aws-sweep/${TS}}"
mkdir -p "$OUT_ROOT"

tofu_out_json="$(AWS_PROFILE=$AWS_PROFILE tofu -chdir="$TOFU_DIR" output -json)"
server_instance_id="$(jq -r '.server_instance_id.value' <<<"$tofu_out_json")"
loadgen_instance_id="$(jq -r '.loadgen_instance_id.value' <<<"$tofu_out_json")"
SERVER_IMAGE="$(jq -r '.loadgen_image.value' <<<"$tofu_out_json")"
LOADTEST_BIN="$(jq -r '.loadgen_entrypoint.value' <<<"$tofu_out_json")"
artifact_config="$(jq -c '.loadgen_artifact.value' <<<"$tofu_out_json")"
server_url="$(jq -r '.server_url.value' <<<"$tofu_out_json")"
artifact_bucket="$(jq -r '.artifact_bucket_name.value' <<<"$tofu_out_json")"
artifact_prefix="$(jq -r '.artifact_prefix.value' <<<"$tofu_out_json")"

if [[ $artifact_prefix != */ ]]; then
	artifact_prefix="${artifact_prefix}/"
fi

cat >"$OUT_ROOT/metadata.txt" <<EOF
timestamp=${TS}
aws_profile=${AWS_PROFILE}
aws_region=${AWS_REGION}
tofu_dir=${TOFU_DIR}
server_instance_id=${server_instance_id}
loadgen_instance_id=${loadgen_instance_id}
server_url=${server_url}
loadgen_image=${SERVER_IMAGE}
loadgen_entrypoint=${LOADTEST_BIN}
artifact_bucket=${artifact_bucket}
artifact_prefix=${artifact_prefix}
workers=${WORKERS}
run_time=${RUN_TIME}
warmup=${WARMUP}
scenario=${SCENARIO}
rps_list=${RPS_LIST}
EOF

AWS_PROFILE=$AWS_PROFILE aws --region "$AWS_REGION" ec2 describe-instances \
	--instance-ids "$server_instance_id" "$loadgen_instance_id" \
	--query '{server:{id:Reservations[0].Instances[0].InstanceId,type:Reservations[0].Instances[0].InstanceType,az:Reservations[0].Instances[0].Placement.AvailabilityZone},loadgen:{id:Reservations[1].Instances[0].InstanceId,type:Reservations[1].Instances[0].InstanceType,az:Reservations[1].Instances[0].Placement.AvailabilityZone}}' \
	--output json >"$OUT_ROOT/instances.json" || true

SUMMARY_CSV="$OUT_ROOT/summary.csv"
cat >"$SUMMARY_CSV" <<'CSV'
rps_target,workers,run_time,warmup,scenario,run_id,exit_code,total_requests,successful_requests,failed_requests,throughput,attempted_throughput,error_rate,p99_latency_ms,max_latency_ms,peak_memory_mb,server_cpu_ns,server_cpu_s,server_mem_current_bytes,server_mem_peak_bytes,token_post_count,authorize_get_count,introspect_post_count,revoke_post_count,par_post_count,metrics_status
CSV

ssm_run() {
	local instance_id="$1" comment="$2" script="$3" evidence="$4"
	python3 "$REPO_ROOT/scripts/perf/ssm_sweep.py" command "$instance_id" "$comment" "$evidence" <<<"$script"
}

restart_server_script=$'set -euo pipefail\ntimeout 30 sudo systemctl restart aegaeon-server\ndeadline=$((SECONDS + 75))\nwhile ((SECONDS < deadline)); do\n  if curl --connect-timeout 2 --max-time 3 -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then\n    echo "SERVER_HEALTH=OK"\n    exit 0\n  fi\n  sleep 1\ndone\necho "SERVER_HEALTH=FAIL" >&2\ntimeout 5 sudo systemctl status aegaeon-server --no-pager -l || true\nexit 1\n'

server_stats_script=$'set -euo pipefail\nsudo systemctl show aegaeon-server \\\n  -p CPUUsageNSec \\\n  -p MemoryCurrent \\\n  -p MemoryPeak \\\n  -p TasksCurrent \\\n  -p NRestarts \\\n  --no-pager\n'

SWEEP_EXIT_CODE=0

IFS=',' read -r -d '' -a rps_values < <(printf '%s\0' "$RPS_LIST")

invocation_index=0
for rps in "${rps_values[@]}"; do
	rps="${rps#"${rps%%[![:space:]]*}"}"
	rps="${rps%"${rps##*[![:space:]]}"}"
	if [[ -z $rps ]]; then
		continue
	fi

	invocation_index=$((invocation_index + 1))
	run_dir="$(mktemp -d "$OUT_ROOT/invocation-${invocation_index}-XXXXXXXX")"
	printf 'rps_target=%s\n' "$rps" >"$run_dir/metadata.txt"
	echo "[perf/aws] === rps=${rps} ==="

	ssm_run "$server_instance_id" "aegaeon: restart server for sweep invocation=${invocation_index}" "$restart_server_script" "$run_dir/ssm-restart" >/dev/null

	# JSON/base64 carries values as data; no remote shell interpolation of user values.
	config_payload="$(
		python3 - "$server_url" "$SERVER_IMAGE" "$artifact_bucket" "$artifact_prefix" "$WORKERS" "$rps" "$RUN_TIME" "$WARMUP" "$SCENARIO" "$LOADTEST_BIN" "$artifact_config" <<'PY'
import base64
import json
import sys
names = ["SERVER_URL", "SERVER_IMAGE", "ARTIFACT_BUCKET", "ARTIFACT_PREFIX", "WORKERS", "RPS", "RUN_TIME", "WARMUP", "SCENARIO", "LOADTEST_BIN"]
config = dict(zip(names, sys.argv[1:11], strict=True))
config["artifact"] = json.loads(sys.argv[11])
print(base64.b64encode(json.dumps(config).encode()).decode())
PY
	)"
	transport_failed=0
	lg_resp="$(python3 "$REPO_ROOT/scripts/perf/ssm_sweep.py" loadtest "$loadgen_instance_id" \
		"aegaeon: run loadtest invocation=${invocation_index}" "$run_dir/ssm-loadgen" <<<"$config_payload")" || transport_failed=1

	lg_stdout="$(jq -r '.StandardOutputContent' <<<"$lg_resp")"
	lg_stderr="$(jq -r '.StandardErrorContent' <<<"$lg_resp")"

	run_id="$(printf '%s\n' "$lg_stdout" | sed -n 's/^RUN_ID=//p' | tail -n 1)"
	exit_code="$(printf '%s\n' "$lg_stdout" | sed -n 's/^EXIT_CODE=//p' | tail -n 1)"
	driver_exit_code="$(printf '%s\n' "$lg_stdout" | sed -n 's/^DRIVER_EXIT_CODE=//p' | tail -n 1)"
	printf '%s' "$lg_stdout" >"$run_dir/ssm_loadgen.stdout.log"
	printf '%s' "$lg_stderr" >"$run_dir/ssm_loadgen.stderr.log"
	if [[ ! $run_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
		echo "[perf/aws] failed to detect RUN_ID in loadgen output" >&2
		echo "$lg_stdout" >&2
		SWEEP_EXIT_CODE=1
		continue
	fi

	RUN_FAILED=$transport_failed
	if [[ ! $exit_code =~ ^(0|[1-9][0-9]{0,2})$ || $exit_code -gt 255 ||
		! $driver_exit_code =~ ^(0|[1-9][0-9]{0,2})$ || $driver_exit_code -gt 255 ||
		$(printf '%s\n' "$lg_stdout" | sed -n '/^EXIT_CODE=/p' | wc -l) -ne 1 ||
		$(printf '%s\n' "$lg_stdout" | sed -n '/^DRIVER_EXIT_CODE=/p' | wc -l) -ne 1 ||
		$(printf '%s\n' "$lg_stdout" | sed -n '/^RUN_ID=/p' | wc -l) -ne 1 ]]; then
		echo "[perf/aws] missing or ambiguous driver outcome" >&2
		RUN_FAILED=1
	elif [[ $exit_code -ne 0 || $driver_exit_code -ne 0 ]]; then
		RUN_FAILED=1
	fi

	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/report.json" \
		"$run_dir/report.json" || RUN_FAILED=1
	for artifact in loadtest.stdout.log loadtest.stderr.log exit_code.txt run-receipt.json client.version.json driver-config.json artifact-receipt.json SOURCE-MANIFEST.json; do
		AWS_PROFILE=$AWS_PROFILE aws s3 cp \
			"s3://${artifact_bucket}/${artifact_prefix}${run_id}/${artifact}" \
			"$run_dir/${artifact}" || RUN_FAILED=1
	done
	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/server.metrics.prom" \
		"$run_dir/server.metrics.prom" ||
		AWS_PROFILE=$AWS_PROFILE aws s3 cp \
			"s3://${artifact_bucket}/${artifact_prefix}${run_id}//server.metrics.prom" \
			"$run_dir/server.metrics.prom" || true

	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/metrics-status.json" \
		"$run_dir/metrics-status.json" || RUN_FAILED=1

	stats_resp="$(ssm_run "$server_instance_id" "aegaeon: collect server stats invocation=${invocation_index}" "$server_stats_script" "$run_dir/ssm-stats")" || RUN_FAILED=1
	stats_stdout="$(jq -r '.StandardOutputContent' <<<"$stats_resp")"
	printf '%s' "$stats_stdout" >"$run_dir/server.systemd.txt"

	server_cpu_ns="$(printf '%s\n' "$stats_stdout" | sed -n 's/^CPUUsageNSec=//p' | tail -n 1)"
	server_mem_cur="$(printf '%s\n' "$stats_stdout" | sed -n 's/^MemoryCurrent=//p' | tail -n 1)"
	server_mem_peak="$(printf '%s\n' "$stats_stdout" | sed -n 's/^MemoryPeak=//p' | tail -n 1)"
	server_cpu_ns="${server_cpu_ns:-0}"
	server_mem_cur="${server_mem_cur:-0}"
	server_mem_peak="${server_mem_peak:-0}"

	server_cpu_s="$(python3 -c 'import sys; print(int(sys.argv[1]) / 1e9)' "$server_cpu_ns")"

	if [[ $RUN_FAILED -ne 0 ]]; then
		SWEEP_EXIT_CODE=1
		continue
	fi

	export PERF_RPS_TARGET="$rps"
	export PERF_WORKERS="$WORKERS"
	export PERF_RUN_TIME="$RUN_TIME"
	export PERF_WARMUP="$WARMUP"
	export PERF_SCENARIO="$SCENARIO"
	export PERF_RUN_ID="$run_id"
	export PERF_EXIT_CODE="$exit_code"
	export PERF_REPORT_PATH="$run_dir/report.json"
	export PERF_METRICS_PATH="$run_dir/server.metrics.prom"
	export PERF_SERVER_CPU_NS="$server_cpu_ns"
	export PERF_SERVER_CPU_S="$server_cpu_s"
	export PERF_SERVER_MEM_CURRENT="$server_mem_cur"
	export PERF_SERVER_MEM_PEAK="$server_mem_peak"

	python3 - <<'PY' >>"$SUMMARY_CSV"
import json
import math
import os
import re
from pathlib import Path

rps_target = os.environ["PERF_RPS_TARGET"]
if not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:e[+-]?(?:0|[1-9][0-9]*))?", rps_target):
    raise ValueError("canonical positive decimal RPS required")
rps_value = float(rps_target)
if not math.isfinite(rps_value) or rps_value <= 0:
    raise ValueError("finite positive f64 RPS required")
workers = int(os.environ["PERF_WORKERS"])
run_time = os.environ["PERF_RUN_TIME"]
warmup_raw = os.environ["PERF_WARMUP"]
match = re.fullmatch(r"(0|[1-9][0-9]*)([smh]?)", warmup_raw)
if match is None:
    raise ValueError("invalid warmup duration")
warmup = int(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600}[match[2]]
scenario = os.environ["PERF_SCENARIO"]
run_id = os.environ["PERF_RUN_ID"]
exit_code = os.environ.get("PERF_EXIT_CODE", "")

report = json.loads(Path(os.environ["PERF_REPORT_PATH"]).read_text())

total = int(report.get("total_requests", 0))
successful = int(report.get("successful_requests", 0))
failed = int(report.get("failed_requests", 0))
throughput = float(report.get("throughput", 0.0))
attempted_throughput = float(report.get("attempted_throughput", throughput))
error_rate = float(report.get("error_rate", 0.0))
p99 = float(report.get("p99_latency_ms", 0.0))
max_lat = float(report.get("max_latency_ms", 0.0))
peak_mem = float(report.get("peak_memory_mb", 0.0))

server_cpu_ns = int(os.environ.get("PERF_SERVER_CPU_NS", "0"))
server_cpu_s = float(os.environ.get("PERF_SERVER_CPU_S", "0"))
server_mem_cur = int(os.environ.get("PERF_SERVER_MEM_CURRENT", "0"))
server_mem_peak = int(os.environ.get("PERF_SERVER_MEM_PEAK", "0"))

counts = {
    ("/token", "POST"): 0,
    ("/authorize", "GET"): 0,
    ("/introspect", "POST"): 0,
    ("/revoke", "POST"): 0,
    ("/par", "POST"): 0,
}

metrics_path = Path(os.environ.get("PERF_METRICS_PATH", ""))
metrics_status = json.loads(metrics_path.with_name("metrics-status.json").read_text())["status"]
if metrics_status not in {"absent", "complete"}:
    raise ValueError("metrics collection incomplete")
if metrics_status == "complete" and not metrics_path.is_file():
    raise ValueError("complete metrics artifact missing")
if metrics_status == "complete":
    for line in metrics_path.read_text().splitlines():
        if not line.startswith("oauth_request_latency_seconds_count"):
            continue
        m = re.match(
            r'oauth_request_latency_seconds_count\{endpoint="([^"]+)",method="([^"]+)"\}\s+([0-9.eE+-]+)$',
            line,
        )
        if not m:
            continue
        endpoint, method, value = m.group(1), m.group(2), m.group(3)
        key = (endpoint, method)
        if key in counts:
            counts[key] = int(float(value))

row = [
    rps_target,
    workers,
    run_time,
    warmup,
    scenario,
    run_id,
    exit_code,
    total,
    successful,
    failed,
    f"{throughput:.6f}",
    f"{attempted_throughput:.6f}",
    f"{error_rate:.6f}",
    f"{p99:.3f}",
    f"{max_lat:.3f}",
    f"{peak_mem:.6f}",
    server_cpu_ns,
    f"{server_cpu_s:.6f}",
    server_mem_cur,
    server_mem_peak,
    counts[("/token", "POST")] if metrics_status == "complete" else "",
    counts[("/authorize", "GET")] if metrics_status == "complete" else "",
    counts[("/introspect", "POST")] if metrics_status == "complete" else "",
    counts[("/revoke", "POST")] if metrics_status == "complete" else "",
    counts[("/par", "POST")] if metrics_status == "complete" else "",
    metrics_status,
]

print(",".join(str(v) for v in row))
PY
done

echo "[perf/aws] sweep done: $OUT_ROOT"

exit "$SWEEP_EXIT_CODE"
