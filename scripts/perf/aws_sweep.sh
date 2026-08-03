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
SERVER_IMAGE="${SERVER_IMAGE:-ghcr.io/cariandrum22/aegaeon/aegaeon-server:latest}"
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
server_image=${SERVER_IMAGE}
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
rps_target,workers,run_time,warmup,scenario,run_id,exit_code,total_requests,successful_requests,failed_requests,throughput,attempted_throughput,error_rate,p99_latency_ms,max_latency_ms,peak_memory_mb,server_cpu_ns,server_cpu_s,server_mem_current_bytes,server_mem_peak_bytes,token_post_count,authorize_get_count,introspect_post_count,revoke_post_count,par_post_count
CSV

ssm_run() {
	local instance_id="$1"
	local comment="$2"
	local script="$3"

	local params_json cmd_id resp status
	params_json="$(python3 -c 'import json,sys; print(json.dumps({"commands":[sys.stdin.read()]}))' <<<"$script")"

	cmd_id="$(AWS_PROFILE=$AWS_PROFILE aws --region "$AWS_REGION" ssm send-command \
		--instance-ids "$instance_id" \
		--document-name AWS-RunShellScript \
		--comment "$comment" \
		--parameters "$params_json" \
		--query 'Command.CommandId' \
		--output text)"

	AWS_PROFILE=$AWS_PROFILE aws --region "$AWS_REGION" ssm wait command-executed \
		--command-id "$cmd_id" \
		--instance-id "$instance_id"

	resp="$(AWS_PROFILE=$AWS_PROFILE aws --region "$AWS_REGION" ssm get-command-invocation \
		--command-id "$cmd_id" \
		--instance-id "$instance_id" \
		--output json)"

	status="$(jq -r '.Status' <<<"$resp")"
	if [[ $status != "Success" ]]; then
		echo "[perf/aws] SSM command failed (instance=$instance_id comment=$comment status=$status)" >&2
		echo "$resp" >&2
		exit 1
	fi

	printf '%s' "$resp"
}

restart_server_script=$'set -euo pipefail\nsudo systemctl restart aegaeon-server\nfor i in $(seq 1 60); do\n  if curl -fsS http://127.0.0.1:8080/health >/dev/null 2>&1; then\n    echo \"SERVER_HEALTH=OK\"\n    exit 0\n  fi\n  sleep 1\ndone\necho \"SERVER_HEALTH=FAIL\" >&2\nsudo systemctl status aegaeon-server --no-pager -l || true\nexit 1\n'

server_stats_script=$'set -euo pipefail\nsudo systemctl show aegaeon-server \\\n  -p CPUUsageNSec \\\n  -p MemoryCurrent \\\n  -p MemoryPeak \\\n  -p TasksCurrent \\\n  -p NRestarts \\\n  --no-pager\n'

IFS=',' read -r -a rps_values <<<"$RPS_LIST"

for rps in "${rps_values[@]}"; do
	rps="$(echo "$rps" | tr -d '[:space:]')"
	if [[ -z $rps ]]; then
		continue
	fi

	echo "[perf/aws] === rps=${rps} ==="

	ssm_run "$server_instance_id" "aegaeon: restart server for sweep rps=${rps}" "$restart_server_script" >/dev/null

	loadgen_script=$(
		cat <<SCRIPT
set -euo pipefail
cat >/etc/aegaeon/loadtest.env <<EOF
SERVER_IMAGE=${SERVER_IMAGE}
SERVER_URL=${server_url}
ARTIFACT_BUCKET=${artifact_bucket}
ARTIFACT_PREFIX=${artifact_prefix}
WORKERS=${WORKERS}
RPS=${rps}
RUN_TIME=${RUN_TIME}
WARMUP=${WARMUP}
SCENARIO=${SCENARIO}
EOF

/usr/local/bin/aegaeon-run-loadtest
LATEST="\$(ls -1dt /opt/aegaeon/results/* | head -1)"
RUN_ID="\$(basename "\$LATEST")"
EXIT_CODE=""
if [[ -f "\$LATEST/exit_code.txt" ]]; then
  EXIT_CODE="\$(cat "\$LATEST/exit_code.txt" | tr -d '\n' || true)"
fi

echo "RUN_ID=\$RUN_ID"
echo "EXIT_CODE=\$EXIT_CODE"
echo "OUT_DIR=\$LATEST"

if [[ -f "\$LATEST/report.json" ]]; then
  curl -fsS "${server_url%/}/metrics" >"\$LATEST/server.metrics.prom" || true
  if [[ -n "${artifact_bucket}" ]]; then
    DEST_PREFIX="s3://${artifact_bucket}/${artifact_prefix}\$RUN_ID/"
    aws s3 cp "\$LATEST/server.metrics.prom" "\$DEST_PREFIX""server.metrics.prom" || true
  fi
fi
SCRIPT
	)

	lg_resp="$(ssm_run "$loadgen_instance_id" "aegaeon: run loadtest rps=${rps}" "$loadgen_script")"
	lg_stdout="$(jq -r '.StandardOutputContent' <<<"$lg_resp")"
	lg_stderr="$(jq -r '.StandardErrorContent' <<<"$lg_resp")"

	run_id="$(printf '%s\n' "$lg_stdout" | sed -n 's/^RUN_ID=//p' | tail -n 1)"
	exit_code="$(printf '%s\n' "$lg_stdout" | sed -n 's/^EXIT_CODE=//p' | tail -n 1)"
	if [[ -z $run_id ]]; then
		echo "[perf/aws] failed to detect RUN_ID in loadgen output" >&2
		echo "$lg_stdout" >&2
		exit 1
	fi

	run_dir="$OUT_ROOT/rps-${rps}"
	mkdir -p "$run_dir"
	printf '%s' "$lg_stdout" >"$run_dir/ssm_loadgen.stdout.log"
	printf '%s' "$lg_stderr" >"$run_dir/ssm_loadgen.stderr.log"

	stats_resp="$(ssm_run "$server_instance_id" "aegaeon: collect server stats rps=${rps}" "$server_stats_script")"
	stats_stdout="$(jq -r '.StandardOutputContent' <<<"$stats_resp")"
	printf '%s' "$stats_stdout" >"$run_dir/server.systemd.txt"

	server_cpu_ns="$(printf '%s\n' "$stats_stdout" | sed -n 's/^CPUUsageNSec=//p' | tail -n 1)"
	server_mem_cur="$(printf '%s\n' "$stats_stdout" | sed -n 's/^MemoryCurrent=//p' | tail -n 1)"
	server_mem_peak="$(printf '%s\n' "$stats_stdout" | sed -n 's/^MemoryPeak=//p' | tail -n 1)"
	server_cpu_ns="${server_cpu_ns:-0}"
	server_mem_cur="${server_mem_cur:-0}"
	server_mem_peak="${server_mem_peak:-0}"

	server_cpu_s="$(python3 -c 'import sys; print(int(sys.argv[1]) / 1e9)' "$server_cpu_ns")"

	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/report.json" \
		"$run_dir/report.json"
	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/loadtest.stdout.log" \
		"$run_dir/loadtest.stdout.log" || true
	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/loadtest.stderr.log" \
		"$run_dir/loadtest.stderr.log" || true
	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/exit_code.txt" \
		"$run_dir/exit_code.txt" || true
	AWS_PROFILE=$AWS_PROFILE aws s3 cp \
		"s3://${artifact_bucket}/${artifact_prefix}${run_id}/server.metrics.prom" \
		"$run_dir/server.metrics.prom" ||
		AWS_PROFILE=$AWS_PROFILE aws s3 cp \
			"s3://${artifact_bucket}/${artifact_prefix}${run_id}//server.metrics.prom" \
			"$run_dir/server.metrics.prom" || true

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
import os
import re
from pathlib import Path

rps_target = int(os.environ["PERF_RPS_TARGET"])
workers = int(os.environ["PERF_WORKERS"])
run_time = os.environ["PERF_RUN_TIME"]
warmup = int(os.environ["PERF_WARMUP"])
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
if metrics_path.exists():
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
    counts[("/token", "POST")],
    counts[("/authorize", "GET")],
    counts[("/introspect", "POST")],
    counts[("/revoke", "POST")],
    counts[("/par", "POST")],
]

print(",".join(str(v) for v in row))
PY
done

echo "[perf/aws] sweep done: $OUT_ROOT"
