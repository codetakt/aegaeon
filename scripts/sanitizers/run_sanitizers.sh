#!/usr/bin/env bash

set -euo pipefail

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*"; }
fail() { printf '[FAIL] %s\n' "$*" >&2; }

SANITIZER_LIST=${SANITIZERS:-address}
SANITIZER_TARGETS=${SANITIZER_TARGETS:-ffi}
SANITIZER_TARGET_ROOT=${SANITIZER_TARGET_DIR:-target/sanitizers}
EXTRA_CARGO_FLAGS=${SANITIZER_CARGO_FLAGS:-}
SANITIZER_TIMEOUT=${SANITIZER_TIMEOUT:-120}
SANITIZER_TIMEOUT_KILL=${SANITIZER_TIMEOUT_KILL:-130}
ASAN_VERIFY_LINK_ORDER=${ASAN_VERIFY_LINK_ORDER:-0}
SANITIZER_FORCE_PRELOAD=${SANITIZER_FORCE_PRELOAD:-0}
SANITIZER_EXEC_FORCE_PRELOAD=${SANITIZER_EXEC_FORCE_PRELOAD:-0}
SANITIZER_BUILD_EXTRA_ARGS=${SANITIZER_BUILD_EXTRA_ARGS:-}
SANITIZER_ADD_DYNAMIC_RT=${SANITIZER_ADD_DYNAMIC_RT:-1}
SANITIZER_EXEC_LD_PRELOAD=${SANITIZER_EXEC_LD_PRELOAD:-}
SANITIZER_ARTIFACT_DIR=${SANITIZER_ARTIFACT_DIR:-}

# Both standalone execution and destructive outer cleanup use one source policy.
# shellcheck source=scripts/sanitizers/sanitizer_paths.sh
source "${BASH_SOURCE[0]%/*}/sanitizer_paths.sh"
workspace=$(pwd -P)
preflight_route "${SANITIZER_ARTIFACT_DIR:-${SANITIZER_TARGET_ROOT}/artifacts}" || exit 1
SANITIZER_ARTIFACT_DIR=$PREFLIGHT_ROUTE
sanitizer_validate_output "$SANITIZER_ARTIFACT_DIR" "$workspace" || exit 1
# Safe owned evidence is failed before any later target or tool preflight fails.
# Unsafe evidence is never initialized or archived.
sanitizer_initialize_evidence || exit 1
PREFLIGHT_PHASE=target
preflight_exit() {
	local status=$?
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		preflight_receipt "$PREFLIGHT_PHASE" "$status" || fail "Failed to update sanitizer preflight evidence"
	fi
	exit "$status"
}
trap preflight_exit EXIT
PREFLIGHT_PHASE=cargo-flags
sanitizer_validate_cargo_flags "$EXTRA_CARGO_FLAGS" "$SANITIZER_BUILD_EXTRA_ARGS" || exit 1
preflight_route "$SANITIZER_TARGET_ROOT" || exit 1
SANITIZER_TARGET_ROOT=$PREFLIGHT_ROUTE
sanitizer_validate_output "$SANITIZER_TARGET_ROOT" "$workspace" || exit 1
# A standalone evidence descendant is supported: standalone has no outer cleanup.
sanitizer_validate_pair "$SANITIZER_TARGET_ROOT" "$SANITIZER_ARTIFACT_DIR" runner || exit 1
PREFLIGHT_PHASE=rustc

if ! command -v rustc >/dev/null 2>&1; then
	fail "rustc not found; enter the devShell first"
	exit 1
fi

PREFLIGHT_PHASE=cargo
if ! command -v cargo >/dev/null 2>&1; then
	fail "cargo not found; enter the devShell first"
	exit 1
fi

RUSTC_BIN=${RUSTC:-$(command -v rustc)}
CARGO_BIN=${CARGO:-$(command -v cargo)}

PREFLIGHT_PHASE=rustc-version
rustc_version="$("${RUSTC_BIN}" --version)"
PREFLIGHT_PHASE=rustc-host
host_triple="$("${RUSTC_BIN}" -vV | awk '/^host:/{print $2}')"

PREFLIGHT_PHASE=clang
clang_path=$(command -v clang || true)
if [[ -z ${clang_path} ]]; then
	fail "clang not found; sanitizers require an LLVM toolchain"
	exit 1
fi

PREFLIGHT_PHASE=runtime
if [[ -n ${SANITIZER_RUNTIME_DIR:-} ]]; then
	clang_resource_dir=""
	clang_lib_dir="${SANITIZER_RUNTIME_DIR}"
else
	clang_resource_dir="$(${clang_path} --print-resource-dir 2>/dev/null || true)"
	clang_lib_dir="${clang_resource_dir}/lib/linux"
fi
if [[ ! -d ${clang_lib_dir} ]]; then
	fail "Unable to locate sanitizer runtime directory (expected ${clang_lib_dir})"
	exit 1
fi

PREFLIGHT_PHASE=host
if [[ -z ${host_triple} ]]; then
	fail "Unable to determine host triple from rustc"
	exit 1
fi

asan_suffix="${host_triple%%-*}"
asan_runtime="${clang_lib_dir}/libclang_rt.asan-${asan_suffix}.so"
if [[ ! -f ${asan_runtime} ]]; then
	fail "ASan runtime not found at ${asan_runtime}"
	exit 1
fi

asan_preinit=""
asan_preinit_ext=""
for candidate_ext in so a; do
	candidate="${clang_lib_dir}/libclang_rt.asan-preinit-${asan_suffix}.${candidate_ext}"
	if [[ -f ${candidate} ]]; then
		asan_preinit="${candidate}"
		asan_preinit_ext="${candidate_ext}"
		break
	fi
done
have_asan_preinit=0
if [[ -n ${asan_preinit} ]]; then
	have_asan_preinit=1
else
	warn "ASan preinit runtime not found under ${clang_lib_dir}; interceptor coverage may remain incomplete"
fi

libasan_path="${LIBASAN_PATH:-}"
if [[ -z ${libasan_path} || ! -f ${libasan_path} ]]; then
	libasan_path=$(gcc -print-file-name=libasan.so 2>/dev/null || true)
fi
if [[ -z ${libasan_path} || ! -f ${libasan_path} ]]; then
	warn "libasan.so not found; relying on clang ASan runtime only (set LIBASAN_PATH to override)"
	libasan_path=""
fi

libcxxabi_path="${LIBCXXABI_PATH:-}"
if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
	search_roots=(
		"$(dirname "${clang_lib_dir}")"
		"${clang_lib_dir}"
	)
	for root in "${search_roots[@]}"; do
		[[ -d ${root} ]] || continue
		libcxxabi_path=$(find "${root}" -maxdepth 3 -name 'libc++abi.so' -print -quit 2>/dev/null || true)
		[[ -n ${libcxxabi_path} ]] && break
	done
fi
if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
	libcxxabi_path=$(find /nix/store -maxdepth 3 -name 'libc++abi.so' -print -quit 2>/dev/null || true)
fi
if [[ -z ${libcxxabi_path} || ! -f ${libcxxabi_path} ]]; then
	warn "libc++abi.so not found; ASan may miss C++ exception interceptors (set LIBCXXABI_PATH to override)"
fi

# Build LD_PRELOAD list for optional test execution override
ld_preload_parts=()
if [[ ${have_asan_preinit} -eq 1 && ${asan_preinit_ext} == "so" ]]; then
	ld_preload_parts+=("${asan_preinit}")
fi
ld_preload_parts+=("${asan_runtime}")
if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" && -n ${libcxxabi_path} && -f ${libcxxabi_path} ]]; then
	ld_preload_parts+=("${libcxxabi_path}")
fi
ld_preload_base_exec=$(
	IFS=:
	printf '%s' "${ld_preload_parts[*]}"
)

# Build-phase LD_PRELOAD (rarely used; off by default)
ld_preload_base=""
if [[ ${SANITIZER_FORCE_PRELOAD} == "1" ]]; then
	ld_preload_base="${ld_preload_base_exec}"
	if [[ -n ${libasan_path} && -f ${libasan_path} ]]; then
		ld_preload_base="${ld_preload_base}:${libasan_path}"
	fi
	if [[ -n ${LD_PRELOAD:-} ]]; then
		ld_preload_base="${ld_preload_base}:${LD_PRELOAD}"
	fi
	info "Build phase LD_PRELOAD enabled (SANITIZER_FORCE_PRELOAD=1): ${ld_preload_base}"
fi

info "Using rustc toolchain (${rustc_version})"
info "Detected ASan runtime dir: ${clang_lib_dir}"

export LD_LIBRARY_PATH="${clang_lib_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

sanitize_flags_base=()
if [[ -n ${SANITIZER_RUSTFLAGS:-} ]]; then
	# shellcheck disable=SC2206 # word splitting intentional for flag parsing
	sanitizer_env_flags=(${SANITIZER_RUSTFLAGS})
	sanitize_flags_base+=("${sanitizer_env_flags[@]}")
fi
if [[ ${SANITIZER_ADD_DYNAMIC_RT} == "1" ]]; then
	# Dynamic linking: add library paths and explicit runtime linking
	sanitize_flags_base+=(
		"-L" "native=${clang_lib_dir}"
		"-C" "link-args=-Wl,-rpath,${clang_lib_dir}"
	)
	sanitize_flags_base+=(
		"-C" "link-arg=-l:libclang_rt.asan-${asan_suffix}.so"
	)
	if [[ ${have_asan_preinit} -eq 1 ]]; then
		if [[ ${asan_preinit_ext} == "so" ]]; then
			sanitize_flags_base+=(
				"-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.so"
			)
		else
			sanitize_flags_base+=(
				"-C" "link-arg=-Wl,-whole-archive"
				"-C" "link-arg=-l:libclang_rt.asan-preinit-${asan_suffix}.${asan_preinit_ext}"
				"-C" "link-arg=-Wl,-no-whole-archive"
			)
		fi
		sanitize_flags_base+=(
			"-C" "link-arg=-Wl,-u,__asan_preinit"
		)
	fi
fi
curve_flags=(
	"--cfg" 'curve25519_dalek_backend="serial"'
	"-C" "target-feature=-avx2,-avx512ifma,-avx512vl,-avx512f,-avx512bw,-avx512dq,-avx512cd"
)

PREFLIGHT_PHASE=tools
for tool in python3 nm readelf; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		fail "$tool not found; sanitizer execution and evidence require it"
		exit 1
	fi
done

if [[ ${SANITIZER_EXEC_FORCE_PRELOAD} == "1" ]]; then
	exec_ld_preload="${ld_preload_base_exec}"
else
	exec_ld_preload="${SANITIZER_EXEC_LD_PRELOAD}"
fi

exec python3 - "$SANITIZER_LIST" "$SANITIZER_TARGETS" "$SANITIZER_TARGET_ROOT" \
	"${SANITIZER_ARTIFACT_DIR:-${SANITIZER_TARGET_ROOT}/artifacts}" \
	"$CARGO_BIN" "$host_triple" "${sanitize_flags_base[*]}" "${curve_flags[*]}" \
	"$EXTRA_CARGO_FLAGS" "$SANITIZER_BUILD_EXTRA_ARGS" \
	"${SANITIZER_BUILD_TIMEOUT:-$SANITIZER_TIMEOUT}" \
	"${SANITIZER_RUN_TIMEOUT:-$SANITIZER_TIMEOUT}" "$SANITIZER_TIMEOUT_KILL" \
	"$clang_lib_dir" "$ASAN_VERIFY_LINK_ORDER" "$exec_ld_preload" <<'PYTHON'
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import subprocess
import sys
import tempfile
import time

# Required default-profile targets, independently frozen before this repair.
FFI_TARGETS = {
    "ffi", "aead_buffer_boundary_test", "dpop_header_test", "dpop_proof_test",
    "dpop_uri_test", "equivalence_pkce_test", "jose_header_runtime_test",
    "oidc_hash_runtime_test", "pkce_verifier_test",
}


class Failure(Exception):
    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status if status > 0 else 128 - status


def require(condition, message):
    if not condition:
        raise Failure(message)


def duration(value):
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd]?)", value)
    require(match is not None, f"Invalid sanitizer deadline: {value!r}")
    seconds = float(match[1]) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]
    require(math.isfinite(seconds) and seconds > 0, "Sanitizer deadlines must be positive and finite")
    return seconds


def selection(value, label):
    values = value.replace(",", " ").split()
    require(values and len(values) == len(set(values)), f"Empty or duplicate {label} selection")
    require(all(re.fullmatch(r"[A-Za-z0-9_-]+", item) for item in values), f"Invalid {label} selection")
    return values


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(text):
    return json.loads(text, object_pairs_hook=unique_object)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def group_alive(pgid):
    # A reparented zombie has exited; it is not a running descendant. Linux is
    # also the platform of the existing lib/linux ASan runtime configuration.
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
                return True
        except (FileNotFoundError, ProcessLookupError):
            continue
    return False


def terminate(process, grace):
    active = group_alive(process.pid)
    if active:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + grace
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        if group_alive(process.pid):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 5
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.01)
    process.wait(timeout=5)
    require(not group_alive(process.pid), "Sanitizer descendants survived cleanup")
    return active


def interrupted(signum, frame):
    raise Failure(f"Sanitizer supervisor interrupted by signal {signum}", 128 + signum)


for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, interrupted)

(
    sanitizer_text, package_text, target_text, artifact_text, cargo, host,
    base_flags, curve_flags, extra_text, build_extra_text, build_limit_text,
    run_limit_text, grace_text, runtime_text, link_order, preload,
) = sys.argv[1:]
workspace = Path.cwd().resolve()
artifacts = Path(artifact_text).resolve()
summary = {"status": "failed", "workspace": str(workspace), "host": host, "commands": [], "units": []}
counter = 0
kill_grace = 1


def save():
    fd, name = tempfile.mkstemp(prefix=".run-summary-", dir=artifacts)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
        os.replace(temporary, artifacts / "run-summary.json")
    finally:
        temporary.unlink(missing_ok=True)


def command(args, environment, seconds, phase, *, echo=False):
    global counter
    counter += 1
    prefix = artifacts / f"{counter:03d}-{phase}"
    record = {"args": args, "phase": phase, "deadline_seconds": seconds, "status": "not-started"}
    summary["commands"].append(record)
    process = None
    started = time.monotonic()
    interrupted_failure = None
    original_status = None
    timed_out = False
    lingering = False
    try:
        with prefix.with_suffix(".stdout.log").open("wb") as out, prefix.with_suffix(".stderr.log").open("wb") as err:
            process = subprocess.Popen(args, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            record["pid"] = process.pid
            record["status"] = "running"
            selector = selectors.DefaultSelector()
            for pipe, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            try:
                while selector.get_map() or process.poll() is None:
                    if not timed_out and time.monotonic() - started >= seconds:
                        timed_out = True
                        terminate(process, kill_grace)
                    elif process.poll() is not None and group_alive(process.pid):
                        lingering = terminate(process, kill_grace)
                    for key, _ in selector.select(0.02):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        (out if key.data == "stdout" else err).write(data)
                        if echo:
                            stream = sys.stdout.buffer if key.data == "stdout" else sys.stderr.buffer
                            stream.write(data)
                            stream.flush()
                process.wait(timeout=5)
                # A descendant may close its inherited output and outlive the leader.
                lingering = terminate(process, kill_grace) or lingering
            finally:
                selector.close()
    except Exception as error:
        original_status = process.poll() if process is not None else None
        interrupted_failure = error
    finally:
        if process is not None:
            # Preserve a status already observed before final cleanup can fail.
            if original_status is None:
                original_status = process.poll()
            try:
                terminate(process, kill_grace)
            except Exception as error:
                interrupted_failure = interrupted_failure or error
            record["exit_code"] = process.poll()
            for pipe in (process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()
        record["elapsed_seconds"] = time.monotonic() - started
        record["timed_out"] = timed_out
        record["lingering_descendants"] = lingering
        record["stdout"] = str(prefix.with_suffix(".stdout.log"))
        record["stderr"] = str(prefix.with_suffix(".stderr.log"))
    status = record.get("exit_code")
    record["status"] = "failed" if interrupted_failure or timed_out or lingering or status != 0 else "completed"
    failure_status = (original_status or getattr(interrupted_failure, "status", 1)) if interrupted_failure else (status or 1)
    if timed_out:
        failure_status = 124
    try:
        save()
    except Exception as error:
        raise Failure(f"{phase} evidence write failed: {error}", failure_status) from error
    if timed_out:
        raise Failure(f"{phase} exceeded its deadline", 124)
    if interrupted_failure:
        raise Failure(f"{phase} capture/cleanup failed: {interrupted_failure}", failure_status)
    if status != 0:
        raise Failure(f"{phase} failed with exit {status}", status or 1)
    require(not lingering, f"{phase} left running descendants")
    return prefix.with_suffix(".stdout.log").read_text()


def listed(text):
    names = []
    for line in text.splitlines():
        if not line.strip():
            continue
        require(line.endswith(": test") and line[:-6] and line == line.strip(), f"Malformed libtest listing: {line!r}")
        names.append(line[:-6])
    require(len(names) == len(set(names)), "Duplicate libtest identity")
    return set(names)


def completed(text, names, ignored):
    started = set()
    finished = {}
    suites = []
    for line in text.splitlines():
        require(line.strip(), "Empty libtest event")
        event = parse_json(line)
        require(isinstance(event, dict), "Malformed libtest event")
        if event.get("type") == "suite":
            suites.append(event)
            require(len(suites) <= 2, "Duplicate libtest suite event")
            expected_event = "started" if len(suites) == 1 else "ok"
            require(event.get("event") == expected_event, "Missing normal libtest suite completion")
            if len(suites) == 1:
                require(type(event.get("test_count")) is int and event["test_count"] == len(names), "Libtest suite discovery count mismatch")
            else:
                require(set(finished) == names, "Suite completed before named test execution")
        elif event.get("type") == "test":
            require(len(suites) == 1, "Test event outside active suite")
            name = event.get("name")
            require(isinstance(name, str) and name in names, f"Unknown completed test: {name}")
            if event.get("event") == "started":
                require(name not in started and name not in finished, "Duplicate started test")
                started.add(name)
            else:
                require(name not in finished, "Duplicate completed test")
                require(name in ignored or name in started, "Test completed without starting")
                finished[name] = event.get("event")
        else:
            raise Failure("Unknown libtest event type")
    require(len(suites) == 2, "Missing normal libtest suite completion")
    require(set(finished) == names and started >= names - ignored, "Missing named test execution")
    require(all(finished[name] == ("ignored" if name in ignored else "ok") for name in names), "Failed or incorrectly ignored test")
    result = suites[1]
    expected_counts = {"passed": len(names - ignored), "ignored": len(ignored), "failed": 0, "filtered_out": 0}
    require(all(type(result.get(key)) is int and result[key] == value for key, value in expected_counts.items()), "Libtest totals do not match named execution")
    return {"started": sorted(started), "completed": sorted(names - ignored), "ignored": sorted(ignored)}


exit_status = 0
try:
    sanitizers = selection(sanitizer_text, "sanitizer")
    packages = selection(package_text, "package")
    require(sanitizers == ["address"], "Only the configured address sanitizer is supported")
    build_seconds, run_seconds, kill_grace = map(duration, (build_limit_text, run_limit_text, grace_text))
    extra = shlex.split(extra_text)
    build_extra = shlex.split(build_extra_text)
    require(build_extra in ([], ["-Zbuild-std=std"], ["-Z", "build-std=std"]), "Only the supported build-std=std option is permitted")
    forbidden = {"--config", "--target", "--target-dir", "--message-format", "--package", "-p", "--lib", "--tests", "--test", "--bin", "--bins", "--workspace", "--all", "--exclude", "--manifest-path", "--release", "--profile", "--all-targets", "--examples", "--example", "--benches", "--bench", "--"}
    require(not any(flag.split("=", 1)[0] in forbidden or (flag.startswith("-p") and flag != "--") for flag in extra), "Cargo flags cannot override required sanitizer selection, configuration or native target")
    artifacts.mkdir(parents=True, exist_ok=True)
    summary.update({"sanitizers": sanitizers, "packages": packages, "build_deadline_seconds": build_seconds, "run_deadline_seconds": run_seconds, "kill_grace_seconds": kill_grace, "runtime_directory": runtime_text})
    metadata = parse_json(command([cargo, *build_extra, "metadata", "--format-version", "1", "--no-deps"], os.environ.copy(), build_seconds, "metadata"))
    require(Path(metadata["workspace_root"]).resolve() == workspace, "Cargo metadata belongs to a different workspace")
    require(isinstance(metadata.get("packages"), list), "Malformed Cargo metadata packages")
    package_records = {package["name"]: package for package in metadata["packages"]}
    require(len(package_records) == len(metadata["packages"]), "Duplicate Cargo metadata package")
    for sanitizer in sanitizers:
        for package_name in packages:
            require(package_name in package_records, f"Unknown sanitizer package: {package_name}")
            package = package_records[package_name]
            targets = {target["name"]: target for target in package["targets"] if target.get("test") is True and set(target["kind"]) & {"lib", "test"}}
            require(len(targets) == sum(target.get("test") is True and bool(set(target["kind"]) & {"lib", "test"}) for target in package["targets"]), "Duplicate Cargo target identity")
            require(all(re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in targets), "Invalid Cargo target identity")
            require(targets, "Empty required sanitizer target inventory")
            if package_name == "ffi":
                require(set(targets) >= FFI_TARGETS, "Missing required baseline ffi target")
            target_dir = (Path(target_text) / f"{sanitizer}-{package_name}").resolve()
            rustflags = f"{base_flags} -Z sanitizer={sanitizer} {curve_flags}".strip()
            unit = {"package": package_name, "package_id": package["id"], "sanitizer": sanitizer, "status": "not-run", "rustflags": rustflags, "target_directory": str(target_dir), "targets": [{"name": name, "status": "not-run", "source": str(Path(target["src_path"]).resolve()), "source_sha256": digest(Path(target["src_path"]))} for name, target in targets.items()]}
            summary["units"].append(unit)
            build_env = {**os.environ, "RUSTFLAGS": rustflags, "RUSTDOCFLAGS": rustflags, "CARGO_TARGET_DIR": str(target_dir), "ASAN_OPTIONS": "abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order=0:verbosity=0", "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0", "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"}
            build_env.pop("CARGO_ENCODED_RUSTFLAGS", None)
            build_env.pop("CARGO_ENCODED_RUSTDOCFLAGS", None)
            output = command([cargo, *build_extra, "test", *extra, "-p", package_name, "--lib", "--tests", "--no-run", "--target", host, "--message-format=json-render-diagnostics"], build_env, build_seconds, f"build-{sanitizer}-{package_name}")
            found = {}
            build_finished = []
            for line in output.splitlines():
                if not line.strip():
                    continue
                record = parse_json(line)
                require(isinstance(record, dict) and isinstance(record.get("reason"), str), "Malformed Cargo JSON record")
                if record["reason"] == "build-finished":
                    require(type(record.get("success")) is bool, "Malformed Cargo build-finished record")
                    build_finished.append(record["success"])
                    continue
                require(record["reason"] in {"compiler-artifact", "compiler-message", "build-script-executed"}, "Unknown Cargo JSON record")
                if record["reason"] != "compiler-artifact":
                    continue
                profile = record.get("profile")
                require(isinstance(profile, dict) and type(profile.get("test")) is bool, "Malformed Cargo artifact profile")
                if not profile["test"]:
                    continue
                target = record.get("target", {})
                name = target.get("name")
                require(record.get("package_id") == package["id"] and name in targets, "Unrelated sanitizer test artifact")
                require(name not in found, "Duplicate sanitizer test artifact")
                expected = targets[name]
                require(type(record.get("fresh")) is bool, "Malformed Cargo artifact freshness")
                features = record.get("features")
                require(isinstance(features, list) and all(isinstance(feature, str) for feature in features) and len(features) == len(set(features)), "Malformed Cargo artifact features")
                require(target.get("kind") == expected["kind"] and Path(target.get("src_path", "")).resolve() == Path(expected["src_path"]).resolve(), "Cargo target identity mismatch")
                require(isinstance(record.get("executable"), str), "Missing sanitizer test executable")
                binary = Path(record["executable"]).resolve()
                require(binary.is_relative_to(target_dir / host / "debug/deps") and binary.is_file() and os.access(binary, os.X_OK), "Missing, stale or outside-target sanitizer executable")
                require(all(binary != previous[0] for previous in found.values()), "Duplicate sanitizer executable")
                require(isinstance(record.get("filenames"), list) and record["executable"] in record["filenames"], "Executable is not bound to Cargo artifact filenames")
                found[name] = (binary, record)
            require(build_finished == [True], "Missing successful Cargo build-finished record")
            require(set(found) == set(targets), "Missing required sanitizer test artifacts")
            unit["status"] = "built"
            run_env = {**os.environ, "ASAN_OPTIONS": f"abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order={link_order}:verbosity=0", "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0", "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"}
            if preload:
                run_env["LD_PRELOAD"] = preload + (":" + os.environ["LD_PRELOAD"] if os.environ.get("LD_PRELOAD") else "")
            for target_result in unit["targets"]:
                name = target_result["name"]
                binary, record = found[name]
                target_result.update({"binary": str(binary), "binary_sha256": digest(binary), "cargo_artifact": record, "status": "built"})
                symbols = command(["nm", str(binary)], os.environ.copy(), run_seconds, f"symbols-{name}")
                require("__asan_init" in symbols and "__asan_report_" in symbols and ("asan.module_ctor" in symbols or "___asan_gen_" in symbols), "Sanitizer binary lacks ASan instrumentation markers")
                elf = command(["readelf", "-d", str(binary)], os.environ.copy(), run_seconds, f"runtime-{name}")
                target_result["runtime_linkage"] = "dynamic" if "libclang_rt.asan" in elf else "embedded"
                all_names = listed(command([str(binary), "--list", "--format", "terse"], run_env, run_seconds, f"list-{name}"))
                ignored = listed(command([str(binary), "--list", "--ignored", "--format", "terse"], run_env, run_seconds, f"ignored-{name}"))
                require(ignored <= all_names, "Ignored test identities are not in required inventory")
                inactive = package_name == "ffi" and name == "oidc_hash_runtime_test" and "lowstar_hash" not in record["features"]
                require(all_names - ignored or (inactive and not all_names), "Required sanitizer binary has no runnable tests")
                target_result.update({"expected_tests": sorted(all_names), "ignored_tests": sorted(ignored), "applicability": "lowstar_hash feature disabled" if inactive and not all_names else "required"})
                executed = command([str(binary), "-Z", "unstable-options", "--format", "json"], run_env, run_seconds, f"run-{name}", echo=True)
                require(digest(binary) == target_result["binary_sha256"], "Sanitizer executable changed during execution")
                target_result.update(completed(executed, all_names, ignored))
                target_result["status"] = "completed"
                save()
            unit["status"] = "completed"
    summary["status"] = "completed"
except Exception as error:
    summary["error"] = str(error)
    exit_status = getattr(error, "status", 1)
    print(f"[FAIL] Sanitizer execution failed: {error}", file=sys.stderr)
finally:
    try:
        if artifacts.is_dir():
            save()
    except Exception as error:
        print(f"[FAIL] Sanitizer evidence write failed: {error}", file=sys.stderr)
        exit_status = exit_status or 1
if exit_status == 0:
    print(f"[INFO] Sanitizer-backed tests completed; evidence: {artifacts / 'run-summary.json'}")
raise SystemExit(exit_status)
PYTHON
