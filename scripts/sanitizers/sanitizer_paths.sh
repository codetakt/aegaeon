#!/usr/bin/env bash
# Shared lexical path and immutable source policy for sanitizer outputs.
# Cleanup is Linux/Python fd-relative: existing component identities must agree.
# O_NOFOLLOW rejects route aliases; recursive removal does not follow child links.
# This does not claim atomicity against arbitrary concurrent namespace mutation.

preflight_route() {
	local remaining=$1 component route=/
	[[ $remaining == /* ]] || remaining="$PWD/$remaining"
	remaining=${remaining#/}
	while [[ -n $remaining ]]; do
		component=${remaining%%/*}
		if [[ $remaining == */* ]]; then
			remaining=${remaining#*/}
		else
			remaining=""
		fi
		case "$component" in
		"" | .) continue ;;
		..)
			route=${route%/*}
			[[ -n $route ]] || route=/
			continue
			;;
		esac
		route="${route%/}/$component"
		if [[ -L $route || (-e $route && ! -d $route) ]]; then
			fail "Unsafe sanitizer evidence/target route"
			return 1
		fi
	done
	# shellcheck disable=SC2034 # Shared result consumed by sourced callers.
	PREFLIGHT_ROUTE=$route
}

protected_source_paths=(
	.cargo
	.flakehub
	.github
	assets
	c
	ci
	crates
	db
	dev-tools
	docs
	examples
	fstar
	fuzz
	generated
	include
	infra
	nix
	proofs
	scripts
	spec
	supply-chain
	tests
	xtask
	.git
	artifacts/ct
	artifacts/karamel
	.actrc
	.commitlint-baseline
	.dockerignore
	.editorconfig
	.env.act.example
	.gitignore
	.markdownlint.json
	.markdownlintignore
	.typos.toml
	AGENTS.md
	CHANGELOG.md
	CODE_OF_CONDUCT.md
	CONTRIBUTING.md
	Cargo.lock
	Cargo.toml
	Dockerfile
	LICENSE
	README.md
	SECURITY.md
	atlas.hcl
	clippy.toml
	commitlint.config.cjs
	deny.toml
	eslint.config.cjs
	flake.lock
	flake.nix
	package-lock.json
	package.json
	pyproject.toml
	rust-toolchain.toml
	tsconfig.json
	artifacts/.gitkeep
	artifacts/README.md
	artifacts/compliance/validate.log
	artifacts/compliance/validate_20251017T074801.log
	artifacts/compliance/validate_20251017T075131.log
	artifacts/compliance/validate_20251017T080003.log
	artifacts/compliance/validate_20251017T083441.log
	artifacts/compliance/validate_20251017T093959.log
	artifacts/compliance/validate_20251017T095748.log
	artifacts/compliance/validate_20251017T131719.log
	artifacts/compliance/validate_20251017T145742.log
	artifacts/compliance/validate_20251018T172713.log
	artifacts/compliance/validate_20251115T121250Z.log
	artifacts/compliance/validate_20251115T121436Z.log
	artifacts/compliance/validate_20251115T122037Z.log
	artifacts/compliance/validate_20251206T001314Z.log
	artifacts/compliance/validate_compliance_matrix.log
	artifacts/conformance/.gitkeep
	artifacts/conformance/bootstrap/.gitkeep
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/export.zip
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/plan.json
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/results.json
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/30ZKPD6BkXaFWg0.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/30ZKPD6BkXaFWg0.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/AG16L44c3QUNkKK.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/AG16L44c3QUNkKK.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/BuDrMYcqiJAMnuF.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/BuDrMYcqiJAMnuF.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/C54c43IdPiHlmrq.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/C54c43IdPiHlmrq.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/DTlsERDY5U47kjo.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/DTlsERDY5U47kjo.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/E0jHxBkZgsS5EV2.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/E0jHxBkZgsS5EV2.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/H4u5hXE3F2KXJav.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/H4u5hXE3F2KXJav.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/Hqc5XkwQXsLHbEx.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/Hqc5XkwQXsLHbEx.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/KaCDGB63sykT1v2.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/KaCDGB63sykT1v2.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/LAIfrrs0uGsyvje.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/LAIfrrs0uGsyvje.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/N9BOLTjkQO6Fs9S.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/N9BOLTjkQO6Fs9S.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/NJJe2svewJ7YSxE.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/NJJe2svewJ7YSxE.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ObvC7MbVeyHS7ab.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ObvC7MbVeyHS7ab.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QYnJx5CFtTVe32T.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QYnJx5CFtTVe32T.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QiOc9agkHY466Jc.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QiOc9agkHY466Jc.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/S6atThBFyRjLb70.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/S6atThBFyRjLb70.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ScmWl62UWWlj4Iq.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ScmWl62UWWlj4Iq.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/SuehZ9kajpIjpnW.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/SuehZ9kajpIjpnW.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/VX0z3tlN8OXi3sN.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/VX0z3tlN8OXi3sN.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/WdAMD58ev8gSU7Y.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/WdAMD58ev8gSU7Y.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/a5rdIdHr50lmWVC.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/a5rdIdHr50lmWVC.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aFabFKopgauiNBp.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aFabFKopgauiNBp.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aUmgkqTYE5ocauf.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aUmgkqTYE5ocauf.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/d3QV6TPNikCBbQq.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/d3QV6TPNikCBbQq.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/eB7yjz7BTcTwcdI.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/eB7yjz7BTcTwcdI.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/geAg6ss3Zveves3.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/geAg6ss3Zveves3.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/hyhnnMFuRC2hK2R.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/hyhnnMFuRC2hK2R.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/io4vv69oYbTBDln.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/io4vv69oYbTBDln.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/lXNt1cEacr4PTw4.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/lXNt1cEacr4PTw4.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/oFnzq1GFBf1RQHy.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/oFnzq1GFBf1RQHy.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vAOO5JgXwYcuxpq.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vAOO5JgXwYcuxpq.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vPm6XPOaGDOAWLE.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vPm6XPOaGDOAWLE.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/y1JntB67dMkhrea.html
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/y1JntB67dMkhrea.png
	artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/suite_commit.txt
	artifacts/conformance/oidcc-config-certification-test-plan/plan-export/export.zip
	artifacts/conformance/oidcc-config-certification-test-plan/plan-export/plan.json
	artifacts/conformance/oidcc-config-certification-test-plan/plan-export/results.json
	artifacts/conformance/oidcc-config-certification-test-plan/plan-export/suite_commit.txt
	artifacts/ct/dudect/report.json
	artifacts/kani/report.json
	artifacts/kani/report.log
	artifacts/kani/run_20260804T065437.log
	artifacts/karamel/Bearer_validation.ml
	artifacts/karamel/FStar_Pervasives_Native.ml
	artifacts/karamel/JoseNatLemmas.c
	artifacts/karamel/JoseNatLemmas.h
	artifacts/karamel/Jose_Arith_Bounds.c
	artifacts/karamel/Jose_Arith_Bounds.h
	artifacts/karamel/Jose_Context.c
	artifacts/karamel/Jose_Context.h
	artifacts/karamel/Jose_LowStar_Json_Stack.c
	artifacts/karamel/Jose_LowStar_Json_Stack.h
	artifacts/karamel/Jose_Utf8Lemmas.c
	artifacts/karamel/Jose_Utf8Lemmas.h
	artifacts/karamel/Makefile.basic
	artifacts/karamel/Makefile.include
	artifacts/karamel/internal/FStar.h
	artifacts/oidc/oidc_tests_20251215.log
	artifacts/release/kms-hsm-classifications/aws-kms-ap-northeast-1-rs256-claim-preserving.json
	artifacts/release/kms-hsm-classifications/aws-kms-localstack-rs256-claim-preserving.json
	artifacts/release/kms-hsm-classifications/aws-kms-validation-ap-northeast-1-rs256-claim-preserving.json
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/metadata.txt
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/summary.json
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/test.log
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/metadata.txt
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/summary.json
	artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/test.log
	artifacts/release/kms-hsm-classifications/evidence/localstack-oidc-kms-summary.json
	artifacts/release/kms-hsm-classifications/external-finished-jwt-gateway-compat-only.json
	artifacts/security/.gitkeep
	artifacts/security/history/.gitkeep
	artifacts/tamarin/README.md
	artifacts/tamarin/manual/authcode_authcode_session_integrity.log
	artifacts/tamarin/manual/authcode_code_injection.log
	artifacts/tamarin/manual/authcode_code_replay.log
	artifacts/tamarin/manual/authcode_csrf_protection.log
	artifacts/tamarin/manual/authcode_state_echo_integrity.log
	artifacts/tamarin/manual/authorize_error_redirect_state.log
	artifacts/tamarin/manual/authorize_success_redirect_code_state.log
	artifacts/tamarin/manual/bearer_bearer_bcp.log
	artifacts/tamarin/manual/bearer_cnf_single_key.log
	artifacts/tamarin/manual/client_auth_client_authentication.log
	artifacts/tamarin/manual/client_auth_private_key_jwt.log
	artifacts/tamarin/manual/client_auth_token_endpoint_auth_required.log
	artifacts/tamarin/manual/common.log
	artifacts/tamarin/manual/common_common_model.log
	artifacts/tamarin/manual/dpop_dpop_replay.log
	artifacts/tamarin/manual/introspection_introspection_security.log
	artifacts/tamarin/manual/jwt_bearer_jwt_bearer_security.log
	artifacts/tamarin/manual/oidc_id_token_nonce.log
	artifacts/tamarin/manual/oidc_iss_mixup.log
	artifacts/tamarin/manual/oidc_logout_session_termination.log
	artifacts/tamarin/manual/oidc_oidc_core.log
	artifacts/tamarin/manual/par_jar_par_fixation.log
	artifacts/tamarin/manual/par_par_redirect_integrity.log
	artifacts/tamarin/manual/par_par_security.log
	artifacts/tamarin/manual/pkce_pkce_security.log
	artifacts/tamarin/manual/rar_rar_authorization_details.log
	artifacts/tamarin/manual/resource_resource_indicators.log
	artifacts/tamarin/manual/revocation_revocation_auth.log
	artifacts/tamarin/manual/stepup_stepup_soundness.log
	artifacts/tamarin/manual/token_exchange_token_exchange_security.log
)

sanitizer_validate_output() {
	local output=$1 workspace=$2 source_path protected
	if [[ $output == "$workspace" || $workspace == "${output%/}/"* ]]; then
		fail "Sanitizer evidence/target routes overlap protected workspace or outputs"
		return 1
	fi
	for source_path in "${protected_source_paths[@]}"; do
		protected="$workspace/$source_path"
		if [[ $output == "$protected" || $output == "$protected/"* || $protected == "${output%/}/"* ]]; then
			fail "Sanitizer evidence/target route overlaps protected source inputs"
			return 1
		fi
	done
}

sanitizer_validate_pair() {
	local target=$1 evidence=$2 role=$3
	if [[ $target == "$evidence" || $target == "${evidence%/}/"* ||
		($role == cleanup && $evidence == "${target%/}/"*) ]]; then
		fail "Sanitizer evidence/target routes overlap protected workspace or outputs"
		return 1
	fi
}

sanitizer_validate_cargo_flags() {
	python3 -I - "$1" "${2:-}" <<'CARGO_FLAGS'
import shlex
import sys

forbidden = {"--config", "--target", "--target-dir", "--message-format", "--package", "-p", "--lib", "--tests", "--test", "--bin", "--bins", "--workspace", "--all", "--exclude", "--manifest-path", "--release", "-r", "--profile", "--all-targets", "--examples", "--example", "--benches", "--bench", "--"}
try:
    extra = shlex.split(sys.argv[1])
    build_extra = shlex.split(sys.argv[2])
    if build_extra not in ([], ["-Zbuild-std=std"], ["-Z", "build-std=std"]):
        raise ValueError("unsupported build option")
    if any(flag.split("=", 1)[0] in forbidden or flag.startswith("-p") for flag in extra):
        raise ValueError("selection override")
except ValueError:
    print("[FAIL] Cargo flags/build options cannot override required sanitizer selection, configuration or native target", file=sys.stderr)
    raise SystemExit(1) from None
CARGO_FLAGS
}

preflight_receipt() {
	python3 -I - "$SANITIZER_ARTIFACT_DIR" "$1" "$2" "${3:-}" "${4:-}" <<'PREFLIGHT'
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

root = Path(sys.argv[1])
phase, status = sys.argv[2], int(sys.argv[3])
summary = root / "run-summary.json"
if root.stat().st_uid != os.getuid():
    raise ValueError("Evidence directory must belong to the producer")
owned = [summary] if summary.exists() else []
owned.extend(path for path in root.iterdir() if re.fullmatch(
    r"[0-9]{3,}-(?:metadata|(?:build|symbols|runtime|list|ignored|run)-[A-Za-z0-9_-]+)\.(?:stdout|stderr)\.log", path.name
))
for path in owned:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_uid != os.getuid():
        raise ValueError("Unsafe sanitizer evidence file alias or ownership")
if phase == "initialize":
    receipt = {"status": "failed", "stage": "preflight", "commands": [], "units": []}
    if owned:
        history = Path(tempfile.mkdtemp(prefix=".previous-attempt-", dir=root))
        if summary in owned:
            os.replace(summary, history / summary.name)
        receipt["previous_attempt"] = history.name
else:
    receipt = json.loads(summary.read_text())
    receipt.update(status="failed", stage="preflight", preflight_phase=phase, exit_code=status)
    if sys.argv[4]:
        receipt["logging_exit_code"] = int(sys.argv[4])
    if sys.argv[5]:
        receipt["cleanup_exit_code"] = int(sys.argv[5])
fd, name = tempfile.mkstemp(prefix=".preflight-summary-", dir=root)
try:
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    os.replace(name, summary)
finally:
    Path(name).unlink(missing_ok=True)
# Initialize failure before preserving old raw logs: a copy failure cannot leave
# an old completed summary current. Original raw files remain untouched.
if phase == "initialize" and owned:
    for path in owned:
        if path != summary:
            shutil.copy2(path, history / path.name)
PREFLIGHT
}

sanitizer_initialize_evidence() {
	local summary_path="$SANITIZER_ARTIFACT_DIR/run-summary.json" previous
	if [[ -L $summary_path || (-e $summary_path && ! -f $summary_path) ]]; then
		fail "Unsafe sanitizer summary destination"
		return 1
	fi
	mkdir -p -- "$SANITIZER_ARTIFACT_DIR" || return 1
	if [[ ! -O $SANITIZER_ARTIFACT_DIR || (-f $summary_path && ! -O $summary_path) ]]; then
		fail "Sanitizer evidence must belong to the producer"
		return 1
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		(
			set -o noclobber
			printf '%s\n' '{"status":"failed","stage":"preflight","error":"python3 evidence writer unavailable"}' >"$SANITIZER_ARTIFACT_DIR/preflight-failed-$BASHPID.json"
		) || return 1
		if [[ -f $summary_path ]]; then
			previous=$(mktemp "$SANITIZER_ARTIFACT_DIR/.previous-summary-XXXXXXXX") || return 1
			mv -T -- "$summary_path" "$previous" || return 1
		fi
		fail "python3 not found; sanitizer attempt failed before preflight evidence writer"
		return 1
	fi
	preflight_receipt initialize 1
}

sanitizer_target_binding() {
	python3 -I - "$1" "$2" <<'SANITIZER_BINDING'
import json
import os
import stat
import sys

def remove_contents(directory):
    # Every traversal remains anchored to an open, no-follow directory handle.
    for entry in os.scandir(directory):
        info = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(entry.name, flags, dir_fd=directory)
            try:
                opened = os.fstat(child)
                if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("Sanitizer child entry changed; refusing cleanup")
                remove_contents(child)
                current = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("Sanitizer child entry changed; refusing cleanup")
                os.rmdir(entry.name, dir_fd=directory)
            finally:
                os.close(child)
        else:
            os.unlink(entry.name, dir_fd=directory)

operation, value = sys.argv[1:]
if operation not in {"prepare", "validate", "cleanup"}:
    raise ValueError("Unknown sanitizer path binding operation")
flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
if operation == "prepare":
    target = value
    expected = None
else:
    expected = json.loads(value)
    target = expected["target"]
parts = target.split("/")[1:]
if not parts or not all(parts):
    raise ValueError("Invalid validated sanitizer target")
identities = []
fd = os.open("/", flags)
try:
    identities.append([os.fstat(fd).st_dev, os.fstat(fd).st_ino])
    for index, name in enumerate(parts):
        if operation == "prepare":
            try:
                os.mkdir(name, dir_fd=fd)
            except FileExistsError:
                pass
        child = os.open(name, flags, dir_fd=fd)
        metadata = os.fstat(child)
        if index == len(parts) - 1 and metadata.st_uid != os.getuid():
            os.close(child)
            raise ValueError("Sanitizer target directory must belong to the producer")
        identities.append([metadata.st_dev, metadata.st_ino])
        if expected is not None and identities != expected["identities"][:len(identities)]:
            os.close(child)
            raise ValueError("Sanitizer target component identity changed; refusing cleanup")
        if index == len(parts) - 1 and operation == "cleanup":
            try:
                remove_contents(child)
                # Only remove the lexical entry if it still identifies the opened target.
                entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or [entry.st_dev, entry.st_ino] != identities[-1]:
                    raise ValueError("Sanitizer target entry changed; refusing cleanup")
                os.rmdir(name, dir_fd=fd)
            finally:
                os.close(child)
            break
        os.close(fd)
        fd = child
    if operation == "prepare":
        print(json.dumps({"target": target, "identities": identities}))
finally:
    os.close(fd)
SANITIZER_BINDING
}
