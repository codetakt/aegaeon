"""Exercise the real sanitizer wrapper with controlled Cargo and libtest tools."""

from __future__ import annotations

import contextlib
import json
import os
import runpy
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/sanitizers/run_sanitizers.sh"
PATH_HELPER = ROOT / "scripts/sanitizers/sanitizer_paths.sh"
TARGETS = (
    "ffi",
    "aead_buffer_boundary_test",
    "dpop_header_test",
    "dpop_proof_test",
    "dpop_uri_test",
    "equivalence_pkce_test",
    "jose_header_runtime_test",
    "oidc_hash_runtime_test",
    "pkce_verifier_test",
)

PROTECTED_SOURCE_INPUTS = (
    ".cargo",
    ".flakehub",
    ".github",
    "assets",
    "c",
    "ci",
    "crates",
    "db",
    "dev-tools",
    "docs",
    "examples",
    "fstar",
    "fuzz",
    "generated",
    "include",
    "infra",
    "nix",
    "proofs",
    "scripts",
    "spec",
    "supply-chain",
    "tests",
    "xtask",
    ".git",
    "artifacts/ct",
    "artifacts/karamel",
    ".actrc",
    ".commitlint-baseline",
    ".dockerignore",
    ".editorconfig",
    ".env.act.example",
    ".gitignore",
    ".markdownlint.json",
    ".markdownlintignore",
    ".typos.toml",
    "AGENTS.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "Cargo.lock",
    "Cargo.toml",
    "Dockerfile",
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "atlas.hcl",
    "clippy.toml",
    "commitlint.config.cjs",
    "deny.toml",
    "eslint.config.cjs",
    "flake.lock",
    "flake.nix",
    "package-lock.json",
    "package.json",
    "pyproject.toml",
    "rust-toolchain.toml",
    "tsconfig.json",
    "artifacts/.gitkeep",
    "artifacts/README.md",
    "artifacts/compliance/validate.log",
    "artifacts/compliance/validate_20251017T074801.log",
    "artifacts/compliance/validate_20251017T075131.log",
    "artifacts/compliance/validate_20251017T080003.log",
    "artifacts/compliance/validate_20251017T083441.log",
    "artifacts/compliance/validate_20251017T093959.log",
    "artifacts/compliance/validate_20251017T095748.log",
    "artifacts/compliance/validate_20251017T131719.log",
    "artifacts/compliance/validate_20251017T145742.log",
    "artifacts/compliance/validate_20251018T172713.log",
    "artifacts/compliance/validate_20251115T121250Z.log",
    "artifacts/compliance/validate_20251115T121436Z.log",
    "artifacts/compliance/validate_20251115T122037Z.log",
    "artifacts/compliance/validate_20251206T001314Z.log",
    "artifacts/compliance/validate_compliance_matrix.log",
    "artifacts/conformance/.gitkeep",
    "artifacts/conformance/bootstrap/.gitkeep",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/export.zip",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/plan.json",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/results.json",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/30ZKPD6BkXaFWg0.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/30ZKPD6BkXaFWg0.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/AG16L44c3QUNkKK.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/AG16L44c3QUNkKK.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/BuDrMYcqiJAMnuF.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/BuDrMYcqiJAMnuF.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/C54c43IdPiHlmrq.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/C54c43IdPiHlmrq.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/DTlsERDY5U47kjo.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/DTlsERDY5U47kjo.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/E0jHxBkZgsS5EV2.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/E0jHxBkZgsS5EV2.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/H4u5hXE3F2KXJav.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/H4u5hXE3F2KXJav.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/Hqc5XkwQXsLHbEx.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/Hqc5XkwQXsLHbEx.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/KaCDGB63sykT1v2.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/KaCDGB63sykT1v2.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/LAIfrrs0uGsyvje.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/LAIfrrs0uGsyvje.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/N9BOLTjkQO6Fs9S.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/N9BOLTjkQO6Fs9S.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/NJJe2svewJ7YSxE.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/NJJe2svewJ7YSxE.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ObvC7MbVeyHS7ab.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ObvC7MbVeyHS7ab.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QYnJx5CFtTVe32T.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QYnJx5CFtTVe32T.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QiOc9agkHY466Jc.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/QiOc9agkHY466Jc.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/S6atThBFyRjLb70.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/S6atThBFyRjLb70.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ScmWl62UWWlj4Iq.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/ScmWl62UWWlj4Iq.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/SuehZ9kajpIjpnW.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/SuehZ9kajpIjpnW.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/VX0z3tlN8OXi3sN.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/VX0z3tlN8OXi3sN.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/WdAMD58ev8gSU7Y.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/WdAMD58ev8gSU7Y.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/a5rdIdHr50lmWVC.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/a5rdIdHr50lmWVC.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aFabFKopgauiNBp.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aFabFKopgauiNBp.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aUmgkqTYE5ocauf.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/aUmgkqTYE5ocauf.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/d3QV6TPNikCBbQq.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/d3QV6TPNikCBbQq.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/eB7yjz7BTcTwcdI.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/eB7yjz7BTcTwcdI.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/geAg6ss3Zveves3.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/geAg6ss3Zveves3.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/hyhnnMFuRC2hK2R.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/hyhnnMFuRC2hK2R.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/io4vv69oYbTBDln.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/io4vv69oYbTBDln.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/lXNt1cEacr4PTw4.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/lXNt1cEacr4PTw4.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/oFnzq1GFBf1RQHy.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/oFnzq1GFBf1RQHy.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vAOO5JgXwYcuxpq.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vAOO5JgXwYcuxpq.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vPm6XPOaGDOAWLE.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/vPm6XPOaGDOAWLE.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/y1JntB67dMkhrea.html",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/screenshots_20260330T102147Z/y1JntB67dMkhrea.png",
    "artifacts/conformance/oidcc-basic-certification-test-plan/plan-export/suite_commit.txt",
    "artifacts/conformance/oidcc-config-certification-test-plan/plan-export/export.zip",
    "artifacts/conformance/oidcc-config-certification-test-plan/plan-export/plan.json",
    "artifacts/conformance/oidcc-config-certification-test-plan/plan-export/results.json",
    "artifacts/conformance/oidcc-config-certification-test-plan/plan-export/suite_commit.txt",
    "artifacts/ct/dudect/report.json",
    "artifacts/kani/report.json",
    "artifacts/kani/report.log",
    "artifacts/kani/run_20260804T065437.log",
    "artifacts/karamel/Bearer_validation.ml",
    "artifacts/karamel/FStar_Pervasives_Native.ml",
    "artifacts/karamel/JoseNatLemmas.c",
    "artifacts/karamel/JoseNatLemmas.h",
    "artifacts/karamel/Jose_Arith_Bounds.c",
    "artifacts/karamel/Jose_Arith_Bounds.h",
    "artifacts/karamel/Jose_Context.c",
    "artifacts/karamel/Jose_Context.h",
    "artifacts/karamel/Jose_LowStar_Json_Stack.c",
    "artifacts/karamel/Jose_LowStar_Json_Stack.h",
    "artifacts/karamel/Jose_Utf8Lemmas.c",
    "artifacts/karamel/Jose_Utf8Lemmas.h",
    "artifacts/karamel/Makefile.basic",
    "artifacts/karamel/Makefile.include",
    "artifacts/karamel/internal/FStar.h",
    "artifacts/oidc/oidc_tests_20251215.log",
    "artifacts/release/kms-hsm-classifications/aws-kms-ap-northeast-1-rs256-claim-preserving.json",
    "artifacts/release/kms-hsm-classifications/aws-kms-localstack-rs256-claim-preserving.json",
    "artifacts/release/kms-hsm-classifications/aws-kms-validation-ap-northeast-1-rs256-claim-preserving.json",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/metadata.txt",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/summary.json",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-ap-northeast-1-bb0a6c43/test.log",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/metadata.txt",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/summary.json",
    "artifacts/release/kms-hsm-classifications/evidence/aws-kms-validation-8071664/test.log",
    "artifacts/release/kms-hsm-classifications/evidence/localstack-oidc-kms-summary.json",
    "artifacts/release/kms-hsm-classifications/external-finished-jwt-gateway-compat-only.json",
    "artifacts/security/.gitkeep",
    "artifacts/security/history/.gitkeep",
    "artifacts/tamarin/README.md",
    "artifacts/tamarin/manual/authcode_authcode_session_integrity.log",
    "artifacts/tamarin/manual/authcode_code_injection.log",
    "artifacts/tamarin/manual/authcode_code_replay.log",
    "artifacts/tamarin/manual/authcode_csrf_protection.log",
    "artifacts/tamarin/manual/authcode_state_echo_integrity.log",
    "artifacts/tamarin/manual/authorize_error_redirect_state.log",
    "artifacts/tamarin/manual/authorize_success_redirect_code_state.log",
    "artifacts/tamarin/manual/bearer_bearer_bcp.log",
    "artifacts/tamarin/manual/bearer_cnf_single_key.log",
    "artifacts/tamarin/manual/client_auth_client_authentication.log",
    "artifacts/tamarin/manual/client_auth_private_key_jwt.log",
    "artifacts/tamarin/manual/client_auth_token_endpoint_auth_required.log",
    "artifacts/tamarin/manual/common.log",
    "artifacts/tamarin/manual/common_common_model.log",
    "artifacts/tamarin/manual/dpop_dpop_replay.log",
    "artifacts/tamarin/manual/introspection_introspection_security.log",
    "artifacts/tamarin/manual/jwt_bearer_jwt_bearer_security.log",
    "artifacts/tamarin/manual/oidc_id_token_nonce.log",
    "artifacts/tamarin/manual/oidc_iss_mixup.log",
    "artifacts/tamarin/manual/oidc_logout_session_termination.log",
    "artifacts/tamarin/manual/oidc_oidc_core.log",
    "artifacts/tamarin/manual/par_jar_par_fixation.log",
    "artifacts/tamarin/manual/par_par_redirect_integrity.log",
    "artifacts/tamarin/manual/par_par_security.log",
    "artifacts/tamarin/manual/pkce_pkce_security.log",
    "artifacts/tamarin/manual/rar_rar_authorization_details.log",
    "artifacts/tamarin/manual/resource_resource_indicators.log",
    "artifacts/tamarin/manual/revocation_revocation_auth.log",
    "artifacts/tamarin/manual/stepup_stepup_soundness.log",
    "artifacts/tamarin/manual/token_exchange_token_exchange_security.log",
)

# One fixture dispatches by executable identity. It emits realistic Cargo and
# libtest records; no compiler execution or synthetic Git commits are involved.
FIXTURE = r"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

root = Path(os.environ["SANITIZER_FIXTURE"])
mode = os.environ.get("SANITIZER_FIXTURE_MODE", "success")
tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as output:
    output.write(
        json.dumps(
            {
                "tool": tool,
                "args": args,
                "flags": os.environ.get("RUSTFLAGS"),
                "encoded_flags": os.environ.get("CARGO_ENCODED_RUSTFLAGS"),
                "asan_options": os.environ.get("ASAN_OPTIONS"),
            }
        )
        + "\n"
    )


def stall(closed=False):
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)",
        ],
        stdout=subprocess.DEVNULL if closed else None,
        stderr=subprocess.DEVNULL if closed else None,
    )
    (root / "child.pid").write_text(str(child.pid))
    if closed and not mode.endswith("descendant"):
        os.close(1)
        os.close(2)
    if mode.endswith("descendant"):
        return
    time.sleep(60)


if tool == "rustc":
    if mode == "rustc-version-failure" and "--version" in args:
        sys.exit(23)
    if mode == "bad-host":
        print("rustc unknown")
    elif "-vV" in args:
        print("host: x86_64-unknown-linux-gnu")
    else:
        print("rustc nightly fixture")
elif tool == "clang":
    print(root / "runtime")
elif tool == "nm":
    print("__asan_init __asan_report_load8 ___asan_gen_" if mode != "uninstrumented" else "main")
elif tool == "readelf":
    print("NEEDED libc.so.6")
elif tool == "cargo":
    metadata = json.loads((root / "metadata.json").read_text())
    if "metadata" in args:
        if mode == "metadata-missing":
            metadata["packages"][0]["targets"].pop()
        if mode == "metadata-duplicate":
            metadata["packages"][0]["targets"].append(metadata["packages"][0]["targets"][0])
        if mode == "metadata-wrong-root":
            metadata["workspace_root"] = "/different-workspace"
        print(json.dumps(metadata))
        sys.exit(0)
    if mode.startswith("build-") and mode in {
        "build-timeout",
        "build-closed-timeout",
        "build-descendant",
        "build-closed-descendant",
        "build-failure-descendant",
    }:
        stall(mode in {"build-closed-timeout", "build-closed-descendant"})
    if mode in {"build-failure", "build-failure-descendant"}:
        print("deliberate compiler error", file=sys.stderr)
        sys.exit(7)
    if mode == "build-signal":
        os.kill(os.getpid(), signal.SIGTERM)
    target_dir = Path(os.environ["CARGO_TARGET_DIR"]) / "x86_64-unknown-linux-gnu/debug/deps"
    target_dir.mkdir(parents=True, exist_ok=True)
    package_name = args[args.index("-p") + 1]
    package = next(item for item in metadata["packages"] if item["name"] == package_name)
    targets = package["targets"]
    for index, target in enumerate(targets):
        binary = target_dir / f"nonstandard-name-{index}"
        binary.write_text((root / "fixture").read_text())
        binary.chmod(0o755)
        record = {
            "reason": "compiler-artifact",
            "package_id": package["id"],
            "target": target,
            "profile": {"test": True},
            "fresh": mode == "fresh-cache",
            "features": ["lowstar_hash"] if mode == "oidc-feature-enabled" else [],
            "executable": str(binary),
            "filenames": [str(binary)],
        }
        if index == 0:
            if mode == "artifact-missing":
                continue
            if mode == "artifact-wrong-package":
                record["package_id"] = "different"
            if mode == "artifact-wrong-source":
                record["target"] = {**target, "src_path": str(root / "wrong.rs")}
            if mode == "artifact-outside-root":
                record["executable"] = str(root / "fixture")
                record["filenames"] = [record["executable"]]
            if mode == "artifact-missing-binary":
                binary.unlink()
            if mode == "artifact-no-executable":
                record["executable"] = None
            if mode == "artifact-no-filename":
                record["filenames"] = []
            if mode == "artifact-bad-features":
                record["features"] = "lowstar_hash"
            if mode == "artifact-bad-profile":
                record["profile"]["test"] = "true"
            if mode == "artifact-bad-fresh":
                record["fresh"] = "true"
            if mode == "artifact-malformed":
                print("{broken")
                continue
        if mode == "artifact-zero":
            continue
        print(json.dumps(record))
        if index == 0 and mode == "artifact-duplicate":
            print(json.dumps(record))
    if mode == "artifact-unknown-reason":
        print(json.dumps({"reason": "unknown"}))
    if mode != "missing-build-finished":
        print(json.dumps({"reason": "build-finished", "success": mode != "false-build-finished"}))
else:
    index = int(tool.rsplit("-", 1)[1])
    package_name = Path(sys.argv[0]).parents[3].name.removeprefix("address-")
    packages = json.loads((root / "metadata.json").read_text())["packages"]
    targets = next(item["targets"] for item in packages if item["name"] == package_name)
    name = targets[index]["name"]
    zero = name == "oidc_hash_runtime_test" or mode == "empty-tests"
    names = [] if zero else [name + "::required"]
    ignored = [name + "::ignored"] if mode == "ignored-policy" and not zero else []
    if "--list" in args:
        if mode == "list-failure":
            sys.exit(8)
        if mode == "list-malformed":
            print("unrecognised list output")
        else:
            for item in ignored if "--ignored" in args else names + ignored:
                print(item + ": test")
        sys.exit(0)
    if index == 0 and mode in {
        "run-timeout",
        "run-closed-timeout",
        "run-descendant",
        "run-closed-descendant",
    }:
        stall(mode in {"run-closed-timeout", "run-closed-descendant"})
    if mode == "run-failure":
        sys.exit(9)
    if mode == "run-signal":
        os.kill(os.getpid(), signal.SIGABRT)
    if mode == "run-malformed":
        print("not JSON")
        sys.exit(0)
    if mode == "run-empty":
        sys.exit(0)
    print(json.dumps({"type": "suite", "event": "started", "test_count": len(names + ignored)}))
    for item in names:
        if mode != "run-no-start":
            print(json.dumps({"type": "test", "event": "started", "name": item}))
        if mode != "run-missing-completion":
            print(json.dumps({"type": "test", "event": "ok", "name": item}))
        if mode == "run-duplicate":
            print(json.dumps({"type": "test", "event": "ok", "name": item}))
    for item in ignored:
        print(json.dumps({"type": "test", "event": "ignored", "name": item}))
    print(
        json.dumps(
            {
                "type": "suite",
                "event": "ok",
                "passed": len(names),
                "ignored": len(ignored),
                "failed": 0,
                "filtered_out": 0,
            }
        )
    )
"""


class SanitizerFixture:
    """Shared sanitizer setup and helpers without discovered test methods."""

    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        runtime = self.root / "runtime"
        runtime.mkdir()
        (runtime / "libclang_rt.asan-x86_64.so").touch()
        (runtime / "libclang_rt.asan-preinit-x86_64.a").touch()
        self.fixture = self.root / "fixture"
        self.fixture.write_text(f"#!{sys.executable}\n{FIXTURE}")
        self.fixture.chmod(0o755)
        for tool in ("rustc", "cargo", "clang", "nm", "readelf"):
            (self.bin / tool).symlink_to(self.fixture)
        for tool in ("python3", "awk", "dirname", "find", "mkdir", "mktemp", "mv"):
            (self.bin / tool).symlink_to(shutil.which(tool))
        targets = []
        for name in TARGETS:
            source = self.root / f"{name}.rs"
            source.write_text("// controlled source identity\n")
            targets.append(
                {
                    "name": name,
                    "kind": ["lib" if name == "ffi" else "test"],
                    "test": True,
                    "src_path": str(source),
                }
            )
        (self.root / "metadata.json").write_text(
            json.dumps(
                {
                    "workspace_root": str(self.root),
                    "packages": [{"name": "ffi", "id": "ffi-identity", "targets": targets}],
                }
            )
        )
        self.environment = {
            **os.environ,
            "PATH": str(self.bin),
            "SANITIZER_FIXTURE": str(self.root),
            "SANITIZER_RUNTIME_DIR": str(runtime),
            "LIBASAN_PATH": str(runtime / "libclang_rt.asan-x86_64.so"),
            "LIBCXXABI_PATH": str(runtime / "libclang_rt.asan-x86_64.so"),
            "SANITIZER_ARTIFACT_DIR": str(self.root / "evidence"),
            "SANITIZER_TARGET_DIR": str(self.root / "target"),
            "SANITIZER_TIMEOUT": "10",
            "SANITIZER_TIMEOUT_KILL": "0.05",
        }
        for variable in (
            "RUSTC",
            "CARGO",
            "LD_PRELOAD",
            "SANITIZER_RUSTFLAGS",
            "SANITIZER_CARGO_FLAGS",
            "SANITIZER_BUILD_EXTRA_ARGS",
            "SANITIZERS",
            "SANITIZER_TARGETS",
            "SANITIZER_BUILD_TIMEOUT",
            "SANITIZER_RUN_TIMEOUT",
            "ASAN_VERIFY_LINK_ORDER",
        ):
            self.environment.pop(variable, None)

    def run_wrapper(self, mode="success", **overrides):
        return subprocess.run(  # noqa: S603
            [shutil.which("bash"), str(WRAPPER)],
            cwd=self.root,
            env={**self.environment, "SANITIZER_FIXTURE_MODE": mode, **overrides},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def summary(self):
        return json.loads((self.root / "evidence/run-summary.json").read_text())

    def add_package(self, name):
        metadata_path = self.root / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        source = self.root / f"{name}.rs"
        source.write_text("// additional package source identity\n")
        metadata["packages"].append(
            {
                "name": name,
                "id": f"{name}-identity",
                "targets": [{"name": name, "kind": ["lib"], "test": True, "src_path": str(source)}],
            }
        )
        metadata_path.write_text(json.dumps(metadata))

    def assert_child_stopped(self):
        child = int((self.root / "child.pid").read_text())
        stat = Path(f"/proc/{child}/stat")

        def stopped():
            try:
                return stat.read_text().rsplit(")", 1)[1].split()[0] in {"Z", "X"}
            except FileNotFoundError:
                return True

        deadline = time.monotonic() + 5
        while not stopped() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(stopped())  # noqa: PT009 - active under Python -O

    def wait_for_child_pid(self):
        child_pid = self.root / "child.pid"
        deadline = time.monotonic() + 5
        while (
            not child_pid.exists() or child_pid.stat().st_size == 0
        ) and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(child_pid.exists() and child_pid.stat().st_size > 0)  # noqa: PT009 - active under Python -O

    def seed_completed_preflight(self):
        evidence = self.root / "evidence"
        evidence.mkdir(exist_ok=True)
        raw = b'{"status":"completed","commands":[],"units":[]}\n'
        (evidence / "run-summary.json").write_bytes(raw)
        (evidence / "001-metadata.stdout.log").write_bytes(b"retained raw output\n")
        (evidence / "unrelated-sentinel").write_bytes(b"untouched\n")
        return evidence, raw

    def assert_failed_preflight_preserved(self, result, evidence, raw):
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(self.summary()["status"], "failed")  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(self.summary()["stage"], "preflight")  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(self.summary()["exit_code"], result.returncode)  # noqa: PT009 - active under unittest and Python -O
        self.assertNotIn("Sanitizer-backed tests completed", result.stdout)  # noqa: PT009 - active under unittest and Python -O
        previous = evidence / self.summary()["previous_attempt"]
        self.assertEqual((previous / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(  # noqa: PT009 - active under unittest and Python -O
            (previous / "001-metadata.stdout.log").read_bytes(), b"retained raw output\n"
        )
        self.assertEqual(  # noqa: PT009 - active under unittest and Python -O
            (evidence / "001-metadata.stdout.log").read_bytes(), b"retained raw output\n"
        )
        self.assertEqual((evidence / "unrelated-sentinel").read_bytes(), b"untouched\n")  # noqa: PT009 - active under unittest and Python -O

    def prepare_preflight_alias(self, kind, evidence, external, sentinel):
        if kind in {"directory-symlink", "normalized-symlink"}:
            alias = self.root / kind
            alias.symlink_to(external, target_is_directory=True)
            return alias if kind == "directory-symlink" else alias / ".." / "evidence"
        if kind == "overlap":
            return self.root
        path = evidence / (
            "001-metadata.stdout.log" if kind.startswith("raw-log") else "run-summary.json"
        )
        path.unlink()
        if kind.endswith("symlink"):
            path.symlink_to(sentinel)
        else:
            os.link(sentinel, path)
        return evidence

    def restore_preflight_alias(self, evidence):
        for name, raw in [
            ("run-summary.json", b'{"status":"completed"}'),
            ("001-metadata.stdout.log", b"retained raw output\n"),
        ]:
            path = evidence / name
            if path.is_symlink() or path.stat().st_nlink > 1:
                path.unlink()
                path.write_bytes(raw)

    def seed_completed_at(self, evidence):
        evidence.mkdir(parents=True, exist_ok=True)
        raw = b'{"status":"completed","commands":[],"units":[]}\n'
        (evidence / "run-summary.json").write_bytes(raw)
        (evidence / "001-metadata.stdout.log").write_bytes(b"previous raw bytes\n")
        (evidence / "unrelated-sentinel").write_bytes(b"source sentinel\n")
        return raw

    def boundary_snapshot(self):
        snapshot = {}
        for folder, directories, files in os.walk(self.root, followlinks=False):
            root = Path(folder)
            for name in [*directories, *files]:
                path = root / name
                metadata = path.lstat()
                content = (
                    os.readlink(path).encode()  # noqa: PTH115 - preserve literal link bytes without Path normalization
                    if path.is_symlink()
                    else None
                    if path.is_dir()
                    else path.read_bytes()
                )
                snapshot[str(path.relative_to(self.root))] = (
                    metadata.st_mode,
                    metadata.st_uid,
                    content,
                )
        return snapshot

    def assert_source_boundary_rejected(self, route, variable):
        self.seed_completed_at(route)
        before = self.boundary_snapshot()
        result = self.run_wrapper("rustc-version-failure", **{variable: str(route)})
        after = self.boundary_snapshot()
        if variable == "SANITIZER_TARGET_DIR":
            before = {
                key: value
                for key, value in before.items()
                if key != "evidence" and not key.startswith("evidence/")
            }
            after = {
                key: value
                for key, value in after.items()
                if key != "evidence" and not key.startswith("evidence/")
            }
            if (self.bin / "python3").exists():
                self.assertEqual(self.summary()["status"], "failed")  # noqa: PT009 - safe evidence fails first
            else:
                markers = list((self.root / "evidence").glob("preflight-failed-*.json"))
                self.assertTrue(markers)  # noqa: PT009 - missing writer still leaves explicit failure
                self.assertTrue(  # noqa: PT009 - active under -O
                    all(json.loads(marker.read_text())["status"] == "failed" for marker in markers)
                )
        self.assertEqual(after, before)  # noqa: PT009 - source and unsafe evidence remain exact
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - remains active under Python -O
        diagnostic = (
            "attempt failed"
            if variable == "SANITIZER_TARGET_DIR" and not (self.bin / "python3").exists()
            else "overlaps protected source inputs"
        )
        self.assertIn(diagnostic, result.stderr)  # noqa: PT009 - safe marker first, source and tools untouched
        self.assertFalse((self.root / "calls.jsonl").exists())  # noqa: PT009 - no compiler/runtime fixture launched
        self.assertNotIn("Sanitizer-backed tests completed", result.stdout)  # noqa: PT009 - no success message


class SanitizerTests(SanitizerFixture, unittest.TestCase):
    def test_nonstandard_names_and_cache_bound_to_all_required_targets(self):
        for mode in ("success", "fresh-cache", "ignored-policy"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                self.assertTrue(result.returncode == 0, result.stderr)  # noqa: PT009 - active under Python -O
                summary = self.summary()
                self.assertTrue(summary["status"] == "completed")  # noqa: PT009 - active under Python -O
                targets = summary["units"][0]["targets"]
                self.assertTrue({target["name"] for target in targets} == set(TARGETS))  # noqa: PT009 - active under Python -O
                self.assertTrue(all(target["status"] == "completed" for target in targets))  # noqa: PT009 - active under Python -O
                self.assertTrue(sum(len(target["completed"]) for target in targets) == 8)  # noqa: PT009 - active under Python -O
                oidc = next(
                    target for target in targets if target["name"] == "oidc_hash_runtime_test"
                )
                self.assertTrue(oidc["completed"] == [])  # noqa: PT009 - active under Python -O
                self.assertTrue(oidc["applicability"] == "lowstar_hash feature disabled")  # noqa: PT009 - active under Python -O
                build = next(
                    command
                    for command in summary["commands"]
                    if command["phase"].startswith("build-")
                )
                self.assertTrue(build["args"][-3:-1] == ["--target", "x86_64-unknown-linux-gnu"])  # noqa: PT009 - active under Python -O
                self.assertTrue("--lib" in build["args"])  # noqa: PT009 - active under Python -O
                self.assertTrue("--tests" in build["args"])  # noqa: PT009 - active under Python -O
                self.assertTrue(  # noqa: PT009 - active under Python -O
                    'curve25519_dalek_backend="serial"' in summary["units"][0]["rustflags"]
                )

    def test_non_ffi_package_selection_rejects_before_cargo_inventory(self):
        self.add_package("additional")
        result = self.run_wrapper(SANITIZER_TARGETS="additional")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009 - active under Python -O
        self.assertIn("must include the required ffi package", result.stderr)  # noqa: PT009 - active under Python -O
        summary = self.summary()
        self.assertEqual(summary["status"], "failed")  # noqa: PT009 - active under Python -O
        self.assertEqual(summary["units"], [])  # noqa: PT009 - active under Python -O
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertFalse(  # noqa: PT009 - active under Python -O
            any(
                call["tool"] == "cargo" and ("metadata" in call["args"] or "test" in call["args"])
                for call in calls
            )
        )

    def test_ffi_and_additional_package_both_complete_required_inventory(self):
        self.add_package("additional")
        result = self.run_wrapper(SANITIZER_TARGETS="ffi,additional")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009 - active under Python -O
        summary = self.summary()
        self.assertEqual(summary["status"], "completed")  # noqa: PT009 - active under Python -O
        self.assertEqual([unit["package"] for unit in summary["units"]], ["ffi", "additional"])  # noqa: PT009 - active under Python -O
        ffi, additional = summary["units"]
        self.assertEqual({target["name"] for target in ffi["targets"]}, set(TARGETS))  # noqa: PT009 - active under Python -O
        self.assertTrue(all(target["status"] == "completed" for target in ffi["targets"]))  # noqa: PT009 - active under Python -O
        self.assertEqual(additional["targets"][0]["name"], "additional")  # noqa: PT009 - active under Python -O
        self.assertEqual(additional["targets"][0]["completed"], ["additional::required"])  # noqa: PT009 - active under Python -O
        self.assertEqual(additional["targets"][0]["status"], "completed")  # noqa: PT009 - active under Python -O

    def test_metadata_additions_are_required_and_flags_are_owned(self):
        metadata_path = self.root / "metadata.json"
        metadata = json.loads(metadata_path.read_text())
        source = self.root / "additional_test.rs"
        source.write_text("// additional test target\n")
        metadata["packages"][0]["targets"].append(
            {
                "name": "additional_test",
                "kind": ["test"],
                "test": True,
                "src_path": str(source),
            }
        )
        metadata_path.write_text(json.dumps(metadata))
        result = self.run_wrapper(CARGO_ENCODED_RUSTFLAGS="-Copt-level=3")
        self.assertTrue(result.returncode == 0, result.stderr)  # noqa: PT009 - active under Python -O
        targets = self.summary()["units"][0]["targets"]
        self.assertTrue(len(targets) == 10)  # noqa: PT009 - active under Python -O
        self.assertTrue(targets[-1]["completed"] == ["additional_test::required"])  # noqa: PT009 - active under Python -O
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        builds = [call for call in calls if call["tool"] == "cargo" and "test" in call["args"]]
        self.assertTrue(builds[0]["encoded_flags"] is None)  # noqa: PT009 - active under Python -O

    def test_artifact_inventory_and_record_failures(self):
        modes = (
            "artifact-zero",
            "artifact-missing",
            "artifact-wrong-package",
            "artifact-wrong-source",
            "artifact-outside-root",
            "artifact-missing-binary",
            "artifact-no-executable",
            "artifact-no-filename",
            "artifact-bad-features",
            "artifact-bad-profile",
            "artifact-bad-fresh",
            "artifact-malformed",
            "artifact-duplicate",
            "artifact-unknown-reason",
            "missing-build-finished",
            "false-build-finished",
            "metadata-missing",
            "metadata-duplicate",
            "metadata-wrong-root",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                self.assertTrue(result.returncode != 0, (mode, result.stdout))  # noqa: PT009 - active under Python -O
                self.assertTrue(self.summary()["status"] == "failed")  # noqa: PT009 - active under Python -O

    def test_stale_outputs_cannot_mask_compile_failure(self):
        self.assertTrue(self.run_wrapper().returncode == 0)  # noqa: PT009 - active under Python -O
        result = self.run_wrapper("build-failure")
        self.assertTrue(result.returncode == 7, result.stderr)  # noqa: PT009 - active under Python -O
        self.assertTrue(self.summary()["units"][0]["status"] == "not-run")  # noqa: PT009 - active under Python -O
        self.assertTrue(  # noqa: PT009 - active under Python -O
            "deliberate compiler error"
            in next((self.root / "evidence").glob("*-build-*.stderr.log")).read_text()
        )

    def test_list_named_execution_and_instrumentation_failures(self):
        for mode in (
            "uninstrumented",
            "list-failure",
            "list-malformed",
            "empty-tests",
            "run-malformed",
            "run-empty",
            "run-no-start",
            "run-missing-completion",
            "run-duplicate",
            "oidc-feature-enabled",
        ):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                self.assertTrue(result.returncode != 0, (mode, result.stdout))  # noqa: PT009 - active under Python -O
                self.assertTrue(self.summary()["status"] == "failed")  # noqa: PT009 - active under Python -O

    def test_final_cleanup_failure_preserves_observed_child_exit(self):
        # Execute the actual supervisor with a real child; fail final cleanup
        # after wait observes exit, preserving the original exit/signal status.
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        supervisor_type = namespace["Supervisor"]
        for child, expected in (
            ("import sys;sys.exit(9)", 9),
            ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)", 143),
            ("import sys;sys.exit(0)", 1),
        ):
            with self.subTest(child=child):
                artifacts = Path(self.enterContext(tempfile.TemporaryDirectory()))
                for error in (
                    OSError("controlled final cleanup failure"),
                    namespace["Failure"]("controlled final cleanup failure"),
                ):
                    with self.subTest(error=type(error).__name__):
                        terminate = Mock(side_effect=[False, error])
                        supervisor = supervisor_type(artifacts, {"commands": []}, 1)
                        with (
                            patch.dict(
                                supervisor_type.command.__globals__,
                                terminate=terminate,
                                group_alive=lambda _pid: False,
                            ),
                            patch.object(supervisor, "save"),
                            self.assertRaisesRegex(  # noqa: PT027 - unittest discovery without pytest
                                namespace["Failure"], "controlled final cleanup"
                            ) as caught,
                        ):
                            supervisor.command(
                                [sys.executable, "-c", child], os.environ.copy(), 5, "probe"
                            )
                        self.assertEqual(caught.exception.status, expected)  # noqa: PT009 - active under Python -O
                        self.assertEqual(terminate.call_count, 2)  # noqa: PT009 - active under Python -O
                        self.assertEqual(supervisor.summary["commands"][0]["status"], "failed")  # noqa: PT009 - active under Python -O
                        self.assertTrue((artifacts / "001-probe.stdout.log").is_file())  # noqa: PT009 - active under Python -O
                        self.assertTrue((artifacts / "001-probe.stderr.log").is_file())  # noqa: PT009 - active under Python -O

    def test_proc_inspection_failure_still_kills_group_and_reaps_leader(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        terminate, group_alive = namespace["terminate"], namespace["group_alive"]
        for phase in ("first", "grace", "final"):
            with self.subTest(phase=phase):
                (self.root / "child.pid").unlink(missing_ok=True)
                process = subprocess.Popen(  # noqa: S603 - controlled real process group
                    [str(self.bin / "cargo"), "test", "-p", "ffi"],
                    env={**self.environment, "SANITIZER_FIXTURE_MODE": "build-timeout"},
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                error = PermissionError(f"controlled {phase} proc inspection failure")
                inspections = 0

                def inspect(pgid, *, phase=phase, process=process, error=error):
                    nonlocal inspections
                    inspections += 1
                    if (
                        (phase == "first" and inspections == 1)
                        or (phase == "grace" and inspections == 2)
                        or (phase == "final" and process.returncode is not None)
                    ):
                        raise error
                    return group_alive(pgid)

                try:
                    self.wait_for_child_pid()
                    self.assertTrue(group_alive(process.pid))  # noqa: PT009 - active under Python -O
                    with (
                        patch.dict(terminate.__globals__, group_alive=inspect),
                        self.assertRaises(PermissionError) as caught,  # noqa: PT027 - unittest discovery
                    ):
                        terminate(process, 0.05)
                    self.assertIs(caught.exception, error)  # noqa: PT009 - retain original inspection error
                    self.assertIsNotNone(process.returncode)  # noqa: PT009 - leader was reaped by terminate
                    self.assertLess(process.returncode, 0)  # noqa: PT009 - active under Python -O
                    self.assert_child_stopped()
                    self.assertFalse(group_alive(process.pid))  # noqa: PT009 - actual process-group state
                finally:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)

    def test_command_proc_inspection_failure_preserves_observed_child_exit(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        supervisor_type = namespace["Supervisor"]
        for child, child_exit, expected in (
            ("import sys;sys.exit(9)", 9, 9),
            ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)", -signal.SIGTERM, 143),
            ("import sys;sys.exit(0)", 0, 1),
        ):
            with self.subTest(child=child):
                artifacts = Path(self.enterContext(tempfile.TemporaryDirectory()))
                supervisor = supervisor_type(artifacts, {"commands": []}, 0.05)
                with (
                    patch.dict(
                        supervisor_type.command.__globals__,
                        group_alive=Mock(side_effect=PermissionError("controlled proc denial")),
                    ),
                    self.assertRaisesRegex(  # noqa: PT027 - unittest discovery
                        namespace["Failure"], "controlled proc denial"
                    ) as caught,
                ):
                    supervisor.command([sys.executable, "-c", child], os.environ.copy(), 5, "probe")
                self.assertEqual(caught.exception.status, expected)  # noqa: PT009 - active under Python -O
                saved = json.loads((artifacts / "run-summary.json").read_text())
                self.assertEqual(saved["commands"][0]["exit_code"], child_exit)  # noqa: PT009 - original exit retained
                self.assertEqual(saved["commands"][0]["status"], "failed")  # noqa: PT009 - no false completed receipt

    def test_command_proc_inspection_failure_preserves_supervisor_signal(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        supervisor_type = namespace["Supervisor"]
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signum=signum):
                (self.root / "child.pid").unlink(missing_ok=True)
                artifacts = Path(self.enterContext(tempfile.TemporaryDirectory()))
                supervisor = supervisor_type(artifacts, {"commands": []}, 0.05)
                processes = []

                def interrupt_capture(
                    process, *_args, _signum=signum, _processes=processes, **_kwargs
                ):
                    _processes.append(process)
                    self.wait_for_child_pid()
                    raise namespace["Interrupted"](_signum)

                try:
                    with (
                        patch.object(supervisor, "capture", side_effect=interrupt_capture),
                        patch.dict(
                            supervisor_type.command.__globals__,
                            group_alive=Mock(side_effect=PermissionError("controlled proc denial")),
                        ),
                        self.assertRaises(namespace["Failure"]) as caught,  # noqa: PT027 - unittest discovery
                    ):
                        supervisor.command(
                            [str(self.bin / "cargo"), "test", "-p", "ffi"],
                            {**self.environment, "SANITIZER_FIXTURE_MODE": "build-timeout"},
                            5,
                            "probe",
                        )
                    self.assertEqual(caught.exception.status, 128 + signum)  # noqa: PT009 - retain supervisor interruption
                    saved = json.loads((artifacts / "run-summary.json").read_text())
                    self.assertEqual(saved["commands"][0]["exit_code"], -signal.SIGKILL)  # noqa: PT009 - cleanup killed and reaped leader
                    self.assertEqual(saved["commands"][0]["status"], "failed")  # noqa: PT009 - active under Python -O
                    self.assert_child_stopped()
                finally:
                    for process in processes:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)

    def test_evidence_write_interruptions_preserve_signal_and_prior_failure(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        supervisor_type = namespace["Supervisor"]
        for child_status in (0, 9, 143):
            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                with self.subTest(child_status=child_status, signum=signum):
                    supervisor = supervisor_type(self.root, {"commands": []})
                    record = {
                        "phase": "run",
                        "exit_code": child_status,
                        "timed_out": False,
                        "lingering_descendants": False,
                    }
                    with (
                        patch.object(
                            supervisor, "save", side_effect=namespace["Interrupted"](signum)
                        ),
                        self.assertRaises(namespace["Failure"]) as caught,  # noqa: PT027 - unittest discovery
                    ):
                        supervisor.finish_command(record, None, None)
                    self.assertEqual(caught.exception.status, child_status or 128 + signum)  # noqa: PT009

    def test_final_evidence_failure_preserves_signal_and_prior_failure(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        supervisor_type = namespace["Supervisor"]
        settings = [""] * len(namespace["Settings"].__dataclass_fields__)
        settings[3] = str(self.root)
        for prior_status in (0, 9, 143):
            for failure in (
                OSError("controlled evidence write failure"),
                *(
                    namespace["Interrupted"](sig)
                    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
                ),
            ):
                with self.subTest(prior_status=prior_status, failure=str(failure)):
                    with (
                        patch.object(
                            supervisor_type,
                            "execute",
                            side_effect=namespace["Failure"]("earlier child failure", prior_status)
                            if prior_status
                            else None,
                        ),
                        patch.object(supervisor_type, "save", side_effect=failure),
                        patch.object(signal, "signal"),
                        patch.object(sys, "argv", ["sanitizer_runner.py", *settings]),
                    ):
                        status = namespace["main"]()
                    self.assertEqual(status, prior_status or getattr(failure, "status", 1))  # noqa: PT009

    def test_original_exits_and_crash_signals_propagate(self):
        for mode, expected in (("build-signal", 143), ("run-failure", 9), ("run-signal", 134)):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                self.assertTrue(result.returncode == expected, result.stderr)  # noqa: PT009 - active under Python -O

    def test_build_run_watchdogs_and_closed_output_kill_descendants(self):
        for mode in ("build-timeout", "build-closed-timeout", "run-timeout", "run-closed-timeout"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(
                    mode, SANITIZER_BUILD_TIMEOUT="0.5", SANITIZER_RUN_TIMEOUT="0.5"
                )
                self.assertTrue(result.returncode == 124, result.stderr)  # noqa: PT009 - active under Python -O
                self.assertTrue(  # noqa: PT009 - active under Python -O
                    any(command["timed_out"] for command in self.summary()["commands"])
                )
                self.assert_child_stopped()

    def test_normal_leader_exit_with_running_descendants_fails(self):
        for mode in (
            "build-descendant",
            "run-descendant",
            "build-closed-descendant",
            "run-closed-descendant",
            "build-failure-descendant",
        ):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                self.assertTrue(  # noqa: PT009 - active under Python -O
                    result.returncode == (7 if mode == "build-failure-descendant" else 1),
                    result.stderr,
                )
                self.assertTrue(  # noqa: PT009 - active under Python -O
                    any(command["lingering_descendants"] for command in self.summary()["commands"])
                )
                self.assert_child_stopped()

    def test_wrapper_interrupt_cleans_descendants(self):
        for mode in ("build-timeout", "run-timeout"):
            for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                with self.subTest(mode=mode, signal=signum):
                    (self.root / "child.pid").unlink(missing_ok=True)
                    process = subprocess.Popen(  # noqa: S603
                        [shutil.which("bash"), str(WRAPPER)],
                        cwd=self.root,
                        env={**self.environment, "SANITIZER_FIXTURE_MODE": mode},
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    try:
                        deadline = time.monotonic() + 5
                        while (
                            not (self.root / "child.pid").exists() and time.monotonic() < deadline
                        ):
                            time.sleep(0.01)
                        self.assertTrue((self.root / "child.pid").exists())  # noqa: PT009 - active under Python -O
                        process.send_signal(signum)
                        _, stderr = process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 128 + signum, stderr)  # noqa: PT009 - active under Python -O
                        self.assertIn(f"interrupted by signal {signum}", self.summary()["error"])  # noqa: PT009 - active under Python -O
                        self.assertEqual(self.summary()["status"], "failed")  # noqa: PT009 - active under Python -O
                        self.assert_child_stopped()
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate()

    def test_invalid_selections_deadlines_and_cargo_overrides_fail(self):
        for key, value in (
            ("SANITIZERS", "address,address"),
            ("SANITIZERS", "thread"),
            ("SANITIZERS", " "),
            ("SANITIZER_TARGETS", "unknown"),
            ("SANITIZER_TARGETS", "ffi,ffi"),
            ("SANITIZER_BUILD_TIMEOUT", "0"),
            ("SANITIZER_RUN_TIMEOUT", "NaN"),
            ("SANITIZER_TIMEOUT_KILL", "-1"),
            ("SANITIZER_CARGO_FLAGS", "--target=other"),
            ("SANITIZER_CARGO_FLAGS", "-pffi"),
            ("SANITIZER_CARGO_FLAGS", "--release"),
        ):
            with self.subTest(key=key, value=value):
                self.assertTrue(self.run_wrapper(**{key: value}).returncode != 0)  # noqa: PT009 - active under Python -O

    def test_invalid_link_order_rejects_before_cargo_with_failed_receipt(self):
        for value in ("2", "true", "0 1", "0,1", "0:detect_stack_use_after_return=0"):
            with self.subTest(value=value):
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                result = self.run_wrapper(ASAN_VERIFY_LINK_ORDER=value)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009 - active under Python -O
                self.assertIn("ASan link-order setting must be 0 or 1", result.stderr)  # noqa: PT009 - actual admission failure
                summary = self.summary()
                self.assertEqual(summary["status"], "failed")  # noqa: PT009 - current receipt
                self.assertEqual(summary["commands"], [])  # noqa: PT009 - no metadata or build child
                self.assertEqual(summary["units"], [])  # noqa: PT009 - active under Python -O
                self.assertNotIn("Sanitizer-backed tests completed", result.stdout)  # noqa: PT009 - active under Python -O
                calls = [
                    json.loads(line)
                    for line in (self.root / "calls.jsonl").read_text().splitlines()
                ]
                self.assertFalse(  # noqa: PT009 - version probes may run, inventory/build may not
                    any(
                        call["tool"] == "cargo"
                        and ("metadata" in call["args"] or "test" in call["args"])
                        for call in calls
                    )
                )

    def test_direct_runner_invalid_link_order_never_launches_cargo(self):
        for value in ("", "2", "true", "0 1", "0,1", "0:detect_stack_use_after_return=0"):
            with self.subTest(value=value):
                evidence = self.root / "evidence"
                evidence.mkdir(exist_ok=True)
                (self.root / "calls.jsonl").unlink(missing_ok=True)
                settings = [
                    "address",
                    "ffi",
                    str(self.root / "target"),
                    str(evidence),
                    "cargo",
                    "x86_64-unknown-linux-gnu",
                    "",
                    "",
                    "",
                    "",
                    "10",
                    "10",
                    "0.05",
                    str(self.root / "runtime"),
                    value,
                    "",
                ]
                result = subprocess.run(  # noqa: S603 - actual direct runner entry
                    [
                        sys.executable,
                        "-I",
                        str(ROOT / "scripts/sanitizers/sanitizer_runner.py"),
                        *settings,
                    ],
                    cwd=self.root,
                    env=self.environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009 - active under Python -O
                self.assertIn("ASan link-order setting must be 0 or 1", result.stderr)  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "calls.jsonl").exists())  # noqa: PT009 - no Cargo child
                self.assertEqual(self.summary()["status"], "failed")  # noqa: PT009 - failed current receipt
                self.assertEqual(self.summary()["commands"], [])  # noqa: PT009 - active under Python -O
                self.assertEqual(self.summary()["units"], [])  # noqa: PT009 - active under Python -O

    def test_link_order_one_and_empty_default_keep_fixed_asan_policy(self):
        for value, expected in (("1", "1"), ("", "0")):
            with self.subTest(value=value):
                calls_path = self.root / "calls.jsonl"
                calls_path.unlink(missing_ok=True)
                result = self.run_wrapper(ASAN_VERIFY_LINK_ORDER=value)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009 - supported settings
                self.assertEqual(self.summary()["status"], "completed")  # noqa: PT009 - active under Python -O
                calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
                runtime_calls = [
                    call for call in calls if call["tool"].startswith("nonstandard-name-")
                ]
                self.assertTrue(runtime_calls)  # noqa: PT009 - actual runtime children observed
                self.assertTrue(  # noqa: PT009 - fixed options retained, only boolean propagated
                    all(
                        call["asan_options"]
                        == (
                            "abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:"
                            f"verify_asan_link_order={expected}:verbosity=0"
                        )
                        for call in runtime_calls
                    )
                )

    def test_missing_required_tools_runtime_and_host_fail(self):
        for tool in ("rustc", "cargo", "clang", "python3", "nm", "readelf"):
            link = self.bin / tool
            original = link.readlink()
            link.unlink()
            try:
                with self.subTest(tool=tool):
                    self.assertTrue(self.run_wrapper().returncode != 0)  # noqa: PT009 - active under Python -O
            finally:
                link.symlink_to(original)
        self.assertTrue(  # noqa: PT009 - active under Python -O
            self.run_wrapper(SANITIZER_RUNTIME_DIR=str(self.root / "missing")).returncode != 0
        )
        self.assertTrue(self.run_wrapper("bad-host").returncode != 0)  # noqa: PT009 - active under Python -O
        (self.root / "runtime/libclang_rt.asan-x86_64.so").unlink()
        self.assertTrue(self.run_wrapper().returncode != 0)  # noqa: PT009 - active under Python -O

    def test_output_failure_cannot_report_success(self):
        (self.root / "blocked").write_text("not a directory")
        result = self.run_wrapper(SANITIZER_ARTIFACT_DIR=str(self.root / "blocked/evidence"))
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
        evidence = self.root / "evidence"
        evidence.mkdir()
        (evidence / "002-build-address-ffi.stdout.log").mkdir()
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
        self.assertFalse((evidence / "run-summary.json").exists())  # noqa: PT009 - early unsafe destination
        (evidence / "002-build-address-ffi.stdout.log").rmdir()
        (evidence / "run-summary.json").mkdir()
        self.assertNotEqual(self.run_wrapper().returncode, 0)  # noqa: PT009 - active under Python -O

    def test_version_failure_invalidates_old_completed_receipt(self):
        evidence, raw = self.seed_completed_preflight()
        result = self.run_wrapper("rustc-version-failure")
        self.assertEqual(result.returncode, 23)  # noqa: PT009 - active under unittest and Python -O
        self.assert_failed_preflight_preserved(result, evidence, raw)
        self.assertEqual(self.summary()["preflight_phase"], "rustc-version")  # noqa: PT009 - active under unittest and Python -O

    def test_missing_preflight_tools_preserve_old_raw_evidence(self):
        for tool in ("rustc", "cargo", "clang", "nm", "readelf"):
            with self.subTest(tool=tool):
                evidence, raw = self.seed_completed_preflight()
                link = self.bin / tool
                original = link.readlink()
                link.unlink()
                try:
                    result = self.run_wrapper()
                    self.assert_failed_preflight_preserved(result, evidence, raw)
                finally:
                    link.symlink_to(original)

    def test_runtime_and_host_preflight_failures_replace_stale_success(self):
        for mode, overrides, phase in (
            ("success", {"SANITIZER_RUNTIME_DIR": str(self.root / "missing-runtime")}, "runtime"),
            ("bad-host", {}, "host"),
            ("success", {"SANITIZER_RUNTIME_DIR": str(self.root / "empty-runtime")}, "runtime"),
        ):
            with self.subTest(mode=mode, overrides=overrides):
                (self.root / "empty-runtime").mkdir(exist_ok=True)
                evidence, raw = self.seed_completed_preflight()
                result = self.run_wrapper(mode, **overrides)
                self.assert_failed_preflight_preserved(result, evidence, raw)
                self.assertEqual(self.summary()["preflight_phase"], phase)  # noqa: PT009 - active under Python -O

    def test_missing_python_archives_summary_without_truncation(self):
        evidence, raw = self.seed_completed_preflight()
        (self.bin / "python3").unlink()
        result = self.run_wrapper()
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under unittest and Python -O
        self.assertFalse((evidence / "run-summary.json").exists())  # noqa: PT009 - active under unittest and Python -O
        previous = list(evidence.glob(".previous-summary-*"))
        self.assertEqual(len(previous), 1)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(previous[0].read_bytes(), raw)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(  # noqa: PT009 - active under unittest and Python -O
            (evidence / "001-metadata.stdout.log").read_bytes(), b"retained raw output\n"
        )
        self.assertIn("attempt failed", result.stderr)  # noqa: PT009 - active under unittest and Python -O

    def test_missing_python_archive_tool_failure_has_explicit_failed_marker(self):
        (self.bin / "python3").unlink()
        for tool in ("mktemp", "mv"):
            with self.subTest(tool=tool):
                evidence, raw = self.seed_completed_preflight()
                link = self.bin / tool
                original = link.readlink()
                link.unlink()
                try:
                    result = self.run_wrapper()
                    self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
                    self.assertEqual((evidence / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - cannot rename without tool
                    markers = list(evidence.glob("preflight-failed-*.json"))
                    self.assertTrue(markers)  # noqa: PT009 - explicit failed attempt marker
                    self.assertTrue(  # noqa: PT009 - active under Python -O
                        all(json.loads(p.read_text())["status"] == "failed" for p in markers)
                    )
                    self.assertNotIn("Sanitizer-backed tests completed", result.stdout)  # noqa: PT009 - active under Python -O
                finally:
                    link.symlink_to(original)

    def test_preflight_aliases_and_overlaps_cannot_mutate_external_bytes(self):
        external = self.root.parent / (self.root.name + "-external")
        external.mkdir()
        self.addCleanup(shutil.rmtree, external)
        sentinel = external / "run-summary.json"
        sentinel.write_bytes(b"external completed sentinel\n")
        evidence, _raw = self.seed_completed_preflight()
        for kind in (
            "summary-symlink",
            "summary-hardlink",
            "directory-symlink",
            "normalized-symlink",
            "raw-log-symlink",
            "raw-log-hardlink",
            "overlap",
        ):
            with self.subTest(kind=kind):
                setting = self.prepare_preflight_alias(kind, evidence, external, sentinel)
                result = self.run_wrapper(SANITIZER_ARTIFACT_DIR=str(setting))
                self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under unittest and Python -O
                self.assertEqual(sentinel.read_bytes(), b"external completed sentinel\n")  # noqa: PT009 - active under unittest and Python -O
                self.assertEqual((evidence / "unrelated-sentinel").read_bytes(), b"untouched\n")  # noqa: PT009 - active under unittest and Python -O
                self.restore_preflight_alias(evidence)

    def test_unwritable_output_fails_before_tools_and_keeps_prior_bytes(self):
        evidence, raw = self.seed_completed_preflight()
        evidence.chmod(0o500)
        try:
            result = self.run_wrapper()
            self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under unittest and Python -O
            self.assertEqual((evidence / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - active under unittest and Python -O
            self.assertFalse((self.root / "calls.jsonl").exists())  # noqa: PT009 - active under unittest and Python -O
            self.assertNotIn("Sanitizer-backed tests completed", result.stdout)  # noqa: PT009 - active under unittest and Python -O
        finally:
            evidence.chmod(0o700)

    def test_raw_history_copy_failure_keeps_current_receipt_failed(self):
        evidence, raw = self.seed_completed_preflight()
        body = PATH_HELPER.read_text().split("<<'PREFLIGHT'\n", 1)[1].split("\nPREFLIGHT", 1)[0]
        with (
            patch.object(sys, "argv", ["preflight", str(evidence), "initialize", "1"]),
            patch("shutil.copy2", side_effect=OSError("controlled history copy failure")),
            self.assertRaisesRegex(OSError, "controlled history copy"),  # noqa: PT027 - unittest direct control
        ):
            exec(compile(body, str(WRAPPER), "exec"), {})  # noqa: S102 - trusted exact embedded preflight
        self.assertEqual(self.summary()["status"], "failed")  # noqa: PT009 - active under Python -O
        previous = evidence / self.summary()["previous_attempt"]
        self.assertEqual((previous / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - preserve original summary bytes
        self.assertEqual(  # noqa: PT009 - preserve original raw bytes
            (evidence / "001-metadata.stdout.log").read_bytes(), b"retained raw output\n"
        )

    def test_source_child_completed_evidence_is_unchanged_before_tools(self):
        for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR"):
            with self.subTest(variable=variable):
                self.assert_source_boundary_rejected(self.root / "crates/server", variable)

    def test_independent_source_inventory_rejects_equal_and_descendant_outputs(self):
        cases = [
            (relative, suffix, variable)
            for relative in PROTECTED_SOURCE_INPUTS
            for suffix in ("", "nested output\n")
            for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR")
        ]
        inputs = b"".join(
            b"\0".join(
                (
                    str(index).encode(),
                    variable.encode(),
                    str(self.root / relative / suffix).encode(),
                )
            )
            + b"\0"
            for index, (relative, suffix, variable) in enumerate(cases)
        )
        before = self.boundary_snapshot()
        result = subprocess.run(  # noqa: S603 - exact shared guards with complete independent cases
            [
                shutil.which("bash"),
                "-c",
                r"""
set -euo pipefail
source "$1"
workspace=$2
fail() { diagnostic=$*; }
while IFS= read -r -d '' case_id; do
    IFS= read -r -d '' variable && IFS= read -r -d '' route || exit 2
    case "$variable" in
        SANITIZER_ARTIFACT_DIR|SANITIZER_TARGET_DIR) ;;
        *) exit 2 ;;
    esac
    diagnostic=""
    if preflight_route "$route" && sanitizer_validate_output "$PREFLIGHT_ROUTE" "$workspace"; then
        status=0
    else
        status=$?
    fi
    printf '%s\0%s\0%s\0' "$case_id" "$status" "$diagnostic"
done
""",
                "source-boundary-fixture",
                str(PATH_HELPER),
                str(self.root),
            ],
            cwd=self.root,
            env={"PATH": os.environ["PATH"]},
            input=inputs,
            capture_output=True,
            check=False,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009 - active under Python -O
        self.assertEqual(result.stderr, b"")  # noqa: PT009 - strict batch protocol
        self.assertEqual(self.boundary_snapshot(), before)  # noqa: PT009 - all source bytes unchanged
        fields = result.stdout.split(b"\0")
        self.assertEqual(fields.pop(), b"")  # noqa: PT009 - reject missing final frame
        self.assertEqual(len(fields), 3 * len(cases))  # noqa: PT009 - exact complete inventory
        for index, (relative, suffix, variable) in enumerate(cases):
            with self.subTest(relative=relative, suffix=suffix, variable=variable):
                case_id, status, diagnostic = fields[3 * index : 3 * index + 3]
                self.assertEqual(case_id, str(index).encode())  # noqa: PT009 - reject duplicate/reordered IDs
                self.assertEqual(status, b"1")  # noqa: PT009 - exact rejection status
                self.assertIn(b"overlaps protected source inputs", diagnostic)  # noqa: PT009 - exact guard

    def test_tracked_artifact_ancestors_are_rejected_before_writes(self):
        for relative in (
            "artifacts",
            "artifacts/security",
            "artifacts/conformance",
            "artifacts/kani",
            "artifacts/release/kms-hsm-classifications/evidence",
            "artifacts/tamarin/manual",
        ):
            for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR"):
                with self.subTest(relative=relative, variable=variable):
                    self.assert_source_boundary_rejected(self.root / relative, variable)

    def test_source_boundary_guard_precedes_missing_python_marker(self):
        (self.bin / "python3").unlink()
        for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR"):
            with self.subTest(variable=variable):
                self.assert_source_boundary_rejected(
                    self.root / "generated/required-inputs", variable
                )

    def test_generated_sibling_default_external_and_normalized_outputs_remain_supported(self):
        external = Path(self.enterContext(tempfile.TemporaryDirectory()))
        sources = [
            self.root / relative
            for relative in (
                "Cargo.lock",
                "crates/server/lib.rs",
                "artifacts/README.md",
                "artifacts/security/.gitkeep",
                "artifacts/ct/required-input",
                "artifacts/karamel/required-input",
            )
        ]
        for source in sources:
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"unchanged independent source input\n")
        routes = (
            ("", "", self.root / "target/sanitizers/artifacts"),
            (
                "artifacts/security/latest",
                "target/sanitizers",
                self.root / "artifacts/security/latest",
            ),
            (
                "artifacts/conformance/new-generated-output",
                "target/generated-sibling",
                self.root / "artifacts/conformance/new-generated-output",
            ),
            (str(external / "evidence"), str(external / "target"), external / "evidence"),
            (
                "artifacts/security/latest outputs\n/unused/../evidence\n",
                "target/nested outputs\n/unused/../builds\n",
                self.root / "artifacts/security/latest outputs\n/evidence\n",
            ),
        )
        for artifact, target, evidence in routes:
            with self.subTest(artifact=artifact, target=target):
                raw = self.seed_completed_at(evidence)
                result = self.run_wrapper(
                    SANITIZER_ARTIFACT_DIR=artifact, SANITIZER_TARGET_DIR=target
                )
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009 - active under Python -O
                receipt = json.loads((evidence / "run-summary.json").read_text())
                self.assertEqual(receipt["status"], "completed")  # noqa: PT009 - full controlled tool route completed
                histories = list(evidence.glob(".previous-attempt-*"))
                self.assertEqual(len(histories), 1)  # noqa: PT009 - original hidden history naming retained
                self.assertEqual((histories[0] / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - preserves exact previous bytes
                self.assertEqual(  # noqa: PT009 - raw history remains exact
                    (histories[0] / "001-metadata.stdout.log").read_bytes(), b"previous raw bytes\n"
                )
                for source in sources:
                    self.assertEqual(source.read_bytes(), b"unchanged independent source input\n")  # noqa: PT009 - sibling sources remain unchanged

    def test_normalized_and_newline_routes_keep_success_and_history(self):
        evidence, raw = self.seed_completed_preflight()
        target = self.root / "nested outputs\n" / "unused" / ".." / "target"
        result = self.run_wrapper(SANITIZER_TARGET_DIR=str(target))
        self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(self.summary()["status"], "completed")  # noqa: PT009 - active under unittest and Python -O
        histories = list(evidence.glob(".previous-attempt-*"))
        self.assertEqual(len(histories), 1)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual((histories[0] / "run-summary.json").read_bytes(), raw)  # noqa: PT009 - active under unittest and Python -O
        self.assertEqual(  # noqa: PT009 - active under unittest and Python -O
            (histories[0] / "001-metadata.stdout.log").read_bytes(), b"retained raw output\n"
        )

    def test_safe_evidence_is_failed_before_target_symlink_or_file_preflight(self):
        external = Path(self.enterContext(tempfile.TemporaryDirectory()))
        sentinel = external / "run-summary.json"
        sentinel.write_bytes(b"external completed sentinel\n")
        (self.root / "target-alias").symlink_to(external, target_is_directory=True)
        (self.root / "target-file").write_bytes(b"target file sentinel\n")
        for target in ("target-alias", "target-file", "generated/unsafe-target", "evidence/target"):
            with self.subTest(target=target):
                evidence, raw = self.seed_completed_preflight()
                result = self.run_wrapper(SANITIZER_TARGET_DIR=target)
                self.assert_failed_preflight_preserved(result, evidence, raw)
                self.assertEqual(self.summary()["preflight_phase"], "target")  # noqa: PT009 - active under Python -O
                self.assertEqual(sentinel.read_bytes(), b"external completed sentinel\n")  # noqa: PT009 - external bytes preserved
                self.assertEqual(  # noqa: PT009 - file preserved
                    (self.root / "target-file").read_bytes(), b"target file sentinel\n"
                )
                self.assertFalse((self.root / "calls.jsonl").exists())  # noqa: PT009 - no compiler/runtime preflight


class SanitizerLoggingFixture(SanitizerFixture):
    """Shared shell/log setup without inheriting behavioral test methods."""

    def setUp(self):
        super().setUp()
        self.suite = self.root / "scripts/security/run_security_suite.sh"
        for relative in (
            "scripts/security/run_security_suite.sh",
            "scripts/sanitizers/sanitizer_paths.sh",
            "scripts/sanitizers/open_security_log.py",
            "scripts/sanitizers/sanitizer_options.py",
            "scripts/sanitizers/security_stage.sh",
        ):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
        self.shared = self.root / "shared"
        self.environment.update(
            SECURITY_ARTIFACT_DIR=str(self.shared),
            SECURITY_HISTORY_DIR=str(self.root / "history"),
            SANITIZER_TARGET_DIR=str(self.root / "suite-target"),
        )
        self.environment.pop("SANITIZER_SECURITY_LOG_FD", None)
        for tool in ("bash", "tee", "rm"):
            (self.bin / tool).symlink_to(shutil.which(tool))
        self.make_tool("git", f"print({str(self.root)!r})")
        self.make_tool(
            "nix",
            """
import os
from pathlib import Path
root = Path(os.environ["SANITIZER_FIXTURE"])
evidence = Path(os.environ["SANITIZER_ARTIFACT_DIR"])
(root / "producer-called").write_text("inert model only")
mode = os.environ.get("MODEL_CHILD", "success")
if mode == "replace-log":
    log = root / "shared/summary/security.log"
    log.rename(log.with_name("retained-security.log"))
    log.symlink_to(root / "external-log")
if mode == "cleanup-swap":
    target = Path(os.environ["SANITIZER_TARGET_DIR"])
    target.rename(target.with_name("held-target"))
    target.mkdir()
(evidence / "run-summary.json").write_text('{"status":"completed","commands":[],"units":[]}')
print("inert modeled sanitizer output")
raise SystemExit(23 if mode == "child-failure" else 0)
""",
        )
        self.real_tee = shutil.which("tee")
        (self.bin / "tee").unlink()
        self.make_tool(
            "tee",
            f"""
import os
import subprocess
import sys
raw = sys.stdin.buffer.read()
phase = os.environ.get("MODEL_LOG_FAILURE", "")
markers = {{"shared-initial-log": b"starting security suite", "initial-log": b">>> sanitizer smoke",
           "final-log": b"<<< sanitizer smoke: ok", "shared-final-log": b"suite finished",
           "child-failure": b"sanitizer smoke: failed",
           "cleanup-failure": b"sanitizer cleanup: failed"}}
if phase and markers[phase] in raw:
    raise SystemExit(47)
fds = tuple(int(arg[14:]) for arg in sys.argv[1:] if arg.startswith("/proc/self/fd/"))
raise SystemExit(subprocess.run([{self.real_tee!r}, *sys.argv[1:]],
                              input=raw, pass_fds=fds).returncode)
""",
        )

    def make_tool(self, name, source):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n{source}\n")
        path.chmod(0o755)

    def run_suite(self, pass_fds=(), **overrides):
        return subprocess.run(  # noqa: S603 - controlled real shell and inert tools
            [shutil.which("bash"), str(self.suite), "--stage", "sanitizers"],
            cwd=self.root,
            env={**self.environment, **overrides},
            capture_output=True,
            text=True,
            pass_fds=pass_fds,
            timeout=20,
            check=False,
        )

    def shared_receipt(self):
        return json.loads((self.shared / "sanitizers/run-summary.json").read_text())


class SanitizerLoggingTests(SanitizerLoggingFixture, unittest.TestCase):
    """Actual shell/log boundaries with inert modeled Nix producer only."""

    def test_bound_recovery_protects_history_and_accepts_a_prefix_sibling(self):
        for relation in ("equal", "ancestor", "descendant", "relative", "sibling"):
            with self.subTest(relation=relation):
                evidence = self.shared / "sanitizers"
                evidence.mkdir(parents=True, exist_ok=True)
                summary = evidence / "run-summary.json"
                summary.write_bytes(
                    b'{"status":"failed","stage":"preflight","commands":[],"units":[]}\n'
                )
                target = self.root / f"cleanup-{relation}"
                history = {
                    "equal": target,
                    "ancestor": target / "history",
                    "descendant": target.parent,
                    "relative": target,
                    "sibling": target.with_name(target.name + "-history"),
                }[relation]
                target.mkdir()
                history.mkdir(exist_ok=True)
                retained = history / f"retained-{relation}.json"
                retained.write_bytes(b"retained history\n")
                binding = subprocess.run(  # noqa: S603 - real helper, isolated owned fixture
                    [
                        shutil.which("bash"),
                        "-p",
                        "-c",
                        (
                            'source "$1"; binding=$(sanitizer_target_binding prepare "$2"); '
                            'printf "%s\\n" "$binding"; sanitizer_target_binding prepare "$3"; '
                            'sanitizer_target_binding summary-snapshot "$binding"'
                        ),
                        "recovery-history",
                        str(self.root / "scripts/sanitizers/sanitizer_paths.sh"),
                        str(evidence),
                        str(target),
                    ],
                    cwd=self.root,
                    env=self.environment,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(binding.returncode, 0, binding.stderr)  # noqa: PT009
                evidence_binding, cleanup_binding, initial = map(
                    json.loads, binding.stdout.splitlines()
                )
                evidence_binding["initial_summary"] = initial
                before = summary.read_bytes()
                result = subprocess.run(  # noqa: S603 - actual fixed bound recovery entry
                    [
                        sys.executable,
                        "-I",
                        str(self.root / "scripts/sanitizers/open_security_log.py"),
                        "recover-bound",
                        str(evidence),
                        json.dumps(evidence_binding),
                        str(target),
                        json.dumps(cleanup_binding),
                        "67",
                    ],
                    cwd=self.root,
                    env={
                        **self.environment,
                        "SECURITY_HISTORY_DIR": os.path.relpath(history, self.root)
                        if relation == "relative"
                        else str(history),
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0 if relation == "sibling" else 1)  # noqa: PT009
                self.assertEqual(retained.read_bytes(), b"retained history\n")  # noqa: PT009
                if relation == "sibling":
                    self.assertFalse(target.exists())  # noqa: PT009
                    self.assertEqual(json.loads(summary.read_bytes())["exit_code"], 67)  # noqa: PT009
                else:
                    self.assertTrue(target.is_dir())  # noqa: PT009
                    self.assertEqual(summary.read_bytes(), before)  # noqa: PT009

    def test_default_and_normalized_artifact_routes_keep_absolute_log(self):
        for configured, relative in (
            ("", "artifacts/security/latest"),
            ("artifacts/security/latest/unused/../.", "artifacts/security/latest"),
            ("relative logs\n/unused/../security\n", "relative logs\n/security\n"),
        ):
            with self.subTest(configured=configured):
                result = self.run_suite(SECURITY_ARTIFACT_DIR=configured)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009 - active under Python -O
                artifact = self.root / relative
                log = artifact / "summary/security.log"
                self.assertIn(f"suite finished. log: {log}", log.read_text())  # noqa: PT009
                receipt = json.loads((artifact / "sanitizers/run-summary.json").read_text())
                self.assertEqual(receipt["status"], "completed")  # noqa: PT009

    def test_inherited_descriptor_flags_reject_before_truncation(self):
        summary = self.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        original = b"unchanged inherited log bytes\n"
        for flags in (os.O_RDONLY, os.O_RDONLY | os.O_APPEND, os.O_WRONLY, os.O_RDWR):
            with self.subTest(flags=flags):
                log.write_bytes(original)
                fd = os.open(log, flags)
                try:
                    result = self.run_suite(pass_fds=(fd,), SANITIZER_SECURITY_LOG_FD=str(fd))
                finally:
                    os.close(fd)
                self.assertNotEqual(result.returncode, 0)  # noqa: PT009
                self.assertEqual(log.read_bytes(), original)  # noqa: PT009
                self.assertFalse((self.root / "producer-called").exists())  # noqa: PT009
                self.assertEqual(self.shared_receipt()["status"], "failed")  # noqa: PT009

    def test_inherited_append_descriptor_keeps_all_resumed_logging(self):
        summary = self.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        for access in (os.O_WRONLY, os.O_RDWR):
            with self.subTest(access=access):
                log.write_text("stale inherited bytes\n")
                fd = os.open(log, access | os.O_APPEND)
                try:
                    result = self.run_suite(pass_fds=(fd,), SANITIZER_SECURITY_LOG_FD=str(fd))
                finally:
                    os.close(fd)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
                retained = log.read_text()
                self.assertNotIn("stale inherited bytes", retained)  # noqa: PT009
                self.assertIn("starting security suite", retained)  # noqa: PT009
                self.assertIn("inert modeled sanitizer output", retained)  # noqa: PT009
                self.assertIn("sanitizer smoke: ok", retained)  # noqa: PT009
                self.assertIn(f"suite finished. log: {log}", retained)  # noqa: PT009
                self.assertEqual(self.shared_receipt()["status"], "completed")  # noqa: PT009

    def test_safe_opener_truncates_once_after_inherited_admission(self):  # noqa: PLR0912, PLR0915 - real bound/compatibility/replacement handoffs
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/open_security_log.py"))
        log = self.root / "owned-log"
        original = b"old bytes survive opener before resumed validation\n"
        log.write_bytes(original)
        with patch("os.ftruncate", wraps=os.ftruncate) as truncate:
            fd = namespace["checked_log"](str(log))
            try:
                self.assertEqual(log.read_bytes(), original)  # noqa: PT009
                self.assertEqual(truncate.call_count, 0)  # noqa: PT009
                resumed = namespace["checked_log"](str(log), fd)
                try:
                    truncate.assert_called_once_with(resumed, 0)
                    self.assertEqual(log.read_bytes(), b"")  # noqa: PT009
                    os.write(fd, b"first log\n")
                    os.lseek(resumed, 0, os.SEEK_SET)
                    os.write(resumed, b"second log\n")
                    self.assertEqual(log.read_bytes(), b"first log\nsecond log\n")  # noqa: PT009
                finally:
                    os.close(resumed)
            finally:
                os.close(fd)

        # Execute the real opener and resumed wrapper through a controlled Bash
        # handoff. Replacement happens after evidence admission, before re-exec.
        for operation in ("bound", "bound-replacement", "compatibility"):
            with self.subTest(operation=operation):
                fixture = SanitizerLoggingTests()
                self.addCleanup(fixture.doCleanups)
                fixture.setUp()
                fixture.environment.pop("SANITIZER_EVIDENCE_BINDING", None)
                fixture.environment["MODEL_REEXEC"] = operation
                real_bash = shutil.which("bash")
                (fixture.bin / "bash").unlink()
                fixture.make_tool(
                    "bash",
                    f"""
import json
import os
import stat
import sys
from pathlib import Path
root = Path(os.environ["SANITIZER_FIXTURE"])
evidence = root / "shared/sanitizers"
def snapshot(directory):
    return {{str(path.relative_to(directory)): {{
        "mode": stat.S_IMODE(path.stat().st_mode),
        "bytes": path.read_bytes().hex() if path.is_file() else None,
    }} for path in [directory, *sorted(directory.rglob("*"))]}}
if (sys.argv[1:2] == [str(root / "scripts/security/run_security_suite.sh")]
        and "SANITIZER_SECURITY_LOG_FD" in os.environ):
    record = {{"binding": os.environ.get("SANITIZER_EVIDENCE_BINDING"),
               "argv": sys.argv[1:]}}
    if os.environ["MODEL_REEXEC"] == "bound-replacement":
        record["original"] = snapshot(evidence)
        evidence.rename(root / "held-evidence")
        evidence.mkdir()
        (evidence / "run-summary.json").write_bytes(b'{{"status":"completed"}}\\n')
        (evidence / "retained.stdout.log").write_bytes(b"replacement raw bytes\\n")
        (evidence / "sentinel").write_bytes(b"replacement sentinel\\n")
        record["replacement"] = snapshot(evidence)
    (root / "reexec-record.json").write_text(json.dumps(record))
os.execv({real_bash!r}, [{real_bash!r}, *sys.argv[1:]])
""",
                )
                summary = fixture.shared / "summary"
                summary.mkdir(parents=True)
                log = summary / "security.log"
                retained = b"retained shared log before re-exec\n"
                log.write_bytes(retained)
                if operation == "compatibility":
                    result = subprocess.run(  # noqa: S603 - real fixed helper with controlled paths/tools
                        [
                            sys.executable,
                            "-I",
                            str(fixture.root / "scripts/sanitizers/open_security_log.py"),
                            "open-exec",
                            str(log),
                            "--stage",
                            "sanitizers",
                        ],
                        cwd=fixture.root,
                        env=fixture.environment,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        check=False,
                    )
                else:
                    result = fixture.run_suite()
                record = json.loads((fixture.root / "reexec-record.json").read_text())
                self.assertEqual(record["argv"], [str(fixture.suite), "--stage", "sanitizers"])  # noqa: PT009
                if operation == "bound-replacement":
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009
                    self.assertFalse((fixture.root / "producer-called").exists())  # noqa: PT009
                    self.assertEqual(log.read_bytes(), retained)  # noqa: PT009
                    for name, directory in (
                        ("original", fixture.root / "held-evidence"),
                        ("replacement", fixture.shared / "sanitizers"),
                    ):
                        snapshot = {
                            str(path.relative_to(directory)): {
                                "mode": stat.S_IMODE(path.stat().st_mode),
                                "bytes": path.read_bytes().hex() if path.is_file() else None,
                            }
                            for path in [directory, *sorted(directory.rglob("*"))]
                        }
                        self.assertEqual(snapshot, record[name])  # noqa: PT009 - no initialization/archive/output writes
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)  # noqa: PT009
                    self.assertEqual(fixture.shared_receipt()["status"], "completed")  # noqa: PT009
                    self.assertTrue((fixture.root / "producer-called").exists())  # noqa: PT009
                    self.assertIn("suite finished", log.read_text())  # noqa: PT009
                    self.assertNotIn(retained.decode(), log.read_text())  # noqa: PT009
                if operation == "compatibility":
                    self.assertIsNone(record["binding"])  # noqa: PT009 - legacy environment remains unchanged
                else:
                    self.assertIsNotNone(record["binding"])  # noqa: PT009 - shell-local binding survives actual exec
                    self.assertEqual(  # noqa: PT009 - active under Python -O
                        json.loads(record["binding"])["target"],
                        str(fixture.shared / "sanitizers"),
                    )

    def test_inherited_descriptor_identity_aliases_reject_before_truncation(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/open_security_log.py"))
        log = self.root / "owned-log"
        external = self.root / "external-log"
        original = b"external original bytes\n"
        external.write_bytes(original)
        fd = os.open(external, os.O_WRONLY | os.O_APPEND)
        try:
            for kind in ("different-inode", "symlink", "hardlink"):
                with self.subTest(kind=kind):
                    if kind == "different-inode":
                        log.write_bytes(b"independent log bytes\n")
                    elif kind == "symlink":
                        log.symlink_to(external)
                    else:
                        log.hardlink_to(external)
                    self.assertRaises((OSError, ValueError), namespace["checked_log"], str(log), fd)  # noqa: PT027 - active under Python -O
                    self.assertEqual(external.read_bytes(), original)  # noqa: PT009
                    log.unlink()
        finally:
            os.close(fd)

    def test_target_dir_override_rejects_before_target_or_cargo(self):
        for flags in ("--target-dir elsewhere", "--target-dir=elsewhere"):
            with self.subTest(flags=flags):
                result = self.run_wrapper(SANITIZER_CARGO_FLAGS=flags)
                self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "target").exists())  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "elsewhere").exists())  # noqa: PT009 - active under Python -O
                self.assertEqual(self.summary()["preflight_phase"], "cargo-flags")  # noqa: PT009 - active under Python -O

                evidence = self.shared / "sanitizers"
                evidence.mkdir(parents=True, exist_ok=True)
                completed = b'{"status":"completed","commands":[],"units":[]}\n'
                raw = b"retained previous sanitizer output\n"
                (evidence / "run-summary.json").write_bytes(completed)
                (evidence / "001-metadata.stdout.log").write_bytes(raw)
                result = self.run_suite(SANITIZER_CARGO_FLAGS=flags)

                receipt = self.shared_receipt()
                self.assertEqual(receipt["status"], "failed")  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["preflight_phase"], "cargo-flags")  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["exit_code"], result.returncode)  # noqa: PT009 - active under Python -O
                history = evidence / receipt["previous_attempt"]
                self.assertEqual((history / "run-summary.json").read_bytes(), completed)  # noqa: PT009 - active under Python -O
                self.assertEqual((history / "001-metadata.stdout.log").read_bytes(), raw)  # noqa: PT009 - active under Python -O
                self.assertEqual((evidence / "001-metadata.stdout.log").read_bytes(), raw)  # noqa: PT009 - active under Python -O
                self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "suite-target").exists())  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "producer-called").exists())  # noqa: PT009 - active under Python -O

    def test_shared_log_aliases_reject_before_truncation(self):
        summary = self.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        external = self.root / "external-log"
        external.write_bytes(b"external original")
        for kind in ("symlink", "hardlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    log.symlink_to(external)
                elif kind == "hardlink":
                    log.hardlink_to(external)
                elif kind == "directory":
                    log.mkdir()
                else:
                    os.mkfifo(log)
                result = self.run_suite()
                self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
                self.assertEqual(external.read_bytes(), b"external original")  # noqa: PT009 - active under Python -O
                self.assertFalse((self.root / "producer-called").exists())  # noqa: PT009 - active under Python -O
                self.assertEqual(self.shared_receipt()["status"], "failed")  # noqa: PT009 - active under Python -O
                if kind == "directory":
                    log.rmdir()
                else:
                    log.unlink()

    def test_regular_log_and_leaf_swap_retain_validated_descriptor(self):
        summary = self.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        log.write_text("old bytes to truncate")
        external = self.root / "external-log"
        external.write_bytes(b"external original")
        result = self.run_suite(MODEL_CHILD="replace-log")
        self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009 - active under Python -O
        retained = (summary / "retained-security.log").read_text()
        self.assertNotIn("old bytes to truncate", retained)  # noqa: PT009 - active under Python -O
        self.assertIn("starting security suite", retained)  # noqa: PT009 - active under Python -O
        self.assertIn("sanitizer smoke: ok", retained)  # noqa: PT009 - active under Python -O
        self.assertIn(f"suite finished. log: {log}", retained)  # noqa: PT009 - active under Python -O
        self.assertEqual(external.read_bytes(), b"external original")  # noqa: PT009 - active under Python -O
        self.assertEqual(self.shared_receipt()["status"], "completed")  # noqa: PT009 - active under Python -O

    def test_initial_final_and_suite_logging_failures_invalidate_receipt(self):
        for phase in ("shared-initial-log", "initial-log", "final-log", "shared-final-log"):
            with self.subTest(phase=phase):
                result = self.run_suite(MODEL_LOG_FAILURE=phase)
                self.assertEqual(result.returncode, 47, result.stderr)  # noqa: PT009 - active under Python -O
                receipt = self.shared_receipt()
                self.assertEqual(receipt["status"], "failed")  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["preflight_phase"], phase)  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["exit_code"], 47)  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["logging_exit_code"], 47)  # noqa: PT009 - active under Python -O

    def test_logging_failure_preserves_child_and_cleanup_priority(self):
        for child, phase, expected in (
            ("child-failure", "child-failure", 23),
            ("cleanup-swap", "cleanup-failure", 1),
        ):
            with self.subTest(child=child):
                result = self.run_suite(MODEL_CHILD=child, MODEL_LOG_FAILURE=phase)
                self.assertEqual(result.returncode, expected, result.stderr)  # noqa: PT009 - active under Python -O
                receipt = self.shared_receipt()
                self.assertEqual(receipt["status"], "failed")  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["exit_code"], expected)  # noqa: PT009 - active under Python -O
                self.assertEqual(receipt["logging_exit_code"], 47)  # noqa: PT009 - active under Python -O
                target = self.root / "suite-target"
                if target.exists():
                    target.rmdir()

    def test_safe_opener_wrong_owner_rejects_before_truncation(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/open_security_log.py"))
        log = self.root / "owned-log"
        log.write_bytes(b"original bytes")
        real_fstat = os.fstat

        def wrong_owner(fd):
            info = real_fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                return info
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_nlink=info.st_nlink,
                st_uid=os.getuid() + 1,
                st_dev=info.st_dev,
                st_ino=info.st_ino,
            )

        with patch("os.fstat", side_effect=wrong_owner):
            self.assertRaises(ValueError, namespace["checked_log"], str(log))  # noqa: PT027 - active under Python -O
        self.assertEqual(log.read_bytes(), b"original bytes")  # noqa: PT009 - active under Python -O

    def test_forged_descriptor_marker_does_not_skip_log_admission(self):
        summary = self.shared / "summary"
        summary.mkdir(parents=True)
        log = summary / "security.log"
        log.write_bytes(b"unchanged original")
        result = self.run_suite(SANITIZER_SECURITY_LOG_FD="9999")
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
        self.assertEqual(log.read_bytes(), b"unchanged original")  # noqa: PT009 - active under Python -O
        self.assertFalse((self.root / "producer-called").exists())  # noqa: PT009 - active under Python -O
        self.assertEqual(self.shared_receipt()["status"], "failed")  # noqa: PT009 - active under Python -O


class SanitizerLauncherReceiptTests(SanitizerLoggingFixture, unittest.TestCase):
    """Actual wrapper launcher failures with isolated receipt fault controls."""

    def setUp(self):
        super().setUp()
        self.make_tool(
            "nix",
            """
import json
import os
from pathlib import Path
root = Path(os.environ["SANITIZER_FIXTURE"])
evidence = Path(os.environ["SANITIZER_ARTIFACT_DIR"])
summary = evidence / "run-summary.json"
initial = summary.read_bytes()
(root / "initial-summary").write_bytes(initial)
(root / "initial-identity").write_text(str(summary.stat().st_ino))
(root / "producer-called").write_text("inert launcher control only")
mode = os.environ.get("MODEL_RECEIPT_CHILD", "launcher-failure")
if mode.startswith("detailed-"):
    receipt = {"status": "failed" if mode == "detailed-failure" else "completed",
               "stage": "runtime", "commands": [{"exit_code": 29}],
               "units": [{"package": "ffi", "status": "observed"}],
               "retained_detail": "exact child bytes"}
    summary.write_bytes(json.dumps(receipt, indent=1).encode() + b"\\n\\n")
elif mode == "replacement-identical":
    summary.rename(root / "held-summary")
    summary.write_bytes(initial)
elif mode == "changed-initial":
    summary.write_bytes(initial + b" ")
elif mode == "malformed":
    summary.write_bytes(b"{malformed child receipt\\n")
elif mode in {"leaf-symlink", "leaf-hardlink", "leaf-directory"}:
    summary.rename(root / "held-summary")
    external = root / "external-summary"
    external.write_bytes(b"external receipt remains exact\\n")
    if mode == "leaf-symlink":
        summary.symlink_to(external)
    elif mode == "leaf-hardlink":
        summary.hardlink_to(external)
    else:
        summary.mkdir()
elif mode == "route-replacement":
    evidence.rename(root / "held-evidence")
    evidence.mkdir()
    summary.write_bytes(b'{"status":"completed","retained":"replacement"}\\n')
    (evidence / "sentinel").write_bytes(b"replacement namespace remains exact\\n")
elif mode == "launcher-cleanup-swap":
    target = Path(os.environ["SANITIZER_TARGET_DIR"])
    target.rename(root / "held-target")
    target.mkdir()
    (target / "sentinel").write_bytes(b"replacement target remains exact\\n")
if summary.is_file():
    (root / "child-summary").write_bytes(summary.read_bytes())
print("inert modeled launcher exits before acceptance")
raise SystemExit(23)
""",
        )
        (self.bin / "python3").unlink()
        self.make_tool(
            "python3",
            """
import os
import sys
from pathlib import Path
fault = os.environ.get("MODEL_RECEIPT_FAULT", "")
operation = sys.argv[3] if len(sys.argv) > 3 and sys.argv[1:3] == ["-I", "-"] else ""
root = Path(os.environ["SANITIZER_FIXTURE"])
if operation == "summary-snapshot" and fault == "malformed-snapshot":
    summary = root / "shared/sanitizers/run-summary.json"
    summary.write_bytes(b"{malformed snapshot receipt\\n")
    (root / "fault-summary").write_bytes(summary.read_bytes())
if operation == "launcher-failure" and fault:
    code = sys.stdin.read()
    if fault == "recording-failure":
        prefix = ('import os\\n'
                  'def reject_replace(*args, **kwargs):\\n'
                  '    raise OSError("controlled receipt replace failure")\\n'
                  'os.replace = reject_replace\\n')
    elif fault == "wrong-owner":
        prefix = f"import os\\nos.getuid = lambda: {os.getuid() + 1}\\n"
    else:
        prefix = ""
    os.execv(sys.executable, [sys.executable, "-I", "-c", prefix + code, *sys.argv[3:]])
os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
""",
        )

    def launcher_case(self, mode="launcher-failure", **overrides):
        fixture = SanitizerLauncherReceiptTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        return fixture, fixture.run_suite(MODEL_RECEIPT_CHILD=mode, **overrides)

    def test_early_launcher_failure_records_exit_and_archives_stale_success(self):
        evidence = self.shared / "sanitizers"
        evidence.mkdir(parents=True)
        stale = b'{"status":"completed","commands":["stale"],"units":[]}\n'
        (evidence / "run-summary.json").write_bytes(stale)
        result = self.run_suite()
        self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
        receipt = self.shared_receipt()
        self.assertEqual(receipt["preflight_phase"], "launcher")  # noqa: PT009
        self.assertEqual(receipt["exit_code"], 23)  # noqa: PT009
        self.assertEqual(receipt["status"], "failed")  # noqa: PT009
        self.assertEqual(receipt["commands"], [])  # noqa: PT009
        self.assertEqual(receipt["units"], [])  # noqa: PT009
        self.assertFalse((self.root / "suite-target").exists())  # noqa: PT009
        preserved = [
            path.read_bytes() for path in evidence.glob(".previous-attempt-*/run-summary.json")
        ]
        self.assertIn(stale, preserved)  # noqa: PT009

    def test_child_failure_and_success_receipts_preserve_exact_bytes(self):
        for mode in ("detailed-failure", "detailed-success"):
            with self.subTest(mode=mode):
                fixture, result = self.launcher_case(mode)
                self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
                actual = fixture.shared / "sanitizers/run-summary.json"
                self.assertEqual(actual.read_bytes(), (fixture.root / "child-summary").read_bytes())  # noqa: PT009
                self.assertNotIn("preflight_phase", fixture.shared_receipt())  # noqa: PT009

    def test_changed_content_and_replaced_identity_preserve_exact_receipts(self):
        for mode in ("changed-initial", "replacement-identical"):
            with self.subTest(mode=mode):
                fixture, result = self.launcher_case(mode)
                self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
                summary = fixture.shared / "sanitizers/run-summary.json"
                self.assertEqual(  # noqa: PT009 - active under Python -O
                    summary.read_bytes(), (fixture.root / "child-summary").read_bytes()
                )
                if mode == "replacement-identical":
                    self.assertNotEqual(  # noqa: PT009 - active under Python -O
                        summary.stat().st_ino, int((fixture.root / "initial-identity").read_text())
                    )

    def test_unsafe_summary_aliases_and_malformed_child_are_unchanged(self):
        for mode in ("leaf-symlink", "leaf-hardlink", "leaf-directory", "malformed"):
            with self.subTest(mode=mode):
                fixture, result = self.launcher_case(mode)
                self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
                summary = fixture.shared / "sanitizers/run-summary.json"
                if mode == "leaf-directory":
                    self.assertTrue(summary.is_dir())  # noqa: PT009
                    self.assertEqual(list(summary.iterdir()), [])  # noqa: PT009
                else:
                    self.assertEqual(  # noqa: PT009 - active under Python -O
                        summary.read_bytes(), (fixture.root / "child-summary").read_bytes()
                    )
                if mode.startswith("leaf-"):
                    self.assertEqual(  # noqa: PT009 - active under Python -O
                        (fixture.root / "external-summary").read_bytes(),
                        b"external receipt remains exact\n",
                    )

    def test_replaced_route_retains_original_and_replacement_receipts(self):
        fixture, result = self.launcher_case("route-replacement")
        self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
        self.assertEqual(  # noqa: PT009 - active under Python -O
            (fixture.root / "held-evidence/run-summary.json").read_bytes(),
            (fixture.root / "initial-summary").read_bytes(),
        )
        summary = fixture.shared / "sanitizers/run-summary.json"
        self.assertEqual(summary.read_bytes(), (fixture.root / "child-summary").read_bytes())  # noqa: PT009
        self.assertEqual(  # noqa: PT009 - active under Python -O
            (summary.parent / "sentinel").read_bytes(), b"replacement namespace remains exact\n"
        )
        self.assertIn("remaining output stages held", result.stdout)  # noqa: PT009

    def test_recording_failure_and_wrong_owner_preserve_initial_and_primary_exit(self):
        for fault in ("recording-failure", "wrong-owner"):
            with self.subTest(fault=fault):
                fixture, result = self.launcher_case(MODEL_RECEIPT_FAULT=fault)
                self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
                evidence = fixture.shared / "sanitizers"
                self.assertEqual(  # noqa: PT009 - active under Python -O
                    (evidence / "run-summary.json").read_bytes(),
                    (fixture.root / "initial-summary").read_bytes(),
                )
                self.assertEqual(list(evidence.glob(".launcher-summary-*")), [])  # noqa: PT009

    def test_malformed_snapshot_rejects_before_launcher_without_replacement(self):
        result = self.run_suite(MODEL_RECEIPT_FAULT="malformed-snapshot")
        self.assertNotEqual(result.returncode, 0, result.stderr)  # noqa: PT009
        self.assertFalse((self.root / "producer-called").exists())  # noqa: PT009
        self.assertEqual(  # noqa: PT009 - active under Python -O
            (self.shared / "sanitizers/run-summary.json").read_bytes(),
            (self.root / "fault-summary").read_bytes(),
        )
        self.assertFalse((self.root / "suite-target").exists())  # noqa: PT009

    def test_launcher_with_cleanup_and_logging_failures_keeps_primary_status(self):
        for mode, phase in (
            ("launcher-failure", "child-failure"),
            ("launcher-cleanup-swap", "cleanup-failure"),
        ):
            with self.subTest(mode=mode):
                fixture, result = self.launcher_case(mode, MODEL_LOG_FAILURE=phase)
                self.assertEqual(result.returncode, 23, result.stderr)  # noqa: PT009
                receipt = fixture.shared_receipt()
                self.assertEqual(receipt["status"], "failed")  # noqa: PT009
                self.assertEqual(receipt["exit_code"], 23)  # noqa: PT009
                self.assertEqual(receipt["logging_exit_code"], 47)  # noqa: PT009
                if mode == "launcher-cleanup-swap":
                    self.assertEqual(receipt["cleanup_exit_code"], 1)  # noqa: PT009
                    self.assertEqual(  # noqa: PT009 - active under Python -O
                        (fixture.root / "suite-target/sentinel").read_bytes(),
                        b"replacement target remains exact\n",
                    )


class SanitizerCargoChannelTests(SanitizerLoggingFixture, unittest.TestCase):
    """Owned argument channels fail before tools and preserve evidence history."""

    def test_runner_rejects_compiler_overrides_without_shell_preflight(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_runner.py"))
        settings = SimpleNamespace(
            sanitizer_text="address",
            package_text="ffi",
            build_limit_text="10",
            run_limit_text="10",
            grace_text="1",
            extra_text="",
            build_extra_text="",
        )
        for variable in (
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_UNMODELED",
        ):
            for value in ("", "/unrecorded/compiler-override-secret"):
                with self.subTest(variable=variable, empty=not value):
                    summary = {"commands": []}
                    supervisor = namespace["Supervisor"](self.root / "no-output", summary)
                    with (
                        patch.dict(os.environ, {variable: value}, clear=True),
                        self.assertRaisesRegex(ValueError, "Inherited Rust compiler overrides"),  # noqa: PT027 - unittest control remains active under -O
                    ):
                        supervisor.execute(settings, self.root)
                    self.assertEqual(summary["commands"], [])  # noqa: PT009 - active under -O
                    self.assertFalse(supervisor.artifacts.exists())  # noqa: PT009

    def assert_channel_rejected(self, variable, value, route, case):
        evidence = self.root / "evidence" if route == "standalone" else self.shared / "sanitizers"
        evidence.mkdir(parents=True, exist_ok=True)
        completed = b'{"status":"completed","commands":[],"units":[]}\n'
        raw = b"prior controlled sanitizer bytes\n"
        (evidence / "run-summary.json").write_bytes(completed)
        (evidence / "001-metadata.stdout.log").write_bytes(raw)
        protected = self.root / "crates/protected-input"
        protected.parent.mkdir(exist_ok=True)
        protected.write_bytes(b"protected source sentinel\n")
        result = (self.run_wrapper if route == "standalone" else self.run_suite)(
            **{variable: value}
        )
        (self.root / f"rejected-{case}-{route}.json").write_text(
            json.dumps(
                {
                    "variable": variable,
                    "value": value,
                    "exit": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
                sort_keys=True,
            )
        )
        receipt = json.loads((evidence / "run-summary.json").read_text())
        self.assertNotEqual(result.returncode, 0)  # noqa: PT009 - active under Python -O
        self.assertEqual(receipt["status"], "failed")  # noqa: PT009
        self.assertEqual(receipt["preflight_phase"], "cargo-flags")  # noqa: PT009
        self.assertEqual(receipt["exit_code"], result.returncode)  # noqa: PT009
        history = evidence / receipt["previous_attempt"]
        self.assertEqual((history / "run-summary.json").read_bytes(), completed)  # noqa: PT009
        self.assertEqual((history / "001-metadata.stdout.log").read_bytes(), raw)  # noqa: PT009
        self.assertEqual((evidence / "001-metadata.stdout.log").read_bytes(), raw)  # noqa: PT009
        self.assertEqual(protected.read_bytes(), b"protected source sentinel\n")  # noqa: PT009
        for relative in (
            "target",
            "suite-target",
            "producer-called",
            "calls.jsonl",
            "crates/protected-output",
        ):
            self.assertFalse((self.root / relative).exists(), relative)  # noqa: PT009

    def test_config_split_and_equal_reject_both_channels_before_effects(self):
        for variable in ("SANITIZER_CARGO_FLAGS", "SANITIZER_BUILD_EXTRA_ARGS"):
            for value in (
                "--config build.target-dir=crates/protected-output",
                "--config=build.target-dir=crates/protected-output",
                "--config build.rustflags=[]",
                "--config=build.rustflags=[]",
            ):
                for route in ("standalone", "suite"):
                    case = f"{variable}-{value.replace(' ', '_').replace('/', '_')}"
                    with self.subTest(variable=variable, value=value, route=route):
                        self.assert_channel_rejected(variable, value, route, case)

    def test_release_alias_rejects_both_routes_before_effects(self):
        for route in ("standalone", "suite"):
            with self.subTest(route=route):
                self.assert_channel_rejected("SANITIZER_CARGO_FLAGS", "-r", route, "release")

    def test_runtime_release_alias_rejects_before_tools(self):
        namespace = runpy.run_path(str(ROOT / "scripts/sanitizers/sanitizer_options.py"))
        for flag in ("-r", "--release"):
            with self.subTest(flag=flag):
                self.assertRaises(ValueError, namespace["cargo_flags"], flag, "")  # noqa: PT027 - actual shared runtime admission function, active under Python -O

    def test_unstable_and_unknown_flags_reject_both_routes_before_effects(self):
        for index, value in enumerate(
            (
                "-Z build-std=core",
                "-Zbuild-std=core",
                "-Z build-std=std",
                "-Zbuild-std=std",
                "-Z unstable-options",
                "-Zunstable-options",
                "-qr",
                "-rq",
                "-vpffi",
                "--future-build-option",
                "positional-filter",
                "--target=x86_64-unknown-linux-gnu",
            )
        ):
            for route in ("standalone", "suite"):
                with self.subTest(value=value, route=route):
                    self.assert_channel_rejected(
                        "SANITIZER_CARGO_FLAGS", value, route, f"unstable-{index}"
                    )

    def test_supported_feature_options_keep_owned_native_arguments(self):
        for value in ("--features fixture_feature", "--features=fixture_feature"):
            with self.subTest(value=value):
                calls = self.root / "calls.jsonl"
                if calls.exists():
                    calls.unlink()
                result = self.run_wrapper(SANITIZER_CARGO_FLAGS=value)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
                receipt = self.summary()
                self.assertEqual(receipt["status"], "completed")  # noqa: PT009
                self.assertEqual(len(receipt["units"][0]["targets"]), len(TARGETS))  # noqa: PT009
                self.assertIn("-Z sanitizer=address", receipt["units"][0]["rustflags"])  # noqa: PT009
                cargo_calls = [
                    json.loads(line)
                    for line in calls.read_text().splitlines()
                    if json.loads(line)["tool"] == "cargo"
                ]
                build = next(call["args"] for call in cargo_calls if "test" in call["args"])
                self.assertEqual(  # noqa: PT009 - supported features reach actual controlled Cargo
                    build[1:3] if value.startswith("--features ") else build[1:2], value.split()
                )
                self.assertIn("--lib", build)  # noqa: PT009
                self.assertIn("--tests", build)  # noqa: PT009
                self.assertEqual(build[-3:-1], ["--target", "x86_64-unknown-linux-gnu"])  # noqa: PT009
                result = self.run_suite(SANITIZER_CARGO_FLAGS=value)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
                self.assertEqual(self.shared_receipt()["status"], "completed")  # noqa: PT009

    def test_build_global_alternate_selection_is_rejected_before_effects(self):
        for index, value in enumerate(
            (
                "--manifest-path crates/Cargo.toml",
                "--target other",
                "-p other",
                "-Zbuild-std=core",
                "-Zbuild-std=std --config build.target-dir=crates/protected-output",
                "--locked",
                '"unterminated',
            )
        ):
            for route in ("standalone", "suite"):
                with self.subTest(value=value, route=route):
                    self.assert_channel_rejected(
                        "SANITIZER_BUILD_EXTRA_ARGS", value, route, str(index)
                    )

    def test_empty_and_fixed_build_std_keep_native_selection(self):
        for value, prefix in (
            ("", []),
            ("-Zbuild-std=std", ["-Zbuild-std=std"]),
            ("-Z build-std=std", ["-Z", "build-std=std"]),
        ):
            with self.subTest(value=value):
                calls = self.root / "calls.jsonl"
                if calls.exists():
                    calls.unlink()
                result = self.run_wrapper(SANITIZER_BUILD_EXTRA_ARGS=value)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
                receipt = self.summary()
                self.assertEqual(receipt["status"], "completed")  # noqa: PT009
                self.assertEqual(len(receipt["units"][0]["targets"]), len(TARGETS))  # noqa: PT009
                self.assertIn(f"native={self.root / 'runtime'}", receipt["units"][0]["rustflags"])  # noqa: PT009
                self.assertIn("-Z sanitizer=address", receipt["units"][0]["rustflags"])  # noqa: PT009
                self.assertIn('curve25519_dalek_backend="serial"', receipt["units"][0]["rustflags"])  # noqa: PT009
                cargo_calls = [
                    json.loads(line)
                    for line in calls.read_text().splitlines()
                    if json.loads(line)["tool"] == "cargo"
                ]
                self.assertEqual(  # noqa: PT009 - active under Python -O
                    cargo_calls[0]["args"],
                    [*prefix, "metadata", "--format-version", "1", "--no-deps"],
                )
                build = next(call["args"] for call in cargo_calls if "test" in call["args"])
                self.assertEqual(build[: len(prefix) + 1], [*prefix, "test"])  # noqa: PT009
                self.assertIn("--lib", build)  # noqa: PT009
                self.assertIn("--tests", build)  # noqa: PT009
                self.assertEqual(build[-3:-1], ["--target", "x86_64-unknown-linux-gnu"])  # noqa: PT009
                result = self.run_suite(SANITIZER_BUILD_EXTRA_ARGS=value)
                self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
                self.assertEqual(self.shared_receipt()["status"], "completed")  # noqa: PT009

    def test_sanctioned_build_std_entrypoint_keeps_compiler_route(self):
        result = subprocess.run(  # noqa: S603 - fixed script with inert compiler/Cargo fixtures only
            [shutil.which("bash"), str(ROOT / "scripts/sanitizers/run_sanitizers_build_std.sh")],
            cwd=self.root,
            env={**self.environment, "ASAN_DIR": str(self.root / "runtime")},
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)  # noqa: PT009
        self.assertEqual(self.summary()["status"], "completed")  # noqa: PT009
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        cargo_calls = [call["args"] for call in calls if call["tool"] == "cargo"]
        self.assertTrue(all(args[0] == "-Zbuild-std=std" for args in cargo_calls))  # noqa: PT009
        self.assertIn(f"native={self.root / 'runtime'}", self.summary()["units"][0]["rustflags"])  # noqa: PT009
        self.assertIn("-Z sanitizer=address", self.summary()["units"][0]["rustflags"])  # noqa: PT009


if __name__ == "__main__":
    unittest.main()
