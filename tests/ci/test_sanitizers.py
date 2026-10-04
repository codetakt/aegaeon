"""Exercise the real sanitizer wrapper with controlled Cargo and libtest tools."""

from __future__ import annotations

import ast
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
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
    targets = metadata["packages"][0]["targets"]
    for index, target in enumerate(targets):
        binary = target_dir / f"nonstandard-name-{index}"
        binary.write_text((root / "fixture").read_text())
        binary.chmod(0o755)
        record = {
            "reason": "compiler-artifact",
            "package_id": "ffi-identity",
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
    targets = json.loads((root / "metadata.json").read_text())["packages"][0]["targets"]
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


class SanitizerTests(unittest.TestCase):
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

    def test_nonstandard_names_and_cache_bound_to_all_required_targets(self):
        for mode in ("success", "fresh-cache", "ignored-policy"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode == 0, result.stderr
                summary = self.summary()
                assert summary["status"] == "completed"
                targets = summary["units"][0]["targets"]
                assert {target["name"] for target in targets} == set(TARGETS)
                assert all(target["status"] == "completed" for target in targets)
                assert sum(len(target["completed"]) for target in targets) == 8
                oidc = next(
                    target for target in targets if target["name"] == "oidc_hash_runtime_test"
                )
                assert oidc["completed"] == []
                assert oidc["applicability"] == "lowstar_hash feature disabled"
                build = next(
                    command
                    for command in summary["commands"]
                    if command["phase"].startswith("build-")
                )
                assert build["args"][-3:-1] == ["--target", "x86_64-unknown-linux-gnu"]
                assert "--lib" in build["args"]
                assert "--tests" in build["args"]
                assert 'curve25519_dalek_backend="serial"' in summary["units"][0]["rustflags"]

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
        assert result.returncode == 0, result.stderr
        targets = self.summary()["units"][0]["targets"]
        assert len(targets) == 10
        assert targets[-1]["completed"] == ["additional_test::required"]
        calls = [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]
        builds = [call for call in calls if call["tool"] == "cargo" and "test" in call["args"]]
        assert builds[0]["encoded_flags"] is None

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
                assert result.returncode != 0, (mode, result.stdout)
                assert self.summary()["status"] == "failed"

    def test_stale_outputs_cannot_mask_compile_failure(self):
        assert self.run_wrapper().returncode == 0
        result = self.run_wrapper("build-failure")
        assert result.returncode == 7, result.stderr
        assert self.summary()["units"][0]["status"] == "not-run"
        assert (
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
                assert result.returncode != 0, (mode, result.stdout)
                assert self.summary()["status"] == "failed"

    def test_final_cleanup_failure_preserves_observed_child_exit(self):
        # Compile only the actual command/Failure definitions; execute a real
        # child, with the final terminate call failing after wait observes exit.
        text = WRAPPER.read_text().split("<<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
        parsed = ast.parse(text)
        definitions = [
            item
            for item in parsed.body
            if isinstance(item, (ast.FunctionDef, ast.ClassDef))
            and item.name in {"command", "Failure", "require"}
        ]
        self.assertEqual(len(definitions), 3)  # noqa: PT009 - active under Python -O
        for child, expected in (
            ("import sys;sys.exit(9)", 9),
            ("import os,signal;os.kill(os.getpid(),signal.SIGTERM)", 143),
            ("import sys;sys.exit(0)", 1),
        ):
            with self.subTest(child=child):
                artifacts = Path(self.enterContext(tempfile.TemporaryDirectory()))
                terminate = Mock(side_effect=[False, OSError("controlled final cleanup failure")])
                namespace = {
                    "subprocess": subprocess,
                    "selectors": selectors,
                    "os": os,
                    "sys": sys,
                    "time": time,
                    "artifacts": artifacts,
                    "summary": {"commands": []},
                    "counter": 0,
                    "kill_grace": 1,
                    "group_alive": lambda _pid: False,
                    "terminate": terminate,
                    "save": lambda: None,
                }
                code = ast.fix_missing_locations(ast.Module(body=definitions, type_ignores=[]))
                exec(compile(code, str(WRAPPER), "exec"), namespace)  # noqa: S102 - exact local definitions
                with self.assertRaisesRegex(  # noqa: PT027 - unittest discovery without pytest
                    namespace["Failure"], "controlled final cleanup"
                ) as caught:
                    namespace["command"](
                        [sys.executable, "-c", child], os.environ.copy(), 5, "probe"
                    )
                self.assertEqual(caught.exception.status, expected)  # noqa: PT009 - active under Python -O
                self.assertEqual(terminate.call_count, 2)  # noqa: PT009 - active under Python -O
                self.assertEqual(namespace["summary"]["commands"][0]["status"], "failed")  # noqa: PT009 - active under Python -O
                self.assertTrue((artifacts / "001-probe.stdout.log").is_file())  # noqa: PT009 - active under Python -O
                self.assertTrue((artifacts / "001-probe.stderr.log").is_file())  # noqa: PT009 - active under Python -O

    def test_original_exits_and_crash_signals_propagate(self):
        for mode, expected in (("build-signal", 143), ("run-failure", 9), ("run-signal", 134)):
            with self.subTest(mode=mode):
                result = self.run_wrapper(mode)
                assert result.returncode == expected, result.stderr

    def assert_child_stopped(self):
        child = int((self.root / "child.pid").read_text())
        stat = Path(f"/proc/{child}/stat")
        assert not stat.exists() or stat.read_text().rsplit(")", 1)[1].split()[0] in {"Z", "X"}

    def test_build_run_watchdogs_and_closed_output_kill_descendants(self):
        for mode in ("build-timeout", "build-closed-timeout", "run-timeout", "run-closed-timeout"):
            with self.subTest(mode=mode):
                result = self.run_wrapper(
                    mode, SANITIZER_BUILD_TIMEOUT="0.5", SANITIZER_RUN_TIMEOUT="0.5"
                )
                assert result.returncode == 124, result.stderr
                assert any(command["timed_out"] for command in self.summary()["commands"])
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
                assert result.returncode == (7 if mode == "build-failure-descendant" else 1), (
                    result.stderr
                )
                assert any(
                    command["lingering_descendants"] for command in self.summary()["commands"]
                )
                self.assert_child_stopped()

    def test_wrapper_interrupt_cleans_descendants(self):
        process = subprocess.Popen(  # noqa: S603
            [shutil.which("bash"), str(WRAPPER)],
            cwd=self.root,
            env={**self.environment, "SANITIZER_FIXTURE_MODE": "build-timeout"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "child.pid").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert (self.root / "child.pid").exists()
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=10)
            assert process.returncode == 143, stderr
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
                assert self.run_wrapper(**{key: value}).returncode != 0

    def test_missing_required_tools_runtime_and_host_fail(self):
        for tool in ("rustc", "cargo", "clang", "python3", "nm", "readelf"):
            link = self.bin / tool
            original = link.readlink()
            link.unlink()
            try:
                with self.subTest(tool=tool):
                    assert self.run_wrapper().returncode != 0
            finally:
                link.symlink_to(original)
        assert self.run_wrapper(SANITIZER_RUNTIME_DIR=str(self.root / "missing")).returncode != 0
        assert self.run_wrapper("bad-host").returncode != 0
        (self.root / "runtime/libclang_rt.asan-x86_64.so").unlink()
        assert self.run_wrapper().returncode != 0

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
        for mode, overrides in (
            ("success", {"SANITIZER_RUNTIME_DIR": str(self.root / "missing-runtime")}),
            ("bad-host", {}),
            ("success", {"SANITIZER_RUNTIME_DIR": str(self.root / "empty-runtime")}),
        ):
            with self.subTest(mode=mode, overrides=overrides):
                (self.root / "empty-runtime").mkdir(exist_ok=True)
                evidence, raw = self.seed_completed_preflight()
                result = self.run_wrapper(mode, **overrides)
                self.assert_failed_preflight_preserved(result, evidence, raw)

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

    def test_source_child_completed_evidence_is_unchanged_before_tools(self):
        for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR"):
            with self.subTest(variable=variable):
                self.assert_source_boundary_rejected(self.root / "crates/server", variable)

    def test_independent_source_inventory_rejects_equal_and_descendant_outputs(self):
        for relative in PROTECTED_SOURCE_INPUTS:
            for suffix in ("", "nested output\n"):
                route = self.root / relative / suffix
                for variable in ("SANITIZER_ARTIFACT_DIR", "SANITIZER_TARGET_DIR"):
                    with self.subTest(relative=relative, suffix=suffix, variable=variable):
                        self.assert_source_boundary_rejected(route, variable)

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
        for target in ("target-alias", "target-file", "generated/unsafe-target"):
            with self.subTest(target=target):
                evidence, raw = self.seed_completed_preflight()
                result = self.run_wrapper(SANITIZER_TARGET_DIR=target)
                self.assert_failed_preflight_preserved(result, evidence, raw)
                self.assertEqual(sentinel.read_bytes(), b"external completed sentinel\n")  # noqa: PT009 - external bytes preserved
                self.assertEqual(  # noqa: PT009 - file preserved
                    (self.root / "target-file").read_bytes(), b"target file sentinel\n"
                )
                self.assertFalse((self.root / "calls.jsonl").exists())  # noqa: PT009 - no compiler/runtime preflight


if __name__ == "__main__":
    unittest.main()
