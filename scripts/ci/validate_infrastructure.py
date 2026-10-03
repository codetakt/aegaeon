#!/usr/bin/env python3
"""Validate repository OpenTofu modules without cloud credentials or deployment.

This checks static provider compatibility and explicit configuration contracts.
It does not read deployed state, plan changes, or establish deployment safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

MODULE_ROOT = PurePosixPath("infra/tofu")
MODULES = ("aegaeon-aws-staging", "oidc-aws-kms-parity", "perf-aws-ec2")
SUPPORT_PATHS = {
    "scripts/ci/validate_infrastructure.py": MODULES,
    "tests/ci/test_infrastructure_validation.py": MODULES,
    ".github/workflows/infrastructure-validation.yml": MODULES,
    "scripts/perf/aws_sweep.sh": ("perf-aws-ec2",),
    "scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh": ("oidc-aws-kms-parity",),
}
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|//[^\n]*|\#[^\n]*|[{}]', re.DOTALL)
ENV_NAME = re.compile(r"\bAEGAEON_[A-Za-z0-9_]+\b")
COMMAND_TIMEOUT = 300


def require(condition: bool, message: str) -> None:  # noqa: FBT001 - predicate guard
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def uncomment(text: str) -> str:
    return TOKEN.sub(lambda m: m[0] if m[0][0] in '"{}' else " ", text)


def block(text: str, header: str) -> str:
    """Extract one explicit HCL block, respecting strings/comments and nesting."""
    text = uncomment(text)
    matches = list(re.finditer(r"(?m)^\s*" + re.escape(header) + r"\s*\{", text))
    require(len(matches) == 1, f"Expected exactly one {header} block")
    start = matches[0].end()
    depth = 1
    for token in TOKEN.finditer(text, start):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return text[start : token.start()]
    raise ValueError(f"Unclosed {header} block")


def top_level(text: str) -> str:
    text = uncomment(text)
    result = []
    depth = 0
    start = 0
    for token in TOKEN.finditer(text):
        if token[0] == "{":
            if depth == 0:
                result.append(text[start : token.start()])
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                result.append(" {} ")
                start = token.end()
    require(depth == 0, "Unbalanced HCL block")
    result.append(text[start:])
    return "".join(result)


def assignment(text: str, name: str) -> str:
    matches = re.findall(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*([^\n]+)", top_level(text))
    require(len(matches) == 1, f"Expected one explicit {name} assignment")
    return str(matches[0].strip())


def select_modules(root: Path, paths: list[str] | None) -> list[Path]:
    available = root / str(MODULE_ROOT)
    require(available.is_dir(), "Missing infra/tofu directory")
    discovered = sorted(p.name for p in available.iterdir() if p.is_dir())
    require(discovered == sorted(MODULES), "Unknown or missing infrastructure module")
    selected = set(MODULES) if paths is None else set()
    require(paths is None or bool(paths), "Empty infrastructure path selection")
    for raw in paths or []:
        if raw in SUPPORT_PATHS:
            selected.update(SUPPORT_PATHS[raw])
            continue
        path = PurePosixPath(raw)
        require(raw == str(path) and not path.is_absolute(), f"Noncanonical path: {raw!r}")
        require(not any(ord(c) < 32 for c in raw), "Control character in path")
        require(".." not in path.parts and len(path.parts) == 4, f"Invalid module path: {raw}")
        require(path.parts[:2] == MODULE_ROOT.parts, f"Not an infrastructure input: {raw}")
        require(path.parts[2] in MODULES, f"Unknown module: {raw}")
        selected.add(path.parts[2])
    modules = [available / name for name in sorted(selected)]
    for module in modules:
        require(not module.is_symlink(), f"Symlink module: {module}")
        require(module.resolve().is_relative_to(root.resolve()), "Module escapes repository")
    return modules


def module_inputs(module: Path) -> list[Path]:
    inputs = []
    for path in sorted(module.iterdir()):
        require(not path.is_symlink(), f"Symlink module input: {path}")
        if path.name == ".terraform":
            continue  # Never use preexisting initialization or state.
        require(path.is_file(), f"Unsupported module input: {path}")
        allowed = path.name in {".terraform.lock.hcl", ".gitignore", "README.md"}
        require(allowed or path.suffix in {".tf", ".tftpl"}, f"Unexpected input: {path}")
        inputs.append(path)
    names = {p.name for p in inputs}
    require(
        {"versions.tf", ".terraform.lock.hcl"} <= names, "Missing provider declarations or lock"
    )
    require(any(p.suffix == ".tf" for p in inputs), "Empty module")
    return inputs


def lock_contract(module: Path) -> dict[str, str]:
    declarations = block((module / "versions.tf").read_text(), "terraform")
    providers = block(declarations, "required_providers")
    lock = (module / ".terraform.lock.hcl").read_text()
    names = re.findall(r"(?m)^\s*(\w+)\s*=\s*\{", providers)
    require(bool(names) and set(names) <= {"aws", "random"}, "Unreviewed provider declarations")
    locked = re.findall(r'(?m)^provider "([^"]+)"\s*\{', uncomment(lock))
    require(len(locked) == len(names), "Unexpected or missing locked provider")
    result = {}
    for name in names:
        declaration = block(providers, name + " =")
        source = json.loads(assignment(declaration, "source"))
        require(source == f"hashicorp/{name}", "Unexpected provider source")
        selected = block(lock, f'provider "registry.opentofu.org/{source}"')
        wanted = json.loads(assignment(declaration, "version"))
        actual = json.loads(assignment(selected, "constraints"))
        require(wanted == actual, f"Stale lock constraints for {name}: {actual} != {wanted}")
        version = json.loads(assignment(selected, "version"))
        require(bool(re.fullmatch(r"\d+\.\d+\.\d+", version)), "Unrecognized provider version")
        require(bool(re.search(r'"(?:h1|zh):[^"\s]+"', selected)), "Provider checksums missing")
        result[name] = version
    return result


def runtime_contract(module: Path, root: Path) -> dict[str, Any]:
    names = set()
    for path in module_inputs(module):
        if path.suffix in {".tf", ".tftpl"}:
            names.update(ENV_NAME.findall(uncomment(path.read_text())))
    rust = sorted((root / "crates/server/src").rglob("*.rs"))
    require(bool(rust), "Runtime environment contract source is missing")
    source_bytes = {p: p.read_bytes() for p in rust}
    known = set().union(*(set(ENV_NAME.findall(raw.decode())) for raw in source_bytes.values()))
    require(names <= known, f"Unknown runtime environment names: {sorted(names - known)}")
    return {
        "environment_names": sorted(names),
        "runtime_sources": {
            str(p.relative_to(root)): hashlib.sha256(raw).hexdigest()
            for p, raw in source_bytes.items()
        },
    }


def resource_contract(module: Path, providers: dict[str, str]) -> None:
    if module.name == "perf-aws-ec2":
        instances = (module / "instances.tf").read_text()
        for name in ("server", "loadgen"):
            body = block(instances, f'resource "aws_instance" "{name}"')
            require(
                assignment(body, "user_data_replace_on_change") == "true",
                "EC2 replacement contract changed",
            )
            metadata = block(body, "metadata_options")
            require(assignment(metadata, "http_tokens") == '"required"', "EC2 requires IMDSv2")
        return
    key = block((module / "kms.tf").read_text(), 'resource "aws_kms_key" "oidc_signing"')
    require(assignment(key, "key_usage") == '"SIGN_VERIFY"', "OIDC KMS key must sign")
    require(
        assignment(key, "customer_master_key_spec") == '"RSA_2048"',
        "OIDC parity key must be RSA_2048",
    )
    if module.name == "aegaeon-aws-staging":
        redis = block(
            (module / "redis.tf").read_text(), 'resource "aws_elasticache_replication_group" "main"'
        )
        for name in ("at_rest_encryption_enabled", "transit_encryption_enabled"):
            require(assignment(redis, name) == "true", f"Redis requires {name}")
        require(
            assignment(redis, "auth_token") == "random_password.redis_auth_token.result",
            "Redis auth token contract changed",
        )
        if int(providers["aws"].split(".")[0]) >= 6:
            require(
                assignment(redis, "auth_token_update_strategy") == '"ROTATE"',
                "AWS 6 requires preserved explicit Redis ROTATE strategy",
            )


def isolated_environment(work: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AWS_", "TF_", "TOFU_"))}
    empty = work / "empty-aws-config"
    empty.write_text("")
    config = work / "tofurc"
    config.write_text("provider_installation { direct {} }\n")
    env.update(
        {
            "TF_CLI_CONFIG_FILE": str(config),
            "TF_DATA_DIR": str(work / "tf-data"),
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
            "AWS_SHARED_CREDENTIALS_FILE": str(empty),
            "AWS_CONFIG_FILE": str(empty),
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    return env


class Commands:
    def __init__(self, output: Path, env: dict[str, str]) -> None:
        self.output = output
        self.env = env
        self.records: list[dict[str, Any]] = []

    def run(self, argv: list[str], cwd: Path, stdin: str | None = None) -> str:
        label = f"{len(self.records):02d}-{Path(argv[0]).name}-{argv[1]}"
        started = time.monotonic()
        record: dict[str, Any] = {
            "argv": argv,
            "cwd": str(cwd),
            "stdout": label + ".stdout",
            "stderr": label + ".stderr",
        }
        self.records.append(record)
        try:
            result = subprocess.run(
                argv,
                cwd=cwd,
                env=self.env,
                input=stdin,
                text=True,
                capture_output=True,
                timeout=COMMAND_TIMEOUT,
                check=False,
            )
            record.update(exit=result.returncode, seconds=time.monotonic() - started)
            (self.output / record["stdout"]).write_text(result.stdout)
            (self.output / record["stderr"]).write_text(result.stderr)
            require(
                result.returncode == 0,
                f"Command failed ({result.returncode}): {argv}; see {self.output}",
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            record.update(error=str(error), seconds=time.monotonic() - started)
            if isinstance(error, subprocess.TimeoutExpired):
                (self.output / record["stdout"]).write_bytes(error.stdout or b"")
                (self.output / record["stderr"]).write_bytes(error.stderr or b"")
            raise
        else:
            return result.stdout
        finally:
            (self.output / "commands.json").write_text(json.dumps(self.records, indent=2) + "\n")


def template_values() -> dict[str, Any]:
    return {
        "aws_region": "us-east-1",
        "server_image": "registry.example/aegaeon:test",
        "server_port": 8080,
        "expose_metrics_on_main": True,
        "trusted_proxies": "127.0.0.1/32",
        "ghcr_auth_enabled": True,
        "ghcr_username": "fixture",
        "ghcr_token_ssm_parameter_name": "/aegaeon/registry-token",
        "ghcr_token_secretsmanager_secret": "",
        "server_url": "http://server.example:8080",
        "artifact_bucket": "aegaeon-fixture",
        "artifact_prefix": "ci/",
        "auto_run_loadtest": True,
        "workers": 2,
        "rps": 10,
        "run_time": "10s",
        "warmup": "1s",
        "scenario": "health",
    }


def rendered_contract(rendered: str, role: str, *, enabled: bool) -> None:
    require("--password-stdin" in rendered, "Registry credentials must use password stdin")
    require("--with-decryption" in rendered, "SSM secret retrieval contract missing")
    require(
        "GHCR_TOKEN_SSM_PARAMETER_NAME=/aegaeon/registry-token" in rendered,
        "Template lost secret reference",
    )
    if role == "server":
        require(
            f"AEGAEON_EXPOSE_METRICS_ON_MAIN={int(enabled)}\n" in rendered,
            "Metrics boolean rendering changed",
        )
        require(
            "AEGAEON_TRUSTED_PROXIES=127.0.0.1/32\n" in rendered, "Trusted proxy rendering changed"
        )
        require(
            "registry.example/aegaeon:test --host 0.0.0.0 --port 8080" in rendered,
            "Server CLI rendering changed",
        )
    else:
        require(
            "SERVER_URL=http://server.example:8080\n" in rendered,
            "Loadtest target rendering changed",
        )
        require(
            '--report-file "/results/report.json"' in rendered, "Loadtest report contract changed"
        )
        require(
            ("systemctl start aegaeon-loadtest.service" in rendered) == enabled,
            "Auto-run conditional changed",
        )


def check_templates(module: Path, commands: Commands, tofu: str, bash: str, work: Path) -> int:
    templates = sorted(module.glob("*.tftpl"))
    expected = (
        {"user_data_server.sh.tftpl", "user_data_loadgen.sh.tftpl"}
        if module.name == "perf-aws-ec2"
        else set()
    )
    require({p.name for p in templates} == expected, "Unreviewed template inventory")
    evaluation = work / "template-evaluation"
    evaluation.mkdir()
    for template in templates:
        for enabled in (False, True):
            values = template_values()
            values.update(expose_metrics_on_main=enabled, auto_run_loadtest=enabled)
            expression = (
                f"jsonencode(templatefile({json.dumps(str(template))}, {json.dumps(values)}))\n"
            )
            raw = commands.run([tofu, "console", "-no-color"], evaluation, expression)
            rendered = json.loads(json.loads(raw))
            role = template.name.split("_")[2].split(".")[0]
            rendered_contract(rendered, role, enabled=enabled)
            commands.run([bash, "-n"], evaluation, rendered)
    return len(templates) * 2


def check_support(module: Path, root: Path, commands: Commands, bash: str) -> dict[str, str]:
    sources = {}
    for path, modules in SUPPORT_PATHS.items():
        if path.endswith(".sh") and module.name in modules:
            source = root / path
            require(source.is_file() and not source.is_symlink(), f"Missing support script: {path}")
            raw = source.read_bytes()
            sources[path] = hashlib.sha256(raw).hexdigest()
            commands.run([bash, "-n"], module, raw.decode())
    return sources


def installed_providers(work: Path) -> dict[str, str]:
    directory = work / "tf-data/providers"
    binaries = sorted(directory.rglob("terraform-provider-*"))
    require(bool(binaries), "Initialized provider binaries missing")
    return {str(path.relative_to(directory)): digest(path) for path in binaries if path.is_file()}


def validate_schema(commands: Commands, tofu: str, module: Path) -> dict[str, Any]:
    validation = json.loads(commands.run([tofu, "validate", "-json", "-no-color"], module))
    require(isinstance(validation, dict), "Malformed validation result")
    require(
        validation.get("valid") is True and validation.get("error_count") == 0,
        "OpenTofu returned invalid validation result",
    )
    return dict(validation)


def initialize_providers(
    copy: Path, source: Path, commands: Commands, tofu: str, work: Path
) -> dict[str, Any]:
    providers = lock_contract(copy)
    commands.run(
        [tofu, "init", "-backend=false", "-lockfile=readonly", "-input=false", "-no-color"],
        copy,
    )
    require(
        digest(copy / ".terraform.lock.hcl") == digest(source / ".terraform.lock.hcl"),
        "OpenTofu rewrote readonly lock",
    )
    return {"providers": providers, "installed_providers": installed_providers(work)}


def validate_module(
    module: Path, root: Path, output: Path, tools: dict[str, str]
) -> dict[str, Any]:
    output.mkdir()
    inputs = {str(p.relative_to(root)): digest(p) for p in module_inputs(module)}
    report: dict[str, Any] = {
        "module": str(module.relative_to(root)),
        "inputs": inputs,
        "status": "failed",
    }
    try:
        with tempfile.TemporaryDirectory(prefix="aegaeon-infra-") as temporary:
            work = Path(temporary)
            copy = work / module.name
            copy.mkdir()
            for source in module_inputs(module):
                shutil.copyfile(source, copy / source.name)
            commands = Commands(output, isolated_environment(work))
            report["commands"] = commands.records
            report["tools"] = json.loads(commands.run([tools["tofu"], "version", "-json"], copy))
            commands.run([tools["tofu"], "fmt", "-check", "-diff"], copy)
            report.update(initialize_providers(copy, module, commands, tools["tofu"], work))
            report["validation"] = validate_schema(commands, tools["tofu"], copy)
            report["runtime_contract"] = runtime_contract(copy, root)
            resource_contract(copy, report["providers"])
            report["rendered_template_cases"] = check_templates(
                copy, commands, tools["tofu"], tools["bash"], work
            )
            report["support_scripts"] = check_support(module, root, commands, tools["bash"])
            require(
                digest(copy / ".terraform.lock.hcl") == digest(module / ".terraform.lock.hcl"),
                "OpenTofu rewrote readonly lock",
            )
            checked_sources = {
                **inputs,
                **report["runtime_contract"]["runtime_sources"],
                **report["support_scripts"],
            }
            require(
                all(digest(root / path) == value for path, value in checked_sources.items()),
                "Repository inputs changed during validation",
            )
            report["status"] = "passed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    finally:
        (output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def toolchain_provenance(root: Path, output: Path, tools: dict[str, str]) -> dict[str, Any]:
    inputs = [
        root / "flake.nix",
        root / "flake.lock",
        root / "pyproject.toml",
        root / ".github/workflows/infrastructure-validation.yml",
    ]
    for path in inputs:
        require(path.is_file() and not path.is_symlink(), f"Missing toolchain input: {path}")
    inputs.extend(sorted((root / "nix").rglob("*.nix")))
    inputs.extend(sorted((root / ".github/actions/setup-nix-ci").rglob("*")))
    source_hashes = {str(p.relative_to(root)): digest(p) for p in inputs if p.is_file()}
    executables = {**tools, "python": sys.executable}
    stores = set()
    for executable in executables.values():
        path = Path(executable).resolve()
        require(path.parts[1:3] == ("nix", "store"), f"Tool is not Nix-pinned: {path}")
        stores.add(str(Path(*path.parts[:4])))
    commands = Commands(output, dict(os.environ))
    closure = json.loads(
        commands.run([tools["nix"], "path-info", "--json", "--recursive", *sorted(stores)], root)
    )
    return {
        "toolchain_sources": source_hashes,
        "executable_paths": executables,
        "nix_closure": closure,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--paths-json",
        type=Path,
        help="JSON array of changed infra/tofu paths; omitted means all modules",
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts/infrastructure-validation"))
    args = parser.parse_args()
    summary: dict[str, Any] = {
        "status": "failed",
        "scope": "Static infrastructure validation; no deployed state or live AWS assurance",
    }
    args.output.mkdir(parents=True, exist_ok=False)
    try:
        paths = None if args.paths_json is None else json.loads(args.paths_json.read_text())
        require(
            paths is None or (isinstance(paths, list) and all(isinstance(p, str) for p in paths)),
            "Paths must be a JSON string array",
        )
        modules = select_modules(args.root.resolve(), paths)
        tools = {name: shutil.which(name) for name in ("tofu", "bash", "nix")}
        require(all(tools.values()), "Required tools unavailable: tofu, bash and nix")
        resolved = {name: str(path) for name, path in tools.items()}
        summary["tool_hashes"] = {
            name: digest(Path(path).resolve()) for name, path in resolved.items()
        }
        summary["runner_sha256"] = digest(Path(__file__))
        summary["provenance"] = toolchain_provenance(args.root.resolve(), args.output, resolved)
        summary["modules"] = [
            validate_module(module, args.root.resolve(), args.output / module.name, resolved)
            for module in modules
        ]
        require(
            all(item["status"] == "passed" for item in summary["modules"]),
            "Infrastructure validation failed; see module diagnostics",
        )
        require(
            all(
                digest(args.root / path) == value
                for path, value in summary["provenance"]["toolchain_sources"].items()
            ),
            "Toolchain inputs changed during validation",
        )
        summary["status"] = "passed"
    except (OSError, ValueError) as error:
        summary["error"] = str(error)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Infrastructure validation: {summary['status']}; evidence: {args.output}")
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
