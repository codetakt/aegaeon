"""Fixed infrastructure selection and module-local input admission."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from infrastructure_support.common import (
    DELIVERY_PACKAGE_SHA256,
    MODULE_ROOT,
    MODULES,
    VALIDATOR_SUPPORT_PATHS,
    require,
)

if TYPE_CHECKING:
    from pathlib import Path


SUPPORT_PATHS = {
    "scripts/ci/validate_infrastructure.py": MODULES,
    "tests/ci/test_infrastructure_validation.py": MODULES,
    ".github/workflows/infrastructure-validation.yml": MODULES,
    "tests/ci/test_perf_runtime_delivery.py": ("perf-aws-ec2",),
    "tests/ci/test_perf_delivery_package.py": ("perf-aws-ec2",),
    "scripts/perf/aws_sweep.sh": ("perf-aws-ec2",),
    "scripts/validation/run_oidc_aws_kms_parity_from_tofu.sh": ("oidc-aws-kms-parity",),
}


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
        if raw in {
            str(MODULE_ROOT / "perf-aws-ec2" / "runtime_delivery" / name)
            for name in DELIVERY_PACKAGE_SHA256
        }:
            selected.add("perf-aws-ec2")
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
        if module.name == "perf-aws-ec2" and path.name == "runtime_delivery":
            require(path.is_dir(), "Missing fixed guest package directory")
            entries = sorted(path.iterdir())
            require(
                {entry.name for entry in entries} == set(DELIVERY_PACKAGE_SHA256),
                "Unexpected guest package inventory",
            )
            for entry in entries:
                require(entry.is_file() and not entry.is_symlink(), "Unsafe guest package input")
            inputs.extend(entries)
            continue
        require(path.is_file(), f"Unsupported module input: {path}")
        allowed = path.name in {".terraform.lock.hcl", ".gitignore", "README.md"}
        allowed |= module.name == "perf-aws-ec2" and path.name == "delivery_helper.py"
        require(allowed or path.suffix in {".tf", ".tftpl"}, f"Unexpected input: {path}")
        inputs.append(path)
    names = {p.name for p in inputs}
    require(
        {"versions.tf", ".terraform.lock.hcl"} <= names, "Missing provider declarations or lock"
    )
    require(any(p.suffix == ".tf" for p in inputs), "Empty module")
    return inputs


SUPPORT_PATHS.update(dict.fromkeys(VALIDATOR_SUPPORT_PATHS, MODULES))
