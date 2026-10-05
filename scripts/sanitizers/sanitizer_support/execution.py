"""Orchestrate admitted native sanitizer packages and test executables."""

from __future__ import annotations

import os
import runpy
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sanitizer_support.core import asan_options, digest, duration, parse_json, require, selection
from sanitizer_support.protocol import (
    build_artifacts,
    completed,
    evidence_routes,
    listed,
    target_inventory,
    target_key,
    target_selector,
)
from sanitizer_support.supervision import CommandSupervisor

if TYPE_CHECKING:
    from sanitizer_support.core import Settings
    from sanitizer_support.protocol import TargetInventory, TargetKey


class Supervisor(CommandSupervisor):
    """Build and execute every admitted target under command supervision."""

    def execute(self, settings: Settings, workspace: Path) -> None:
        sanitizers = selection(settings.sanitizer_text, "sanitizer")
        packages = selection(settings.package_text, "package")
        require("ffi" in packages, "Package selection must include the required ffi package")
        require(sanitizers == ["address"], "Only the configured address sanitizer is supported")
        require(settings.link_order in {"0", "1"}, "ASan link-order setting must be 0 or 1")
        build_seconds, run_seconds, kill_grace = map(
            duration, (settings.build_limit_text, settings.run_limit_text, settings.grace_text)
        )
        options = runpy.run_path(
            str(Path(__file__).parents[1] / "sanitizer_options.py"), run_name="sanitizer_options"
        )
        options["validate_compiler_environment"](os.environ)
        extra, build_extra = options["cargo_flags"](settings.extra_text, settings.build_extra_text)
        self.kill_grace = kill_grace
        self.evidence.prepare()
        self.summary.update(
            {
                "sanitizers": sanitizers,
                "packages": packages,
                "build_deadline_seconds": build_seconds,
                "run_deadline_seconds": run_seconds,
                "kill_grace_seconds": kill_grace,
                "runtime_directory": settings.runtime_text,
            }
        )
        metadata = parse_json(
            self.command(
                [settings.cargo, *build_extra, "metadata", "--format-version", "1", "--no-deps"],
                os.environ.copy(),
                build_seconds,
                "metadata",
            )
        )
        require(
            Path(metadata["workspace_root"]).resolve() == workspace,
            "Cargo metadata belongs to a different workspace",
        )
        require(isinstance(metadata.get("packages"), list), "Malformed Cargo metadata packages")
        package_records = {package["name"]: package for package in metadata["packages"]}
        require(
            len(package_records) == len(metadata["packages"]), "Duplicate Cargo metadata package"
        )
        inventories = {}
        for package_name in packages:
            require(package_name in package_records, f"Unknown sanitizer package: {package_name}")
            inventories[package_name] = target_inventory(package_records[package_name])
        routes = evidence_routes(inventories)
        for package_name in packages:
            self.execute_package(
                settings,
                package_records[package_name],
                (build_seconds, run_seconds),
                (extra, build_extra),
                (
                    inventories[package_name],
                    {key: routes[package_name, key] for key in inventories[package_name]},
                ),
            )

    def execute_package(
        self,
        settings: Settings,
        package: dict[str, Any],
        deadlines: tuple[float, float],
        options: tuple[list[str], list[str]],
        inventory: tuple[TargetInventory, dict[TargetKey, str]],
    ) -> None:
        extra, build_extra = options
        package_name, sanitizer = package["name"], "address"
        targets, labels = inventory
        target_dir = (Path(settings.target_text) / f"{sanitizer}-{package_name}").resolve()
        rustflags = f"{settings.base_flags} -Z sanitizer={sanitizer} {settings.curve_flags}".strip()
        unit = {
            "package": package_name,
            "package_id": package["id"],
            "sanitizer": sanitizer,
            "status": "not-run",
            "rustflags": rustflags,
            "target_directory": str(target_dir),
            "targets": [
                {
                    "name": key[0],
                    "kind": list(key[1]),
                    "evidence_label": labels[key],
                    "status": "not-run",
                    "source": str(Path(target["src_path"]).resolve()),
                    "source_sha256": digest(Path(target["src_path"])),
                }
                for key, target in targets.items()
            ],
        }
        self.summary["units"].append(unit)
        build_env = {
            **os.environ,
            "RUSTFLAGS": rustflags,
            "RUSTDOCFLAGS": rustflags,
            "CARGO_TARGET_DIR": str(target_dir),
            "ASAN_OPTIONS": asan_options("0"),
            "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        }
        build_env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        build_env.pop("CARGO_ENCODED_RUSTDOCFLAGS", None)
        output = self.command(
            [
                settings.cargo,
                *build_extra,
                "test",
                *extra,
                "-p",
                package_name,
                *(argument for key in targets for argument in target_selector(key)),
                "--no-run",
                "--target",
                settings.host,
                "--message-format=json-render-diagnostics",
            ],
            build_env,
            deadlines[0],
            f"build-{sanitizer}-{package_name}",
        )
        found = build_artifacts(output, package, targets, target_dir / settings.host / "debug")
        unit["status"] = "built"
        run_env = {
            **os.environ,
            "ASAN_OPTIONS": asan_options(settings.link_order),
            "LSAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
            "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1",
        }
        if settings.preload:
            run_env["LD_PRELOAD"] = settings.preload + (
                ":" + os.environ["LD_PRELOAD"] if os.environ.get("LD_PRELOAD") else ""
            )
        for target_result in unit["targets"]:
            self.execute_binary(
                target_result,
                found[target_key(target_result)],
                run_env,
                deadlines[1],
                package_name=package_name,
            )
        unit["status"] = "completed"

    def execute_binary(
        self,
        target_result: dict[str, Any],
        artifact: tuple[Path, dict[str, Any]],
        run_env: dict[str, str],
        run_seconds: float,
        *,
        package_name: str,
    ) -> None:
        name = target_result["name"]
        label = target_result["evidence_label"]
        binary, record = artifact
        target_result.update(
            {
                "binary": str(binary),
                "binary_sha256": digest(binary),
                "cargo_artifact": record,
                "status": "built",
            }
        )
        symbols = self.command(
            ["nm", str(binary)], os.environ.copy(), run_seconds, f"symbols-{label}"
        )
        require(
            "__asan_init" in symbols
            and "__asan_report_" in symbols
            and ("asan.module_ctor" in symbols or "___asan_gen_" in symbols),
            "Sanitizer binary lacks ASan instrumentation markers",
        )
        elf = self.command(
            ["readelf", "-d", str(binary)], os.environ.copy(), run_seconds, f"runtime-{label}"
        )
        target_result["runtime_linkage"] = "dynamic" if "libclang_rt.asan" in elf else "embedded"
        all_names = listed(
            self.command(
                [str(binary), "--list", "--format", "terse"], run_env, run_seconds, f"list-{label}"
            )
        )
        ignored = listed(
            self.command(
                [str(binary), "--list", "--ignored", "--format", "terse"],
                run_env,
                run_seconds,
                f"ignored-{label}",
            )
        )
        require(ignored <= all_names, "Ignored test identities are not in required inventory")
        inactive = (
            package_name == "ffi"
            and name == "oidc_hash_runtime_test"
            and target_result["kind"] == ["test"]
            and "lowstar_hash" not in record["features"]
        )
        require(
            all_names - ignored or (inactive and not all_names),
            "Required sanitizer binary has no runnable tests",
        )
        target_result.update(
            {
                "expected_tests": sorted(all_names),
                "ignored_tests": sorted(ignored),
                "applicability": "lowstar_hash feature disabled"
                if inactive and not all_names
                else "required",
            }
        )
        executed = self.command(
            [str(binary), "--test", "-Z", "unstable-options", "--format", "json"],
            run_env,
            run_seconds,
            f"run-{label}",
            echo=True,
        )
        require(
            digest(binary) == target_result["binary_sha256"],
            "Sanitizer executable changed during execution",
        )
        target_result.update(completed(executed, all_names, ignored))
        target_result["status"] = "completed"
        self.save()
