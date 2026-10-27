"""Dispatch the fuzz evidence CLI without weakening required execution or cleanup."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fuzz_support.archives import (
    package_upload,
)
from fuzz_support.collection import (
    collect_corpus,
)
from fuzz_support.execution import (
    cleanup_result,
    execution_cache,
    finish_run,
    prepare_run,
    record_environment,
    record_target,
)
from fuzz_support.filesystem import (
    EVIDENCE_ERROR,
    invalid,
    validate_cargo_home_paths,
    validate_collection_roots,
    validate_restore_cargo_home,
)
from fuzz_support.recovery import (
    backup_cleanup,
    cleanup_cache,
    remove_cleanup,
    restore_cleanup,
)
from fuzz_support.source import (
    configured_cache,
    validate_compiler_environment,
    validate_evidence_route,
    validate_git_environment,
    validate_preflight,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--validate-git-environment", action="store_true")
    actions.add_argument("--validate-cache", type=Path)
    actions.add_argument("--validate-preflight", type=Path)
    actions.add_argument("--package-upload", type=Path)
    actions.add_argument("--cleanup-cache", nargs=2, metavar=("DIR", "RUN_ID"))
    actions.add_argument("--remove-cleanup", nargs=2, metavar=("DIR", "RUN_ID"))
    actions.add_argument("--execution-cache", type=Path)
    actions.add_argument("--prepare-run", type=Path)
    actions.add_argument("--record-environment", type=Path)
    actions.add_argument("--record-target", nargs=4, metavar=("DIR", "TARGET", "PHASE", "EXIT"))
    actions.add_argument("--finish-run", nargs=2, metavar=("DIR", "EXIT"))
    actions.add_argument("--cleanup-result", nargs=2, metavar=("DIR", "EXIT"))
    actions.add_argument("--backup-cleanup", type=Path)
    actions.add_argument("--restore-cleanup", nargs=4, metavar=("DIR", "RUN_ID", "EXIT", "REASON"))
    return parser.parse_args()


def cleanup_action(  # noqa: PLR0912, PLR0915 - one guarded dispatch for each cleanup action
    args: argparse.Namespace,
) -> int | None:
    result = None
    if args.validate_git_environment:
        validate_git_environment()
        result = 0
    elif args.validate_preflight:
        validate_preflight(args.validate_preflight)
        result = 0
    elif args.validate_cache:
        configured_cache(args.validate_cache)
        result = 0
    elif args.execution_cache:
        print(str(execution_cache(args.execution_cache)) + "\n.", end="")
        result = 0
    elif args.cleanup_cache:
        directory, run_id = args.cleanup_cache
        print(str(cleanup_cache(Path(directory), run_id)) + "\n.", end="")
        result = 0
    elif args.remove_cleanup:
        directory, run_id = args.remove_cleanup
        remove_cleanup(Path(directory), run_id)
        result = 0
    elif args.cleanup_result:
        directory, code = args.cleanup_result
        cleanup_result(Path(directory), int(code))
        result = 0
    elif args.backup_cleanup:
        print(backup_cleanup(args.backup_cleanup))
        result = 0
    elif args.restore_cleanup:
        directory, run_id, code, reason = args.restore_cleanup
        result = (
            0 if restore_cleanup(Path(directory), run_id, int(code), reason) else EVIDENCE_ERROR
        )
    return result


def validate_action_routes(args: argparse.Namespace) -> None:
    for name in (
        "prepare_run",
        "record_environment",
        "execution_cache",
        "validate_cache",
        "validate_preflight",
        "backup_cleanup",
    ):
        action = getattr(args, name)
        if action is not None:
            directory = validate_evidence_route(action)
            validate_cargo_home_paths([directory], "execution")
            setattr(args, name, directory)
            validate_collection_roots()
    for name in (
        "cleanup_cache",
        "remove_cleanup",
        "record_target",
        "finish_run",
        "cleanup_result",
    ):
        action = getattr(args, name)
        if action is not None:
            directory = validate_evidence_route(Path(action[0]))
            validate_cargo_home_paths([directory], "execution")
            action[0] = str(directory)
            validate_collection_roots()
    if args.restore_cleanup is not None:
        # Raw-root failures belong to restore_cleanup's recovery error handler.
        args.restore_cleanup[0] = str(validate_evidence_route(Path(args.restore_cleanup[0])))
        validate_restore_cargo_home(Path(args.restore_cleanup[0]))


def record_target_action(action: list[str]) -> int:
    directory, name, phase, code = action
    if phase not in ("build", "run"):
        invalid("unknown execution phase")
    return 0 if record_target(Path(directory), name, phase, int(code)) else 1


def main() -> int:
    args = parse_arguments()
    result = 0
    try:
        if args.package_upload:
            package_upload(args.package_upload)
            return 0
        validate_compiler_environment()
        validate_action_routes(args)
        recovery_result = cleanup_action(args)
        if recovery_result is not None:
            result = recovery_result
        elif args.prepare_run:
            prepare_run(args.prepare_run)
        elif args.record_environment:
            record_environment(args.record_environment)
        elif args.record_target:
            result = record_target_action(args.record_target)
        elif args.finish_run:
            directory, code = args.finish_run
            result = 0 if finish_run(Path(directory), int(code)) else 1
        else:
            collect_corpus()
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"[security] fuzz evidence failed: {error}", file=sys.stderr)
        result = EVIDENCE_ERROR
    return result
