"""Normal admission refuses known failures, incomplete observations and source races."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from check_merge_readiness import (
    MAIN_WORKFLOWS,
    MAX_PAGES,
    REPOSITORY,
    Reader,
    candidate,
    check,
    check_candidate_checks,
    check_candidate_runs,
    check_main_runs,
    check_statuses,
    main,
)

HEAD, BASE = "a" * 40, "b" * 40
ROOT = Path(__file__).resolve().parents[2]


def workflow(name="ci.yml", number=1):
    return {
        "id": number,
        "run_attempt": 1,
        "run_started_at": "2026-11-01T00:00:00Z",
        "updated_at": f"2026-11-01T00:00:{number % 60:02d}Z",
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "event": "push",
        "head_branch": "main",
        "head_sha": BASE,
        "path": f".github/workflows/{name}",
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{number}",
        "pull_requests": [{"number": 9}],
    }


def check_run(name="Required checks", number=1):
    return {
        "id": number,
        "app": {"id": 15368},
        "head_sha": HEAD,
        "name": name,
        "started_at": (
            datetime(2026, 11, 1, tzinfo=UTC) + timedelta(seconds=number * 2)
        ).isoformat(),
        "completed_at": (
            datetime(2026, 11, 1, tzinfo=UTC) + timedelta(seconds=number * 2 + 1)
        ).isoformat(),
        "status": "completed",
        "conclusion": "success",
        "details_url": f"https://github.com/{REPOSITORY}/actions/runs/1/job/{number}",
    }


def pull_request():
    return {
        "number": 9,
        "state": "open",
        "draft": False,
        "merged": False,
        "head": {"sha": HEAD, "repo": {"full_name": REPOSITORY}},
        "base": {"ref": "main", "repo": {"full_name": REPOSITORY}},
    }


def main_runs():
    return [workflow(name, i + 1) for i, name in enumerate(MAIN_WORKFLOWS)]


def candidate_runs():
    rows = [workflow("pr.yml", 10), workflow("infrastructure-validation.yml", 11)]
    for row in rows:
        row.update(event="pull_request", head_branch="topic", head_sha=HEAD)
    return rows


class MainHealthTests(unittest.TestCase):
    def test_older_run_retry_is_not_hidden_by_newer_success(self):
        for event in ["push", "schedule", "workflow_dispatch"]:
            for state, conclusion in [
                ("queued", None),
                ("in_progress", None),
                ("completed", "failure"),
            ]:
                old = workflow("ci.yml", 1) | {
                    "event": event,
                    "run_attempt": 2,
                    "status": state,
                    "conclusion": conclusion,
                    "updated_at": "2026-11-02T00:00:00Z",
                }
                newer = workflow("ci.yml", 100) | {"event": event}
                with pytest.raises(ValueError, match="successful CI"):
                    check_main_runs(
                        [*(main_runs()[1:] if event == "push" else main_runs()), old, newer], BASE
                    )

    def test_completion_order_inversion_cannot_hide_an_overlapping_failure(self):
        for event in ["push", "schedule", "workflow_dispatch", "dynamic"]:
            failure = workflow("ci.yml", 20) | {
                "event": event,
                "run_started_at": "2026-11-01T01:05:00Z",
                "updated_at": "2026-11-01T01:10:00Z",
                "conclusion": "failure",
            }
            for start in ["01:00:00", "01:07:00", "01:10:00"]:
                success = workflow("ci.yml", 10) | {
                    "event": event,
                    "run_attempt": 2,
                    "run_started_at": f"2026-11-01T{start}Z",
                    "updated_at": "2026-11-01T01:20:00Z",
                }
                with self.subTest(event=event, start=start):
                    with pytest.raises(ValueError, match="successful CI"):
                        check_main_runs([*main_runs(), failure, success], BASE)
                    if event != "push":
                        with pytest.raises(ValueError, match="successful CI"):
                            check_candidate_runs(
                                [
                                    *candidate_runs(),
                                    failure | {"head_sha": HEAD},
                                    success | {"head_sha": HEAD},
                                ],
                                pull_request(),
                            )
            success["run_started_at"] = "2026-11-01T01:10:01Z"
            assert check_main_runs([*main_runs(), failure, success], BASE)

    def test_full_main_inventory_succeeds_but_every_failure_kind_blocks(self):
        assert len(check_main_runs(main_runs(), BASE)) == len(MAIN_WORKFLOWS)
        for conclusion in ["failure", "cancelled", "timed_out", "skipped", "neutral", None]:
            rows = main_runs()
            rows[-2]["conclusion"] = conclusion  # performance.yml: PR293 failure condition
            with pytest.raises(ValueError, match="preview requires successful CI"):
                check_main_runs(rows, BASE)

    def test_missing_older_green_wrong_event_and_unknown_red_do_not_rescue(self):
        failed = workflow("performance.yml", 100)
        failed["conclusion"] = "failure"
        for rows in [[], main_runs()[:-1], [*main_runs(), failed]]:
            with pytest.raises(
                ValueError, match=r"no main-push run|preview requires successful CI"
            ):
                check_main_runs(rows, BASE)
        for field, value in [
            ("head_sha", HEAD),
            ("event", "merge_group"),
            ("head_branch", "topic"),
        ]:
            rows = main_runs()
            rows[0][field] = value
            with pytest.raises(
                ValueError, match=r"unexpected workflow run identity|no main-push run"
            ):
                check_main_runs(rows, BASE)
        failed["path"] = ".github/workflows/new-check.yml"
        with pytest.raises(ValueError, match="preview requires successful CI"):
            check_main_runs([*main_runs(), failed], BASE)

    def test_later_attempt_and_pending_run_override_previous_success(self):
        for state in ["queued", "in_progress", "waiting"]:
            rows = main_runs()
            retry = {**rows[0], "run_attempt": 2, "status": state, "conclusion": None}
            with pytest.raises(ValueError, match="preview requires successful CI"):
                check_main_runs([retry, *rows[1:]], BASE)

    def test_main_push_inventory_matches_workflows(self):
        actual = set()
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            trigger = yaml.safe_load(path.read_text()).get(True, {})
            push = trigger.get("push", {})
            if isinstance(push, dict) and "main" in push.get("branches", []):
                actual.add(path.name)
        assert set(MAIN_WORKFLOWS) == actual

    def test_actual_pr293_base_failure_and_current_main_success(self):
        history = json.loads((ROOT / "tests/ci/fixtures/merge_readiness_history.json").read_text())
        with pytest.raises(ValueError, match="41013155905"):
            check_main_runs(history["failed_main_runs"], history["failed_main"])
        selected = check_main_runs(history["successful_main_runs"], history["successful_main"])
        assert len(selected) == 9

    def test_push_success_does_not_hide_scheduled_or_manual_failure(self):
        for event in ["schedule", "workflow_dispatch", "dynamic"]:
            failed = {**workflow(number=100), "event": event, "conclusion": "failure"}
            with pytest.raises(ValueError, match="preview requires successful CI"):
                check_main_runs([*main_runs(), failed], BASE)


class CandidateTests(unittest.TestCase):
    def test_candidate_retry_manual_and_unrelated_pr_workflow_boundaries(self):
        for event in ["pull_request", "workflow_dispatch", "dynamic"]:
            for state, conclusion in [("queued", None), ("completed", "failure")]:
                retry = candidate_runs()[0] | {
                    "id": 1,
                    "run_attempt": 2,
                    "event": event,
                    "status": state,
                    "conclusion": conclusion,
                    "updated_at": "2026-11-02T00:00:00Z",
                }
                with pytest.raises(ValueError, match="successful CI"):
                    check_candidate_runs([retry, *candidate_runs()], pull_request())
        other = candidate_runs()[0] | {"pull_requests": [{"number": 10}], "conclusion": "failure"}
        assert len(check_candidate_runs([other, *candidate_runs()], pull_request())) == 2
        with pytest.raises(ValueError, match="inventory is incomplete"):
            check_candidate_runs([other], pull_request())

    def test_unrelated_fork_pr_does_not_supply_or_block_required_workflows(self):
        other = candidate_runs()[0] | {
            "pull_requests": [{"number": 10}],
            "head_repository": {"full_name": "another/aegaeon"},
        }
        assert len(check_candidate_runs([other, *candidate_runs()], pull_request())) == 2
        with pytest.raises(ValueError, match="another head repository"):
            check_candidate_runs([other | {"pull_requests": [{"number": 9}]}], pull_request())

    def test_candidate_collector_includes_non_pr_events_before_jobs_exist(self):
        record = {"status": "rejected", "observations": []}
        reader = Reader(record)
        manual = candidate_runs()[0] | {
            "event": "workflow_dispatch",
            "status": "queued",
            "conclusion": None,
        }

        def pages(endpoint, key):
            if "branch=main" in endpoint:
                return main_runs()
            if "actions/runs" in endpoint:
                return (
                    candidate_runs()
                    if "event=pull_request" in endpoint
                    else [*candidate_runs(), manual]
                )
            return [check_run()] if key == "check_runs" else []

        with (
            patch("check_merge_readiness.main_revision", return_value=BASE),
            patch.object(reader, "get", return_value=pull_request()),
            patch.object(reader, "pages", side_effect=pages),
            pytest.raises(ValueError, match="successful CI"),
        ):
            check(reader, 9, HEAD, record)

    def test_required_origin_success_and_other_failed_checks(self):
        assert check_candidate_checks([check_run()], HEAD)
        for update in [{"conclusion": "neutral"}, {"app": {"id": 1}}, {"head_sha": BASE}]:
            with pytest.raises(ValueError, match=r"Required checks|different source"):
                check_candidate_checks([{**check_run(), **update}], HEAD)
        red = {**check_run("OpenTofu modules and template contracts", 2), "conclusion": "failure"}
        with pytest.raises(ValueError, match="Candidate check is not clear"):
            check_candidate_checks([check_run(), red], HEAD)

    def test_new_failure_and_pending_block_without_erasing_history(self):
        old = check_run()
        for state in [("completed", "failure"), ("queued", None)]:
            new = {**old, "id": 2, "status": state[0], "conclusion": state[1]}
            with pytest.raises(ValueError, match="Required checks is not successful"):
                check_candidate_checks([old, new], HEAD)
        old["conclusion"] = "failure"
        rows = [old, check_run(number=2)]
        assert check_candidate_checks(rows, HEAD)[0]["id"] == 2
        assert rows[0]["conclusion"] == "failure"

    def test_same_name_other_application_cannot_hide_a_failure(self):
        failed = {**check_run("scan", 2), "conclusion": "failure"}
        different_app = {**check_run("scan", 3), "app": {"id": 42}}
        with pytest.raises(ValueError, match="Candidate check is not clear"):
            check_candidate_checks([check_run(), failed, different_app], HEAD)

    def test_external_check_updates_cannot_be_hidden_by_larger_ids(self):
        old = check_run("external", 2) | {"app": {"id": 42}}
        newer = check_run("external", 3) | {"app": {"id": 42}}
        for state in ["queued", "in_progress", "waiting"]:
            with pytest.raises(ValueError, match="Candidate check is not clear"):
                check_candidate_checks(
                    [check_run(), old | {"status": state, "conclusion": None}, newer], HEAD
                )
        failed = old | {"conclusion": "failure", "completed_at": newer["completed_at"]}
        with pytest.raises(ValueError, match="Candidate check is not clear"):
            check_candidate_checks([check_run(), failed, newer], HEAD)
        # A completed independent successor can supersede the failure; ID order cannot.
        successor = newer | {
            "id": 1,
            "started_at": "2026-11-02T00:00:00Z",
            "completed_at": "2026-11-02T00:00:01Z",
        }
        assert check_candidate_checks([check_run(), failed, successor], HEAD)

    def test_unassociated_same_head_run_does_not_disappear(self):
        for state, conclusion in [
            ("queued", None),
            ("completed", "failure"),
            ("completed", "success"),
        ]:
            unknown = candidate_runs()[0] | {
                "id": 77,
                "pull_requests": [],
                "status": state,
                "conclusion": conclusion,
            }
            with pytest.raises(ValueError, match="association"):
                check_candidate_runs([*candidate_runs(), unknown], pull_request())

    def test_conditional_check_skip_does_not_prove_recovery_from_failure(self):
        old = check_run("external", 2) | {"conclusion": "failure"}
        for conclusion in ["skipped", "neutral"]:
            current = check_run("external", 3) | {"conclusion": conclusion}
            with pytest.raises(ValueError, match="Candidate check is not clear"):
                check_candidate_checks([check_run(), old, current], HEAD)
            assert check_candidate_checks([check_run(), current], HEAD)

    def test_empty_pr_associations_cannot_authorize_a_fork_candidate(self):
        pr = pull_request()
        pr["head"]["repo"]["full_name"] = "fork/aegaeon"
        rows = [
            row | {"pull_requests": [], "head_repository": pr["head"]["repo"]}
            for row in candidate_runs()
        ]
        with pytest.raises(ValueError, match="association"):
            check_candidate_runs(rows, pr)
        associated = [row | {"pull_requests": [{"number": 9}]} for row in rows]
        assert len(check_candidate_runs(associated, pr)) == 2

    def test_status_failure_and_pending_block(self):
        for state in ["failure", "error", "pending"]:
            with pytest.raises(ValueError, match="Candidate commit status is not clear"):
                check_statuses([{"id": 1, "context": "external", "state": state}])

    def test_workflow_without_created_check_jobs_still_blocks(self):
        rows = candidate_runs()
        rows[0].update(status="queued", conclusion=None)
        with pytest.raises(ValueError, match="preview requires successful CI"):
            check_candidate_runs(rows, pull_request())
        with pytest.raises(ValueError, match="workflow inventory is incomplete"):
            check_candidate_runs(candidate_runs()[:1], pull_request())

    def test_wrong_pr_repository_or_event_is_not_evidence(self):
        for field, value in [
            ("pull_requests", [{"number": 10}]),
            ("head_repository", {"full_name": "other/repo"}),
            ("event", "merge_group"),
        ]:
            rows = candidate_runs()
            rows[0][field] = value
            with pytest.raises(
                ValueError,
                match=(
                    r"workflow identity|workflow event|another head repository|"
                    r"inventory is incomplete"
                ),
            ):
                check_candidate_runs(rows, pull_request())


class CollectionTests(unittest.TestCase):
    def record(self):
        return {"status": "rejected", "observations": []}

    def reader(self, record):
        reader = Reader(record)

        def get(endpoint):
            if endpoint == "git/ref/heads/main":
                return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": BASE}}
            return pull_request()

        def pages(endpoint, key):
            if "branch=main" in endpoint:
                return main_runs()
            if "actions/runs" in endpoint:
                return candidate_runs()
            return [check_run()] if key == "check_runs" else []

        self.enterContext(patch.object(reader, "get", side_effect=get))
        self.enterContext(patch.object(reader, "pages", side_effect=pages))
        return reader

    def test_normal_case_and_old_main_only_missing_guard_negative_control(self):
        record = self.record()
        reader = self.reader(record)
        check(reader, 9, HEAD, record)
        assert record["status"] == "normal-ci-clear"
        broken = main_runs()
        broken[-2]["conclusion"] = "failure"
        with (
            patch.object(
                reader, "pages", side_effect=[broken, [check_run()], [], candidate_runs()] * 2
            ),
            pytest.raises(ValueError, match="preview requires successful CI"),
        ):
            check(reader, 9, HEAD, self.record())
        # The old operation's candidate-only decision passes this same manufactured input.
        assert check_candidate_checks([check_run()], HEAD)

    def test_ref_head_and_run_changes_block(self):
        record = self.record()
        reader = self.reader(record)
        for update in [{"draft": True}, {"state": "closed"}, {"head": {"sha": BASE}}]:
            with (
                patch.object(reader, "get", return_value={**pull_request(), **update}),
                pytest.raises(
                    ValueError, match="Candidate is closed, draft, merged or has changed head"
                ),
            ):
                candidate(reader, 9, HEAD)
        with (
            patch("check_merge_readiness.main_revision", side_effect=[BASE, HEAD]),
            pytest.raises(ValueError, match="Main advanced"),
        ):
            check(reader, 9, HEAD, self.record())
        changed = candidate_runs()
        changed[0]["run_attempt"] = 2
        observations = [
            main_runs(),
            [check_run()],
            [],
            candidate_runs(),
            main_runs(),
            [check_run()],
            [],
            changed,
        ]
        with (
            patch.object(reader, "pages", side_effect=observations),
            pytest.raises(ValueError, match="inventory changed"),
        ):
            check(reader, 9, HEAD, self.record())

    def test_unselected_completed_attempt_changes_require_fresh_evidence(self):
        reader = self.reader(self.record())
        for lane in ["main", "candidate"]:
            old = workflow("ci.yml", 1) if lane == "main" else candidate_runs()[0]
            selected = old | {"id": 50, "updated_at": "2026-11-01T01:00:00Z"}
            changed = old | {"run_attempt": 2, "updated_at": "2026-11-01T00:30:00Z"}
            first_main = [*main_runs()[1:], old, selected] if lane == "main" else main_runs()
            next_main = [*main_runs()[1:], changed, selected] if lane == "main" else main_runs()
            first_candidate = (
                [*candidate_runs(), selected] if lane == "candidate" else candidate_runs()
            )
            next_candidate = (
                [changed, candidate_runs()[1], selected]
                if lane == "candidate"
                else candidate_runs()
            )
            with (
                patch.object(
                    reader,
                    "pages",
                    side_effect=[
                        first_main,
                        [check_run()],
                        [],
                        first_candidate,
                        next_main,
                        [check_run()],
                        [],
                        next_candidate,
                    ],
                ),
                pytest.raises(ValueError, match="inventory changed"),
            ):
                check(reader, 9, HEAD, self.record())

    def test_unselected_check_and_status_changes_require_fresh_evidence(self):
        reader = self.reader(self.record())
        checks = [check_run("external", 2), check_run("external", 3), check_run()]
        statuses = [{"id": n, "context": "external", "state": "success"} for n in [1, 2]]
        for lane in ["checks", "statuses"]:
            next_checks = [row.copy() for row in checks]
            next_statuses = [row.copy() for row in statuses]
            if lane == "checks":
                next_checks[0]["completed_at"] = "2026-11-01T00:00:05.1Z"
            else:
                next_statuses = next_statuses[1:]
            with (
                patch.object(
                    reader,
                    "pages",
                    side_effect=[
                        main_runs(),
                        checks,
                        statuses,
                        candidate_runs(),
                        main_runs(),
                        next_checks,
                        next_statuses,
                        candidate_runs(),
                    ],
                ),
                pytest.raises(ValueError, match="inventory changed"),
            ):
                check(reader, 9, HEAD, self.record())

    def test_pagination_completeness_and_budget(self):
        reader = Reader(self.record())
        with (
            patch.object(reader, "get", return_value={"total_count": 1, "check_runs": []}),
            pytest.raises(ValueError, match="Incomplete"),
        ):
            reader.pages("checks", "check_runs")
        with (
            patch.object(reader, "get", return_value=[{}] * 100) as call,
            pytest.raises(ValueError, match="page budget"),
        ):
            reader.pages("statuses", None)
        assert call.call_count == MAX_PAGES

    def test_duplicate_page_rows_are_not_complete_evidence(self):
        reader = Reader(self.record())
        response = {"total_count": 2, "check_runs": [{"id": 1}, {"id": 1}]}
        with (
            patch.object(reader, "get", return_value=response),
            pytest.raises(ValueError, match="Duplicate GitHub rows"),
        ):
            reader.pages("checks", "check_runs")

    def test_api_timeout_rejects_and_cli_preserves_failure(self):
        for error in [subprocess.TimeoutExpired("gh", 30), ValueError("Malformed API response")]:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "result.json"
                argv = ["guard", "--pr", "9", "--head", HEAD, "--output", str(output)]
                with patch("sys.argv", argv), patch.object(Reader, "get", side_effect=error):
                    assert main() == 1
                    assert json.loads(output.read_text())["status"] == "rejected"
                    with pytest.raises(FileExistsError):
                        main()

    def test_api_deadline_and_get_only_transport(self):
        reader = Reader(self.record())
        reader.deadline = 0
        with patch("check_merge_readiness.subprocess.run") as run:
            with pytest.raises(ValueError, match="deadline"):
                reader.get("git/ref/heads/main")
            run.assert_not_called()
        reader = Reader(self.record())
        with patch("check_merge_readiness.subprocess.run") as run:
            run.return_value.stdout = "{}"
            reader.get("git/ref/heads/main")
            assert run.call_args.args[0] == ["gh", "api", f"repos/{REPOSITORY}/git/ref/heads/main"]
            assert run.call_args.kwargs["timeout"] <= 30
