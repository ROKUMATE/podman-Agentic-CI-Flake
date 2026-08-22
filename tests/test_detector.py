"""Tests for the re-run flake detector (pure logic, no network, no model)."""

from __future__ import annotations

import pytest

from flakectl.detector import SCHEMA, HistoryError, RerunHistory, detect
from flakectl.models import Failure, Verdict

SPEC = "Podman run networking [It] podman run --net=host --add-host"
JOB = "int podman fedora-41 root host sqlite"


def failure(name: str = SPEC, job: str | None = JOB) -> Failure:
    return Failure(test_name=name, output_block="[FAILED] boom", job=job)


def history(*, attempts: list[dict], baseline: list[dict] | None = None) -> RerunHistory:
    return RerunHistory.from_dict(
        {
            "schema": SCHEMA,
            "runs": [
                {
                    "run_id": 1712345678,
                    "head_sha": "a1b2c3d4e5f60718293a",
                    "base_sha": "0000111122223333",
                    "log": "run.log",
                    "job": JOB,
                    "jobs": [{"name": JOB, "attempts": attempts}],
                }
            ],
            "baseline": baseline or [],
        }
    )


def test_failed_then_passed_at_same_sha_is_a_confirmed_flake() -> None:
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
            {"attempt": 2, "conclusion": "success", "failed_tests": []},
        ]
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.verdict is Verdict.CONFIRMED_FLAKE
    assert result.passed_on_attempt == 2
    assert result.attempts_seen == 2
    assert "passed on attempt 2" in result.reason


def test_failing_on_every_attempt_is_a_real_failure() -> None:
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
            {"attempt": 2, "conclusion": "failure", "failed_tests": [SPEC]},
        ]
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.verdict is Verdict.REAL_FAILURE
    assert "failed on all 2 attempts" in result.reason


def test_single_attempt_is_unknown_not_a_guess() -> None:
    hist = history(attempts=[{"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]}])
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.verdict is Verdict.UNKNOWN
    assert "no re-run to compare against" in result.reason


def test_no_history_at_all_is_unknown() -> None:
    result = detect(failure(), None, None)
    assert result.verdict is Verdict.UNKNOWN
    assert result.attempts_seen == 0


def test_a_later_attempt_still_failing_others_does_not_break_the_flake_call() -> None:
    """Attempt 2 fails a *different* spec; ours passed, so ours is a flake."""
    other = "Podman pod create [It] podman pod create --infra-name"
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC, other]},
            {"attempt": 2, "conclusion": "failure", "failed_tests": [other]},
        ]
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.verdict is Verdict.CONFIRMED_FLAKE
    assert result.passed_on_attempt == 2


def test_rerun_signal_is_scoped_to_the_same_job() -> None:
    """Passing in a different job is not a re-run and proves nothing."""
    hist = RerunHistory.from_dict(
        {
            "schema": SCHEMA,
            "runs": [
                {
                    "run_id": 1,
                    "log": "run.log",
                    "jobs": [
                        {
                            "name": JOB,
                            "attempts": [
                                {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]}
                            ],
                        },
                        {
                            "name": "int podman rawhide rootless",
                            "attempts": [{"attempt": 2, "conclusion": "success"}],
                        },
                    ],
                }
            ],
        }
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))
    assert result.verdict is Verdict.UNKNOWN


def test_matching_accepts_the_file_qualified_identity() -> None:
    qualified = "test/e2e/run_networking_test.go::" + SPEC
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [qualified]},
            {"attempt": 2, "conclusion": "success", "failed_tests": []},
        ]
    )
    item = Failure(
        test_name=SPEC,
        output_block="boom",
        job=JOB,
        spec_file="test/e2e/run_networking_test.go",
    )
    assert detect(item, hist, hist.run_for_log("run.log")).verdict is Verdict.CONFIRMED_FLAKE


def test_baseline_failure_on_main_marks_the_change_innocent() -> None:
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
            {"attempt": 2, "conclusion": "failure", "failed_tests": [SPEC]},
        ],
        baseline=[
            {"test": SPEC, "conclusion": "failure", "base_sha": "0000111122223333", "branch": "main"}
        ],
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.verdict is Verdict.REAL_FAILURE
    assert result.caused_by_change is False
    assert "not the cause" in result.reason


def test_baseline_pass_on_main_leaves_the_change_implicated() -> None:
    hist = history(
        attempts=[
            {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
            {"attempt": 2, "conclusion": "failure", "failed_tests": [SPEC]},
        ],
        baseline=[
            {"test": SPEC, "conclusion": "success", "base_sha": "0000111122223333", "branch": "main"}
        ],
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))

    assert result.caused_by_change is True
    assert "passes on main" in result.reason


def test_baseline_is_ignored_when_the_base_commit_differs() -> None:
    hist = history(
        attempts=[{"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]}],
        baseline=[{"test": SPEC, "conclusion": "failure", "base_sha": "deadbeef"}],
    )
    result = detect(failure(), hist, hist.run_for_log("run.log"))
    assert result.caused_by_change is None


def test_unknown_log_name_has_no_run() -> None:
    hist = history(attempts=[{"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]}])
    assert hist.run_for_log("nope.log") is None


def test_log_name_matches_a_path_suffix() -> None:
    hist = RerunHistory.from_dict(
        {"runs": [{"run_id": 1, "log": "samples/race.log", "jobs": []}]}
    )
    assert hist.run_for_log("race.log") is not None


def test_unsupported_schema_is_rejected() -> None:
    with pytest.raises(HistoryError):
        RerunHistory.from_dict({"schema": "something/else", "runs": []})
