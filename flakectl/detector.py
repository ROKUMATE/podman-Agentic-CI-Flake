"""Pillar 2 — decide flake vs real failure from re-run history alone.

The strongest flake signal is free. A job that failed on attempt N and
passed on attempt N+1 for the same commit SHA is, by definition,
non-deterministic; ``/runs/{id}/attempts/{n}`` gives us that without any
model call. This module is pure logic over that history — no network, no
LLM, fully testable.

A secondary signal compares the failing test against ``main`` at the same
base commit. That one does not prove flakiness, so it never upgrades the
verdict on its own; it only records whether the change under test can be
responsible, which the categorizer later uses when weighing
``is_likely_regression``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from flakectl.models import Failure, Verdict

#: Recognised history schema identifier.
SCHEMA = "flakectl/history/v1"

_PASSING_CONCLUSIONS = {"success", "passed", "ok"}


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Why the detector reached the verdict it did.

    ``caused_by_change`` is deliberately tri-state: ``None`` means we have
    no baseline to compare against, which is different from knowing the
    change is innocent.
    """

    verdict: Verdict
    reason: str
    attempts_seen: int = 0
    passed_on_attempt: int | None = None
    caused_by_change: bool | None = None


@dataclass(slots=True)
class Attempt:
    """One re-run of a workflow run, at the same head SHA."""

    attempt: int
    conclusion: str
    failed_tests: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.conclusion.lower() in _PASSING_CONCLUSIONS


@dataclass(slots=True)
class JobHistory:
    """Per-job attempt history within a single workflow run."""

    name: str
    attempts: list[Attempt] = field(default_factory=list)


@dataclass(slots=True)
class Run:
    """A workflow run, its attempts, and the log file it produced."""

    run_id: int | str
    head_sha: str | None = None
    base_sha: str | None = None
    branch: str | None = None
    log: str | None = None
    job: str | None = None
    os: str | None = None
    jobs: list[JobHistory] = field(default_factory=list)


@dataclass(slots=True)
class BaselineResult:
    """Outcome of the same test on another branch at a known base commit."""

    test: str
    conclusion: str
    base_sha: str | None = None
    branch: str = "main"
    job: str | None = None

    @property
    def passed(self) -> bool:
        return self.conclusion.lower() in _PASSING_CONCLUSIONS


class HistoryError(ValueError):
    """Raised when a history document cannot be understood."""


@dataclass(slots=True)
class RerunHistory:
    """Re-run history for a set of workflow runs.

    Mirrors what the Actions API supplies: runs, their attempts, the jobs in
    each attempt, and which tests failed in each. In production this is
    fetched and cached; here it is a JSON file.
    """

    runs: list[Run] = field(default_factory=list)
    baseline: list[BaselineResult] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RerunHistory:
        """Build a history from a parsed JSON document."""
        schema = data.get("schema")
        if schema is not None and schema != SCHEMA:
            raise HistoryError(f"unsupported history schema {schema!r}, expected {SCHEMA!r}")

        runs: list[Run] = []
        for raw_run in data.get("runs", []):
            jobs = [
                JobHistory(
                    name=raw_job["name"],
                    attempts=[
                        Attempt(
                            attempt=int(raw_attempt["attempt"]),
                            conclusion=str(raw_attempt.get("conclusion", "failure")),
                            failed_tests=tuple(raw_attempt.get("failed_tests", ())),
                        )
                        for raw_attempt in raw_job.get("attempts", [])
                    ],
                )
                for raw_job in raw_run.get("jobs", [])
            ]
            runs.append(
                Run(
                    run_id=raw_run.get("run_id", "unknown"),
                    head_sha=raw_run.get("head_sha"),
                    base_sha=raw_run.get("base_sha"),
                    branch=raw_run.get("branch"),
                    log=raw_run.get("log"),
                    job=raw_run.get("job"),
                    os=raw_run.get("os"),
                    jobs=jobs,
                )
            )

        baseline = [
            BaselineResult(
                test=raw["test"],
                conclusion=str(raw.get("conclusion", "success")),
                base_sha=raw.get("base_sha"),
                branch=raw.get("branch", "main"),
                job=raw.get("job"),
            )
            for raw in data.get("baseline", [])
        ]
        return cls(runs=runs, baseline=baseline)

    @classmethod
    def load(cls, path: str) -> RerunHistory:
        """Read a history JSON file from disk."""
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(json.load(handle))

    @classmethod
    def empty(cls) -> RerunHistory:
        """A history with nothing in it — every verdict becomes ``unknown``."""
        return cls()

    def run_for_log(self, log_name: str) -> Run | None:
        """Find the run that produced ``log_name``.

        The log file is this proof-of-concept's stand-in for a job id; in
        production the failure record already knows which job it came from.
        """
        for run in self.runs:
            if run.log and (run.log == log_name or run.log.endswith(f"/{log_name}")):
                return run
        return None


def _matches(failure: Failure, recorded: str) -> bool:
    """Does a recorded failed-test name refer to this failure?

    History may record either the bare spec name or the file-qualified
    identity, so accept both.
    """
    return recorded in {failure.test_name, failure.identity}


def _relevant_jobs(run: Run, failure: Failure) -> list[JobHistory]:
    """Jobs whose attempts can speak to this failure.

    A re-run signal only counts within the same job: a spec that fails
    rootless on Fedora and passes rootful on RHEL is not thereby a flake.
    """
    job_name = failure.job or run.job
    if job_name:
        scoped = [job for job in run.jobs if job.name == job_name]
        if scoped:
            return scoped
    return run.jobs


def _baseline_for(history: RerunHistory, failure: Failure, run: Run | None) -> BaselineResult | None:
    base_sha = run.base_sha if run else None
    for entry in history.baseline:
        if not _matches(failure, entry.test):
            continue
        if base_sha and entry.base_sha and entry.base_sha != base_sha:
            continue
        return entry
    return None


def detect(
    failure: Failure,
    history: RerunHistory | None = None,
    run: Run | None = None,
) -> DetectionResult:
    """Classify a failure's pass/fail pattern across re-runs.

    Args:
        failure: The failure to judge.
        history: Re-run history; ``None`` or empty yields ``unknown``.
        run: The run that produced this failure. Looked up from the
            failure's log name by the caller when not supplied.

    Returns:
        A :class:`DetectionResult`. ``confirmed_flake`` means the same test
        at the same SHA both failed and passed. ``real_failure`` means it
        failed on every attempt. Anything less is ``unknown`` — the detector
        does not guess, it defers to the categorizer.
    """
    if history is None:
        history = RerunHistory.empty()

    if run is None:
        return DetectionResult(
            verdict=Verdict.UNKNOWN,
            reason="no run history available for this log",
        )

    attempts: list[Attempt] = []
    for job in _relevant_jobs(run, failure):
        attempts.extend(job.attempts)
    attempts.sort(key=lambda item: item.attempt)

    failed_on: list[int] = []
    passed_on: list[int] = []
    for attempt in attempts:
        if any(_matches(failure, name) for name in attempt.failed_tests):
            failed_on.append(attempt.attempt)
        elif attempt.passed:
            # The whole job went green, so every test in it passed.
            passed_on.append(attempt.attempt)
        elif attempt.failed_tests:
            # Per-test data exists and ours is not in it: this test passed
            # even though the attempt failed on some other spec.
            passed_on.append(attempt.attempt)
        # Otherwise the attempt failed with no per-test detail: no signal.

    baseline = _baseline_for(history, failure, run)
    caused_by_change: bool | None = None
    baseline_note = ""
    if baseline is not None:
        caused_by_change = baseline.passed
        baseline_note = (
            f"; also fails on {baseline.branch} at the same base commit, "
            "so the change under test is not the cause"
            if not baseline.passed
            else f"; passes on {baseline.branch} at the same base commit"
        )

    if failed_on and passed_on and max(passed_on) > min(failed_on):
        first_pass = min(a for a in passed_on if a > min(failed_on))
        return DetectionResult(
            verdict=Verdict.CONFIRMED_FLAKE,
            reason=(
                f"failed on attempt {min(failed_on)} and passed on attempt {first_pass} "
                f"at the same commit {(run.head_sha or '')[:12]}".rstrip()
                + baseline_note
            ),
            attempts_seen=len(attempts),
            passed_on_attempt=first_pass,
            caused_by_change=caused_by_change,
        )

    if len(failed_on) >= 2 and not passed_on:
        return DetectionResult(
            verdict=Verdict.REAL_FAILURE,
            reason=(
                f"failed on all {len(failed_on)} attempts at the same commit "
                f"{(run.head_sha or '')[:12]}".rstrip() + baseline_note
            ),
            attempts_seen=len(attempts),
            caused_by_change=caused_by_change,
        )

    if not attempts:
        reason = "no attempts recorded for this job"
    elif not failed_on:
        reason = "this test is not named in any recorded attempt"
    else:
        reason = (
            f"only {len(failed_on)} failing attempt with usable data; "
            "no re-run to compare against"
        )

    return DetectionResult(
        verdict=Verdict.UNKNOWN,
        reason=reason + baseline_note,
        attempts_seen=len(attempts),
        caused_by_change=caused_by_change,
    )
