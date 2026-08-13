"""The sample corpus is part of the contract: the demo has to stay green.

These tests pin the categorization of every shipped sample, so a rule or
normaliser change that would quietly break `make demo` fails here first.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flakectl.detector import RerunHistory
from flakectl.models import Verdict
from flakectl.pipeline import PipelineConfig, analyze

SAMPLES = Path(__file__).resolve().parent.parent / "samples"

#: log file -> (expected category, expected re-run verdict)
EXPECTED = {
    "int_fedora41_real_regression.log": ("real_regression", Verdict.REAL_FAILURE),
    "int_fedora41_race_timing.log": ("race_timing", Verdict.CONFIRMED_FLAKE),
    "int_rawhide_infra_registry.log": ("infrastructure", Verdict.CONFIRMED_FLAKE),
    "int_fedora41_test_pollution.log": ("test_pollution", Verdict.CONFIRMED_FLAKE),
    "int_rawhide_env_drift.log": ("environment_drift", Verdict.REAL_FAILURE),
    "sys_fedora41_network_timeout.log": ("network_timeout", Verdict.CONFIRMED_FLAKE),
}


@pytest.fixture(scope="module")
def history() -> RerunHistory:
    return RerunHistory.load(str(SAMPLES / "history.json"))


@pytest.mark.parametrize(("log_name", "expected"), sorted(EXPECTED.items()))
def test_each_sample_lands_on_its_intended_category(
    log_name: str, expected: tuple[str, Verdict], history: RerunHistory
) -> None:
    report = analyze(
        [str(SAMPLES / log_name)], history=history, config=PipelineConfig()
    )
    assert report.total_failures == 1, f"{log_name} should produce exactly one failure"

    triaged = report.triaged[0]
    category, verdict = expected
    assert triaged.analysis.category == category
    assert triaged.verdict is verdict
    assert triaged.analysis.evidence, "every categorization must cite evidence"


def test_the_taxonomy_is_fully_exercised_by_the_corpus() -> None:
    """Every non-abstain category has at least one sample."""
    from flakectl.taxonomy import default_taxonomy

    covered = {category for category, _ in EXPECTED.values()}
    expected = {c.name for c in default_taxonomy() if not c.abstain}
    assert covered == expected


def test_the_regression_sample_is_flagged_and_escalated(history: RerunHistory) -> None:
    report = analyze(
        [str(SAMPLES / "int_fedora41_real_regression.log")],
        history=history,
        config=PipelineConfig(),
    )
    analysis = report.triaged[0].analysis
    assert analysis.is_likely_regression is True
    assert analysis.needs_human is True


def test_environment_drift_reproduces_but_is_not_a_regression(history: RerunHistory) -> None:
    """The distinction the baseline comparison exists to make.

    Both this and the regression sample fail on every attempt. Only one of
    them was caused by the change under test.
    """
    report = analyze(
        [str(SAMPLES / "int_rawhide_env_drift.log")], history=history, config=PipelineConfig()
    )
    triaged = report.triaged[0]

    assert triaged.verdict is Verdict.REAL_FAILURE
    assert triaged.analysis.is_likely_regression is False
    assert "not the cause" in triaged.notes[0]


def test_the_junit_artifact_parses_and_categorizes(history: RerunHistory) -> None:
    report = analyze(
        junit_paths=[str(SAMPLES / "junit_int_remote.xml")],
        history=history,
        config=PipelineConfig(),
    )
    categories = {item.analysis.category for item in report.triaged}

    assert report.total_failures == 2
    assert categories == {"infrastructure", "test_pollution"}
    assert all(item.failure.source_format == "junit" for item in report.triaged)
    assert all(item.failure.job for item in report.triaged)


def test_the_whole_corpus_runs_green_offline(history: RerunHistory) -> None:
    """What `make demo` does, asserted."""
    logs = [str(path) for path in sorted(SAMPLES.glob("*.log"))]
    report = analyze(
        logs,
        [str(SAMPLES / "junit_int_remote.xml")],
        history=history,
        config=PipelineConfig(),
    )

    assert report.total_failures == 8
    assert report.provider == "rules"
    # Exactly one regression across the corpus, and it is not absorbed as a flake.
    assert len(report.likely_regressions) == 1
    assert report.likely_regressions[0].analysis.category == "real_regression"


def test_the_agent_can_read_the_sample_test_sources() -> None:
    """get_test_source is what distinguishes a sleep-based wait from a race."""
    from flakectl.tools import ToolLayer

    tools = ToolLayer(source_root=SAMPLES / "src")
    source = tools.call(
        "get_test_source",
        {
            "spec_file": "/var/tmp/go/src/github.com/containers/podman/test/e2e/"
            "healthcheck_run_test.go",
            "line": 55,
            "context": 30,
        },
    )
    assert "time.Sleep(2 * time.Second)" in source
    assert "Eventually" in source


def test_the_sample_issue_index_is_searchable() -> None:
    import json

    from flakectl.tools import ToolLayer

    issues = json.loads((SAMPLES / "issues.json").read_text(encoding="utf-8"))
    tools = ToolLayer(issues=issues)
    assert "21456" in tools.call("search_issues", {"query": "pasta namespace rootless"})


def test_the_sample_change_history_is_searchable() -> None:
    import json

    from flakectl.tools import ToolLayer

    changes = json.loads((SAMPLES / "recent_changes.json").read_text(encoding="utf-8"))
    tools = ToolLayer(changes=changes)
    result = tools.call("recent_changes", {"path": "cmd/podman/kube"})
    assert "rename --validate" in result
