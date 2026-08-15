"""End-to-end tests for the ingest -> fingerprint -> detect -> categorize pipeline."""

from __future__ import annotations

import json

import pytest

from flakectl.detector import SCHEMA, RerunHistory
from flakectl.models import Verdict
from flakectl.pipeline import PipelineConfig, analyze, ingest
from flakectl.store import Store

SPEC = "Podman run networking [It] podman run --net=host"

GINKGO_LOG = f"""\
Running Suite: Podman E2E Suite - /var/tmp/go/src/github.com/containers/podman/test/e2e
------------------------------
• [FAILED] [10.523 seconds]
{SPEC}
/var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:412

  [FAILED] Error: unable to connect: dial tcp 10.88.0.14:39251: i/o timeout
  In [It] at: /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431
------------------------------

Summarizing 1 Failure:
  [FAIL] {SPEC}
  /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431

Ran 512 of 600 Specs in 1823.456 seconds
FAIL! -- 511 Passed | 1 Failed | 0 Pending | 88 Skipped
"""


@pytest.fixture
def log(tmp_path) -> str:
    path = tmp_path / "int_fedora41.log"
    path.write_text(GINKGO_LOG, encoding="utf-8")
    return str(path)


@pytest.fixture
def history(tmp_path) -> RerunHistory:
    return RerunHistory.from_dict(
        {
            "schema": SCHEMA,
            "runs": [
                {
                    "run_id": 1,
                    "head_sha": "a1b2c3d4e5f6",
                    "log": "int_fedora41.log",
                    "job": "int podman fedora-41 root host sqlite",
                    "os": "fedora-41",
                    "jobs": [
                        {
                            "name": "int podman fedora-41 root host sqlite",
                            "attempts": [
                                {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
                                {"attempt": 2, "conclusion": "success", "failed_tests": []},
                            ],
                        }
                    ],
                }
            ],
        }
    )


def test_ingest_attaches_job_metadata_from_history(log, history) -> None:
    records = ingest([log], history=history)
    assert len(records) == 1
    failure, run, source = records[0]
    assert failure.job == "int podman fedora-41 root host sqlite"
    assert failure.os == "fedora-41"
    assert run is not None
    assert source == log


def test_ingest_prefers_junit_records(tmp_path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        '<testsuite name="S" tests="1" failures="1">'
        '<testcase name="t"><failure message="boom"/></testcase></testsuite>',
        encoding="utf-8",
    )
    records = ingest(junit_paths=[str(xml)])
    assert records[0][0].source_format == "junit"


def test_full_pipeline_categorizes_offline(log, history) -> None:
    report = analyze([log], history=history, config=PipelineConfig())

    assert report.total_failures == 1
    triaged = report.triaged[0]
    assert triaged.analysis.category == "network_timeout"
    assert triaged.analysis.provider == "rules"
    assert triaged.analysis.rule_id == "net-dial-timeout"
    assert triaged.verdict is Verdict.CONFIRMED_FLAKE
    assert triaged.is_new_signature is True
    assert triaged.analysis.needs_human is False


def test_pipeline_records_provenance(log) -> None:
    report = analyze([log], config=PipelineConfig())
    assert report.provider == "rules"
    assert report.prompt_version == "v1"
    assert report.generated_at


def test_second_run_reuses_the_cached_analysis(tmp_path, log, history) -> None:
    """The dedup claim, exercised end to end against a persistent store."""
    db = str(tmp_path / "flakectl.db")
    config = PipelineConfig(db_path=db)

    first = analyze([log], history=history, config=config)
    second = analyze([log], history=history, config=config)

    assert first.cached_analyses == 0
    assert second.cached_analyses == 1
    assert second.triaged[0].occurrences == 2
    assert second.triaged[0].is_new_signature is False
    assert second.triaged[0].analysis.cached is True


def test_dedup_ratio_counts_distinct_signatures(tmp_path, history) -> None:
    """The same flake in two jobs is two failures but one signature."""
    first = tmp_path / "int_fedora41.log"
    first.write_text(GINKGO_LOG, encoding="utf-8")
    second = tmp_path / "int_rawhide.log"
    second.write_text(GINKGO_LOG.replace("10.88.0.14:39251", "10.88.4.201:51022"), encoding="utf-8")

    report = analyze([str(first), str(second)], history=history, config=PipelineConfig())

    assert report.total_failures == 2
    assert report.distinct_fingerprints == 1
    assert report.dedup_ratio == pytest.approx(2.0)
    assert report.cached_analyses == 1


def test_a_reproducible_failure_is_flagged_for_a_human(tmp_path) -> None:
    log = tmp_path / "regression.log"
    log.write_text(
        GINKGO_LOG.replace(
            "Error: unable to connect: dial tcp 10.88.0.14:39251: i/o timeout",
            "Expected <string>: v5.2.0 to equal <string>: v5.3.0",
        ),
        encoding="utf-8",
    )
    history = RerunHistory.from_dict(
        {
            "runs": [
                {
                    "run_id": 2,
                    "log": "regression.log",
                    "job": "int podman fedora-41 root",
                    "jobs": [
                        {
                            "name": "int podman fedora-41 root",
                            "attempts": [
                                {"attempt": 1, "conclusion": "failure", "failed_tests": [SPEC]},
                                {"attempt": 2, "conclusion": "failure", "failed_tests": [SPEC]},
                            ],
                        }
                    ],
                }
            ]
        }
    )

    report = analyze([str(log)], history=history, config=PipelineConfig())
    triaged = report.triaged[0]

    assert triaged.verdict is Verdict.REAL_FAILURE
    assert triaged.analysis.category == "real_regression"
    assert triaged.analysis.is_likely_regression is True
    assert triaged.analysis.needs_human is True
    assert report.likely_regressions == [triaged]


def test_pipeline_accepts_an_open_store(log) -> None:
    with Store() as store:
        analyze([log], config=PipelineConfig(), store=store)
        assert store.failure_count() == 1
        # The store is still usable — the pipeline did not close it.
        assert store.fingerprint_count() == 1


def test_a_passing_log_produces_an_empty_report(tmp_path) -> None:
    path = tmp_path / "green.log"
    path.write_text("Ran 10 of 10 Specs\nSUCCESS! -- 10 Passed | 0 Failed\n", encoding="utf-8")
    report = analyze([str(path)], config=PipelineConfig())

    assert report.total_failures == 0
    assert report.dedup_ratio == 0.0


def test_history_json_round_trips_through_a_file(tmp_path, log) -> None:
    path = tmp_path / "history.json"
    path.write_text(
        json.dumps(
            {
                "schema": SCHEMA,
                "runs": [
                    {
                        "run_id": 3,
                        "log": "int_fedora41.log",
                        "job": "int podman fedora-41 root",
                        "jobs": [
                            {
                                "name": "int podman fedora-41 root",
                                "attempts": [
                                    {
                                        "attempt": 1,
                                        "conclusion": "failure",
                                        "failed_tests": [SPEC],
                                    },
                                    {"attempt": 2, "conclusion": "success"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    report = analyze([log], history=RerunHistory.load(str(path)), config=PipelineConfig())
    assert report.triaged[0].verdict is Verdict.CONFIRMED_FLAKE
