"""CLI tests. Everything here runs offline: no API key, no network."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from flakectl import __version__
from flakectl.cli import app

runner = CliRunner()

SPEC = "Podman run networking [It] podman run --net=host"

GINKGO_LOG = f"""\
Running Suite: Podman E2E Suite - /var/tmp/go/src/github.com/containers/podman/test/e2e
------------------------------
• [FAILED] [10.523 seconds]
{SPEC}
/var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:412

  [FAILED] Error: initializing source docker://quay.io/libpod/alpine: toomanyrequests: Rate exceeded
  In [It] at: /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431
------------------------------

Summarizing 1 Failure:
  [FAIL] {SPEC}
  /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431

Ran 10 of 10 Specs in 12.000 seconds
FAIL! -- 9 Passed | 1 Failed | 0 Pending | 0 Skipped
"""


@pytest.fixture
def log(tmp_path) -> str:
    path = tmp_path / "int_fedora41.log"
    path.write_text(GINKGO_LOG, encoding="utf-8")
    return str(path)


@pytest.fixture
def history_file(tmp_path) -> str:
    path = tmp_path / "history.json"
    path.write_text(
        json.dumps(
            {
                "schema": "flakectl/history/v1",
                "runs": [
                    {
                        "run_id": 1,
                        "log": "int_fedora41.log",
                        "job": "int podman fedora-41 root host sqlite",
                        "os": "fedora-41",
                        "jobs": [
                            {
                                "name": "int podman fedora-41 root host sqlite",
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
    return str(path)


def test_version_prints_the_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_bare_invocation_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Triage Podman CI test failures" in result.stdout


def test_ingest_reports_fingerprints_without_categorizing(log) -> None:
    result = runner.invoke(app, ["ingest", log])
    assert result.exit_code == 0
    assert "Podman run networking" in result.stdout
    assert "1 failure(s), 1 distinct signature(s)." in result.stdout
    assert "signature:" in result.stdout
    # No categorization happened.
    assert "infrastructure" not in result.stdout


def test_ingest_on_a_green_log(tmp_path) -> None:
    path = tmp_path / "green.log"
    path.write_text("SUCCESS! -- 10 Passed | 0 Failed\n", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(path)])
    assert result.exit_code == 0
    assert "No failures found." in result.stdout


def test_analyze_runs_offline_and_writes_a_report(tmp_path, log, history_file) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", log, "--history", history_file, "--offline", "--out", str(out)]
    )

    assert result.exit_code == 0, result.stdout
    assert "infrastructure" in result.stdout
    assert "provider=rules" in result.stdout
    assert out.exists()

    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "flakectl/report/v1"
    assert data["failures"][0]["analysis"]["category"] == "infrastructure"
    assert data["failures"][0]["verdict"] == "confirmed_flake"
    assert data["generated_by"]["dry_run"] is True


def test_analyze_requires_an_input() -> None:
    result = runner.invoke(app, ["analyze"])
    assert result.exit_code != 0
    assert "at least one log file" in result.output


def test_analyze_rejects_an_unknown_provider(log) -> None:
    result = runner.invoke(app, ["analyze", log, "--online", "--provider", "gpt"])
    assert result.exit_code != 0
    assert "unknown provider" in result.output


def test_analyze_rejects_an_unreadable_history(tmp_path, log) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    result = runner.invoke(app, ["analyze", log, "--history", str(bad)])
    assert result.exit_code != 0
    assert "could not read history" in result.output


def test_analyze_accepts_a_junit_report(tmp_path) -> None:
    xml = tmp_path / "junit.xml"
    xml.write_text(
        '<testsuite name="Podman E2E Suite" tests="1" failures="1">'
        '<testcase name="podman pull"><failure message="toomanyrequests: Rate exceeded"/>'
        "</testcase></testsuite>",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    result = runner.invoke(app, ["analyze", "--junit", str(xml), "--out", str(out)])

    assert result.exit_code == 0, result.stdout
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["failures"][0]["source_format"] == "junit"
    assert data["failures"][0]["analysis"]["category"] == "infrastructure"


def test_min_confidence_gate_can_force_abstention(tmp_path, log) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", log, "--min-confidence", "0.99", "--out", str(out)]
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["failures"][0]["analysis"]["category"] == "unknown"
    assert data["failures"][0]["analysis"]["needs_human"] is True


def test_report_renders_a_markdown_digest(tmp_path, log, history_file) -> None:
    report_path = tmp_path / "report.json"
    runner.invoke(app, ["analyze", log, "--history", history_file, "--out", str(report_path)])

    digest = tmp_path / "weekly.md"
    result = runner.invoke(
        app, ["report", "--input", str(report_path), "--out", str(digest)]
    )

    assert result.exit_code == 0, result.stdout
    text = digest.read_text(encoding="utf-8")
    assert "# Weekly flake report" in text
    assert "Dry run — nothing was filed." in text
    assert "flakectl-fingerprint:" in text


def test_report_refuses_no_dry_run(tmp_path, log) -> None:
    """The guardrail: there is no GitHub write path, and it says so."""
    report_path = tmp_path / "report.json"
    runner.invoke(app, ["analyze", log, "--out", str(report_path)])

    result = runner.invoke(app, ["report", "--input", str(report_path), "--no-dry-run"])

    assert result.exit_code == 2
    assert "no GitHub write path" in result.output
    assert "gated on the eval numbers" in result.output


def test_report_on_a_missing_file_fails_cleanly(tmp_path) -> None:
    result = runner.invoke(app, ["report", "--input", str(tmp_path / "nope.json")])
    assert result.exit_code == 2
    assert "could not read report" in result.output


def test_report_rejects_a_foreign_json_document(tmp_path) -> None:
    path = tmp_path / "other.json"
    path.write_text('{"schema": "something/else"}', encoding="utf-8")
    result = runner.invoke(app, ["report", "--input", str(path)])
    assert result.exit_code == 2
    assert "unsupported report schema" in result.output


def test_analyze_persists_to_a_database_across_runs(tmp_path, log, history_file) -> None:
    db = str(tmp_path / "flakectl.db")
    first = runner.invoke(app, ["analyze", log, "--db", db, "--out", str(tmp_path / "a.json")])
    second = runner.invoke(app, ["analyze", log, "--db", db, "--out", str(tmp_path / "b.json")])

    assert first.exit_code == 0 and second.exit_code == 0
    assert "1 reused cached analysis" in second.stdout
