"""Tests for the agent tool layer and its budget caps."""

from __future__ import annotations

import json

import pytest

from flakectl.fingerprint import fingerprint_failure
from flakectl.models import Failure
from flakectl.store import Store
from flakectl.tools import BudgetExceeded, ToolBudget, ToolError, ToolLayer

LOG = "\n".join(f"line {i}" for i in range(1, 501))


@pytest.fixture
def layer(tmp_path) -> ToolLayer:
    source = tmp_path / "test" / "e2e"
    source.mkdir(parents=True)
    (source / "run_networking_test.go").write_text(
        "\n".join(f"\tcode line {i}" for i in range(1, 101)), encoding="utf-8"
    )
    return ToolLayer(
        budget=ToolBudget(),
        logs={"job-1": LOG},
        source_root=tmp_path,
        issues=[{"number": 21456, "title": "Flake: pasta startup race", "state": "open"}],
        changes={"pkg/domain/infra": [{"sha": "abc1234", "subject": "fix scp usernames"}]},
    )


def test_get_log_slice_returns_the_requested_window(layer: ToolLayer) -> None:
    result = layer.call("get_log_slice", {"job_id": "job-1", "offset": 10, "lines": 5})
    assert "[lines 11-15 of 500]" in result
    assert "line 11" in result and "line 15" in result
    assert "line 16" not in result


def test_lines_per_call_is_clamped_not_refused(layer: ToolLayer) -> None:
    """A model asking for the whole log gets the cap, not an error."""
    layer.budget.max_lines_per_call = 20
    layer.budget.max_total_bytes = 1_000_000
    result = layer.call("get_log_slice", {"job_id": "job-1", "offset": 0, "lines": 100000})
    assert "[lines 1-20 of 500]" in result


def test_unknown_job_is_reported_not_raised(layer: ToolLayer) -> None:
    assert "no log retained" in layer.call("get_log_slice", {"job_id": "nope"})


def test_offset_past_end_of_log(layer: ToolLayer) -> None:
    assert "past the end" in layer.call("get_log_slice", {"job_id": "job-1", "offset": 9999})


def test_get_test_source_centres_on_the_failing_line(layer: ToolLayer) -> None:
    result = layer.call(
        "get_test_source", {"spec_file": "test/e2e/run_networking_test.go", "line": 50, "context": 10}
    )
    assert "run_networking_test.go" in result
    assert "code line 50" in result
    assert "   50  " in result  # line numbers are rendered for citation


def test_get_test_source_resolves_by_basename(layer: ToolLayer) -> None:
    """Logs carry absolute runner paths; the checkout is somewhere else."""
    result = layer.call(
        "get_test_source",
        {"spec_file": "/var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go"},
    )
    assert "code line 1" in result


def test_get_test_source_missing_file(layer: ToolLayer) -> None:
    assert "not available" in layer.call("get_test_source", {"spec_file": "nope_test.go"})


def test_search_history_reports_a_new_signature(layer: ToolLayer) -> None:
    with Store() as store:
        layer.store = store
        assert "not been seen before" in layer.call("search_history", {"fingerprint": "deadbeef"})


def test_search_history_reports_counts_and_jobs(layer: ToolLayer) -> None:
    failure = Failure(
        test_name="Podman run networking [It] --net=host",
        output_block="[FAILED] Error: connection refused",
        job="int podman fedora-41 root",
        os="fedora-41",
    )
    fingerprint, signature = fingerprint_failure(failure)
    with Store() as store:
        store.record_failure(failure, fingerprint, signature)
        store.record_failure(failure, fingerprint, signature)
        layer.store = store

        payload = json.loads(layer.call("search_history", {"fingerprint": fingerprint}))

    assert payload["occurrences"] == 2
    assert payload["jobs"] == ["int podman fedora-41 root"]


def test_search_issues_finds_a_known_flake(layer: ToolLayer) -> None:
    payload = json.loads(layer.call("search_issues", {"query": "pasta startup race"}))
    assert payload[0]["number"] == 21456


def test_search_issues_reports_no_match(layer: ToolLayer) -> None:
    assert "no open issues" in layer.call("search_issues", {"query": "entirely unrelated thing"})


def test_recent_changes_finds_commits_touching_the_path(layer: ToolLayer) -> None:
    payload = json.loads(layer.call("recent_changes", {"path": "pkg/domain/infra/abi"}))
    assert payload[0]["sha"] == "abc1234"


def test_recent_changes_reports_a_quiet_path(layer: ToolLayer) -> None:
    assert "no commits" in layer.call("recent_changes", {"path": "pkg/unrelated"})


def test_call_budget_is_hard(layer: ToolLayer) -> None:
    layer.budget.max_calls = 2
    layer.call("search_issues", {"query": "pasta"})
    layer.call("search_issues", {"query": "pasta"})

    with pytest.raises(BudgetExceeded, match="tool call budget"):
        layer.call("search_issues", {"query": "pasta"})


def test_byte_budget_truncates_then_stops(layer: ToolLayer) -> None:
    layer.budget.max_total_bytes = 200

    first = layer.call("get_log_slice", {"job_id": "job-1", "offset": 0, "lines": 200})
    assert "truncated by the analysis byte budget" in first
    assert len(first.encode()) <= 200 + len(
        "\n[flakectl: truncated by the analysis byte budget]"
    )

    with pytest.raises(BudgetExceeded, match="byte budget"):
        layer.call("get_log_slice", {"job_id": "job-1", "offset": 0, "lines": 10})


def test_budget_accounting_is_visible(layer: ToolLayer) -> None:
    layer.call("search_issues", {"query": "pasta"})
    assert layer.budget.calls_used == 1
    assert layer.budget.bytes_used > 0
    assert layer.budget.calls_remaining == layer.budget.max_calls - 1


def test_unknown_tool_raises(layer: ToolLayer) -> None:
    with pytest.raises(ToolError, match="unknown tool"):
        layer.call("rm_rf", {})


def test_bad_arguments_raise(layer: ToolLayer) -> None:
    with pytest.raises(ToolError, match="bad arguments"):
        layer.call("search_issues", {"nonsense": 1})


def test_definitions_cover_every_dispatchable_tool() -> None:
    names = {definition["name"] for definition in ToolLayer.definitions()}
    assert names == {
        "get_log_slice",
        "get_test_source",
        "search_history",
        "search_issues",
        "recent_changes",
    }
    for definition in ToolLayer.definitions():
        assert definition["description"]
        assert definition["input_schema"]["type"] == "object"
        assert definition["input_schema"]["required"]


def test_tools_degrade_gracefully_without_backing_sources() -> None:
    bare = ToolLayer()
    assert "no log retained" in bare.call("get_log_slice", {"job_id": "x"})
    assert "no source checkout" in bare.call("get_test_source", {"spec_file": "x.go"})
    assert "no history store" in bare.call("search_history", {"fingerprint": "x"})
    assert "no issue index" in bare.call("search_issues", {"query": "x"})
    assert "no change history" in bare.call("recent_changes", {"path": "x"})
