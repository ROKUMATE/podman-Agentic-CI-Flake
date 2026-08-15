"""Tests for the reporting layer and its dry-run guardrails."""

from __future__ import annotations

import json

import pytest

from flakectl.models import Analysis, Failure, TriagedFailure, Verdict
from flakectl.pipeline import Report
from flakectl.report import (
    FINGERPRINT_MARKER,
    ReportFormatError,
    from_dict,
    issue_body,
    pr_comment,
    render_markdown,
    render_table,
    to_dict,
    to_json,
)


def triaged(
    *,
    name: str = "Podman run networking [It] --net=host",
    category: str = "network_timeout",
    confidence: float = 0.9,
    fingerprint: str = "abc123def4567890",
    occurrences: int = 3,
    is_new: bool = False,
    needs_human: bool = False,
    regression: bool = False,
    verdict: Verdict = Verdict.CONFIRMED_FLAKE,
) -> TriagedFailure:
    return TriagedFailure(
        failure=Failure(
            test_name=name,
            output_block="[FAILED] dial tcp: i/o timeout",
            spec_file="test/e2e/run_networking_test.go",
            spec_line=431,
            job="int podman fedora-41 root",
            os="fedora-41",
        ),
        fingerprint=fingerprint,
        signature="Error: dial tcp <ip>:<port>: i/o timeout",
        verdict=verdict,
        analysis=Analysis(
            category=category,
            confidence=confidence,
            evidence=["L4: dial tcp 10.88.0.14:39251: i/o timeout"],
            explanation="The socket never came up.",
            suggested_mitigation="Wait on readiness rather than elapsed time.",
            is_likely_regression=regression,
            provider="rules",
            model=None,
            prompt_version="v1",
            rule_id="net-dial-timeout",
            needs_human=needs_human,
        ),
        occurrences=occurrences,
        first_seen="2026-08-01T00:00:00+00:00",
        last_seen="2026-08-29T00:00:00+00:00",
        is_new_signature=is_new,
        notes=["failed on attempt 1 and passed on attempt 2"],
    )


def report(*items: TriagedFailure) -> Report:
    built = Report(
        generated_at="2026-08-29T09:00:00+00:00",
        provider="rules",
        model=None,
        prompt_version="v1",
        triaged=list(items),
        sources=["samples/net.log"],
    )
    built.distinct_fingerprints = len({item.fingerprint for item in items})
    return built


# -- table ----------------------------------------------------------------


def test_table_lists_each_failure_with_its_verdict() -> None:
    text = render_table(report(triaged()))
    assert "Podman run networking" in text
    assert "network_timeout" in text
    assert "abc123def4567890" in text
    assert "flake" in text


def test_table_reports_dedup_and_provenance() -> None:
    first = triaged(fingerprint="aaaa000000000000")
    second = triaged(fingerprint="aaaa000000000000", name="Another spec")
    built = report(first, second)
    built.cached_analyses = 1

    text = render_table(built)
    assert "2 failure(s) · 1 distinct signature(s) · 2.0x dedup" in text
    assert "1 reused cached analysis" in text
    assert "provider=rules" in text
    assert "dry-run" in text


def test_table_handles_an_empty_report() -> None:
    assert render_table(report()) == "No failures found."


def test_long_test_names_are_truncated_not_wrapped() -> None:
    text = render_table(report(triaged(name="x" * 200)), width=20)
    assert "…" in text


# -- json -----------------------------------------------------------------


def test_json_carries_provenance_and_the_dry_run_flag() -> None:
    data = to_dict(report(triaged()))
    assert data["schema"] == "flakectl/report/v1"
    assert data["generated_by"]["agent_generated"] is True
    assert data["generated_by"]["dry_run"] is True
    assert data["generated_by"]["prompt_version"] == "v1"


def test_json_includes_the_full_analysis_per_failure() -> None:
    data = to_dict(report(triaged()))
    entry = data["failures"][0]
    assert entry["fingerprint"] == "abc123def4567890"
    assert entry["verdict"] == "confirmed_flake"
    assert entry["analysis"]["rule_id"] == "net-dial-timeout"
    assert entry["analysis"]["is_likely_regression"] is False
    assert entry["notes"] == ["failed on attempt 1 and passed on attempt 2"]


def test_json_round_trips_through_from_dict() -> None:
    original = report(triaged(), triaged(fingerprint="ffff111111111111", is_new=True))
    original.cached_analyses = 1

    restored = from_dict(json.loads(to_json(original)))

    assert restored.total_failures == 2
    assert restored.provider == "rules"
    assert restored.distinct_fingerprints == 2
    assert restored.cached_analyses == 1
    assert restored.triaged[0].verdict is Verdict.CONFIRMED_FLAKE
    assert restored.triaged[1].is_new_signature is True
    assert restored.triaged[0].analysis.category == "network_timeout"


def test_an_unknown_report_schema_is_rejected() -> None:
    with pytest.raises(ReportFormatError, match="unsupported report schema"):
        from_dict({"schema": "something/else"})


# -- issue and PR comment -------------------------------------------------


def test_issue_body_embeds_the_fingerprint_marker() -> None:
    body = issue_body(triaged(), report())
    assert FINGERPRINT_MARKER.format(fingerprint="abc123def4567890") in body
    assert body.startswith("<!-- flakectl-fingerprint:")


def test_issue_body_cites_evidence_and_provenance() -> None:
    body = issue_body(triaged(), report())
    assert "dial tcp 10.88.0.14:39251: i/o timeout" in body
    assert "Agent-generated by flakectl" in body
    assert "rule `net-dial-timeout`" in body
    assert "**Seen**: 3x" in body


def test_pr_comment_stays_modest_and_marked() -> None:
    comment = pr_comment(triaged())
    assert "likely not caused by your change" in comment
    assert "known flake `abc123def4567890`" in comment
    assert "Agent-generated by flakectl" in comment
    assert "dry-run" in comment


# -- weekly markdown ------------------------------------------------------


def test_markdown_states_it_is_a_dry_run() -> None:
    text = render_markdown(report(triaged()))
    assert "**Dry run — nothing was filed.**" in text
    assert "flakectl does not write to GitHub" in text


def test_markdown_calls_out_new_signatures_separately() -> None:
    text = render_markdown(report(triaged(is_new=True, fingerprint="new0000000000000")))
    section = text.split("## Newly-appeared signatures")[1].split("##")[0]
    assert "new0000000000000" in section
    assert "something changed recently" in section


def test_markdown_reports_no_new_signatures_when_there_are_none() -> None:
    text = render_markdown(report(triaged(is_new=False)))
    section = text.split("## Newly-appeared signatures")[1].split("##")[0]
    assert "_None this run._" in section


def test_markdown_separates_likely_regressions() -> None:
    text = render_markdown(
        report(triaged(category="real_regression", regression=True, needs_human=True))
    )
    section = text.split("## Flagged as likely regressions")[1].split("##")[0]
    assert "Podman run networking" in section


def test_markdown_routes_abstentions_to_a_human_digest() -> None:
    text = render_markdown(report(triaged(category="unknown", needs_human=True)))
    section = text.split("## Digest for human triage")[1].split("##")[0]
    assert "declined to decide" in section
    assert "No issue is filed" in section


def test_markdown_caps_would_be_issue_filings() -> None:
    items = [triaged(fingerprint=f"{index:016d}") for index in range(9)]
    text = render_markdown(report(*items), max_issues=3)
    assert "9 candidate(s); the per-run cap of 3 would allow 3." in text
    assert text.count("<summary>") == 3


def test_abstentions_are_never_candidates_for_filing() -> None:
    text = render_markdown(report(triaged(category="unknown", needs_human=True)))
    section = text.split("## Would-be issue filings")[1].split("##")[0]
    assert "_Nothing met the bar for filing._" in section


def test_pr_comment_section_needs_a_known_high_confidence_flake() -> None:
    fresh = render_markdown(report(triaged(is_new=True)))
    assert "_No known high-confidence flake to comment about._" in fresh

    known = render_markdown(report(triaged(is_new=False)))
    assert "matches known flake" in known


def test_markdown_ranks_by_frequency() -> None:
    rare = triaged(fingerprint="rare000000000000", occurrences=1, name="Rare spec")
    common = triaged(fingerprint="common0000000000", occurrences=42, name="Common spec")
    text = render_markdown(report(rare, common))

    ranked = text.split("## Top flakes by frequency")[1].split("##")[0]
    assert ranked.index("Common spec") < ranked.index("Rare spec")
