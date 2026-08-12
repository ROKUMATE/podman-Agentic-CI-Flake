"""Tests for the evaluation harness and the shipped labelled corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flakectl.evaluate import (
    LabelError,
    LabelledFailure,
    evaluate,
    format_report,
    load_labels,
)
from flakectl.models import Verdict
from flakectl.taxonomy import default_taxonomy

LABELS = Path(__file__).resolve().parent.parent / "eval" / "labels.jsonl"


@pytest.fixture(scope="module")
def corpus() -> list[LabelledFailure]:
    return load_labels(LABELS)


# -- the corpus itself ----------------------------------------------------


def test_the_corpus_loads(corpus: list[LabelledFailure]) -> None:
    assert len(corpus) >= 30
    assert all(example.log for example in corpus)


def test_every_label_is_in_the_taxonomy(corpus: list[LabelledFailure]) -> None:
    valid = set(default_taxonomy().names)
    assert {example.label for example in corpus} <= valid


def test_example_ids_are_unique(corpus: list[LabelledFailure]) -> None:
    ids = [example.id for example in corpus]
    assert len(ids) == len(set(ids))


def test_every_non_abstain_category_has_support(corpus: list[LabelledFailure]) -> None:
    """A category with no examples cannot be measured, so there must be none."""
    labelled = {example.label for example in corpus}
    expected = {c.name for c in default_taxonomy() if not c.abstain}
    assert labelled == expected


def test_the_corpus_covers_all_three_rerun_verdicts(corpus: list[LabelledFailure]) -> None:
    assert {example.verdict for example in corpus} == set(Verdict)


def test_a_baseline_reason_marks_the_change_innocent(corpus: list[LabelledFailure]) -> None:
    with_baseline = [e for e in corpus if "also fails on main" in e.reason]
    assert with_baseline
    assert all(e.as_detection().caused_by_change is False for e in with_baseline)


# -- scoring --------------------------------------------------------------


def test_the_offline_ruleset_scores_the_corpus(corpus: list[LabelledFailure]) -> None:
    result = evaluate(corpus)

    assert result.total == len(corpus)
    assert result.provider == "rules"
    assert 0.0 < result.accuracy <= 1.0
    assert result.accuracy_when_decided >= result.accuracy


def test_no_regression_is_ever_categorized_as_a_flake(corpus: list[LabelledFailure]) -> None:
    """The gate from the proposal's risk table. This one must stay at zero."""
    result = evaluate(corpus)
    assert result.missed_regressions == []
    assert result.missed_regression_rate == 0.0


def test_the_harness_surfaces_known_false_regressions(corpus: list[LabelledFailure]) -> None:
    """The offline fallback over-calls regression when no rule matches.

    This is a real weakness of the deterministic path, and the eval is
    supposed to show it rather than hide it.
    """
    result = evaluate(corpus)
    assert result.false_regressions, "the corpus should include cases the ruleset gets wrong"
    assert 0.0 < result.false_regression_rate < 0.2


def test_abstentions_are_counted_separately_from_wrong_answers(
    corpus: list[LabelledFailure],
) -> None:
    result = evaluate(corpus)

    assert result.abstentions
    assert all(p.predicted == "unknown" for p in result.abstentions)
    assert len(result.decided) + len(result.abstentions) == result.total
    # An abstention is a recall miss, never a precision hit for another category.
    assert all(not p.correct for p in result.abstentions)


def test_a_higher_confidence_gate_trades_answers_for_abstentions(
    corpus: list[LabelledFailure],
) -> None:
    lenient = evaluate(corpus, min_confidence=0.5)
    strict = evaluate(corpus, min_confidence=0.95)

    assert strict.abstention_rate > lenient.abstention_rate
    assert len(strict.decided) < len(lenient.decided)


def test_per_category_scores_are_computed(corpus: list[LabelledFailure]) -> None:
    result = evaluate(corpus)
    infra = result.scores["infrastructure"]

    assert infra.support > 0
    assert 0.0 <= infra.precision <= 1.0
    assert 0.0 <= infra.recall <= 1.0
    assert 0.0 <= infra.f1 <= 1.0


def test_latency_is_measured(corpus: list[LabelledFailure]) -> None:
    result = evaluate(corpus)
    assert result.mean_latency_ms > 0


def test_evaluation_does_not_use_the_cache() -> None:
    """Caching would make repeat signatures free and skew the measurement."""
    duplicated = [
        LabelledFailure(id="a", label="infrastructure", log="Error: toomanyrequests: Rate exceeded"),
        LabelledFailure(id="b", label="infrastructure", log="Error: toomanyrequests: Rate exceeded"),
    ]
    result = evaluate(duplicated)
    assert result.total == 2
    assert all(p.predicted == "infrastructure" for p in result.predictions)


# -- rendering ------------------------------------------------------------


def test_report_shows_the_headline_metrics(corpus: list[LabelledFailure]) -> None:
    text = format_report(evaluate(corpus))

    assert "accuracy" in text
    assert "abstention rate" in text
    assert "missed-regression rate" in text
    assert "false-regression rate" in text
    assert "mean latency" in text
    assert "macro avg" in text


def test_report_excludes_unknown_from_the_precision_table(
    corpus: list[LabelledFailure],
) -> None:
    """Abstaining is not a prediction of a category, so it has no precision."""
    table = format_report(evaluate(corpus)).split("Overall")[0]
    assert "unknown" not in table
    assert "infrastructure" in table


# -- loading errors -------------------------------------------------------


def test_a_malformed_line_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"id": "a", "label": "infrastructure", "log": "x"}\n{oops\n', encoding="utf-8")
    with pytest.raises(LabelError, match="not valid JSON"):
        load_labels(path)


@pytest.mark.parametrize("field", ["id", "label", "log"])
def test_a_missing_required_field_is_rejected(tmp_path, field: str) -> None:
    entry = {"id": "a", "label": "infrastructure", "log": "x"}
    del entry[field]
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps(entry) + "\n", encoding="utf-8")
    with pytest.raises(LabelError, match=f"missing '{field}'"):
        load_labels(path)


def test_an_empty_corpus_is_rejected(tmp_path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n\n", encoding="utf-8")
    with pytest.raises(LabelError, match="no labelled examples"):
        load_labels(path)


def test_a_label_outside_the_taxonomy_is_rejected() -> None:
    with pytest.raises(LabelError, match="outside the taxonomy"):
        evaluate([LabelledFailure(id="a", label="resource", log="boom")])


def test_blank_and_comment_lines_are_skipped(tmp_path) -> None:
    path = tmp_path / "corpus.jsonl"
    path.write_text(
        "// a comment\n\n" + json.dumps({"id": "a", "label": "infrastructure", "log": "x"}) + "\n",
        encoding="utf-8",
    )
    assert len(load_labels(path)) == 1
