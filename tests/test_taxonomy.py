"""Tests for the maintainer-owned taxonomy."""

from __future__ import annotations

import pytest

from flakectl.taxonomy import (
    TaxonomyError,
    UnknownCategory,
    default_taxonomy,
    load_taxonomy,
)

EXPECTED = (
    "infrastructure",
    "network_timeout",
    "race_timing",
    "test_pollution",
    "environment_drift",
    "real_regression",
    "unknown",
)


def test_shipped_taxonomy_matches_the_proposal() -> None:
    assert default_taxonomy().names == EXPECTED


def test_every_category_carries_a_usable_description() -> None:
    for category in default_taxonomy():
        assert category.summary, f"{category.name} has no summary"
        assert category.description, f"{category.name} has no description"


def test_real_regression_escalates_and_is_never_a_flake() -> None:
    taxonomy = default_taxonomy()
    assert taxonomy.get("real_regression").escalate is True
    assert taxonomy.is_flake("real_regression") is False
    assert taxonomy.escalate_categories == (taxonomy.get("real_regression"),)


def test_unknown_is_the_abstain_category() -> None:
    taxonomy = default_taxonomy()
    assert taxonomy.abstain_category.name == "unknown"
    assert taxonomy.is_flake("unknown") is False


def test_flake_categories_exclude_escalation_and_abstention() -> None:
    names = tuple(c.name for c in default_taxonomy().flake_categories)
    assert names == (
        "infrastructure",
        "network_timeout",
        "race_timing",
        "test_pollution",
        "environment_drift",
    )


def test_unknown_category_name_raises() -> None:
    with pytest.raises(UnknownCategory) as excinfo:
        default_taxonomy().get("resource")
    assert "known categories" in str(excinfo.value)


def test_membership_and_length() -> None:
    taxonomy = default_taxonomy()
    assert "race_timing" in taxonomy
    assert "flaky" not in taxonomy
    assert len(taxonomy) == 7


def test_prompt_block_includes_names_and_example_signatures() -> None:
    block = default_taxonomy().prompt_block()
    for name in EXPECTED:
        assert f"- {name}:" in block
    assert "dial tcp: i/o timeout" in block


def test_a_custom_taxonomy_file_is_honoured(tmp_path) -> None:
    """Maintainers can swap the taxonomy without touching Python."""
    path = tmp_path / "custom.yaml"
    path.write_text(
        """
version: 2
categories:
  - name: flaky
    summary: something
    description: anything
  - name: dunno
    summary: abstain
    description: abstain
    abstain: true
""",
        encoding="utf-8",
    )
    taxonomy = load_taxonomy(path)
    assert taxonomy.version == 2
    assert taxonomy.names == ("flaky", "dunno")
    assert taxonomy.abstain_category.name == "dunno"


def test_taxonomy_without_an_abstain_category_is_rejected(tmp_path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        "categories:\n  - name: only\n    summary: s\n    description: d\n", encoding="utf-8"
    )
    with pytest.raises(TaxonomyError, match="abstain"):
        load_taxonomy(path)


def test_duplicate_category_names_are_rejected(tmp_path) -> None:
    path = tmp_path / "dupe.yaml"
    path.write_text(
        "categories:\n  - name: a\n    abstain: true\n  - name: a\n", encoding="utf-8"
    )
    with pytest.raises(TaxonomyError, match="duplicate"):
        load_taxonomy(path)


def test_empty_category_list_is_rejected(tmp_path) -> None:
    path = tmp_path / "empty.yaml"
    path.write_text("version: 1\ncategories: []\n", encoding="utf-8")
    with pytest.raises(TaxonomyError, match="non-empty"):
        load_taxonomy(path)
