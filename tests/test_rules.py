"""Tests for the deterministic pre-filter."""

from __future__ import annotations

import pytest

from flakectl.rules import RulesError, default_rules, load_rules
from flakectl.taxonomy import default_taxonomy


@pytest.mark.parametrize(
    ("text", "expected_category", "expected_rule"),
    [
        (
            "Error: initializing source docker://quay.io/libpod/alpine: "
            "toomanyrequests: Rate exceeded",
            "infrastructure",
            "infra-registry-rate-limit",
        ),
        (
            "Error: pinging container registry quay.io: received unexpected HTTP status: "
            "503 Service Unavailable",
            "infrastructure",
            "infra-registry-5xx",
        ),
        (
            "Error: writing blob: write /var/lib/containers/storage: no space left on device",
            "infrastructure",
            "infra-disk-pressure",
        ),
        (
            "Error: unable to connect: dial tcp 10.88.0.14:39251: i/o timeout",
            "network_timeout",
            "net-dial-timeout",
        ),
        (
            "Error: pulling image: lookup quay.io: no such host",
            "network_timeout",
            "net-dns-failure",
        ),
        (
            "Error: pasta failed with exit code 1: unable to set up namespace",
            "network_timeout",
            "net-podman-stack-startup",
        ),
        (
            'Error: creating container: the container name "test-ctr" is already in use',
            "test_pollution",
            "pollution-name-in-use",
        ),
        (
            "Error: network with name podman1 already exists",
            "test_pollution",
            "pollution-network-exists",
        ),
        (
            "Error: crun: unknown version specified in config",
            "environment_drift",
            "env-runtime-version",
        ),
        (
            "Error: unknown flag: --validate",
            "real_regression",
            "regression-unknown-flag",
        ),
    ],
)
def test_known_signatures_are_classified_without_a_model(
    text: str, expected_category: str, expected_rule: str
) -> None:
    match = default_rules().match(text)
    assert match is not None
    assert match.rule.category == expected_category
    assert match.rule.id == expected_rule


def test_matching_is_case_insensitive_by_default() -> None:
    match = default_rules().match("Error: TOOMANYREQUESTS: rate exceeded")
    assert match is not None
    assert match.rule.id == "infra-registry-rate-limit"


def test_evidence_carries_line_numbers_and_the_matched_text() -> None:
    log = "\n".join(
        [
            "starting podman run",
            "Error: initializing source: toomanyrequests: Rate exceeded",
            "exit status 125",
        ]
    )
    match = default_rules().match(log)
    assert match.evidence == ("L2: Error: initializing source: toomanyrequests: Rate exceeded",)


def test_ordering_puts_pollution_above_generic_infrastructure() -> None:
    """A leaked container name reads like a resource problem but is not one."""
    text = 'the container name "podman-test" is already in use by an existing container'
    assert default_rules().match(text).rule.category == "test_pollution"


def test_none_of_guards_a_rule_from_firing() -> None:
    """A Gomega timeout with a network cause is network, not a bare race."""
    text = "Timed out after 3.000s.\nError: dial tcp 10.88.0.1:5000: i/o timeout"
    assert default_rules().match(text).rule.id == "net-dial-timeout"


def test_all_of_requires_every_pattern() -> None:
    """A nil-pointer panic outside Podman's own packages is not classified."""
    generic_panic = "panic: runtime error: invalid memory address or nil pointer dereference"
    assert default_rules().match(generic_panic) is None

    podman_panic = generic_panic + "\n\tgithub.com/containers/podman/v5/pkg/domain/entities"
    assert default_rules().match(podman_panic).rule.id == "regression-nil-pointer"


def test_unmatched_text_returns_none_so_it_can_reach_the_agent() -> None:
    assert default_rules().match("Expected 3 items, found 2") is None


def test_every_shipped_rule_has_a_mitigation_and_a_known_category() -> None:
    taxonomy = default_taxonomy()
    for rule in default_rules():
        assert rule.mitigation, f"{rule.id} has no mitigation"
        assert rule.category in taxonomy
        assert 0.0 < rule.confidence <= 1.0


def test_rule_lookup_by_id() -> None:
    assert default_rules().get("net-dns-failure").category == "network_timeout"
    assert default_rules().get("does-not-exist") is None


def test_a_custom_ruleset_is_honoured(tmp_path) -> None:
    """Maintainers can add a rule without touching Python."""
    path = tmp_path / "rules.yaml"
    path.write_text(
        """
rules:
  - id: local-known-flake
    category: race_timing
    confidence: 0.99
    any_of:
      - "our very specific in-house signature"
    mitigation: do the thing
""",
        encoding="utf-8",
    )
    engine = load_rules(path)
    assert len(engine) == 1
    assert engine.match("saw our very specific in-house signature today").rule.confidence == 0.99


def test_rule_with_an_unknown_category_is_rejected(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n  - id: r\n    category: resource\n    any_of: ['x']\n", encoding="utf-8"
    )
    with pytest.raises(RulesError, match="not in the taxonomy"):
        load_rules(path)


def test_rule_with_a_bad_regex_is_rejected(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n  - id: r\n    category: race_timing\n    any_of: ['unclosed(']\n",
        encoding="utf-8",
    )
    with pytest.raises(RulesError, match="bad regex"):
        load_rules(path)


def test_rule_with_no_patterns_is_rejected(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - id: r\n    category: race_timing\n", encoding="utf-8")
    with pytest.raises(RulesError, match="at least one"):
        load_rules(path)


def test_out_of_range_confidence_is_rejected(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n  - id: r\n    category: race_timing\n    confidence: 1.5\n    any_of: ['x']\n",
        encoding="utf-8",
    )
    with pytest.raises(RulesError, match="between 0 and 1"):
        load_rules(path)


def test_duplicate_rule_ids_are_rejected(tmp_path) -> None:
    path = tmp_path / "rules.yaml"
    path.write_text(
        "rules:\n"
        "  - id: r\n    category: race_timing\n    any_of: ['x']\n"
        "  - id: r\n    category: race_timing\n    any_of: ['y']\n",
        encoding="utf-8",
    )
    with pytest.raises(RulesError, match="duplicate"):
        load_rules(path)
