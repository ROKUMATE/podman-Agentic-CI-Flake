"""Tests for normalisation and signature extraction."""

from __future__ import annotations

import pytest

from flakectl.normalize import error_signature, normalize


@pytest.mark.parametrize(
    ("raw", "expected_fragment"),
    [
        ("started at 2026-08-29T09:12:44.123456Z ok", "<ts>"),
        ("In [It] at: run_test.go:431 @ 08/29/26 09:12:44.123", "@ <ts>"),
        ("Timed out after 3.000s.", "<dur>"),
        ("• [FAILED] [10.523 seconds]", "<dur>"),
        ("container 4f8a9b2c1d3e4f5a6b7c8d9e0f1a2b3c", "<id>"),
        ("id 550e8400-e29b-41d4-a716-446655440000", "<uuid>"),
        ("dial tcp 10.88.0.14:39251: i/o timeout", "<ip>:<port>"),
        ("panic at 0x7f3c2a1b4d00", "<addr>"),
        ("workdir /var/tmp/podman_test_902133/root", "<tmp>"),
        ("killed pid 48213", "pid <pid>"),
        ("goroutine 17 [running]", "goroutine <pid>"),
        ("failure in node 3 of 6", "<node>"),
        ("wrote 4096 bytes", "<size>"),
    ],
)
def test_each_normaliser_replaces_its_token(raw: str, expected_fragment: str) -> None:
    assert expected_fragment in normalize(raw)


def test_semantic_numbers_survive() -> None:
    """Exit codes and version numbers are signal, not noise."""
    normalized = normalize("Expected exit code 125 to equal 0")
    assert "125" in normalized
    assert "0" in normalized


def test_source_locations_survive() -> None:
    """The failing line number is part of the test's identity."""
    assert "run_networking_test.go:431" in normalize(
        "In [It] at: /home/runner/podman/test/e2e/run_networking_test.go:431"
    )


def test_two_sightings_of_one_flake_normalise_identically() -> None:
    first = """\
[FAILED] Expected
    <int>: 125
to equal
    <int>: 0
dial tcp 10.88.0.14:39251: i/o timeout
In [It] at: /home/runner/podman/test/e2e/run_networking_test.go:431 @ 08/29/26 09:12:44.123
"""
    second = """\
[FAILED] Expected
    <int>: 125
to equal
    <int>: 0
dial tcp 10.88.4.201:51022: i/o timeout
In [It] at: /home/runner/podman/test/e2e/run_networking_test.go:431 @ 08/30/26 22:41:07.882
"""
    assert normalize(first) == normalize(second)


def test_different_failures_do_not_normalise_together() -> None:
    a = normalize("Error: no space left on device")
    b = normalize("Error: container name already in use")
    assert a != b


def test_signature_keeps_only_diagnostic_lines() -> None:
    block = """\
• [FAILED] [10.523 seconds]
Podman run networking [It] podman run --net=host
/home/runner/podman/test/e2e/run_networking_test.go:412

  chatter that means nothing
  more chatter
  [FAILED] Expected exit code 125 to equal 0
  dial tcp 10.88.0.14:39251: i/o timeout
"""
    signature = error_signature(block)
    assert "chatter" not in signature
    assert "Expected exit code 125 to equal 0" in signature
    assert "i/o timeout" in signature
    assert "\n" not in signature


def test_signature_falls_back_to_the_head_when_no_marker_matches() -> None:
    signature = error_signature("first line\nsecond line\nthird line")
    assert signature.startswith("first line")


def test_signature_length_is_bounded() -> None:
    block = "\n".join(f"Error: distinct problem number {i}" for i in range(50))
    assert len(error_signature(block, max_lines=3).split(" | ")) == 3


def test_signature_deduplicates_repeated_lines() -> None:
    block = "Error: connection refused\nError: connection refused\nError: no such host"
    assert error_signature(block) == "Error: connection refused | Error: no such host"


def test_empty_input_yields_empty_signature() -> None:
    assert error_signature("   \n  \n") == ""
