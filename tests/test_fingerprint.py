"""Tests for fingerprinting — the thing that makes model cost O(distinct flakes)."""

from __future__ import annotations

from flakectl.fingerprint import FINGERPRINT_LENGTH, compute_fingerprint, fingerprint_failure
from flakectl.models import Failure

SPEC_FILE = "/home/runner/podman/test/e2e/run_networking_test.go"


def failure(block: str, name: str = "Podman run networking [It] --net=host") -> Failure:
    return Failure(test_name=name, output_block=block, spec_file=SPEC_FILE, spec_line=431)


FIRST_SIGHTING = """\
[FAILED] Expected exit code 125 to equal 0
dial tcp 10.88.0.14:39251: i/o timeout
In [It] at: /home/runner/podman/test/e2e/run_networking_test.go:431 @ 08/29/26 09:12:44.123
"""

SECOND_SIGHTING = """\
[FAILED] Expected exit code 125 to equal 0
dial tcp 10.88.4.201:51022: i/o timeout
In [It] at: /home/runner/podman/test/e2e/run_networking_test.go:431 @ 09/02/26 22:41:07.882
"""


def test_the_same_flake_seen_twice_collapses_to_one_fingerprint() -> None:
    first, _ = fingerprint_failure(failure(FIRST_SIGHTING))
    second, _ = fingerprint_failure(failure(SECOND_SIGHTING))
    assert first == second


def test_a_genuinely_different_failure_gets_a_different_fingerprint() -> None:
    first, _ = fingerprint_failure(failure(FIRST_SIGHTING))
    other, _ = fingerprint_failure(
        failure("[FAILED] Error: no space left on device\nIn [It] at: run_test.go:431")
    )
    assert first != other


def test_the_same_error_in_a_different_spec_is_a_different_fingerprint() -> None:
    """Test identity is half the hash, so one signature can't merge two specs."""
    first, _ = fingerprint_failure(failure(FIRST_SIGHTING))
    elsewhere, _ = fingerprint_failure(
        failure(FIRST_SIGHTING, name="Podman pod create [It] --infra-name")
    )
    assert first != elsewhere


def test_fingerprint_is_short_and_hex() -> None:
    value, _ = fingerprint_failure(failure(FIRST_SIGHTING))
    assert len(value) == FINGERPRINT_LENGTH
    assert all(character in "0123456789abcdef" for character in value)


def test_fingerprint_is_stable_across_calls() -> None:
    item = failure(FIRST_SIGHTING)
    assert compute_fingerprint(item) == compute_fingerprint(item)


def test_signature_is_returned_alongside_the_fingerprint() -> None:
    _, signature = fingerprint_failure(failure(FIRST_SIGHTING))
    assert "Expected exit code 125 to equal 0" in signature
    assert "39251" not in signature  # the ephemeral port is normalised away


def test_precomputed_signature_is_honoured() -> None:
    item = failure(FIRST_SIGHTING)
    value, signature = fingerprint_failure(item)
    assert compute_fingerprint(item, signature) == value
