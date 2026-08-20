"""Tests for the SQLite fingerprint/analysis store."""

from __future__ import annotations

import pytest

from flakectl.fingerprint import fingerprint_failure
from flakectl.models import Analysis, Failure
from flakectl.store import Store


@pytest.fixture
def store() -> Store:
    with Store() as instance:
        yield instance


def failure(block: str = "[FAILED] Error: connection refused", **kwargs) -> Failure:
    defaults = {
        "test_name": "Podman run networking [It] --net=host",
        "spec_file": "test/e2e/run_networking_test.go",
        "job": "int podman fedora-41 root host sqlite",
        "os": "fedora-41",
    }
    return Failure(output_block=block, **{**defaults, **kwargs})


def analysis(**kwargs) -> Analysis:
    defaults = {
        "category": "network_timeout",
        "confidence": 0.82,
        "evidence": ["dial tcp: i/o timeout"],
        "explanation": "The socket timed out reaching the registry.",
        "suggested_mitigation": "Wait on readiness rather than elapsed time.",
        "is_likely_regression": False,
        "provider": "rules",
        "rule_id": "net-dial-timeout",
    }
    return Analysis(**{**defaults, **kwargs})


def test_first_sighting_is_marked_new(store: Store) -> None:
    item = failure()
    fingerprint, signature = fingerprint_failure(item)

    occurrence = store.record_failure(item, fingerprint, signature)

    assert occurrence.is_new is True
    assert occurrence.count == 1
    assert occurrence.first_seen == occurrence.last_seen


def test_second_sighting_increments_rather_than_duplicating(store: Store) -> None:
    item = failure()
    fingerprint, signature = fingerprint_failure(item)

    store.record_failure(item, fingerprint, signature, now="2026-08-29T09:00:00+00:00")
    second = store.record_failure(item, fingerprint, signature, now="2026-09-02T11:00:00+00:00")

    assert second.is_new is False
    assert second.count == 2
    assert second.first_seen == "2026-08-29T09:00:00+00:00"
    assert second.last_seen == "2026-09-02T11:00:00+00:00"
    # Two sightings, one distinct failure mode: this ratio is the model spend saved.
    assert store.failure_count() == 2
    assert store.fingerprint_count() == 1


def test_jobs_and_oses_accumulate_across_sightings(store: Store) -> None:
    item = failure()
    fingerprint, signature = fingerprint_failure(item)
    store.record_failure(item, fingerprint, signature)
    store.record_failure(
        failure(job="int podman rawhide rootless", os="rawhide"), fingerprint, signature
    )

    occurrence = store.occurrence(fingerprint)
    assert occurrence.jobs == (
        "int podman fedora-41 root host sqlite",
        "int podman rawhide rootless",
    )
    assert occurrence.oses == ("fedora-41", "rawhide")


def test_a_cached_analysis_is_returned_and_marked_cached(store: Store) -> None:
    item = failure()
    fingerprint, signature = fingerprint_failure(item)
    store.record_failure(item, fingerprint, signature)
    store.put_analysis(fingerprint, analysis())

    cached = store.get_analysis(fingerprint)

    assert cached is not None
    assert cached.cached is True
    assert cached.category == "network_timeout"
    assert cached.confidence == pytest.approx(0.82)
    assert cached.evidence == ["dial tcp: i/o timeout"]
    assert cached.is_likely_regression is False
    assert cached.rule_id == "net-dial-timeout"


def test_an_unseen_fingerprint_has_no_cached_analysis(store: Store) -> None:
    assert store.get_analysis("0000000000000000") is None


def test_reanalysing_replaces_the_cached_answer(store: Store) -> None:
    item = failure()
    fingerprint, signature = fingerprint_failure(item)
    store.record_failure(item, fingerprint, signature)
    store.put_analysis(fingerprint, analysis())
    store.put_analysis(fingerprint, analysis(category="infrastructure", provider="anthropic"))

    cached = store.get_analysis(fingerprint)
    assert cached.category == "infrastructure"
    assert cached.provider == "anthropic"


def test_top_flakes_are_ordered_by_frequency(store: Store) -> None:
    common = failure("[FAILED] Error: connection refused")
    rare = failure("[FAILED] Error: no space left on device")
    common_fp, common_sig = fingerprint_failure(common)
    rare_fp, rare_sig = fingerprint_failure(rare)

    for _ in range(3):
        store.record_failure(common, common_fp, common_sig)
    store.record_failure(rare, rare_fp, rare_sig)

    top = store.top_flakes()
    assert [entry.fingerprint for entry in top] == [common_fp, rare_fp]
    assert top[0].count == 3


def test_new_since_finds_only_newly_appeared_signatures(store: Store) -> None:
    old = failure("[FAILED] Error: connection refused")
    fresh = failure("[FAILED] Error: no space left on device")
    old_fp, old_sig = fingerprint_failure(old)
    fresh_fp, fresh_sig = fingerprint_failure(fresh)

    store.record_failure(old, old_fp, old_sig, now="2026-08-01T00:00:00+00:00")
    store.record_failure(fresh, fresh_fp, fresh_sig, now="2026-08-29T00:00:00+00:00")

    recent = store.new_since("2026-08-15T00:00:00+00:00")
    assert [entry.fingerprint for entry in recent] == [fresh_fp]


def test_store_persists_to_disk(tmp_path) -> None:
    path = str(tmp_path / "flakectl.db")
    item = failure()
    fingerprint, signature = fingerprint_failure(item)

    with Store(path) as first:
        first.record_failure(item, fingerprint, signature)
        first.put_analysis(fingerprint, analysis())

    with Store(path) as second:
        assert second.occurrence(fingerprint).count == 1
        assert second.get_analysis(fingerprint).category == "network_timeout"
