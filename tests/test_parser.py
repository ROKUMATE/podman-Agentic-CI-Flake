"""Tests for the Pillar 1 raw-log slicer."""

from __future__ import annotations

from flakectl.parser import DEFAULT_BYTE_CAP, parse_log

GINKGO_LOG = """\
Running Suite: Podman E2E Suite - /var/tmp/go/src/github.com/containers/podman/test/e2e
========================================================================
Random Seed: 1756449102

Will run 512 of 600 specs
••••••••••••
------------------------------
• [FAILED] [10.523 seconds]
Podman run networking [It] podman run --net=host --add-host
/var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:412

  [FAILED] Expected
      <int>: 125
  to equal
      <int>: 0

  In [It] at: /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431 @ 08/29/26 09:12:44.123
------------------------------
••••
------------------------------
• [FAILED] [3.001 seconds]
Podman pod create [It] podman pod create --infra-name
/var/tmp/go/src/github.com/containers/podman/test/e2e/pod_create_test.go:80

  [FAILED] Timed out after 3.000s.
  In [It] at: /var/tmp/go/src/github.com/containers/podman/test/e2e/pod_create_test.go:88 @ 08/29/26 09:14:02.900
------------------------------

Summarizing 2 Failures:
  [FAIL] Podman run networking [It] podman run --net=host --add-host
  /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431
  [FAIL] Podman pod create [It] podman pod create --infra-name
  /var/tmp/go/src/github.com/containers/podman/test/e2e/pod_create_test.go:88

Ran 512 of 600 Specs in 1823.456 seconds
FAIL! -- 510 Passed | 2 Failed | 0 Pending | 88 Skipped
Process completed with exit code 1.
"""


def test_ginkgo_log_yields_one_record_per_failing_spec() -> None:
    failures = parse_log(GINKGO_LOG)
    assert len(failures) == 2
    assert [f.test_name for f in failures] == [
        "Podman run networking [It] podman run --net=host --add-host",
        "Podman pod create [It] podman pod create --infra-name",
    ]


def test_ginkgo_failure_carries_suite_location_and_exit_code() -> None:
    first = parse_log(GINKGO_LOG)[0]
    assert first.suite == "Podman E2E Suite"
    # The `In [It] at:` line wins over the spec's declaration site.
    assert first.spec_file.endswith("run_networking_test.go")
    assert first.spec_line == 431
    assert first.exit_code == 1
    assert first.source_format == "ginkgo"
    assert "to equal" in first.output_block


def test_summary_only_failure_is_still_reported() -> None:
    """A spec named in the summary with no detailed block must not be dropped."""
    log = """\
Running Suite: Podman E2E Suite

Summarizing 1 Failure:
  [FAIL] Podman images [It] podman images --format json
  /var/tmp/go/src/github.com/containers/podman/test/e2e/images_test.go:120

Ran 10 of 10 Specs in 4.000 seconds
FAIL! -- 9 Passed | 1 Failed | 0 Pending | 0 Skipped
"""
    failures = parse_log(log)
    assert len(failures) == 1
    assert failures[0].test_name == "Podman images [It] podman images --format json"


def test_output_block_is_capped_at_the_ingestion_layer() -> None:
    noise = "\n".join(f"  padding line {i} of a very chatty spec" for i in range(4000))
    log = GINKGO_LOG.replace("  to equal", noise + "\n  to equal")

    failures = parse_log(log, byte_cap=1024)

    first = failures[0]
    assert first.truncated is True
    assert len(first.output_block.encode()) <= 1024
    assert "elided by ingestion byte cap" in first.output_block
    # Head and tail survive: the assertion and the source location.
    assert "[FAILED] Expected" in first.output_block
    assert "run_networking_test.go:431" in first.output_block


def test_untruncated_block_is_not_marked_truncated() -> None:
    failures = parse_log(GINKGO_LOG, byte_cap=DEFAULT_BYTE_CAP)
    assert all(f.truncated is False for f in failures)


def test_actions_timestamps_and_ansi_colour_are_stripped() -> None:
    noisy = "\n".join(
        f"2026-08-29T09:12:44.1234567Z \x1b[31m{line}\x1b[0m" for line in GINKGO_LOG.split("\n")
    )
    noisy = "2026-08-29T09:12:40.0000000Z ##[group]Run make localintegration\n" + noisy

    failures = parse_log(noisy)

    assert len(failures) == 2
    assert "2026-08-29T09" not in failures[0].output_block
    assert "\x1b[" not in failures[0].output_block


def test_generic_go_test_format() -> None:
    log = """\
=== RUN   TestParseSourceAndDestination
--- FAIL: TestParseSourceAndDestination (0.01s)
    scp_test.go:44: expected "user@host" got "host"
=== RUN   TestOther
--- PASS: TestOther (0.00s)
FAIL
exit status 1
"""
    failures = parse_log(log)
    assert len(failures) == 1
    assert failures[0].test_name == "TestParseSourceAndDestination"
    assert failures[0].source_format == "generic"
    assert failures[0].exit_code == 1
    assert "expected" in failures[0].output_block


def test_generic_tap_bats_format() -> None:
    log = """\
ok 1 podman run --rm
not ok 2 podman network create with subnet
# (in test file test/system/500-networking.bats, line 88)
#   `run_podman network create --subnet 10.0.0.0/24 mynet' failed
ok 3 podman pod create
"""
    failures = parse_log(log)
    assert len(failures) == 1
    assert failures[0].test_name == "podman network create with subnet"
    assert "500-networking.bats" in failures[0].output_block


def test_passing_log_yields_no_failures() -> None:
    log = """\
Running Suite: Podman E2E Suite
••••••••••
Ran 10 of 10 Specs in 4.000 seconds
SUCCESS! -- 10 Passed | 0 Failed | 0 Pending | 0 Skipped
"""
    assert parse_log(log) == []


def test_ingestion_metadata_is_attached_when_supplied() -> None:
    failures = parse_log(GINKGO_LOG, job="int podman fedora-41 root host sqlite", os="fedora-41")
    assert failures[0].job == "int podman fedora-41 root host sqlite"
    assert failures[0].os == "fedora-41"


def test_identity_combines_spec_file_and_test_name() -> None:
    first = parse_log(GINKGO_LOG)[0]
    assert first.identity.endswith("::Podman run networking [It] podman run --net=host --add-host")
    assert "run_networking_test.go" in first.identity
