"""Tests for the preferred (structured artifact) ingestion path."""

from __future__ import annotations

import pytest

from flakectl.junit import JUnitParseError, parse_junit

GINKGO_JUNIT = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" failures="1" errors="1" time="42.0">
  <testsuite name="Podman E2E Suite" tests="3" failures="1" errors="1" hostname="fedora-41">
    <properties>
      <property name="SuiteSucceeded" value="false"></property>
      <property name="job" value="int podman fedora-41 root host sqlite"></property>
    </properties>
    <testcase name="Podman run networking podman run --net=host" classname="Podman E2E Suite" time="10.5">
      <failure message="Expected&#10;    &lt;int&gt;: 125&#10;to equal&#10;    &lt;int&gt;: 0" type="failed">
        [FAILED] Expected exit code 0
        In [It] at: /var/tmp/go/src/github.com/containers/podman/test/e2e/run_networking_test.go:431
      </failure>
    </testcase>
    <testcase name="Podman pod create passes" classname="Podman E2E Suite" time="1.0"></testcase>
    <testcase name="Podman machine init on darwin" classname="Podman E2E Suite" time="0.0">
      <skipped message="Only runs on darwin"></skipped>
    </testcase>
    <testcase name="Podman images errored case" classname="Podman E2E Suite" time="2.0">
      <error message="panic: runtime error" type="panicked">goroutine 1 [running]</error>
    </testcase>
  </testsuite>
</testsuites>
"""


def test_only_failing_and_errored_cases_produce_records() -> None:
    failures = parse_junit(GINKGO_JUNIT)
    assert [f.test_name for f in failures] == [
        "Podman run networking podman run --net=host",
        "Podman images errored case",
    ]


def test_failure_message_and_body_are_both_kept() -> None:
    first = parse_junit(GINKGO_JUNIT)[0]
    assert "to equal" in first.output_block  # from the message attribute
    assert "[FAILED] Expected exit code 0" in first.output_block  # from the element text
    assert first.source_format == "junit"
    assert first.status == "failed"


def test_location_is_recovered_from_the_failure_body() -> None:
    first = parse_junit(GINKGO_JUNIT)[0]
    assert first.spec_file.endswith("run_networking_test.go")
    assert first.spec_line == 431


def test_explicit_file_and_line_attributes_win() -> None:
    xml = """<testsuite name="S" tests="1" failures="1">
      <testcase name="t" file="test/e2e/pod_test.go" line="88">
        <failure message="boom">In [It] at: /other/path_test.go:999</failure>
      </testcase>
    </testsuite>"""
    first = parse_junit(xml)[0]
    assert first.spec_file == "test/e2e/pod_test.go"
    assert first.spec_line == 88


def test_errored_case_is_marked_errored() -> None:
    errored = parse_junit(GINKGO_JUNIT)[1]
    assert errored.status == "errored"
    assert "panic: runtime error" in errored.output_block


def test_job_and_os_come_from_suite_properties() -> None:
    first = parse_junit(GINKGO_JUNIT)[0]
    assert first.job == "int podman fedora-41 root host sqlite"
    assert first.os == "fedora-41"
    assert first.suite == "Podman E2E Suite"


def test_explicit_metadata_overrides_suite_properties() -> None:
    first = parse_junit(GINKGO_JUNIT, job="int podman rawhide rootless", os="rawhide")[0]
    assert first.job == "int podman rawhide rootless"
    assert first.os == "rawhide"


def test_bare_testsuite_root_is_accepted() -> None:
    xml = """<testsuite name="bats" tests="1" failures="1">
      <testcase name="podman network create"><failure message="exit 125"/></testcase>
    </testsuite>"""
    failures = parse_junit(xml)
    assert len(failures) == 1
    assert failures[0].suite == "bats"


def test_output_block_respects_the_byte_cap() -> None:
    xml = f"""<testsuite name="S" tests="1" failures="1">
      <testcase name="t"><failure message="head">{"x" * 20000}</failure></testcase>
    </testsuite>"""
    first = parse_junit(xml, byte_cap=512)[0]
    assert first.truncated is True
    assert len(first.output_block.encode()) <= 512


def test_malformed_xml_raises() -> None:
    with pytest.raises(JUnitParseError):
        parse_junit("<testsuite><testcase></testsuite>")


def test_unexpected_root_element_raises() -> None:
    with pytest.raises(JUnitParseError):
        parse_junit("<report><thing/></report>")
