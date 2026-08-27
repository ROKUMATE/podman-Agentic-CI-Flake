"""Smoke tests for the CLI entry point."""

from __future__ import annotations

from typer.testing import CliRunner

from flakectl import __version__
from flakectl.cli import app

runner = CliRunner()


def test_version_prints_the_package_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_bare_invocation_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Triage Podman CI test failures" in result.stdout
