"""Command-line entry point.

Installed twice: as ``flakectl`` (the name used in the proposal's Phase 1
deliverable) and as ``flake-triage``.
"""

from __future__ import annotations

import typer

from flakectl import __version__

app = typer.Typer(
    name="flakectl",
    help="Triage Podman CI test failures: real regression or flake, and which kind.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _root() -> None:
    """Keep flakectl a multi-command app even when only one command is registered."""


@app.command()
def version() -> None:
    """Print the flakectl version."""
    typer.echo(f"flakectl {__version__}")


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
