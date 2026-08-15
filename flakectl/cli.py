"""Command-line entry point.

Installed twice: as ``flakectl`` (the name used in the proposal's Phase 1
deliverable) and as ``flake-triage``.

Everything runs offline by default. ``--provider anthropic`` and
``--provider ollama`` are opt-in; nothing here reads an API key unless one
of those is explicitly selected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from flakectl import __version__
from flakectl.agent import DEFAULT_MIN_CONFIDENCE
from flakectl.detector import HistoryError, RerunHistory
from flakectl.fingerprint import fingerprint_failure
from flakectl.parser import DEFAULT_BYTE_CAP
from flakectl.pipeline import PipelineConfig, analyze as run_pipeline, ingest as run_ingest
from flakectl.providers import PROVIDER_NAMES, ProviderError
from flakectl.report import (
    DEFAULT_MAX_ISSUES,
    ReportFormatError,
    from_dict,
    render_markdown,
    render_table,
    to_json,
)
from flakectl.store import MEMORY
from flakectl.tools import (
    DEFAULT_MAX_CALLS,
    DEFAULT_MAX_LINES_PER_CALL,
    DEFAULT_MAX_TOTAL_BYTES,
    ToolBudget,
)

app = typer.Typer(
    name="flakectl",
    help="Triage Podman CI test failures: real regression or flake, and which kind.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _root() -> None:
    """flakectl — agentic CI flake categorization and analysis."""


def _load_history(path: str | None) -> RerunHistory | None:
    if path is None:
        return None
    try:
        return RerunHistory.load(path)
    except (OSError, HistoryError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(f"could not read history {path!r}: {exc}") from exc


def _resolve_provider(provider: str, offline: bool) -> str:
    """``--offline`` is the default and always wins if given explicitly."""
    if offline:
        return "rules"
    if provider not in PROVIDER_NAMES:
        raise typer.BadParameter(
            f"unknown provider {provider!r}; choose from {', '.join(PROVIDER_NAMES)}"
        )
    return provider


@app.command()
def version() -> None:
    """Print the flakectl version."""
    typer.echo(f"flakectl {__version__}")


@app.command()
def ingest(
    logs: Annotated[list[str] | None, typer.Argument(help="CI log files to ingest.")] = None,
    junit: Annotated[list[str] | None, typer.Option(help="JUnit/Ginkgo XML report(s).")] = None,
    history: Annotated[str | None, typer.Option(help="Re-run history JSON.")] = None,
    byte_cap: Annotated[int, typer.Option(help="Hard cap per failure window, in bytes.")] = (
        DEFAULT_BYTE_CAP
    ),
) -> None:
    """Slice logs into structured failure records and fingerprint them.

    Pillars 1 and 2 only — no categorization, no model, no store writes.
    Useful for checking what the tool actually extracts from a log.
    """
    records = run_ingest(
        logs or [], junit or [], byte_cap=byte_cap, history=_load_history(history)
    )
    if not records:
        typer.echo("No failures found.")
        raise typer.Exit(code=0)

    for failure, _, source in records:
        fingerprint, signature = fingerprint_failure(failure)
        typer.echo(f"{fingerprint}  {failure.test_name}")
        typer.echo(f"{'':<16}  source: {source} ({failure.source_format})")
        typer.echo(
            f"{'':<16}  spec:   {failure.spec_file or 'unknown'}:{failure.spec_line or '?'}"
        )
        typer.echo(f"{'':<16}  signature: {signature}")
        typer.echo(
            f"{'':<16}  window: {len(failure.output_block.encode())} bytes"
            + (" (truncated)" if failure.truncated else "")
        )
        typer.echo("")

    distinct = len({fingerprint_failure(failure)[0] for failure, _, _ in records})
    typer.echo(f"{len(records)} failure(s), {distinct} distinct signature(s).")


@app.command()
def analyze(
    logs: Annotated[list[str] | None, typer.Argument(help="CI log files to analyze.")] = None,
    junit: Annotated[list[str] | None, typer.Option(help="JUnit/Ginkgo XML report(s).")] = None,
    history: Annotated[str | None, typer.Option(help="Re-run history JSON.")] = None,
    offline: Annotated[
        bool, typer.Option("--offline/--online", help="Use the deterministic ruleset only.")
    ] = True,
    provider: Annotated[
        str, typer.Option(help=f"Categorizer backend: {', '.join(PROVIDER_NAMES)}.")
    ] = "rules",
    model: Annotated[str | None, typer.Option(help="Model id, for model-backed providers.")] = None,
    min_confidence: Annotated[
        float, typer.Option(help="Below this, an answer becomes 'unknown'.")
    ] = DEFAULT_MIN_CONFIDENCE,
    byte_cap: Annotated[int, typer.Option(help="Hard cap per failure window, in bytes.")] = (
        DEFAULT_BYTE_CAP
    ),
    max_tool_calls: Annotated[int, typer.Option(help="Tool calls per analysis.")] = (
        DEFAULT_MAX_CALLS
    ),
    max_tool_bytes: Annotated[int, typer.Option(help="Tool output bytes per analysis.")] = (
        DEFAULT_MAX_TOTAL_BYTES
    ),
    source_root: Annotated[
        str | None, typer.Option(help="Checkout the agent may read test sources from.")
    ] = None,
    db: Annotated[str, typer.Option(help="SQLite store path. Defaults to in-memory.")] = MEMORY,
    out: Annotated[str | None, typer.Option(help="Write the JSON report here.")] = "report.json",
) -> None:
    """Ingest, fingerprint, detect and categorize a set of CI failures.

    Runs the whole pipeline and prints a per-failure table. Offline by
    default: no API key, no network.
    """
    if not logs and not junit:
        raise typer.BadParameter("give at least one log file or --junit report")

    config = PipelineConfig(
        provider_name=_resolve_provider(provider, offline),
        model=model,
        min_confidence=min_confidence,
        byte_cap=byte_cap,
        db_path=db,
        source_root=Path(source_root) if source_root else None,
        budget=ToolBudget(
            max_calls=max_tool_calls,
            max_total_bytes=max_tool_bytes,
            max_lines_per_call=DEFAULT_MAX_LINES_PER_CALL,
        ),
    )

    try:
        report = run_pipeline(
            logs or [], junit or [], history=_load_history(history), config=config
        )
    except ProviderError as exc:
        typer.secho(f"provider error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(render_table(report))

    if out:
        Path(out).write_text(to_json(report), encoding="utf-8")
        typer.echo(f"\nWrote {out}")


@app.command()
def report(
    input: Annotated[str, typer.Option(help="JSON report from `flakectl analyze`.")] = (
        "report.json"
    ),
    out: Annotated[str | None, typer.Option(help="Write the markdown digest here.")] = (
        "weekly-report.md"
    ),
    max_issues: Annotated[int, typer.Option(help="Per-run cap on would-be issues.")] = (
        DEFAULT_MAX_ISSUES
    ),
    top: Annotated[int, typer.Option(help="How many flakes to rank.")] = 10,
    dry_run: Annotated[
        bool, typer.Option("--dry-run/--no-dry-run", help="Dry run is the only supported mode.")
    ] = True,
) -> None:
    """Render the weekly markdown digest from a JSON report.

    Always a dry run: this proof-of-concept renders the issues and PR
    comments it *would* file, and never writes to GitHub.
    """
    if not dry_run:
        typer.secho(
            "--no-dry-run is refused: flakectl has no GitHub write path. Auto-filing is "
            "deliberately gated on the eval numbers justifying it, per category.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        data = json.loads(Path(input).read_text(encoding="utf-8"))
        loaded = from_dict(data)
    except (OSError, json.JSONDecodeError, ReportFormatError, KeyError) as exc:
        typer.secho(f"could not read report {input!r}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    markdown = render_markdown(loaded, max_issues=max_issues, top=top)
    if out:
        Path(out).write_text(markdown, encoding="utf-8")
        typer.echo(f"Wrote {out} ({len(markdown.splitlines())} lines, dry run).")
    else:
        typer.echo(markdown)


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
