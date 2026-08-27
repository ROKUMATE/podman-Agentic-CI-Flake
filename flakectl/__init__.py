"""flakectl — agentic CI flake categorization and analysis.

A proof-of-concept realization of the CNCF/LFX mentorship proposal "Podman —
Agentic CI Flake Categorization and Analysis" (issue #1963, Term 3 2026).

The pipeline is deterministic-first: cheap, reviewable logic (fingerprint
dedup, re-run detection, a maintainer-owned YAML ruleset) resolves everything
it can before a model is ever invoked, and the agent is required to answer
``unknown`` rather than guess.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
