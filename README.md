# flakectl

Agentic CI flake categorization and analysis for Podman CI.

A proof-of-concept built alongside my CNCF/LFX mentorship proposal for
**Podman — Agentic CI Flake Categorization and Analysis** (issue #1963, Term 3 2026).

Given a failing CI log, `flakectl` decides two things:

1. is this a **real failure** or a **flake**, and
2. if it is a flake, **which category** of flake.

Work in progress — this README is filled in as the pipeline lands.

```console
$ flakectl version
```
