# Ticket 009: Modularize under 500 lines and harden skills conformance validators

- **ID**: ticket-009
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Modularize `wellmanifest/skills` conformance validators so every Python file is
strictly under 500 lines, eliminate cross-module SSOT duplication via shared
`standard/skill_primitives.py`, wire `operation_profile_conformance.py` into
`standard/conformance.py --all` so CI runs all three conformance suites, harden
all JSON loaders and validators against duplicate keys, non-RFC3339 timestamps,
path-segment traversal, and inline secret/credential tokens, add `pyproject.toml`,
and close merged `ticket-007` and `ticket-008`.

## Acceptance criteria

- [x] AC-01: Split `standard/conformance.py` (403 lines) and
      `standard/execution_conformance.py` (493 lines) using
      `standard/skill_primitives.py`, `standard/skill_fixtures.py`, and
      `standard/execution_fixtures.py` so every `.py` file is `< 500` lines with
      zero SSOT helper duplication.
- [x] AC-02: Enforce duplicate-key-rejecting `strict_loads`, strict RFC3339 `T`
      timestamps in `validate_grant`, `.`/`..`/`//` segment rejection in
      relative paths and branches, recursive inline secret/executable value
      rejection across all document types, and chain
      `operation_profile_conformance.run_all()` from `standard/conformance.py --all`.
- [x] AC-03: Add `pyproject.toml` and pass `ruff check standard`, all three
      conformance CLIs, `./project/governance-check.sh --base origin/main`, and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
