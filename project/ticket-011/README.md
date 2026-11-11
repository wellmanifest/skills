# Ticket 011: Harden skills primitives and modularize execution conformance

- **ID**: ticket-011
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Harden `standard/skill_primitives.py`, `standard/conformance.py`,
`standard/execution_conformance.py`, and `standard/operation_profile_conformance.py`
against `NaN`/`Infinity`, unbounded JSON/tree nesting (`RecursionError`), symlink
and oversized file reads (`O_NOFOLLOW`), non-string keys and unhashable JSON
fields (`TypeError`), and `.`/`..`/`//` traversal in repository, organization,
and URI reference identifiers; extract `standard/execution_errors.py` so every
Python module stays well below 500 lines with zero SSOT duplication; add
regression coverage in `standard/test_skills_hardening.py`; and mark merged
`ticket-010` `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Extract `standard/execution_errors.py` and harden JSON/file/tree/URI
      validators across `standard/*.py` with regression tests in
      `standard/test_skills_hardening.py`, passing `pytest -q` and all three
      conformance CLIs.
- [x] AC-02: Keep every Python module strictly below 500 lines and pass
      `ruff check standard tests`.
- [x] AC-03: Mark merged `project/ticket-010/README.md` `DONE` / `PUBLICATION`
      and pass `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
