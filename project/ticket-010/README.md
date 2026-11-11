# Ticket 010: Add standalone pytest and unittest suite for governed skills conformance

- **ID**: ticket-010
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Add standalone `tests/test_skills_conformance.py` covering `standard/conformance.py`,
`standard/execution_conformance.py`, `standard/operation_profile_conformance.py`,
and `standard/skill_primitives.py` (including duplicate JSON keys, path-segment
traversal, strict RFC3339 timestamps, inline secret scanning, bool-for-int
rejection, and CLI `--file` exit codes), and close merged `ticket-009`.

## Acceptance criteria

- [x] AC-01: Add `tests/test_skills_conformance.py` (`< 500` lines) runnable via
      both `pytest -q` and `python3 -m unittest`.
- [x] AC-02: Mark merged `project/ticket-009/README.md` `DONE` / `PUBLICATION`.
- [x] AC-03: Pass `ruff check standard tests`, `pytest -q`,
      `./project/governance-check.sh --base origin/main`, and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
