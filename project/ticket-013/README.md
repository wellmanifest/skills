# Ticket 013: Harden skills regular-file inode checks, reference delimiters, and regex anchors

- **ID**: ticket-013
- **Owner**: tom
- **Status**: DONE
- **Workflow state**: PUBLICATION
- **Created**: 2026-11-11

## Goal and scope

Enforce `os.lstat` + `os.fstat` `(st_dev, st_ino)` regular-file identity,
relative ancestor symlink rejection, and `max_bytes` integer/boolean bounds in
`standard/skill_primitives.py:read_regular_utf8`; harden
`validate_safe_reference` against `\`, `?`, `#`, and colon-delimited `..` or
empty segments; centralize `\A...\Z`-anchored regex patterns and
`compile_anchored_pattern` in `standard/skill_primitives.py` and deduplicate
regex constants across `standard/conformance.py`, `standard/execution_errors.py`,
`standard/execution_conformance.py`, and
`standard/operation_profile_conformance.py`; add regression tests in
`standard/test_skills_hardening.py`; and mark merged
`project/ticket-012/README.md` `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Enforce `lstat`+`fstat` inode identity, relative ancestor symlink
      rejection, `max_bytes` bounds, reference delimiter/colon `..` rejection,
      and `\A...\Z` regex anchors across all conformance modules, passing
      `pytest -q` and all three conformance CLIs.
- [x] AC-02: Keep every Python module strictly below 500 lines and pass
      `ruff check standard tests`.
- [x] AC-03: Mark merged `project/ticket-012/README.md` `DONE` / `PUBLICATION`
      and pass `./project/governance-check.sh --base origin/main` and
      `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
