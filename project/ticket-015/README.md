# Ticket 015: Modularize skill_io and harden symlink traversal, JSON bounds, and control-char checks

- **ID**: ticket-015
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, optimizing, and modularizing `< 500` lines across `wellmanifest/*` standard repositories.

Extract bounded regular-file UTF-8 I/O, strict JSON parsing, canonical digesting, and secret-tree scanning into `standard/skill_io.py` (re-exported via `__all__` in `standard/skill_primitives.py`) so every Python module stays well below 500 lines; harden `_reject_ancestor_symlinks` against relative (`sym_dir/..`, `../sym_dir`) and un-normalized absolute symlink-parent traversal; bound JSON integer digits (`<= 309`) before `int()` conversion in `strict_loads`; reject integer overflow in `reject_sensitive_tree`; reject forbidden ASCII C0/DEL control characters in `bounded_text` (and newlines in single-line `title`); and reconcile merged `project/ticket-014/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: `standard/skill_io.py` encapsulates bounded UTF-8 file I/O, strict JSON parsing, canonicalization, and secret-tree checks (re-exported via `__all__` in `standard/skill_primitives.py`), keeping all `standard/*.py` and `tests/*.py` modules strictly `< 500` lines.
- [x] AC-02: `_reject_ancestor_symlinks` rejects relative and un-normalized absolute symlink-parent traversal, `strict_loads` bounds raw integer digits (`<= 309`) before `int()` conversion, `reject_sensitive_tree` rejects `10**400` integer overflow, and `bounded_text` / `validate_definition` reject forbidden ASCII control characters.
- [x] AC-03: Regression tests in `standard/test_skills_hardening.py` pass alongside `ruff check --no-cache standard tests`, all three conformance CLIs, `./project/governance-check.sh --base origin/main`, and `wellman check`, and merged `project/ticket-014/README.md` is marked `DONE`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
