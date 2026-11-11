# Ticket 014: Harden skills JSON overflow/surrogates, absolute ancestor symlinks, and Windows drive paths

- **ID**: ticket-014
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: On 2026-11-11 user authorized auditing, fixing bugs, and hardening across `wellmanifest/*` standard repositories.

Catch 4300-digit integer `ValueError` in `strict_loads`, reject lone UTF-16 surrogates across `assert_json_depth`, `strict_loads`, `canonical`, `sha256_text`, `bounded_text`, `pattern_text`, and `reject_sensitive_tree`, scan JSON object keys with `EXECUTABLE_OR_SECRET_TEXT` in `reject_sensitive_tree`, reject symlink ancestors for both relative and absolute paths in `read_regular_utf8`, reject Windows drive-prefixed paths (`C:foo`) in `validate_safe_relative_path`, expand `standard/test_skills_hardening.py`, and reconcile merged `project/ticket-013/README.md` to `DONE`.

## Acceptance criteria

- [x] AC-01: `strict_loads`, `assert_json_depth`, `canonical`, `sha256_text`, and `reject_sensitive_tree` reject 4300+ digit integers, lone UTF-16 surrogates, and executable/remote/secret object keys with `ContractError`.
- [x] AC-02: `read_regular_utf8` rejects symlink ancestors for both relative and absolute paths, `validate_safe_relative_path` rejects Windows drive-letter prefixes, and all Python modules stay strictly `< 500` lines and pass `ruff check`.
- [x] AC-03: Regression tests in `standard/test_skills_hardening.py` pass alongside all three conformance CLIs, `./project/governance-check.sh --base origin/main`, and `wellman check`, and merged `project/ticket-013/README.md` is marked `DONE`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
