# Ticket 012: Harden skills JSON numeric bounds, schema maxLength parity, and closed-schema checks

- **ID**: ticket-012
- **Owner**: tom
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-11-11

## Goal and scope

Harden `standard/skill_primitives.py` against `1e999` / `-1e999` float overflow
(`_parse_finite_float`), `OverflowError` on huge integers (`10**400`) in
`assert_json_depth` and `canonical`, whitespace/control-character injection in
`validate_safe_reference`, and implicit open object schemas in
`assert_closed_schema` while preserving conditional `"if"` / `"allOf"`
refinements; enforce `skill.schema.json` `maxLength` bounds (`identifier` 160,
`skillId` 160, `diagnosticCode` 80) in `standard/conformance.py:Contracts.ref`;
add regression tests in `standard/test_skills_hardening.py`; and mark merged
`project/ticket-011/README.md` `DONE` / `PUBLICATION`.

## Acceptance criteria

- [x] AC-01: Reject `1e999`/`-1e999` float overflow and `10**400` integer
      overflow in `strict_loads` / `canonical`, whitespace/control chars in
      `validate_safe_reference`, open implicit object `$defs` in
      `assert_closed_schema`, and oversized `identifier`/`skillId`/`diagnosticCode`
      values in `conformance.py`, passing `pytest -q` and all three conformance CLIs.
- [x] AC-02: Keep every Python module strictly below 500 lines and pass
      `ruff check standard tests`.
- [x] AC-03: Mark merged `project/ticket-011/README.md` `DONE` / `PUBLICATION`
      and pass `./project/governance-check.sh --base origin/main` and `wellman check`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
