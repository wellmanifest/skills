# Ticket 003: Define governed skill execution handoff contracts

- **ID**: ticket-003
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-20

## Goal and scope

Define portable, data-only handoff contracts between governed skill selection
and an external POA/repair runtime. Bind one exact repository operation plan to
an external grant reference, independent validation, EQL read-back, rollback
evidence and a canonical structured error record without issuing authority or
executing an effect in this standard repository.

## Acceptance criteria

- [x] AC-01: A closed schema covers plan, external grant binding, terminal
  receipt and structured execution error documents.
- [x] AC-02: Stable operation IDs cover repository bootstrap, OneDev mirror
  registration, profile validation/application, repair and bounded update.
- [x] AC-03: Effectful handoffs bind the finding, target, exact base when one
  exists, catalog, skill, policy and plan digest to a single-use external grant.
- [x] AC-04: Receipts carry redacted evidence references, rollback state,
  independent exact-head validation and terminal EQL read-back.
- [x] AC-05: Error envelopes resolve to a closed canonical error registry and
  cannot contain credentials, bearer grants, shell or argv.
- [x] AC-06: Positive and adversarial conformance plus governance checks pass.

## Authorization

The user's continuing instruction is `SESSION_EXECUTION_AUTHORIZATION` for
this bounded standard change and its protected publication path. It does not
authorize this repository to issue grants, access secrets, execute repository
effects or merge directly.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
