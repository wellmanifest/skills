# Ticket 004: Standardize non-terminal bootstrap follow-ups

- **ID**: ticket-004
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-20

## Goal and scope

Standardize the fail-closed handoff from an independently validated repository
bootstrap subject to runtime-owned, ordered follow-up operations. Add canonical
execution errors for substituted validation evidence, untrusted transport,
out-of-order or incomplete follow-up, and a profile that lacks exact runnable
evidence. Keep transport and execution in adopters; this repository owns only
portable data contracts and composition rules.

## Acceptance criteria

- [x] AC-01: The canonical registry names every new error with a closed class,
  retry policy, reaction and deterministic resolution.
- [x] AC-02: Conformance requires those errors and rejects a registry that
  silently omits one.
- [x] AC-03: Adoption guidance defines exact-once validation consumption and
  preserves non-terminal state until every ordered follow-up is read back.
- [x] AC-04: Bootstrap authority is not inherited by mirror/profile mutations;
  read-only validation and mutating follow-ups retain distinct authority.
- [x] AC-05: Missing profile evidence blocks without inventing commands,
  repository content, secrets, license choices or destructive recovery.
- [x] AC-06: Standard, governance and diff checks pass.

## Authorization

The user's continuing instruction is `SESSION_EXECUTION_AUTHORIZATION` for
this bounded standard change and its protected publication path. It does not
authorize this repository to execute adopter runtimes, access secrets, issue
grants or merge without independent exact-head approval.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
