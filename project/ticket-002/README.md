# Ticket 002: Run skills conformance in hosted CI

- **ID**: ticket-002
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-20

## Goal and scope

Run the existing dependency-free Skill DSL conformance on every pull request,
main update and manual dispatch. Publish one stable hosted check context,
`standards / skills conformance`, that Validator can require after this change
is merged.

## Acceptance criteria

- [x] AC-01: One least-privilege workflow owns the semantic hosted check.
- [x] AC-02: The workflow invokes the existing conformance entrypoint without
  duplicating its rules or installing runtime dependencies.
- [x] AC-03: Pull requests and main updates trigger the same named job.
- [x] AC-04: Local conformance and governance pass.
- [x] AC-05: Diff hygiene passes against exact base `7ffffc3...`.

## Authorization

The request to create and enforce this standard authorizes the bounded
workflow change and protected delivery through independent exact-head
Validator review. It does not authorize direct merge or broader workflow
permissions.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Publication

Validator run `32350666557` approved exact head
`325c1d8eb331213e0a268dfc971e2095f4fa247c`. The Validator GitHub App merged
PR `#2` as `b1650817e77d05e06f88e4fbae98845884fb50b8` on 2026-08-20.
