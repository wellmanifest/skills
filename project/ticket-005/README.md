# Ticket 005: Standardize one-time repository initial-ref publication

- **ID**: ticket-005
- **Owner**: agent:codex under SESSION_EXECUTION_AUTHORIZATION
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-22

## Goal and scope

Define a data-only Skills operation profile for the separately governed
`repository:initial-ref` lifecycle. The profile must pin the immutable
`wellmanifest/git-lifecycle` contract, keep LLM output propose-only, require a
fresh digest-bound single-use grant and preserve independent terminal
validation. Runtime transport, credentials and Git execution remain outside
this repository.

## Acceptance criteria

- [x] AC-01: A closed profile schema rejects unknown fields, executable text,
  URLs, secret material and moving contract references.
- [x] AC-02: The canonical profile pins the exact initial-ref JSON and lifecycle
  artifacts by repository, immutable revision, relative path and SHA-256.
- [x] AC-03: Authority cannot be inherited and execution cannot become terminal
  before independent Validator acceptance or quarantine.
- [x] AC-04: Deterministic conformance includes positive and adversarial cases.
- [x] AC-05: Architecture and adopter guidance explain the boundary between
  Skills selection, domain execution and validation.

## Participants

- Human participant: the initiating conversation; no user-* file was created
  because only a trusted human intake boundary may create it.
- Agent participant: [ai-codex.md](ai-codex.md)
