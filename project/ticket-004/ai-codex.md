---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-004
---
# Participant: codex (AI agent)

## Understanding

The standard already owns exact plan/grant/terminal-receipt/error handoffs, but
does not name the failure modes observed when a runtime consumes a non-terminal
bootstrap validation receipt and then performs ordered mirror/profile
follow-ups. Add portable errors and composition guidance without moving
transport, execution or authority into Wellmanifest.

## Execution plan

1. Add canonical fail-closed errors for receipt, transport, ordering,
   incompleteness and profile-readiness failures.
2. Require their presence in dependency-free conformance.
3. Document exact-once non-terminal consumption and separate authority for
   ordered follow-ups.
4. Run standard and repository governance checks, then use protected delivery.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.
- Added five canonical errors for substituted Validator receipts, untrusted
  transport, follow-up ordering/incompleteness and missing profile evidence.
- Required the additive records in semantic conformance and added an
  adversarial omission case.
- Documented exact-once receipt consumption, non-terminal ordered follow-ups,
  separate mutation authority and fail-closed profile readiness.
- Raised the development standard version to 0.2.0-dev; both conformance suites,
  governance and diff hygiene pass without a runtime dependency.

## Blockers

- None inside the recorded intent; proceed without a second confirmation.
- New authority remains required for destructive action, secret access, new
  external coordination or material objective expansion. Protected delivery
  may be invoked without another prompt when publication is in scope; its
  exact-head trusted approval remains independent evidence.
