---
participant-id: agent:codex
participant: codex
role: agent
ticket: ticket-001
---
# Participant: codex (AI agent)

## Understanding

Wellmanifest already constrains agent roles and repair authority, but lacks a
portable normative contract for the skills those roles consume. The missing
pack must define deterministic `ERROR -> eligible skill` routing and let an
LLM propose ordering only inside schema-bound candidates. Stash, license,
secret and ambiguous changes need explicit non-automatic routes.

## Execution plan

1. Establish one governed local seed baseline.
2. Define the closed Skill DSL document family and constrained request grammar.
3. Add deterministic conformance fixtures including protected error classes.
4. Document composition and adoption by `subactor/*-agent` runtimes.
5. Run conformance, governance and diff hygiene before protected publication.

## Actual changes

- Initialized the bounded ticket and recorded SESSION_EXECUTION_AUTHORIZATION
  from the request to execute this work.
- Adopted `wellmanifest/new-project` v0.18.1 at immutable revision
  `16f7aea148a7f979e5c5abdfd4bc112224904d36`.
- Created the governed seed baseline
  `5f695003be1b42f932e82a73716bda99fbda94a5` before implementation.
- Added closed definition, catalog, selection-request and propose-only selection
  document variants plus a request-only GBNF.
- Added deterministic cross-document validation and protected safety-class
  regressions for stash, license, secret, ambiguity and destructive state.
- Documented composition and the adoption contract for `subactor/*-agent`.

## Blockers

- None inside the recorded intent; proceed without a second confirmation.
- New authority remains required for destructive action, secret access, new
  external coordination or material objective expansion. Protected delivery
  may be invoked without another prompt when publication is in scope; its
  exact-head trusted approval remains independent evidence.

## Risks and controls

- A skill could smuggle authority or arbitrary execution; executable fields and
  grants are absent from the DSL and rejected by conformance.
- An LLM could prioritize a disallowed repair; selection is candidate-bounded,
  advisory and revalidated deterministically.
- Secret, stash, license and ambiguity findings could cause destructive or
  legal changes; those classes require explicit routes and never auto-repair.
