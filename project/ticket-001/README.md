# Ticket 001: Define governed agent Skill DSL standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-20

## Goal and scope

Define a reusable Skill DSL for Doctor, Repair, Validator, Skills and other
declared agents. The standard binds stable diagnostic codes to data-only
operations, preconditions, risk, priority inputs, authority requirements and
validation evidence without embedding executable shell, secrets or grants.

This package composes `wellmanifest/agent`, `priority`, `policy-dsl`, `poa` and
`repair-lifecycle`. It does not redefine their role, authority or mutation
lifecycle and does not execute a Subactor runtime.

## Acceptance criteria

- [x] AC-01: The repository has an immutable published governance adoption and
  a real local seed baseline before standard implementation.
- [x] AC-02: A closed schema defines versioned skill definitions, catalogs,
  selection requests and deterministic selection receipts.
- [x] AC-03: Request-only GBNF excludes shell, argv, URLs, secrets, credentials,
  grants and merge commands from LLM-produced requests.
- [x] AC-04: Stable error routing covers safe automation, stash, license,
  secret and ambiguous-change cases with fail-closed authority classes.
- [x] AC-05: Documentation defines composition, agent-specific use and the
  advisory-only LLM boundary.
- [x] AC-06: Positive and adversarial conformance tests pass.
- [x] AC-07: Governance and diff-hygiene gates pass against the exact baseline.

## Authorization

The request to create this repository and execute the standard creates
`SESSION_EXECUTION_AUTHORIZATION` and the narrow autonomous seed-baseline
authorization. It permits one local governance-only baseline commit while
`HEAD` is unborn and implementation is absent. It does not itself approve a
merge or release.

The same request authorizes the protected publication process: implementation
commit, ticket branch, pull request and independent exact-head Validator. It
does not authorize direct merge, secret access or irreversible remediation.

## Baseline

The local governed seed transaction created
`5f695003be1b42f932e82a73716bda99fbda94a5`. Standard implementation begins
after this SHA and bounded delivery uses it as the exact accepted base.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
