# Ticket 006: Adopt new-project standard 0.18.6

- **ID**: ticket-006
- **Owner**: agent:gemini under SESSION_EXECUTION_AUTHORIZATION
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-23

## Goal and scope

Adopt published `wellmanifest/new-project` 0.18.6 into `wellmanifest/skills` in one atomic transaction through `create_adoption_lock.py`.
Brings the host-agnostic contract (CLAUDE.md, GEMINI.md, Cursor rule, pre-commit hook, agent-hosts.json validator) and `governance / enforce` CI job.

## Acceptance criteria

- [x] AC-01: `python3 .governance/agent_host_check.py --root .` → `GOV-AGENT-HOST-PASS` after `./scripts/install-agent-hosts.sh`.
- [x] AC-02: `./project/governance-check.sh --actor agent` → `GOV-PASS`, all managed digests match lock.
- [x] AC-03: `python3 standard/conformance.py --all` passes; domain contracts unaffected.

## Publication evidence

- Pull request: `wellmanifest/skills#9`
- Frozen and approved head: `7e5f04ac515f0f8afa74776267fa0389341df234`
- Merge commit: `b66f4a95813d85b23fbbe6641661e61c6780f2ca`
- Validator approval: review `5002985142`, run `32664676878`.

## Participants

- Human participant: authorized via active session.
- Agent participant: [ai-gemini.md](ai-gemini.md)
