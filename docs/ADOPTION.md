# Adoption by agent repositories

## Repository layout

An adopting `subactor/*-agent` repository should keep human/agent guidance and
the portable data contract adjacent:

```text
SKILLS/
├── catalog.json
└── govern-repository-remediation/
    ├── SKILL.md
    ├── skill.json
    ├── agents/
    │   └── openai.yaml
    ├── references/
    └── scripts/
```

Only `SKILL.md` and `skill.json` are mandatory. `SKILL.md` is the concise entry
point that tells an agent when and how to load the skill. `skill.json` conforms
to `wellmanifest.skill-definition/v1`. `agents/`, `references/` and `scripts/`
are optional progressive-disclosure resources. Do not add a second README
inside a skill directory. A script must consume validated data and must never
be treated as a grant.

The repository catalog conforms to `wellmanifest.skill-catalog/v1` and pins
each `skill.json` by repository, commit, path and SHA-256. The adopting profile
pins that catalog by the same four external coordinates; neither document
self-references a future commit. The runtime also pins the Wellmanifest schema
and conformance revision. Moving branches, unhashed local files and remote
schema fetching fail closed.

## Agent responsibilities

Doctor:

- emits stable, target-qualified, redacted diagnostic evidence;
- preserves the diagnostic registry version and fingerprint;
- does not choose authority or repair the target.

Skills:

- validates the catalog and definitions before use;
- deduplicates by target repository and fingerprint;
- computes eligible skills and deterministic priority before invoking an LLM;
- validates model output with `skill.v1.gbnf`, the schema and the original
  candidate set;
- hands a data-only proposal to POA; it never executes a repair.

Repair:

- accepts only an exact plan and external grant bound to the finding, target,
  base SHA, catalog, skill, policy/decision and plan digest;
- mutates only through the pull-request effect allowed by its agent profile;
- stops on workspace drift, secret exposure or scope ambiguity.

Validator:

- uses a distinct identity;
- checks the current exact pull-request head, required tests and skill
  completion criteria;
- emits trusted approval only through the protected validation mechanism;
- rejects a changed head and never treats LLM rationale as approval.

Other `*-agent` roles may consume a skill only when their declared
`wellmanifest/agent` profile matches the corresponding phase. A role cannot
gain a new lane or mutation effect from `skill.json` or `SKILL.md`.

## Repository-bootstrap follow-up

Adopters that execute repository bootstrap must preserve the following state
machine:

1. Persist the Repair read-back receipt bound to the exact plan.
2. Accept only an independently produced, closed validation receipt whose
   canonical hash and plan/subject/desired-state bindings match.
3. Consume it once through an authenticated, least-privilege transport. Treat
   exact replay as deduplication and a conflicting replay as
   `SKILL-EXEC-VALIDATION-RECEIPT-MISMATCH`.
4. Keep the execution non-terminal and run the declared mirror registration,
   profile validation and profile application contracts in order. Do not reuse
   bootstrap authority for a later mutation.
5. Emit terminal success only after every follow-up has independent read-back.

Block an administrator credential shared with Validator as
`SKILL-EXEC-VALIDATION-TRANSPORT-UNTRUSTED`. Use
`SKILL-EXEC-FOLLOWUP-ORDER-MISMATCH` for a substituted order,
`SKILL-EXEC-FOLLOWUP-INCOMPLETE` while a bound step remains, and
`SKILL-EXEC-PROFILE-NOT-READY` when exact runnable profile evidence is absent.
These errors never authorize a model to create the missing evidence.

## Deterministic checks

Validate the standard itself:

```bash
python3 standard/conformance.py --all
```

An adopter should run the pinned conformance copy against every definition and
catalog during CI:

```bash
python3 standard/conformance.py --file SKILLS/govern-repository-remediation/skill.json
python3 standard/conformance.py --file SKILLS/catalog.json
```

For an LLM recommendation, retain the exact request separately and validate
the pair. This proves the recommendation did not invent a candidate:

```bash
python3 standard/conformance.py \
  --proposal-with-request evidence/selection-request.json \
  evidence/selection-proposal.json
```

Then run the adopting repository's governance gate and runtime tests. Schema
conformance alone does not prove a script is safe, authorize an effect or
approve a pull request.

For an execution handoff, validate each deterministic document and then its
cross-document binding:

```bash
python3 standard/execution_conformance.py --file evidence/operation-plan.json
python3 standard/execution_conformance.py \
  --grant-with-plan evidence/operation-plan.json evidence/grant-binding.json
python3 standard/execution_conformance.py \
  --receipt-with-plan evidence/operation-plan.json evidence/terminal-receipt.json \
  --grant evidence/grant-binding.json
```

The adopting runtime must resolve `validationChecks` and
`rollbackProfileRef` from its own trusted, pinned registries. It must never
turn an LLM string into a command. For `executionMode=plan-only`, emit a
`planned` terminal receipt with no grant, head or validation evidence. For an
effect, verify the external grant outside model context and consume it once.
Repository bootstrap additionally requires private visibility, expected
absence and read-back of the created repository before dependent mirror or
profile operations become runnable.

## Required CI assertions

An adopting runtime should fail when:

- a `SKILL.md` has no adjacent conforming `skill.json`;
- a catalog entry digest or revision does not match its definition;
- a diagnostic code is absent from the pinned diagnostic registry;
- two active items repeat one `(targetRepository, fingerprint)`;
- a protected safety class uses routine authority;
- a model proposal selects outside the deterministic candidate set;
- a pull-request skill lacks Repair and Validator phases, exact base SHA or
  external authority evidence;
- a receipt contains a secret value, bearer identifier or executable command;
- the pull-request head differs from the head independently validated.
- an effect grant differs from any plan, target, desired-state or policy
  digest, is expired, reusable or authorizes a non-effect;
- a terminal error has no exact record in
  `standard/skill-execution.errors.json`;
- a successful effect lacks EQL read-back, rollback posture or independent
  validation evidence.

## Controlled rollout

1. Add the immutable `wellmanifest/skills` revision to the repository's
   `ADOPT` set without changing its `HOME` or runtime owner.
2. Convert one read-only Doctor finding family and keep Repair disabled.
3. Validate deduplication, ranking and protected decision requests in plan-only
   mode.
4. Enable one routine, pull-request-only capability under an exact standing
   policy or digest-bound grant.
5. Require independent Validator approval and exact-state read-back.
6. Expand diagnostic families only after receipts prove the previous class and
   rollback path.

This rollout creates bounded autonomy. It does not mean that every repository
finding is automatically changed and merged. Routine, explicitly granted
classes can complete end to end; stash, license, secret, ambiguity and
destructive state pause at their typed decision boundary and continue after a
new bound decision is supplied.
