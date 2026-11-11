#!/usr/bin/env python3
"""Dependency-free conformance checks for Wellmanifest skill execution v1."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from standard import execution_fixtures as _efx
    from standard import skill_primitives as _pr
except ImportError:
    import execution_fixtures as _efx  # type: ignore[no-redef]
    import skill_primitives as _pr  # type: ignore[no-redef]

ContractError, canonical, digest = _pr.ContractError, _pr.canonical, _pr.canonical_digest
exact, text, enumeration = _pr.exact, _pr.pattern_text, _pr.enum
boolean, integer, unique_strings = _pr.boolean, _pr.integer, _pr.unique_strings
expect_rejected = _pr.expect_rejected
SCHEMA_URI, OPERATIONS, BASE_BINDINGS = (
    _efx.EXECUTION_SCHEMA_URI, _efx.OPERATIONS, _efx.BASE_BINDINGS
)
plan_digest, idempotency_digest = _efx.plan_digest, _efx.idempotency_digest
artifact, plan_example, grant_example = _efx.artifact, _efx.plan_example, _efx.grant_example
receipt_example, error_example = _efx.receipt_example, _efx.error_example

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "skill-execution.schema.json"
ERRORS_PATH = ROOT / "skill-execution.errors.json"
ERROR_CLASSES = {
    "availability", "configuration", "integrity", "policy", "security", "state", "unknown"
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
SKILL_ID = re.compile(r"^skill\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.v[1-9][0-9]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REFERENCE = re.compile(
    r"^(?:agent|artifact|diagit|evidence|error|grant|policy|profile|receipt)://[A-Za-z0-9._:/-]+$"
)
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
ORGANIZATION = re.compile(r"^[A-Za-z0-9_.-]+$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
DIAGNOSTIC_ID = re.compile(r"^DIAGIT-[A-Z0-9]+-[0-9]{3}$")
DIAGNOSTIC_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*$")

PLAN_KEYS = {
    "$schema", "schema", "planId", "correlationId", "operationId", "skillId", "executionMode",
    "target", "finding", "bindings", "effect", "idempotencyKey", "requiredGrantBindings",
    "planDigest", "llmAuthority",
}
GRANT_KEYS = {
    "$schema", "schema", "grantRef", "grantDigest", "planDigest", "operationId", "skillId",
    "targetRepository", "baseSha", "desiredStateDigest", "findingDigest", "catalogDigest",
    "skillDigest", "policyDigest", "authorizedEffect", "issuedByRef", "expiresAt", "singleUse",
}
RECEIPT_KEYS = {
    "$schema", "schema", "receiptId", "planDigest", "grantRef", "grantDigest", "operationId",
    "targetRepository", "status", "headSha", "evidenceRefs", "validation", "eql", "rollback",
    "terminal", "secretMaterialIncluded",
}
ERROR_KEYS = {
    "$schema", "schema", "errorId", "code", "errorRef", "errorClass", "phase", "retryable",
    "correlationId", "planDigest", "targetRepository", "evidenceRefs", "terminal",
    "secretMaterialIncluded",
}
REQUIRED_BOOTSTRAP_ERRORS = {
    "SKILL-EXEC-VALIDATION-RECEIPT-MISMATCH",
    "SKILL-EXEC-VALIDATION-TRANSPORT-UNTRUSTED",
    "SKILL-EXEC-FOLLOWUP-ORDER-MISMATCH",
    "SKILL-EXEC-FOLLOWUP-INCOMPLETE",
    "SKILL-EXEC-PROFILE-NOT-READY",
}


def reject_sensitive(value: Any) -> None:
    _pr.reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=True)


def _validate_exec_header(value: dict[str, Any], schema: str) -> None:
    if value["$schema"] != SCHEMA_URI or value["schema"] != schema:
        raise ContractError("unsupported document header")


def _validate_exec_artifact(value: Any) -> None:
    value = exact(value, {"repository", "revision", "path", "sha256"})
    text(value["repository"], REPOSITORY, "artifact repository", 200)
    text(value["revision"], COMMIT, "artifact revision", 40)
    _pr.validate_safe_relative_path(value["path"], RELATIVE_PATH, "artifact path", 300)
    text(value["sha256"], SHA256, "artifact digest", 64)


def _validate_target(value: Any) -> dict[str, Any]:
    keys = {
        "organization", "repository", "visibility", "baseBranch", "baseSha", "desiredStateDigest"
    }
    value = exact(value, keys)
    organization = text(value["organization"], ORGANIZATION, "organization", 100)
    repository = text(value["repository"], REPOSITORY, "target repository", 200)
    if repository.split("/", 1)[0].lower() != organization.lower():
        raise ContractError("organization differs from repository owner")
    enumeration(value["visibility"], {"private", "internal", "public"}, "visibility")
    _pr.validate_safe_relative_path(value["baseBranch"], BRANCH, "base branch", 160)
    if value["baseSha"] is not None:
        text(value["baseSha"], COMMIT, "base SHA", 40)
    text(value["desiredStateDigest"], SHA256, "desired state digest", 64)
    return value


def _validate_finding(value: Any) -> dict[str, Any]:
    keys = {"registry", "diagnosticId", "code", "errorClass", "fingerprint", "findingDigest"}
    value = exact(value, keys)
    _validate_exec_artifact(value["registry"])
    text(value["diagnosticId"], DIAGNOSTIC_ID, "diagnostic id", 80)
    text(value["code"], DIAGNOSTIC_CODE, "diagnostic code", 80)
    enumeration(value["errorClass"], ERROR_CLASSES, "error class")
    text(value["fingerprint"], SHA256, "fingerprint", 64)
    text(value["findingDigest"], SHA256, "finding digest", 64)
    return value


def _validate_bindings(value: Any) -> dict[str, str]:
    value = exact(value, {"catalogDigest", "skillDigest", "policyDigest", "priorityProfileDigest"})
    for name, item in value.items():
        text(item, SHA256, name, 64)
    return value


def _validate_effect(value: Any) -> dict[str, Any]:
    value = exact(value, {"kind", "maxChangedFiles", "validationChecks", "rollbackProfileRef"})
    effects = {"none", "repository-create", "mirror-register", "profile-apply", "pull-request"}
    kind = enumeration(value["kind"], effects, "effect")
    changed = integer(value["maxChangedFiles"], 0, 100)
    if (kind == "pull-request") != (changed > 0):
        raise ContractError("only pull-request effects may change repository files")
    for check in unique_strings(value["validationChecks"], 1, 20):
        text(check, IDENTIFIER, "validation check", 160)
    profile = text(value["rollbackProfileRef"], REFERENCE, "rollback profile", 320)
    if not profile.startswith("profile://"):
        raise ContractError("rollback profile must use profile://")
    return value


def validate_plan(value: Any) -> dict[str, Any]:
    value = exact(value, PLAN_KEYS)
    _validate_exec_header(value, "wellmanifest.skill-execution-plan/v1")
    text(value["planId"], IDENTIFIER, "plan id", 160)
    text(value["correlationId"], IDENTIFIER, "correlation id", 160)
    operation = enumeration(value["operationId"], set(OPERATIONS), "operation")
    skill_id = text(value["skillId"], SKILL_ID, "skill id", 160)
    expected_skill, expected_effect = OPERATIONS[operation]
    if skill_id != expected_skill:
        raise ContractError("operation does not use its registered skill")
    mode = enumeration(value["executionMode"], {"plan-only", "apply-requested"}, "execution mode")
    target = _validate_target(value["target"])
    _validate_finding(value["finding"])
    _validate_bindings(value["bindings"])
    effect = _validate_effect(value["effect"])
    if effect["kind"] != expected_effect:
        raise ContractError("operation does not use its registered effect")
    if operation == "repository:bootstrap":
        if target["baseSha"] is not None or target["visibility"] != "private":
            raise ContractError("bootstrap requires expected absence and private visibility")
    elif target["baseSha"] is None:
        raise ContractError("existing repository operation requires exact base SHA")
    if expected_effect == "none" and mode != "plan-only":
        raise ContractError("non-effectful operation must remain plan-only")
    required = set(unique_strings(value["requiredGrantBindings"], 8, 9))
    extra = {"exactBaseSha"} if target["baseSha"] is not None else set()
    if required != (BASE_BINDINGS | extra):
        raise ContractError("required grant bindings are not exact")
    if value["llmAuthority"] != "propose-only":
        raise ContractError("LLM authority is not propose-only")
    text(value["idempotencyKey"], SHA256, "idempotency key", 64)
    if value["idempotencyKey"] != idempotency_digest(value):
        raise ContractError("idempotency key mismatch")
    text(value["planDigest"], SHA256, "plan digest", 64)
    if value["planDigest"] != plan_digest(value):
        raise ContractError("plan digest mismatch")
    reject_sensitive(value)
    return value


def validate_grant(value: Any) -> dict[str, Any]:
    value = exact(value, GRANT_KEYS)
    _validate_exec_header(value, "wellmanifest.skill-grant-binding/v1")
    grant_ref = text(value["grantRef"], REFERENCE, "grant reference", 320)
    if not grant_ref.startswith("grant://"):
        raise ContractError("grant reference must use grant://")
    digest_fields = (
        "grantDigest", "planDigest", "desiredStateDigest", "findingDigest",
        "catalogDigest", "skillDigest", "policyDigest",
    )
    for field in digest_fields:
        text(value[field], SHA256, field, 64)
    operation = enumeration(value["operationId"], set(OPERATIONS), "operation")
    if (
        value["skillId"] != OPERATIONS[operation][0]
        or value["authorizedEffect"] != OPERATIONS[operation][1]
    ):
        raise ContractError("grant operation binding mismatch")
    if value["authorizedEffect"] == "none":
        raise ContractError("grant cannot authorize a non-effect")
    text(value["targetRepository"], REPOSITORY, "target repository", 200)
    if value["baseSha"] is not None:
        text(value["baseSha"], COMMIT, "base SHA", 40)
    issuer = text(value["issuedByRef"], REFERENCE, "issuer reference", 320)
    if not issuer.startswith("agent://"):
        raise ContractError("grant issuer must be an external agent reference")
    _pr.parse_rfc3339_utc(value["expiresAt"], "grant expiry")
    boolean(value["singleUse"], True)
    reject_sensitive(value)
    return value


def validate_grant_pair(
    plan: Any, grant: Any, *, now: datetime | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = validate_plan(plan)
    grant = validate_grant(grant)
    if plan["executionMode"] != "apply-requested" or plan["effect"]["kind"] == "none":
        raise ContractError("plan is not eligible for an effect grant")
    expected = {
        "planDigest": plan["planDigest"],
        "operationId": plan["operationId"],
        "skillId": plan["skillId"],
        "targetRepository": plan["target"]["repository"],
        "baseSha": plan["target"]["baseSha"],
        "desiredStateDigest": plan["target"]["desiredStateDigest"],
        "findingDigest": plan["finding"]["findingDigest"],
        "catalogDigest": plan["bindings"]["catalogDigest"],
        "skillDigest": plan["bindings"]["skillDigest"],
        "policyDigest": plan["bindings"]["policyDigest"],
        "authorizedEffect": plan["effect"]["kind"],
    }
    if any(grant[field] != expected[field] for field in expected):
        raise ContractError("grant differs from exact plan bindings")
    current = now or datetime.now(UTC)
    if _pr.parse_rfc3339_utc(grant["expiresAt"], "grant expiry") <= current:
        raise ContractError("grant is expired")
    return plan, grant


def _validate_validation(value: Any) -> dict[str, Any]:
    keys = {"validatorRef", "subjectDigest", "exactHeadSha", "outcome", "evidenceRef"}
    value = exact(value, keys)
    validator = text(value["validatorRef"], REFERENCE, "validator reference", 320)
    if not validator.startswith("agent://"):
        raise ContractError("validator must be an agent reference")
    text(value["subjectDigest"], SHA256, "validation subject", 64)
    if value["exactHeadSha"] is not None:
        text(value["exactHeadSha"], COMMIT, "validated head", 40)
    enumeration(value["outcome"], {"approved", "rejected"}, "validation outcome")
    text(value["evidenceRef"], REFERENCE, "validation evidence", 320)
    return value


def validate_receipt(value: Any) -> dict[str, Any]:
    value = exact(value, RECEIPT_KEYS)
    _validate_exec_header(value, "wellmanifest.skill-terminal-receipt/v1")
    receipt_ref = text(value["receiptId"], REFERENCE, "receipt id", 320)
    if not receipt_ref.startswith("receipt://"):
        raise ContractError("receipt id must use receipt://")
    text(value["planDigest"], SHA256, "plan digest", 64)
    if (value["grantRef"] is None) != (value["grantDigest"] is None):
        raise ContractError("grant receipt bindings must be both present or absent")
    if value["grantRef"] is not None:
        grant_ref = text(value["grantRef"], REFERENCE, "grant reference", 320)
        if not grant_ref.startswith("grant://"):
            raise ContractError("receipt grant reference must use grant://")
        text(value["grantDigest"], SHA256, "grant digest", 64)
    enumeration(value["operationId"], set(OPERATIONS), "operation")
    text(value["targetRepository"], REPOSITORY, "target repository", 200)
    statuses = {"planned", "succeeded", "blocked", "failed", "rolled-back"}
    status = enumeration(value["status"], statuses, "receipt status")
    if value["headSha"] is not None:
        text(value["headSha"], COMMIT, "receipt head", 40)
    for reference in unique_strings(value["evidenceRefs"], 1, 50):
        text(reference, REFERENCE, "evidence reference", 320)
    validation = None if value["validation"] is None else _validate_validation(value["validation"])
    eql = exact(value["eql"], {"expectationId", "outcome", "evidenceRef"})
    text(eql["expectationId"], IDENTIFIER, "EQL expectation", 160)
    eql_outcome = enumeration(eql["outcome"], {"satisfied", "unsatisfied", "not-run"}, "EQL")
    if (eql["evidenceRef"] is None) != (eql_outcome == "not-run"):
        raise ContractError("EQL evidence and outcome disagree")
    if eql["evidenceRef"] is not None:
        text(eql["evidenceRef"], REFERENCE, "EQL evidence", 320)
    rollback = exact(value["rollback"], {"profileRef", "status", "evidenceRef"})
    profile = text(rollback["profileRef"], REFERENCE, "rollback profile", 320)
    if not profile.startswith("profile://"):
        raise ContractError("rollback profile must use profile://")
    rb_statuses = {"not-needed", "available", "executed", "failed"}
    rollback_status = enumeration(rollback["status"], rb_statuses, "rollback status")
    if (rollback["evidenceRef"] is None) != (rollback_status in {"not-needed", "available"}):
        raise ContractError("rollback evidence and status disagree")
    if rollback["evidenceRef"] is not None:
        text(rollback["evidenceRef"], REFERENCE, "rollback evidence", 320)
    boolean(value["terminal"], True)
    boolean(value["secretMaterialIncluded"], False)
    if status == "planned" and (
        value["grantRef"] is not None
        or validation is not None
        or eql_outcome != "not-run"
        or value["headSha"] is not None
    ):
        raise ContractError("plan-only receipt contains effect evidence")
    if status == "succeeded" and (
        value["grantRef"] is None
        or validation is None
        or validation["outcome"] != "approved"
        or eql_outcome != "satisfied"
    ):
        raise ContractError("successful receipt lacks grant, approval or read-back")
    reject_sensitive(value)
    return value


def validate_receipt_pair(
    plan: Any, receipt: Any, grant: Any | None = None, *, now: datetime | None = None
) -> None:
    plan = validate_plan(plan)
    receipt = validate_receipt(receipt)
    if receipt["planDigest"] != plan["planDigest"] or receipt["operationId"] != plan["operationId"]:
        raise ContractError("receipt differs from plan")
    if receipt["targetRepository"] != plan["target"]["repository"]:
        raise ContractError("receipt target differs from plan")
    if receipt["status"] == "planned":
        if plan["executionMode"] != "plan-only" or grant is not None:
            raise ContractError("planned receipt must terminate a plan-only request")
        return
    if grant is None:
        raise ContractError("effect receipt requires an exact grant")
    _, grant = validate_grant_pair(plan, grant, now=now)
    if receipt["grantRef"] != grant["grantRef"] or receipt["grantDigest"] != grant["grantDigest"]:
        raise ContractError("receipt grant differs from exact grant")
    if receipt["status"] == "succeeded" and plan["effect"]["kind"] == "pull-request":
        head_sha = receipt["headSha"]
        if head_sha is None or receipt["validation"]["exactHeadSha"] != head_sha:
            raise ContractError("pull-request receipt lacks exact-head validation")


def validate_error_catalog(value: Any) -> dict[str, dict[str, Any]]:
    value = exact(value, {"schema", "errors"})
    if value["schema"] != "wellmanifest.skill-execution-error-registry/v1":
        raise ContractError("unknown error registry")
    if not isinstance(value["errors"], list) or not value["errors"]:
        raise ContractError("empty error registry")
    reactions = {"block", "refresh-plan", "request-grant", "rollback", "redact-and-escalate"}
    item_keys = {"code", "errorRef", "errorClass", "retryable", "reaction", "resolution"}
    catalog: dict[str, dict[str, Any]] = {}
    for item in value["errors"]:
        item = exact(item, item_keys)
        code = text(item["code"], DIAGNOSTIC_CODE, "error code", 80)
        reference = text(item["errorRef"], REFERENCE, "error reference", 320)
        if reference != f"error://wellmanifest.skills/{code}":
            raise ContractError("non-canonical error reference")
        enumeration(item["errorClass"], ERROR_CLASSES, "error class")
        boolean(item["retryable"])
        enumeration(item["reaction"], reactions, "error reaction")
        text(item["resolution"], IDENTIFIER, "error resolution", 160)
        if code in catalog:
            raise ContractError("duplicate error code")
        catalog[code] = item
    missing = REQUIRED_BOOTSTRAP_ERRORS - set(catalog)
    if missing:
        joined = ", ".join(sorted(missing))
        raise ContractError(f"error registry omits required bootstrap follow-up errors: {joined}")
    return catalog


def load_error_catalog() -> dict[str, dict[str, Any]]:
    return validate_error_catalog(_pr.load_strict_json(ERRORS_PATH))


def validate_error(value: Any) -> dict[str, Any]:
    value = exact(value, ERROR_KEYS)
    _validate_exec_header(value, "wellmanifest.skill-execution-error/v1")
    text(value["errorId"], IDENTIFIER, "error id", 160)
    text(value["correlationId"], IDENTIFIER, "correlation id", 160)
    if value["planDigest"] is not None:
        text(value["planDigest"], SHA256, "plan digest", 64)
    if value["targetRepository"] is not None:
        text(value["targetRepository"], REPOSITORY, "target repository", 200)
    phases = {"plan", "authorize", "repair", "validate", "publish", "readback", "rollback"}
    enumeration(value["phase"], phases, "phase")
    for reference in unique_strings(value["evidenceRefs"], 0, 20):
        text(reference, REFERENCE, "error evidence", 320)
    boolean(value["terminal"], True)
    boolean(value["secretMaterialIncluded"], False)
    record = load_error_catalog().get(value["code"])
    if record is None:
        raise ContractError("error code has no canonical record")
    if any(value[field] != record[field] for field in ("errorRef", "errorClass", "retryable")):
        raise ContractError("error envelope differs from canonical record")
    reject_sensitive(value)
    return value


def validate_document(value: Any) -> None:
    if not isinstance(value, dict):
        raise ContractError("document must be an object")
    validators: dict[str, Callable[[Any], Any]] = {
        "wellmanifest.skill-execution-plan/v1": validate_plan,
        "wellmanifest.skill-grant-binding/v1": validate_grant,
        "wellmanifest.skill-terminal-receipt/v1": validate_receipt,
        "wellmanifest.skill-execution-error/v1": validate_error,
    }
    validator = validators.get(value.get("schema"))
    if validator is None:
        raise ContractError("unknown document schema")
    validator(value)


def integrity() -> None:
    schema = _pr.load_strict_json(SCHEMA_PATH)
    if schema.get("$id") != SCHEMA_URI or not isinstance(schema.get("$defs"), dict):
        raise ContractError("execution schema integrity failure")
    _pr.assert_closed_schema(schema)
    load_error_catalog()


def run_all() -> None:
    integrity()
    plans = [plan_example(operation) for operation in OPERATIONS]
    for plan in plans:
        validate_plan(plan)
    repair_plan = plan_example()
    grant = grant_example(repair_plan)
    receipt = receipt_example(repair_plan, grant)
    plan_only = plan_example("repository:repair", mode="plan-only")
    planned_receipt = receipt_example(plan_only)
    valid = [*plans, grant, receipt, planned_receipt, error_example()]
    for document in valid:
        validate_document(document)
    now = datetime(2026, 8, 20, tzinfo=UTC)
    validate_grant_pair(repair_plan, grant, now=now)
    validate_receipt_pair(repair_plan, receipt, grant, now=now)
    validate_receipt_pair(plan_only, planned_receipt)

    invalid = _efx.build_adversarial_execution_cases(
        errors_path=ERRORS_PATH,
        validate_plan_fn=validate_plan,
        validate_grant_fn=validate_grant,
        validate_grant_pair_fn=validate_grant_pair,
        validate_receipt_fn=validate_receipt,
        validate_receipt_pair_fn=validate_receipt_pair,
        validate_error_fn=validate_error,
        validate_error_catalog_fn=validate_error_catalog,
    )
    for callback in invalid:
        expect_rejected(callback)
    print(f"PASS: {len(valid)} execution documents, {len(invalid)} adversarial cases")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--file", type=Path)
    parser.add_argument("--grant-with-plan", nargs=2, type=Path, metavar=("PLAN", "GRANT"))
    parser.add_argument("--receipt-with-plan", nargs=2, type=Path, metavar=("PLAN", "RECEIPT"))
    parser.add_argument("--grant", type=Path)
    args = parser.parse_args()
    try:
        integrity()
        if args.all:
            run_all()
        elif args.file:
            validate_document(_pr.load_strict_json(args.file))
            print("PASS: execution document conforms")
        elif args.grant_with_plan:
            plan, grant = (_pr.load_strict_json(path) for path in args.grant_with_plan)
            validate_grant_pair(plan, grant)
            print("PASS: grant is exact-plan-bound")
        elif args.receipt_with_plan:
            plan, receipt = (_pr.load_strict_json(path) for path in args.receipt_with_plan)
            grant = _pr.load_strict_json(args.grant) if args.grant else None
            validate_receipt_pair(plan, receipt, grant)
            print("PASS: receipt is terminal and plan-bound")
        else:
            parser.error("choose --all, --file, --grant-with-plan or --receipt-with-plan")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
