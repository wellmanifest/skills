#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "skill-execution.schema.json"
ERRORS_PATH = ROOT / "skill-execution.errors.json"
SCHEMA_URI = "https://wellmanifest.dev/schemas/skill-execution/v1"
OPERATIONS = {
    "repository:bootstrap": ("skill.repository.bootstrap.v1", "repository-create"),
    "repository:register-mirror": ("skill.repository.register-mirror.v1", "mirror-register"),
    "repository:profile-validate": ("skill.repository.profile-validate.v1", "none"),
    "repository:profile-apply": ("skill.repository.profile-apply.v1", "profile-apply"),
    "repository:repair": ("skill.repository.repair.v1", "pull-request"),
    "repository:update": ("skill.repository.update.v1", "pull-request"),
}
BASE_BINDINGS = {
    "operationId",
    "findingDigest",
    "targetRepository",
    "desiredStateDigest",
    "catalogDigest",
    "skillDigest",
    "policyDigest",
    "planDigest",
}
ERROR_CLASSES = {"availability", "configuration", "integrity", "policy", "security", "state", "unknown"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
SKILL_ID = re.compile(r"^skill\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.v[1-9][0-9]*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REFERENCE = re.compile(r"^(?:agent|artifact|diagit|evidence|error|grant|policy|profile|receipt)://[A-Za-z0-9._:/-]+$")
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
ORGANIZATION = re.compile(r"^[A-Za-z0-9_.-]+$")
BRANCH = re.compile(r"^[A-Za-z0-9._/-]+$")
DIAGNOSTIC_ID = re.compile(r"^DIAGIT-[A-Z0-9]+-[0-9]{3}$")
DIAGNOSTIC_CODE = re.compile(r"^[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*$")
SENSITIVE_KEY_PARTS = ("secret", "credential", "bearer", "password", "token", "shell", "argv")


class ContractError(ValueError):
    pass


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def exact(value: Any, names: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise ContractError(f"object keys differ: expected {sorted(names)}")
    return value


def text(value: Any, pattern: re.Pattern[str], label: str, maximum: int = 320) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or pattern.fullmatch(value) is None:
        raise ContractError(f"invalid {label}")
    return value


def enumeration(value: Any, values: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in values:
        raise ContractError(f"invalid {label}")
    return value


def boolean(value: Any, expected: bool | None = None) -> bool:
    if not isinstance(value, bool) or (expected is not None and value is not expected):
        raise ContractError("invalid boolean")
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError("invalid integer")
    return value


def unique_strings(value: Any, minimum: int, maximum: int) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContractError("invalid list")
    if any(not isinstance(item, str) for item in value) or len(value) != len(set(value)):
        raise ContractError("list must contain unique strings")
    return value


def reject_sensitive(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "secretMaterialIncluded" and child is False:
                continue
            normalized = re.sub(r"[^a-z]", "", key.lower())
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                raise ContractError(f"sensitive or executable field is forbidden: {key}")
            reject_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive(child)


def validate_header(value: dict[str, Any], schema: str) -> None:
    if value["$schema"] != SCHEMA_URI or value["schema"] != schema:
        raise ContractError("unsupported document header")


def validate_artifact(value: Any) -> None:
    value = exact(value, {"repository", "revision", "path", "sha256"})
    text(value["repository"], REPOSITORY, "artifact repository", 200)
    text(value["revision"], COMMIT, "artifact revision", 40)
    path = value["path"]
    if (
        not isinstance(path, str)
        or not path
        or len(path) > 300
        or path.startswith("/")
        or ".." in Path(path).parts
        or RELATIVE_PATH.fullmatch(path) is None
    ):
        raise ContractError("invalid artifact path")
    text(value["sha256"], SHA256, "artifact digest", 64)


def validate_target(value: Any) -> dict[str, Any]:
    value = exact(value, {"organization", "repository", "visibility", "baseBranch", "baseSha", "desiredStateDigest"})
    organization = value["organization"]
    text(organization, ORGANIZATION, "organization", 100)
    repository = text(value["repository"], REPOSITORY, "target repository", 200)
    if repository.split("/", 1)[0].lower() != organization.lower():
        raise ContractError("organization differs from repository owner")
    enumeration(value["visibility"], {"private", "internal", "public"}, "visibility")
    branch = value["baseBranch"]
    if (
        not isinstance(branch, str)
        or not branch
        or len(branch) > 160
        or branch.startswith("/")
        or ".." in branch.split("/")
        or BRANCH.fullmatch(branch) is None
    ):
        raise ContractError("invalid base branch")
    if value["baseSha"] is not None:
        text(value["baseSha"], COMMIT, "base SHA", 40)
    text(value["desiredStateDigest"], SHA256, "desired state digest", 64)
    return value


def validate_finding(value: Any) -> dict[str, Any]:
    value = exact(value, {"registry", "diagnosticId", "code", "errorClass", "fingerprint", "findingDigest"})
    validate_artifact(value["registry"])
    text(value["diagnosticId"], DIAGNOSTIC_ID, "diagnostic id", 80)
    text(value["code"], DIAGNOSTIC_CODE, "diagnostic code", 80)
    enumeration(value["errorClass"], ERROR_CLASSES, "error class")
    text(value["fingerprint"], SHA256, "fingerprint", 64)
    text(value["findingDigest"], SHA256, "finding digest", 64)
    return value


def validate_bindings(value: Any) -> dict[str, str]:
    value = exact(value, {"catalogDigest", "skillDigest", "policyDigest", "priorityProfileDigest"})
    for name, item in value.items():
        text(item, SHA256, name, 64)
    return value


def validate_effect(value: Any) -> dict[str, Any]:
    value = exact(value, {"kind", "maxChangedFiles", "validationChecks", "rollbackProfileRef"})
    kind = enumeration(value["kind"], {"none", "repository-create", "mirror-register", "profile-apply", "pull-request"}, "effect")
    changed = integer(value["maxChangedFiles"], 0, 100)
    if (kind == "pull-request") != (changed > 0):
        raise ContractError("only pull-request effects may change repository files")
    for check in unique_strings(value["validationChecks"], 1, 20):
        text(check, IDENTIFIER, "validation check", 160)
    profile = text(value["rollbackProfileRef"], REFERENCE, "rollback profile", 320)
    if not profile.startswith("profile://"):
        raise ContractError("rollback profile must use profile://")
    return value


def plan_digest(value: dict[str, Any]) -> str:
    payload = copy.deepcopy(value)
    payload.pop("planDigest", None)
    return digest(payload)


def idempotency_digest(value: dict[str, Any]) -> str:
    return digest(
        {
            "operationId": value["operationId"],
            "targetRepository": value["target"]["repository"],
            "findingDigest": value["finding"]["findingDigest"],
            "desiredStateDigest": value["target"]["desiredStateDigest"],
        }
    )


def validate_plan(value: Any) -> dict[str, Any]:
    value = exact(
        value,
        {
            "$schema", "schema", "planId", "correlationId", "operationId", "skillId", "executionMode",
            "target", "finding", "bindings", "effect", "idempotencyKey", "requiredGrantBindings",
            "planDigest", "llmAuthority",
        },
    )
    validate_header(value, "wellmanifest.skill-execution-plan/v1")
    text(value["planId"], IDENTIFIER, "plan id", 160)
    text(value["correlationId"], IDENTIFIER, "correlation id", 160)
    operation = enumeration(value["operationId"], set(OPERATIONS), "operation")
    skill_id = text(value["skillId"], SKILL_ID, "skill id", 160)
    expected_skill, expected_effect = OPERATIONS[operation]
    if skill_id != expected_skill:
        raise ContractError("operation does not use its registered skill")
    mode = enumeration(value["executionMode"], {"plan-only", "apply-requested"}, "execution mode")
    target = validate_target(value["target"])
    validate_finding(value["finding"])
    validate_bindings(value["bindings"])
    effect = validate_effect(value["effect"])
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
    expected_bindings = BASE_BINDINGS | ({"exactBaseSha"} if target["baseSha"] is not None else set())
    if required != expected_bindings:
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
    value = exact(
        value,
        {
            "$schema", "schema", "grantRef", "grantDigest", "planDigest", "operationId", "skillId",
            "targetRepository", "baseSha", "desiredStateDigest", "findingDigest", "catalogDigest",
            "skillDigest", "policyDigest", "authorizedEffect", "issuedByRef", "expiresAt", "singleUse",
        },
    )
    validate_header(value, "wellmanifest.skill-grant-binding/v1")
    grant_ref = text(value["grantRef"], REFERENCE, "grant reference", 320)
    if not grant_ref.startswith("grant://"):
        raise ContractError("grant reference must use grant://")
    for field in ("grantDigest", "planDigest", "desiredStateDigest", "findingDigest", "catalogDigest", "skillDigest", "policyDigest"):
        text(value[field], SHA256, field, 64)
    operation = enumeration(value["operationId"], set(OPERATIONS), "operation")
    if value["skillId"] != OPERATIONS[operation][0] or value["authorizedEffect"] != OPERATIONS[operation][1]:
        raise ContractError("grant operation binding mismatch")
    if value["authorizedEffect"] == "none":
        raise ContractError("grant cannot authorize a non-effect")
    text(value["targetRepository"], REPOSITORY, "target repository", 200)
    if value["baseSha"] is not None:
        text(value["baseSha"], COMMIT, "base SHA", 40)
    issuer = text(value["issuedByRef"], REFERENCE, "issuer reference", 320)
    if not issuer.startswith("agent://"):
        raise ContractError("grant issuer must be an external agent reference")
    try:
        expires = datetime.fromisoformat(value["expiresAt"].replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ContractError("invalid grant expiry") from exc
    if expires.tzinfo is None:
        raise ContractError("grant expiry must include timezone")
    boolean(value["singleUse"], True)
    reject_sensitive(value)
    return value


def validate_grant_pair(plan: Any, grant: Any, *, now: datetime | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
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
    expires = datetime.fromisoformat(grant["expiresAt"].replace("Z", "+00:00"))
    if expires <= current:
        raise ContractError("grant is expired")
    return plan, grant


def validate_validation(value: Any) -> dict[str, Any]:
    value = exact(value, {"validatorRef", "subjectDigest", "exactHeadSha", "outcome", "evidenceRef"})
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
    value = exact(
        value,
        {
            "$schema", "schema", "receiptId", "planDigest", "grantRef", "grantDigest", "operationId",
            "targetRepository", "status", "headSha", "evidenceRefs", "validation", "eql", "rollback",
            "terminal", "secretMaterialIncluded",
        },
    )
    validate_header(value, "wellmanifest.skill-terminal-receipt/v1")
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
    status = enumeration(value["status"], {"planned", "succeeded", "blocked", "failed", "rolled-back"}, "receipt status")
    if value["headSha"] is not None:
        text(value["headSha"], COMMIT, "receipt head", 40)
    for reference in unique_strings(value["evidenceRefs"], 1, 50):
        text(reference, REFERENCE, "evidence reference", 320)
    validation = None if value["validation"] is None else validate_validation(value["validation"])
    eql = exact(value["eql"], {"expectationId", "outcome", "evidenceRef"})
    text(eql["expectationId"], IDENTIFIER, "EQL expectation", 160)
    eql_outcome = enumeration(eql["outcome"], {"satisfied", "unsatisfied", "not-run"}, "EQL outcome")
    if (eql["evidenceRef"] is None) != (eql_outcome == "not-run"):
        raise ContractError("EQL evidence and outcome disagree")
    if eql["evidenceRef"] is not None:
        text(eql["evidenceRef"], REFERENCE, "EQL evidence", 320)
    rollback = exact(value["rollback"], {"profileRef", "status", "evidenceRef"})
    profile = text(rollback["profileRef"], REFERENCE, "rollback profile", 320)
    if not profile.startswith("profile://"):
        raise ContractError("rollback profile must use profile://")
    rollback_status = enumeration(rollback["status"], {"not-needed", "available", "executed", "failed"}, "rollback status")
    if (rollback["evidenceRef"] is None) != (rollback_status in {"not-needed", "available"}):
        raise ContractError("rollback evidence and status disagree")
    if rollback["evidenceRef"] is not None:
        text(rollback["evidenceRef"], REFERENCE, "rollback evidence", 320)
    boolean(value["terminal"], True)
    boolean(value["secretMaterialIncluded"], False)
    if status == "planned":
        if value["grantRef"] is not None or validation is not None or eql_outcome != "not-run" or value["headSha"] is not None:
            raise ContractError("plan-only receipt contains effect evidence")
    if status == "succeeded":
        if value["grantRef"] is None or validation is None or validation["outcome"] != "approved" or eql_outcome != "satisfied":
            raise ContractError("successful receipt lacks grant, approval or read-back")
    reject_sensitive(value)
    return value


def validate_receipt_pair(plan: Any, receipt: Any, grant: Any | None = None, *, now: datetime | None = None) -> None:
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
        validation = receipt["validation"]
        if receipt["headSha"] is None or validation["exactHeadSha"] != receipt["headSha"]:
            raise ContractError("pull-request receipt lacks exact-head validation")


def validate_error_catalog(value: Any) -> dict[str, dict[str, Any]]:
    value = exact(value, {"schema", "errors"})
    if value["schema"] != "wellmanifest.skill-execution-error-registry/v1":
        raise ContractError("unknown error registry")
    if not isinstance(value["errors"], list) or not value["errors"]:
        raise ContractError("empty error registry")
    catalog: dict[str, dict[str, Any]] = {}
    for item in value["errors"]:
        item = exact(item, {"code", "errorRef", "errorClass", "retryable", "reaction", "resolution"})
        code = text(item["code"], DIAGNOSTIC_CODE, "error code", 80)
        reference = text(item["errorRef"], REFERENCE, "error reference", 320)
        if reference != f"error://wellmanifest.skills/{code}":
            raise ContractError("non-canonical error reference")
        enumeration(item["errorClass"], ERROR_CLASSES, "error class")
        boolean(item["retryable"])
        enumeration(item["reaction"], {"block", "refresh-plan", "request-grant", "rollback", "redact-and-escalate"}, "error reaction")
        text(item["resolution"], IDENTIFIER, "error resolution", 160)
        if code in catalog:
            raise ContractError("duplicate error code")
        catalog[code] = item
    required = {
        "SKILL-EXEC-VALIDATION-RECEIPT-MISMATCH",
        "SKILL-EXEC-VALIDATION-TRANSPORT-UNTRUSTED",
        "SKILL-EXEC-FOLLOWUP-ORDER-MISMATCH",
        "SKILL-EXEC-FOLLOWUP-INCOMPLETE",
        "SKILL-EXEC-PROFILE-NOT-READY",
    }
    missing = required - set(catalog)
    if missing:
        raise ContractError(
            "error registry omits required bootstrap follow-up errors: "
            + ", ".join(sorted(missing))
        )
    return catalog


def load_error_catalog() -> dict[str, dict[str, Any]]:
    return validate_error_catalog(json.loads(ERRORS_PATH.read_text(encoding="utf-8")))


def validate_error(value: Any) -> dict[str, Any]:
    value = exact(
        value,
        {
            "$schema", "schema", "errorId", "code", "errorRef", "errorClass", "phase", "retryable",
            "correlationId", "planDigest", "targetRepository", "evidenceRefs", "terminal",
            "secretMaterialIncluded",
        },
    )
    validate_header(value, "wellmanifest.skill-execution-error/v1")
    text(value["errorId"], IDENTIFIER, "error id", 160)
    text(value["correlationId"], IDENTIFIER, "correlation id", 160)
    if value["planDigest"] is not None:
        text(value["planDigest"], SHA256, "plan digest", 64)
    if value["targetRepository"] is not None:
        text(value["targetRepository"], REPOSITORY, "target repository", 200)
    enumeration(value["phase"], {"plan", "authorize", "repair", "validate", "publish", "readback", "rollback"}, "phase")
    for reference in unique_strings(value["evidenceRefs"], 0, 20):
        text(reference, REFERENCE, "error evidence", 320)
    boolean(value["terminal"], True)
    boolean(value["secretMaterialIncluded"], False)
    catalog = load_error_catalog()
    record = catalog.get(value["code"])
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


def artifact() -> dict[str, str]:
    return {
        "repository": "subactor/diagit",
        "revision": "a" * 40,
        "path": "src/diagit/diagnostics.v2.json",
        "sha256": "b" * 64,
    }


def plan_example(operation: str = "repository:repair", *, mode: str | None = None) -> dict[str, Any]:
    skill_id, effect = OPERATIONS[operation]
    base_sha = None if operation == "repository:bootstrap" else "c" * 40
    execution_mode = mode or ("plan-only" if effect == "none" else "apply-requested")
    value: dict[str, Any] = {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-execution-plan/v1",
        "planId": "plan.repository-001",
        "correlationId": "correlation.repository-001",
        "operationId": operation,
        "skillId": skill_id,
        "executionMode": execution_mode,
        "target": {
            "organization": "subactor",
            "repository": "subactor/example",
            "visibility": "private" if operation == "repository:bootstrap" else "public",
            "baseBranch": "main",
            "baseSha": base_sha,
            "desiredStateDigest": "d" * 64,
        },
        "finding": {
            "registry": artifact(),
            "diagnosticId": "DIAGIT-GIT-002",
            "code": "DETACHED_HEAD",
            "errorClass": "integrity",
            "fingerprint": "e" * 64,
            "findingDigest": "f" * 64,
        },
        "bindings": {
            "catalogDigest": "1" * 64,
            "skillDigest": "2" * 64,
            "policyDigest": "3" * 64,
            "priorityProfileDigest": "4" * 64,
        },
        "effect": {
            "kind": effect,
            "maxChangedFiles": 5 if effect == "pull-request" else 0,
            "validationChecks": ["repository.governance", "repository.tests"],
            "rollbackProfileRef": "profile://subactor/repository-rollback/v1",
        },
        "idempotencyKey": "0" * 64,
        "requiredGrantBindings": sorted(BASE_BINDINGS | ({"exactBaseSha"} if base_sha else set())),
        "planDigest": "0" * 64,
        "llmAuthority": "propose-only",
    }
    value["idempotencyKey"] = idempotency_digest(value)
    value["planDigest"] = plan_digest(value)
    return value


def grant_example(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-grant-binding/v1",
        "grantRef": "grant://subactor/repository/001",
        "grantDigest": "5" * 64,
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
        "issuedByRef": "agent://subactor/authority-controller",
        "expiresAt": "2099-01-01T00:00:00Z",
        "singleUse": True,
    }


def receipt_example(plan: dict[str, Any], grant: dict[str, Any] | None = None) -> dict[str, Any]:
    planned = grant is None
    head = None if planned or plan["effect"]["kind"] != "pull-request" else "6" * 40
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-terminal-receipt/v1",
        "receiptId": "receipt://subactor/repository/001",
        "planDigest": plan["planDigest"],
        "grantRef": None if planned else grant["grantRef"],
        "grantDigest": None if planned else grant["grantDigest"],
        "operationId": plan["operationId"],
        "targetRepository": plan["target"]["repository"],
        "status": "planned" if planned else "succeeded",
        "headSha": head,
        "evidenceRefs": ["evidence://subactor/repository/001"],
        "validation": None if planned else {
            "validatorRef": "agent://subactor/validator-agent",
            "subjectDigest": "7" * 64,
            "exactHeadSha": head,
            "outcome": "approved",
            "evidenceRef": "evidence://subactor/validation/001",
        },
        "eql": {
            "expectationId": "eql.repository-001",
            "outcome": "not-run" if planned else "satisfied",
            "evidenceRef": None if planned else "evidence://subactor/readback/001",
        },
        "rollback": {
            "profileRef": plan["effect"]["rollbackProfileRef"],
            "status": "available",
            "evidenceRef": None,
        },
        "terminal": True,
        "secretMaterialIncluded": False,
    }


def error_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-execution-error/v1",
        "errorId": "execution.error-001",
        "code": "SKILL-EXEC-GRANT-MISMATCH",
        "errorRef": "error://wellmanifest.skills/SKILL-EXEC-GRANT-MISMATCH",
        "errorClass": "security",
        "phase": "authorize",
        "retryable": False,
        "correlationId": "correlation.repository-001",
        "planDigest": "8" * 64,
        "targetRepository": "subactor/example",
        "evidenceRefs": ["evidence://subactor/authorization/001"],
        "terminal": True,
        "secretMaterialIncluded": False,
    }


def expect_rejected(callback: Callable[[], Any]) -> None:
    try:
        callback()
    except ContractError:
        return
    raise ContractError("adversarial fixture accepted")


def integrity() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if schema.get("$id") != SCHEMA_URI or not isinstance(schema.get("$defs"), dict):
        raise ContractError("execution schema integrity failure")
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
    validate_grant_pair(repair_plan, grant, now=datetime(2026, 8, 20, tzinfo=UTC))
    validate_receipt_pair(repair_plan, receipt, grant, now=datetime(2026, 8, 20, tzinfo=UTC))
    validate_receipt_pair(plan_only, planned_receipt)

    invalid: list[Callable[[], Any]] = []
    bad = plan_example()
    bad["planDigest"] = "9" * 64
    invalid.append(lambda bad=bad: validate_plan(bad))
    bad = plan_example("repository:bootstrap")
    bad["target"]["visibility"] = "public"
    bad["planDigest"] = plan_digest(bad)
    invalid.append(lambda bad=bad: validate_plan(bad))
    bad = plan_example()
    bad["requiredGrantBindings"].remove("exactBaseSha")
    bad["planDigest"] = plan_digest(bad)
    invalid.append(lambda bad=bad: validate_plan(bad))
    bad = grant_example(repair_plan)
    bad["targetRepository"] = "subactor/other"
    invalid.append(lambda bad=bad: validate_grant_pair(repair_plan, bad, now=datetime(2026, 8, 20, tzinfo=UTC)))
    bad = grant_example(repair_plan)
    bad["expiresAt"] = "2020-01-01T00:00:00Z"
    invalid.append(lambda bad=bad: validate_grant_pair(repair_plan, bad, now=datetime(2026, 8, 20, tzinfo=UTC)))
    bad = receipt_example(repair_plan, grant)
    bad["validation"]["exactHeadSha"] = "a" * 40
    invalid.append(lambda bad=bad: validate_receipt_pair(repair_plan, bad, grant, now=datetime(2026, 8, 20, tzinfo=UTC)))
    bad = receipt_example(repair_plan, grant)
    bad["eql"]["outcome"] = "unsatisfied"
    invalid.append(lambda bad=bad: validate_receipt(bad))
    bad = error_example()
    bad["errorRef"] = "error://wellmanifest.skills/OTHER"
    invalid.append(lambda bad=bad: validate_error(bad))
    bad = error_example()
    bad["credential"] = "opaque"
    invalid.append(lambda bad=bad: validate_error(bad))
    error_registry = json.loads(ERRORS_PATH.read_text(encoding="utf-8"))
    error_registry["errors"] = [
        item
        for item in error_registry["errors"]
        if item["code"] != "SKILL-EXEC-PROFILE-NOT-READY"
    ]
    invalid.append(lambda error_registry=error_registry: validate_error_catalog(error_registry))
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
            validate_document(json.loads(args.file.read_text(encoding="utf-8")))
            print("PASS: execution document conforms")
        elif args.grant_with_plan:
            plan, grant = (json.loads(path.read_text(encoding="utf-8")) for path in args.grant_with_plan)
            validate_grant_pair(plan, grant)
            print("PASS: grant is exact-plan-bound")
        elif args.receipt_with_plan:
            plan, receipt = (json.loads(path.read_text(encoding="utf-8")) for path in args.receipt_with_plan)
            grant = json.loads(args.grant.read_text(encoding="utf-8")) if args.grant else None
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
