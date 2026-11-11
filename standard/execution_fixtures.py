#!/usr/bin/env python3
"""Reference and adversarial fixtures for Wellmanifest skill execution v1."""

from __future__ import annotations

import copy
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    from standard.skill_primitives import canonical_digest, load_strict_json, strict_loads
except ImportError:
    from skill_primitives import canonical_digest, load_strict_json, strict_loads

EXECUTION_SCHEMA_URI = "https://wellmanifest.dev/schemas/skill-execution/v1"
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


def plan_digest(value: dict[str, Any]) -> str:
    payload = copy.deepcopy(value)
    payload.pop("planDigest", None)
    return canonical_digest(payload)


def idempotency_digest(value: dict[str, Any]) -> str:
    return canonical_digest(
        {
            "operationId": value["operationId"],
            "targetRepository": value["target"]["repository"],
            "findingDigest": value["finding"]["findingDigest"],
            "desiredStateDigest": value["target"]["desiredStateDigest"],
        }
    )


def artifact() -> dict[str, str]:
    return {
        "repository": "subactor/diagit",
        "revision": "a" * 40,
        "path": "src/diagit/diagnostics.v2.json",
        "sha256": "b" * 64,
    }


def plan_example(
    operation: str = "repository:repair", *, mode: str | None = None
) -> dict[str, Any]:
    skill_id, effect = OPERATIONS[operation]
    base_sha = None if operation == "repository:bootstrap" else "c" * 40
    execution_mode = mode or ("plan-only" if effect == "none" else "apply-requested")
    value: dict[str, Any] = {
        "$schema": EXECUTION_SCHEMA_URI,
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
        "requiredGrantBindings": sorted(
            BASE_BINDINGS | ({"exactBaseSha"} if base_sha else set())
        ),
        "planDigest": "0" * 64,
        "llmAuthority": "propose-only",
    }
    value["idempotencyKey"] = idempotency_digest(value)
    value["planDigest"] = plan_digest(value)
    return value


def grant_example(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": EXECUTION_SCHEMA_URI,
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
        "$schema": EXECUTION_SCHEMA_URI,
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
        "validation": None
        if planned
        else {
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
        "$schema": EXECUTION_SCHEMA_URI,
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


def build_adversarial_execution_cases(
    *,
    errors_path: Path,
    validate_plan_fn: Callable[[Any], Any],
    validate_grant_fn: Callable[[Any], Any],
    validate_grant_pair_fn: Callable[..., Any],
    validate_receipt_fn: Callable[[Any], Any],
    validate_receipt_pair_fn: Callable[..., Any],
    validate_error_fn: Callable[[Any], Any],
    validate_error_catalog_fn: Callable[[Any], Any],
) -> list[Callable[[], Any]]:
    now = datetime(2026, 8, 20, tzinfo=UTC)
    repair_plan = plan_example()
    grant = grant_example(repair_plan)
    invalid: list[Callable[[], Any]] = []

    bad = plan_example()
    bad["planDigest"] = "9" * 64
    invalid.append(lambda bad=bad: validate_plan_fn(bad))

    bad = plan_example("repository:bootstrap")
    bad["target"]["visibility"] = "public"
    bad["planDigest"] = plan_digest(bad)
    invalid.append(lambda bad=bad: validate_plan_fn(bad))

    bad = plan_example()
    bad["requiredGrantBindings"].remove("exactBaseSha")
    bad["planDigest"] = plan_digest(bad)
    invalid.append(lambda bad=bad: validate_plan_fn(bad))

    bad = plan_example()
    bad["finding"]["registry"]["path"] = "src/./diagnostics.v2.json"
    bad["planDigest"] = plan_digest(bad)
    invalid.append(lambda bad=bad: validate_plan_fn(bad))

    bad = grant_example(repair_plan)
    bad["targetRepository"] = "subactor/other"
    invalid.append(lambda bad=bad: validate_grant_pair_fn(repair_plan, bad, now=now))

    bad = grant_example(repair_plan)
    bad["expiresAt"] = "2020-01-01T00:00:00Z"
    invalid.append(lambda bad=bad: validate_grant_pair_fn(repair_plan, bad, now=now))

    bad = grant_example(repair_plan)
    bad["expiresAt"] = "2099-01-01 00:00:00+00:00"
    invalid.append(lambda bad=bad: validate_grant_fn(bad))

    bad = receipt_example(repair_plan, grant)
    bad["validation"]["exactHeadSha"] = "a" * 40
    invalid.append(lambda bad=bad: validate_receipt_pair_fn(repair_plan, bad, grant, now=now))

    bad = receipt_example(repair_plan, grant)
    bad["eql"]["outcome"] = "unsatisfied"
    invalid.append(lambda bad=bad: validate_receipt_fn(bad))

    bad = error_example()
    bad["errorRef"] = "error://wellmanifest.skills/OTHER"
    invalid.append(lambda bad=bad: validate_error_fn(bad))

    bad = error_example()
    bad["credential"] = "opaque"
    invalid.append(lambda bad=bad: validate_error_fn(bad))

    bad = error_example()
    bad["evidenceRefs"] = ["evidence://subactor/ghp_1234567890abcdef1234567890abcdef"]
    invalid.append(lambda bad=bad: validate_error_fn(bad))

    error_registry = load_strict_json(errors_path)
    error_registry["errors"] = [
        item
        for item in error_registry["errors"]
        if item["code"] != "SKILL-EXEC-PROFILE-NOT-READY"
    ]
    invalid.append(lambda reg=error_registry: validate_error_catalog_fn(reg))
    invalid.append(lambda: strict_loads('{"terminal":true,"terminal":false}'))
    return invalid
