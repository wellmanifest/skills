#!/usr/bin/env python3
"""Error registry and envelope conformance helpers for Wellmanifest skill execution v1."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from standard import execution_fixtures as _efx
    from standard import skill_primitives as _pr
except ImportError:
    import execution_fixtures as _efx  # type: ignore[no-redef]
    import skill_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
exact = _pr.exact
text = _pr.pattern_text
enumeration = _pr.enum
boolean = _pr.boolean
unique_strings = _pr.unique_strings
SCHEMA_URI = _efx.EXECUTION_SCHEMA_URI

ROOT = Path(__file__).resolve().parent
ERRORS_PATH = ROOT / "skill-execution.errors.json"
ERROR_CLASSES = {
    "availability",
    "configuration",
    "integrity",
    "policy",
    "security",
    "state",
    "unknown",
}
SHA256 = _pr.SHA256
IDENTIFIER = _pr.IDENTIFIER
REPOSITORY = _pr.REPOSITORY
REFERENCE = _pr.REFERENCE
DIAGNOSTIC_CODE = _pr.DIAGNOSTIC_CODE

ERROR_KEYS = {
    "$schema",
    "schema",
    "errorId",
    "code",
    "errorRef",
    "errorClass",
    "phase",
    "retryable",
    "correlationId",
    "planDigest",
    "targetRepository",
    "evidenceRefs",
    "terminal",
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


def validate_exec_header(value: dict[str, Any], schema: str) -> None:
    if value["$schema"] != SCHEMA_URI or value["schema"] != schema:
        raise ContractError("unsupported document header")


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
        reference = _pr.validate_safe_reference(
            item["errorRef"], REFERENCE, "error reference", 320
        )
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
    validate_exec_header(value, "wellmanifest.skill-execution-error/v1")
    text(value["errorId"], IDENTIFIER, "error id", 160)
    code = text(value["code"], DIAGNOSTIC_CODE, "error code", 80)
    text(value["correlationId"], IDENTIFIER, "correlation id", 160)
    if value["planDigest"] is not None:
        text(value["planDigest"], SHA256, "plan digest", 64)
    if value["targetRepository"] is not None:
        _pr.validate_safe_repository(
            value["targetRepository"], REPOSITORY, "target repository", 200
        )
    phases = {"plan", "authorize", "repair", "validate", "publish", "readback", "rollback"}
    enumeration(value["phase"], phases, "phase")
    for reference in unique_strings(value["evidenceRefs"], 0, 20):
        _pr.validate_safe_reference(reference, REFERENCE, "error evidence", 320)
    boolean(value["terminal"], True)
    boolean(value["secretMaterialIncluded"], False)
    record = load_error_catalog().get(code)
    if record is None:
        raise ContractError("error code has no canonical record")
    if any(value[field] != record[field] for field in ("errorRef", "errorClass", "retryable")):
        raise ContractError("error envelope differs from canonical record")
    reject_sensitive(value)
    return value
