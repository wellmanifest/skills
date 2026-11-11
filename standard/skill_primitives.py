#!/usr/bin/env python3
"""Shared deterministic primitives for Wellmanifest governed skills conformance."""

from __future__ import annotations

import importlib.util
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from standard.skill_io import (
        EXECUTABLE_OR_SECRET_TEXT,
        MAX_JSON_BYTES,
        MAX_JSON_DEPTH,
        MAX_JSON_INT_DIGITS,
        SENSITIVE_KEY_PARTS,
        ContractError,
        _check_finite_number,
        _check_utf8_str,
        _reject_ancestor_symlinks,
        assert_closed_schema,
        assert_json_depth,
        canonical,
        canonical_digest,
        load_strict_json,
        read_regular_utf8,
        reject_sensitive_tree,
        sha256_text,
        strict_loads,
    )
except ImportError:
    from skill_io import (  # type: ignore[no-redef]
        EXECUTABLE_OR_SECRET_TEXT,
        MAX_JSON_BYTES,
        MAX_JSON_DEPTH,
        MAX_JSON_INT_DIGITS,
        SENSITIVE_KEY_PARTS,
        ContractError,
        _check_finite_number,
        _check_utf8_str,
        _reject_ancestor_symlinks,
        assert_closed_schema,
        assert_json_depth,
        canonical,
        canonical_digest,
        load_strict_json,
        read_regular_utf8,
        reject_sensitive_tree,
        sha256_text,
        strict_loads,
    )

__all__ = [
    "COMMIT",
    "DIAGNOSTIC_CODE",
    "DIAGNOSTIC_ID",
    "EXECUTABLE_OR_SECRET_TEXT",
    "IDENTIFIER",
    "MAX_JSON_BYTES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_INT_DIGITS",
    "ORGANIZATION",
    "REFERENCE",
    "RELATIVE_PATH",
    "REPOSITORY",
    "RFC3339_TIMESTAMP",
    "SENSITIVE_KEY_PARTS",
    "SHA256",
    "SKILL_ID",
    "WINDOWS_DRIVE_PREFIX",
    "ContractError",
    "_check_finite_number",
    "_check_utf8_str",
    "_reject_ancestor_symlinks",
    "assert_closed_schema",
    "assert_json_depth",
    "boolean",
    "bounded_text",
    "canonical",
    "canonical_digest",
    "compile_anchored_pattern",
    "enum",
    "exact",
    "expect_rejected",
    "integer",
    "load_sibling_module",
    "load_strict_json",
    "parse_rfc3339_utc",
    "pattern_text",
    "read_regular_utf8",
    "reject_sensitive_tree",
    "sha256_text",
    "strict_loads",
    "unique_strings",
    "validate_safe_organization",
    "validate_safe_reference",
    "validate_safe_relative_path",
    "validate_safe_repository",
]

WINDOWS_DRIVE_PREFIX = re.compile(r"\A[A-Za-z]:")
RFC3339_TIMESTAMP = re.compile(
    r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
COMMIT = re.compile(r"\A[a-f0-9]{40}\Z")
SHA256 = re.compile(r"\A[a-f0-9]{64}\Z")
IDENTIFIER = re.compile(r"\A[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*\Z")
SKILL_ID = re.compile(r"\Askill\.[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*\.v[1-9][0-9]*\Z")
REPOSITORY = re.compile(r"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
RELATIVE_PATH = re.compile(r"\A[A-Za-z0-9._/-]+\Z")
ORGANIZATION = re.compile(r"\A[A-Za-z0-9_.-]+\Z")
REFERENCE = re.compile(
    r"\A(?:agent|artifact|diagit|evidence|error|grant|policy|profile|receipt)://[A-Za-z0-9._:/-]+\Z"
)
DIAGNOSTIC_CODE = re.compile(r"\A[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*\Z")
DIAGNOSTIC_ID = re.compile(r"\ADIAGIT-[A-Z0-9]+-[0-9]{3}\Z")


def compile_anchored_pattern(raw: str) -> re.Pattern[str]:
    if not isinstance(raw, str) or not raw:
        raise ContractError("invalid regex pattern")
    body = raw[1:] if raw.startswith("^") else raw
    if body.endswith("$") and not body.endswith(r"\$"):
        body = body[:-1]
    return re.compile(rf"\A(?:{body})\Z")


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    if any(not isinstance(key, str) for key in value):
        raise ContractError("expected string object keys")
    optional_keys = optional or set()
    keys = set(value)
    if keys - required - optional_keys:
        raise ContractError("undeclared field")
    if required - keys:
        raise ContractError("missing field")
    return value


def bounded_text(
    value: Any,
    minimum: int = 1,
    maximum: int = 1000,
    *,
    allow_newlines: bool = True,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ContractError("invalid string")
    _check_utf8_str(value)
    allowed_ctrl = ("\n", "\t") if allow_newlines else ()
    if any((ord(ch) < 32 and ch not in allowed_ctrl) or ord(ch) == 127 for ch in value):
        raise ContractError("invalid string")
    if EXECUTABLE_OR_SECRET_TEXT.search(value):
        raise ContractError("executable, remote or secret text is forbidden")
    return value


def pattern_text(value: Any, pattern: re.Pattern[str], label: str, maximum: int = 320) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or pattern.fullmatch(value) is None
    ):
        raise ContractError(f"invalid {label}")
    _check_utf8_str(value)
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError("invalid integer")
    return value


def boolean(value: Any, expected: bool | None = None) -> bool:
    if not isinstance(value, bool) or (expected is not None and value is not expected):
        raise ContractError("invalid boolean")
    return value


def enum(value: Any, accepted: set[str], label: str = "enum") -> str:
    if not isinstance(value, str) or value not in accepted:
        raise ContractError(f"invalid {label}")
    return value


def unique_strings(value: Any, minimum: int, maximum: int = 100) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContractError("invalid list")
    if any(not isinstance(item, str) for item in value) or len(value) != len(set(value)):
        raise ContractError("list must contain unique strings")
    return value


def validate_safe_relative_path(
    value: Any, pattern: re.Pattern[str], label: str = "relative path", maximum: int = 300
) -> str:
    if isinstance(value, str) and WINDOWS_DRIVE_PREFIX.match(value):
        raise ContractError(f"invalid {label}")
    text = pattern_text(value, pattern, label, maximum)
    if text.startswith("/") or text.endswith("/") or "\\" in text or "//" in text:
        raise ContractError(f"invalid {label}")
    segments = text.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ContractError(f"invalid {label}")
    return text


def validate_safe_organization(
    value: Any, pattern: re.Pattern[str], label: str = "organization", maximum: int = 100
) -> str:
    org = pattern_text(value, pattern, label, maximum)
    if org in {".", ".."}:
        raise ContractError(f"invalid {label}")
    return org


def validate_safe_repository(
    value: Any, pattern: re.Pattern[str], label: str = "repository", maximum: int = 200
) -> str:
    repo = pattern_text(value, pattern, label, maximum)
    parts = repo.split("/")
    if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
        raise ContractError(f"invalid {label}")
    return repo


def validate_safe_reference(
    value: Any, pattern: re.Pattern[str], label: str = "reference", maximum: int = 320
) -> str:
    if isinstance(value, str) and (
        any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)
        or any(ch in value for ch in ("\\", "?", "#"))
    ):
        raise ContractError(f"invalid {label}")
    ref = pattern_text(value, pattern, label, maximum)
    _, sep, remainder = ref.partition("://")
    if (
        not sep
        or not remainder
        or remainder[0] in {"/", ":"}
        or remainder[-1] in {"/", ":"}
        or "//" in remainder
        or "::" in remainder
    ):
        raise ContractError(f"invalid {label}")
    if any(segment in {"", ".", ".."} for segment in re.split(r"[/:]", remainder)):
        raise ContractError(f"invalid {label}")
    return ref


def parse_rfc3339_utc(value: Any, label: str = "timestamp") -> datetime:
    if not isinstance(value, str) or RFC3339_TIMESTAMP.fullmatch(value) is None:
        raise ContractError(f"invalid {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"invalid {label}") from exc
    if parsed.tzinfo is None:
        raise ContractError(f"{label} must include timezone")
    return parsed


def expect_rejected(callback: Callable[[], Any]) -> None:
    try:
        callback()
    except ContractError:
        return
    raise ContractError("adversarial fixture accepted")


def load_sibling_module(current_file: str, filename: str, module_name: str) -> Any:
    sibling_path = Path(current_file).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, sibling_path)
    if spec is None or spec.loader is None:
        raise ContractError(f"{filename} module is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
