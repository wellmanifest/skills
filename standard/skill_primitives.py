#!/usr/bin/env python3
"""Shared deterministic primitives for Wellmanifest governed skills conformance."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

EXECUTABLE_OR_SECRET_TEXT = re.compile(
    r"(?:https?://|bearer\s|-----BEGIN|\b(?:ba)?sh\s+-c\b|\bgit\s+(?:merge|push|reset)\b|"
    r"\bcurl\s|\bwget\s|\$\(|`|\bgh[pousr]_[A-Za-z0-9_]{16,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{16,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|\bAKIA[0-9A-Z]{16}\b)",
    re.I,
)
SENSITIVE_KEY_PARTS = (
    "secret",
    "credential",
    "bearer",
    "password",
    "token",
    "apikey",
    "privatekey",
    "shell",
    "argv",
)
RFC3339_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)


class ContractError(ValueError):
    """A bounded conformance failure that does not echo untrusted content."""


def _unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def strict_loads(raw: str) -> Any:
    return json.loads(raw, object_pairs_hook=_unique_object_pairs)


def load_strict_json(path: Path) -> Any:
    return strict_loads(path.read_text(encoding="utf-8"))


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_text(canonical(value))


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    optional_keys = optional or set()
    if set(value) - required - optional_keys:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing field")
    return value


def bounded_text(value: Any, minimum: int = 1, maximum: int = 1000) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
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
    text = pattern_text(value, pattern, label, maximum)
    if text.startswith("/") or text.endswith("/") or "\\" in text or "//" in text:
        raise ContractError(f"invalid {label}")
    segments = text.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ContractError(f"invalid {label}")
    return text


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


def reject_sensitive_tree(
    value: Any,
    *,
    allowed_schema_uris: set[str] | frozenset[str] = frozenset(),
    check_keys: bool = True,
    _allow_schema_value: bool = False,
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "secretMaterialIncluded" and child is False:
                continue
            if check_keys:
                normalized = re.sub(r"[^a-z]", "", key.lower())
                if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                    raise ContractError(f"sensitive or executable field is forbidden: {key}")
            is_allowed_schema = key == "$schema" and child in allowed_schema_uris
            reject_sensitive_tree(
                child,
                allowed_schema_uris=allowed_schema_uris,
                check_keys=check_keys,
                _allow_schema_value=is_allowed_schema,
            )
    elif isinstance(value, list):
        for child in value:
            reject_sensitive_tree(
                child,
                allowed_schema_uris=allowed_schema_uris,
                check_keys=check_keys,
            )
    elif isinstance(value, str) and not _allow_schema_value:
        if EXECUTABLE_OR_SECRET_TEXT.search(value):
            raise ContractError("document contains executable, remote or secret text")


def assert_closed_schema(node: Any) -> None:
    if isinstance(node, dict):
        if node.get("type") == "object" and node.get("additionalProperties") is not False:
            raise ContractError("open object schema")
        for child in node.values():
            assert_closed_schema(child)
    elif isinstance(node, list):
        for child in node:
            assert_closed_schema(child)


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
