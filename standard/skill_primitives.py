#!/usr/bin/env python3
"""Shared deterministic primitives for Wellmanifest governed skills conformance."""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64

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


def _reject_json_constant(_name: str) -> Any:
    raise ContractError("non-finite JSON number is forbidden")


def _parse_finite_float(token: str) -> float:
    parsed = float(token)
    if not math.isfinite(parsed):
        raise ContractError("non-finite JSON number is forbidden")
    return parsed


def _check_finite_number(value: int | float) -> None:
    try:
        finite = math.isfinite(float(value))
    except OverflowError as exc:
        raise ContractError("non-finite JSON number is forbidden") from exc
    if not finite:
        raise ContractError("non-finite JSON number is forbidden")


def assert_json_depth(value: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise ContractError("JSON nesting exceeds maximum depth")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("expected string object keys")
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            _check_finite_number(current)


def strict_loads(raw: str) -> Any:
    if not isinstance(raw, str):
        raise ContractError("expected JSON text")
    if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise ContractError("JSON input exceeds maximum size")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ContractError("invalid or excessively nested JSON") from exc
    assert_json_depth(parsed)
    return parsed


def read_regular_utf8(path: Path, max_bytes: int = MAX_JSON_BYTES) -> str:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR, errno.EISDIR}:
            raise ContractError("refusing symlink or directory input") from exc
        raise
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("input path must be a regular file")
        if info.st_size > max_bytes:
            raise ContractError("input file exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ContractError("input file exceeds maximum size")
            chunks.append(chunk)
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("input file must be valid UTF-8") from exc


def load_strict_json(path: Path) -> Any:
    return strict_loads(read_regular_utf8(path))


def canonical(value: Any) -> str:
    assert_json_depth(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ContractError("value is not canonicalizable JSON") from exc


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_text(canonical(value))


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
    if isinstance(value, str) and any(
        ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value
    ):
        raise ContractError(f"invalid {label}")
    ref = pattern_text(value, pattern, label, maximum)
    _, sep, remainder = ref.partition("://")
    if (
        not sep
        or not remainder
        or remainder.startswith("/")
        or remainder.endswith("/")
        or "//" in remainder
    ):
        raise ContractError(f"invalid {label}")
    if any(segment in {"", ".", ".."} for segment in remainder.split("/")):
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


def reject_sensitive_tree(
    value: Any,
    *,
    allowed_schema_uris: set[str] | frozenset[str] = frozenset(),
    check_keys: bool = True,
    _allow_schema_value: bool = False,
) -> None:
    stack: list[tuple[Any, bool, int]] = [(value, _allow_schema_value, 0)]
    while stack:
        current, allow_schema, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("JSON nesting exceeds maximum depth")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise ContractError("expected string object keys")
                if key == "secretMaterialIncluded" and child is False:
                    continue
                if check_keys:
                    normalized = re.sub(r"[^a-z]", "", key.lower())
                    if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                        raise ContractError(f"sensitive or executable field is forbidden: {key}")
                is_allowed_schema = (
                    key == "$schema" and isinstance(child, str) and child in allowed_schema_uris
                )
                stack.append((child, is_allowed_schema, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, False, depth + 1))
        elif isinstance(current, str) and not allow_schema:
            if EXECUTABLE_OR_SECRET_TEXT.search(current):
                raise ContractError("document contains executable, remote or secret text")
        elif isinstance(current, float) and not math.isfinite(current):
            raise ContractError("non-finite JSON number is forbidden")


def assert_closed_schema(node: Any) -> None:
    predicate_keys = {"if", "not", "contains", "propertyNames"}
    overlay_keys = predicate_keys | {"then", "else", "allOf"}
    stack: list[tuple[Any, int, bool, bool]] = [(node, 0, False, False)]
    while stack:
        current, depth, in_predicate, in_overlay = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise ContractError("JSON nesting exceeds maximum depth")
        if isinstance(current, dict):
            is_explicit_obj = current.get("type") == "object"
            is_implicit_obj = not in_overlay and (
                "properties" in current or "patternProperties" in current
            )
            if (
                not in_predicate
                and (is_explicit_obj or is_implicit_obj)
                and current.get("additionalProperties") is not False
            ):
                raise ContractError("open object schema")
            for key, child in current.items():
                child_pred = in_predicate or key in predicate_keys
                child_over = in_overlay or key in overlay_keys
                stack.append((child, depth + 1, child_pred, child_over))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1, in_predicate, in_overlay))


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
