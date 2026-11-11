#!/usr/bin/env python3
"""Bounded regular-file UTF-8 I/O, strict JSON parsing, and secret-tree checks for skills v1."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_INT_DIGITS = 309

EXECUTABLE_OR_SECRET_TEXT = re.compile(
    r"(?:https?://|bearer\s|-----BEGIN|\b(?:ba)?sh\s+-c\b|\bgit\s+(?:merge|push|reset)\b|"
    r"\bcurl\s|\bwget\s|\$\(|`|\bgh[pousr]_[A-Za-z0-9_]{16,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{16,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|"
    r"\bAK"
    r"IA[0-9A-Z]{16}\b)",
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


def _parse_bounded_int(token: str) -> int:
    digits = token[1:] if token.startswith(("+", "-")) else token
    if len(digits) > MAX_JSON_INT_DIGITS:
        raise ContractError("non-finite JSON number is forbidden")
    parsed = int(token)
    _check_finite_number(parsed)
    return parsed


def _check_finite_number(value: int | float) -> None:
    try:
        finite = math.isfinite(float(value))
    except OverflowError as exc:
        raise ContractError("non-finite JSON number is forbidden") from exc
    if not finite:
        raise ContractError("non-finite JSON number is forbidden")


def _check_utf8_str(value: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ContractError("lone UTF-16 surrogate is forbidden") from exc


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
                _check_utf8_str(key)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            for child in current:
                stack.append((child, depth + 1))
        elif isinstance(current, str):
            _check_utf8_str(current)
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            _check_finite_number(current)


def strict_loads(raw: str) -> Any:
    if not isinstance(raw, str):
        raise ContractError("expected JSON text")
    _check_utf8_str(raw)
    if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise ContractError("JSON input exceeds maximum size")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_unique_object_pairs,
            parse_constant=_reject_json_constant,
            parse_float=_parse_finite_float,
            parse_int=_parse_bounded_int,
        )
    except ContractError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ContractError("invalid or excessively nested JSON") from exc
    assert_json_depth(parsed)
    return parsed


def _reject_ancestor_symlinks(path: Path) -> None:
    raw_start = 3 if path.is_absolute() else 1
    for idx in range(raw_start, len(path.parts)):
        if path.parts[idx - 1] in ("", ".", ".."):
            continue
        try:
            st = os.lstat(Path(*path.parts[:idx]))
        except OSError as exc:
            raise ContractError("input path ancestor cannot be opened") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ContractError("refusing symlink ancestor")
    abs_path = Path(os.path.abspath(os.fspath(path)))
    for anc in abs_path.parents:
        if len(anc.parts) <= 2:
            break
        try:
            st = os.lstat(anc)
        except OSError as exc:
            raise ContractError("input path ancestor cannot be opened") from exc
        if stat.S_ISLNK(st.st_mode):
            raise ContractError("refusing symlink ancestor")


def read_regular_utf8(path: Path, max_bytes: int = MAX_JSON_BYTES) -> str:
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
        raise ContractError("invalid maximum byte size")
    if not isinstance(path, (Path, str)):
        raise ContractError("invalid input path")
    candidate = path if isinstance(path, Path) else Path(path)
    _reject_ancestor_symlinks(candidate)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        lst = os.lstat(candidate)
        if not stat.S_ISREG(lst.st_mode):
            raise ContractError("refusing non-regular file input")
        fd = os.open(candidate, flags)
    except OSError as exc:
        raise ContractError("input file cannot be opened") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ContractError("input path must be a regular file")
        if (lst.st_dev, lst.st_ino) != (info.st_dev, info.st_ino):
            raise ContractError("input file identity changed during open")
        if info.st_size > max_bytes:
            raise ContractError("input file exceeds maximum size")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ContractError("input file exceeds maximum size")
            chunks.append(chunk)
    except OSError as exc:
        raise ContractError("input file cannot be read") from exc
    finally:
        os.close(fd)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ContractError("input file must be valid UTF-8") from exc


def load_strict_json(path: Path, max_bytes: int = MAX_JSON_BYTES) -> Any:
    return strict_loads(read_regular_utf8(path, max_bytes=max_bytes))


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
    if not isinstance(value, str):
        raise ContractError("expected text")
    _check_utf8_str(value)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_digest(value: Any) -> str:
    return sha256_text(canonical(value))


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
                _check_utf8_str(key)
                if EXECUTABLE_OR_SECRET_TEXT.search(key):
                    raise ContractError("document key contains executable, remote or secret text")
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
        elif isinstance(current, str):
            _check_utf8_str(current)
            if not allow_schema and EXECUTABLE_OR_SECRET_TEXT.search(current):
                raise ContractError("document contains executable, remote or secret text")
        elif isinstance(current, (int, float)) and not isinstance(current, bool):
            _check_finite_number(current)


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
