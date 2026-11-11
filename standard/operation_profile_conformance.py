#!/usr/bin/env python3
"""Dependency-free semantic checks for skill operation profiles v1."""

from __future__ import annotations

import argparse
import copy
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from standard.skill_primitives import (
        ContractError,
        assert_closed_schema,
        exact,
        expect_rejected,
        load_strict_json,
        pattern_text,
        reject_sensitive_tree,
        strict_loads,
        unique_strings,
        validate_safe_relative_path,
    )
except ImportError:
    from skill_primitives import (
        ContractError,
        assert_closed_schema,
        exact,
        expect_rejected,
        load_strict_json,
        pattern_text,
        reject_sensitive_tree,
        strict_loads,
        unique_strings,
        validate_safe_relative_path,
    )

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "skill-operation-profile.schema.json"
PROFILE_PATH = ROOT / "repository-initial-ref.operation-profile.json"
SCHEMA_URI = "https://wellmanifest.dev/schemas/skill-operation-profile/v1"
REVISION = "72ade3b6c7ad68f617a50871a1f7466e7a868ab9"
ARTIFACTS = {
    "operationContract": (
        "standard/repository-initial-ref.schema.json",
        "6fdba8c71765cb217219bd3f459258170f7f1eaf70bb60970c4d3ecc68f0d724",
    ),
    "lifecycleContract": (
        "standard/repository-initial-ref.lifecycle",
        "7ac49adfb92dac1d03e10efb382290e0e08c367b5ec655933d12db30803dbe2c",
    ),
}
IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*$")
COMMIT = re.compile(r"^[a-f0-9]{40}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RELATIVE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")


def unique_identifiers(value: Any, minimum: int, maximum: int = 12) -> list[str]:
    items = unique_strings(value, minimum, maximum)
    for item in items:
        pattern_text(item, IDENTIFIER, "identifier", 160)
    return items


def _validate_profile_artifact(
    value: Any, expected_path: str, expected_digest: str
) -> None:
    value = exact(value, {"repository", "revision", "path", "sha256"})
    pattern_text(value["repository"], REPOSITORY, "repository", 200)
    pattern_text(value["revision"], COMMIT, "revision", 40)
    validate_safe_relative_path(value["path"], RELATIVE_PATH, "path", 300)
    pattern_text(value["sha256"], SHA256, "digest", 64)
    if value != {
        "repository": "wellmanifest/git-lifecycle",
        "revision": REVISION,
        "path": expected_path,
        "sha256": expected_digest,
    }:
        raise ContractError("initial-ref artifact pin mismatch")


def _validate_profile_phase(value: Any, expected_role: str) -> None:
    value = exact(value, {"role", "consumes", "produces", "requires", "prohibits"})
    if value["role"] != expected_role:
        raise ContractError("phase order or role mismatch")
    for field in ("consumes", "produces", "requires", "prohibits"):
        unique_identifiers(value[field], 1, 10)


def validate_profile(value: Any) -> None:
    value = exact(
        value,
        {
            "$schema",
            "schema",
            "profileId",
            "operationId",
            "effect",
            "operationContract",
            "lifecycleContract",
            "phases",
            "authority",
            "completion",
            "runtimeOwnership",
            "llmAuthority",
            "secretMaterialIncluded",
        },
    )
    if (
        value["$schema"] != SCHEMA_URI
        or value["schema"] != "wellmanifest.skill-operation-profile/v1"
    ):
        raise ContractError("unsupported profile document")
    if value["profileId"] != "profile.repository.initial-ref.v1":
        raise ContractError("unsupported profile id")
    if (
        value["operationId"] != "repository:initial-ref"
        or value["effect"] != "initial-ref-publish"
    ):
        raise ContractError("operation boundary mismatch")
    for field, (path, artifact_digest) in ARTIFACTS.items():
        _validate_profile_artifact(value[field], path, artifact_digest)

    phases = value["phases"]
    roles = ["doctor-agent", "skills-agent", "domain-executor", "validator-agent"]
    if not isinstance(phases, list) or len(phases) != len(roles):
        raise ContractError("profile must have exactly four phases")
    for phase, role in zip(phases, roles, strict=True):
        _validate_profile_phase(phase, role)
    if "repository.mutation" not in phases[0]["prohibits"]:
        raise ContractError("Doctor mutation prohibition missing")
    if not {"authority.issue", "operation.execute"} <= set(phases[1]["prohibits"]):
        raise ContractError("Skills authority boundary missing")
    if not {"authority.inherit", "ref.force-push", "validation.self"} <= set(
        phases[2]["prohibits"]
    ):
        raise ContractError("executor safety boundary missing")
    if not {"validation.self", "ref.delete"} <= set(phases[3]["prohibits"]):
        raise ContractError("Validator independence boundary missing")

    authority = exact(
        value["authority"],
        {
            "mode",
            "requiredBindings",
            "singleUse",
            "inheritedAuthority",
            "whenMissing",
        },
    )
    required = {
        "planDigest",
        "repositoryRef",
        "targetBranchRef",
        "sourceCommitSha",
        "sourceTreeDigest",
        "allowlistDigest",
    }
    bindings = authority["requiredBindings"]
    if (
        not isinstance(bindings, list)
        or len(bindings) != len(set(bindings))
        or authority["mode"] != "digest-bound"
        or set(bindings) != required
    ):
        raise ContractError("authority bindings mismatch")
    if (
        authority["singleUse"] is not True
        or authority["inheritedAuthority"] is not False
        or authority["whenMissing"] != "block"
    ):
        raise ContractError("authority is not fail-closed and single-use")

    completion = exact(
        value["completion"],
        {
            "publicationState",
            "publicationTerminal",
            "terminalStates",
            "independentValidation",
            "automaticRefDeletion",
        },
    )
    if completion != {
        "publicationState": "initial-ref-published",
        "publicationTerminal": False,
        "terminalStates": ["accepted", "quarantined"],
        "independentValidation": True,
        "automaticRefDeletion": False,
    }:
        raise ContractError("completion lifecycle mismatch")

    ownership = exact(
        value["runtimeOwnership"],
        {"executor", "transport", "credentials", "grantVerification"},
    )
    if set(ownership.values()) != {"runtime-adopter"}:
        raise ContractError("runtime responsibility moved into the standard")
    if value["llmAuthority"] != "propose-only" or value["secretMaterialIncluded"] is not False:
        raise ContractError("model or secret boundary mismatch")
    reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=False)


def schema_integrity() -> None:
    schema = load_strict_json(SCHEMA_PATH)
    if schema.get("$id") != SCHEMA_URI or schema.get("additionalProperties") is not False:
        raise ContractError("schema identity or closure mismatch")
    assert_closed_schema(schema)


def run_all() -> None:
    schema_integrity()
    profile = load_strict_json(PROFILE_PATH)
    validate_profile(profile)
    invalid: list[Callable[[], Any]] = []
    mutations: list[tuple[str, Callable[[dict[str, Any]], Any]]] = [
        ("moving revision", lambda item: item["operationContract"].update(revision="main")),
        (
            "contract substitution",
            lambda item: item["operationContract"].update(
                path="standard/git-lifecycle.lifecycle"
            ),
        ),
        (
            "authority inheritance",
            lambda item: item["authority"].update(inheritedAuthority=True),
        ),
        ("reusable grant", lambda item: item["authority"].update(singleUse=False)),
        (
            "binding omission",
            lambda item: item["authority"]["requiredBindings"].remove("sourceTreeDigest"),
        ),
        (
            "terminal publication",
            lambda item: item["completion"].update(publicationTerminal=True),
        ),
        (
            "self validation",
            lambda item: item["phases"][3]["prohibits"].remove("validation.self"),
        ),
        (
            "automatic deletion",
            lambda item: item["completion"].update(automaticRefDeletion=True),
        ),
        (
            "runtime ownership",
            lambda item: item["runtimeOwnership"].update(executor="wellmanifest-skills"),
        ),
        ("executable text", lambda item: item["phases"][2]["requires"].append("git push")),
    ]
    for _, mutate in mutations:
        candidate = copy.deepcopy(profile)
        mutate(candidate)
        invalid.append(lambda candidate=candidate: validate_profile(candidate))
    invalid.append(lambda: strict_loads('{"effect":"initial-ref-publish","effect":"none"}'))
    for callback in invalid:
        expect_rejected(callback)
    print(f"PASS: 1 operation profile, {len(invalid)} adversarial cases")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--file", type=Path)
    args = parser.parse_args()
    try:
        schema_integrity()
        if args.all:
            run_all()
        elif args.file:
            validate_profile(load_strict_json(args.file))
            print(f"PASS: {args.file}")
        else:
            parser.error("choose --all or --file")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
