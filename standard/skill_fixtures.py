#!/usr/bin/env python3
"""Reference and adversarial fixtures for Wellmanifest governed skills v1."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

try:
    from standard.skill_primitives import canonical, sha256_text, strict_loads
except ImportError:
    from skill_primitives import canonical, sha256_text, strict_loads

SCHEMA_URI = "https://wellmanifest.dev/schemas/skills/v1"


def artifact(path: str = "SKILLS/repository-repair/skill.json") -> dict[str, str]:
    return {
        "repository": "subactor/skills-agent",
        "revision": "a" * 40,
        "path": path,
        "sha256": "b" * 64,
    }


def phase(role: str) -> dict[str, list[str]]:
    return {
        "consumes": [f"{role}.input"],
        "produces": [f"{role}.receipt"],
        "requires": ["evidence.redacted"],
        "prohibits": ["authority.self-issued"],
    }


def definition_example(safety: str = "routine") -> dict[str, Any]:
    modes = {
        "routine": "digest-bound",
        "stash": "human-decision",
        "license": "human-decision",
        "secret": "secret-intake",
        "ambiguous": "human-decision",
        "destructive": "human-decision",
    }
    bindings = ["findingDigest", "targetRepository", "catalogDigest", "skillDigest"]
    if modes[safety] in {"human-decision", "secret-intake"}:
        bindings.append("decisionRef")
    effect = "pull-request" if safety in {"routine", "license", "ambiguous"} else "none"
    if effect == "pull-request":
        bindings.append("exactBaseSha")
    executor = "repair-agent" if effect == "pull-request" else "human"
    if safety == "secret":
        executor = "secret-intake"
    agent_phases: dict[str, Any] = {"doctor-agent": phase("doctor")}
    if effect == "pull-request":
        agent_phases["repair-agent"] = phase("repair")
        agent_phases["validator-agent"] = phase("validator")
    agent_phases["skills-agent"] = phase("skills")
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-definition/v1",
        "skillId": f"skill.repository.{safety}-remediation.v1",
        "version": "1.0.0",
        "title": f"Governed {safety} remediation",
        "description": "Route a stable diagnostic through bounded agent phases.",
        "match": {
            "diagnosticCodes": [f"DIAGIT-{safety.upper()}-001"],
            "errorClasses": ["state" if safety == "stash" else "policy"],
            "fallback": False,
        },
        "routing": {
            "safetyClass": safety,
            "basePriority": "P2",
            "deduplication": {"key": "fingerprint", "scope": "target-repository"},
        },
        "authority": {
            "mode": modes[safety],
            "requiredBindings": bindings,
            "whenMissing": "block",
        },
        "operation": {
            "capability": f"repository.{safety}.remediate",
            "executor": executor,
            "effect": effect,
            "maxChangedFiles": 3 if effect == "pull-request" else 0,
        },
        "agents": agent_phases,
        "completionCriteria": ["diagnosis.bound", "authority.verified", "outcome.read-back"],
        "llmAuthority": "propose-only",
    }


def request_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-selection-request/v1",
        "requestId": "selection.batch-001",
        "catalogDigest": "c" * 64,
        "policyDigest": "d" * 64,
        "priorityProfileDigest": "e" * 64,
        "findings": [
            {
                "fingerprint": "f" * 64,
                "targetRepository": "subactor/platform",
                "diagnosticCode": "DIAGIT-GIT-008",
                "errorClass": "state",
                "severity": "medium",
                "occurrences": 2,
                "eligibleSkills": ["skill.repository.stash-remediation.v1"],
                "deterministicPriority": "P1",
            }
        ],
    }


def proposal_example(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-selection-proposal/v1",
        "catalogDigest": request["catalogDigest"],
        "requestDigest": sha256_text(canonical(request)),
        "effect": "propose-only",
        "selections": [
            {
                "fingerprint": "f" * 64,
                "skillId": "skill.repository.stash-remediation.v1",
                "priorityAdjustment": 5,
                "reasonCode": "operator-impact",
                "rationale": "Preserve operator-owned workspace state before later work.",
            }
        ],
    }


def catalog_example() -> dict[str, Any]:
    return {
        "$schema": SCHEMA_URI,
        "schema": "wellmanifest.skill-catalog/v1",
        "catalogId": "subactor.repository-remediation",
        "version": "1.0.0",
        "entries": [
            {
                "skillId": "skill.repository.routine-remediation.v1",
                "definition": artifact("SKILLS/routine/skill.json"),
                "safetyClass": "routine",
                "diagnosticCodes": ["DIAGIT-GIT-001"],
            }
        ],
        "defaultRoute": "block",
    }


def build_adversarial_skill_cases(
    validate_doc: Callable[[Any], None],
    validate_pair_fn: Callable[[Any, Any], None],
    request: dict[str, Any],
) -> list[Callable[[], Any]]:
    cases: list[Callable[[], Any]] = []

    stash_bad = definition_example("stash")
    stash_bad["authority"]["mode"] = "standing-policy"
    cases.append(lambda d=stash_bad: validate_doc(d))

    license_bad = definition_example("license")
    license_bad["authority"]["mode"] = "digest-bound"
    cases.append(lambda d=license_bad: validate_doc(d))

    secret_bad = definition_example("secret")
    secret_bad["operation"] = {
        "capability": "repository.secret.repair",
        "executor": "repair-agent",
        "effect": "pull-request",
        "maxChangedFiles": 1,
    }
    secret_bad["authority"]["requiredBindings"].append("exactBaseSha")
    cases.append(lambda d=secret_bad: validate_doc(d))

    ambiguous_bad = definition_example("ambiguous")
    ambiguous_bad["authority"]["requiredBindings"].remove("decisionRef")
    cases.append(lambda d=ambiguous_bad: validate_doc(d))

    routine_bad = definition_example("routine")
    routine_bad["operation"]["shell"] = "ignored"
    cases.append(lambda d=routine_bad: validate_doc(d))

    secret_leak = definition_example("routine")
    secret_leak["description"] = "Leak ghp_1234567890abcdef1234567890abcdef token."
    cases.append(lambda d=secret_leak: validate_doc(d))

    dup_catalog = catalog_example()
    dup_catalog["entries"].append(copy.deepcopy(dup_catalog["entries"][0]))
    cases.append(lambda d=dup_catalog: validate_doc(d))

    traversal_catalog = catalog_example()
    traversal_catalog["entries"][0]["definition"]["path"] = "SKILLS/../escape/skill.json"
    cases.append(lambda d=traversal_catalog: validate_doc(d))

    auth_proposal = proposal_example(request)
    auth_proposal["authority"] = "approved"
    cases.append(lambda d=auth_proposal: validate_doc(d))

    out_of_bounds_proposal = proposal_example(request)
    out_of_bounds_proposal["selections"][0]["priorityAdjustment"] = 26
    cases.append(lambda d=out_of_bounds_proposal: validate_doc(d))

    escaped = proposal_example(request)
    escaped["selections"][0]["skillId"] = "skill.repository.other-remediation.v1"
    cases.append(lambda d=escaped: validate_pair_fn(request, d))

    cases.append(lambda: strict_loads('{"effect":"propose-only","effect":"execute"}'))
    return cases
