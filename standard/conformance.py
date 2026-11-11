#!/usr/bin/env python3
"""Dependency-free conformance checks for Wellmanifest governed skills v1."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from standard import skill_fixtures as _fx
    from standard import skill_primitives as _pr
except ImportError:
    import skill_fixtures as _fx  # type: ignore[no-redef]
    import skill_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
canonical = _pr.canonical
digest = _pr.sha256_text
exact = _pr.exact
string = _pr.bounded_text
integer = _pr.integer
enum = _pr.enum
unique_strings = _pr.unique_strings
SCHEMA_URI = _fx.SCHEMA_URI
artifact = _fx.artifact
phase = _fx.phase
definition_example = _fx.definition_example
request_example = _fx.request_example
proposal_example = _fx.proposal_example
catalog_example = _fx.catalog_example

ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "skill.schema.json"
GRAMMAR_PATH = ROOT / "skill.v1.gbnf"
SCHEMA_DIGEST = "4e59a6c771958afe17057d42469130a5abd9071042e763f76136f6c72c0705c0"
GRAMMAR_DIGEST = "c01fbcbcd004ac955b700fdfe1b8bb538119159d02b48e93d9823278c058c835"
PROTECTED_HUMAN = {"stash", "license", "ambiguous", "destructive"}
ERROR_CLASSES = {
    "availability", "configuration", "integrity", "policy", "security", "state", "unknown"
}
DEFINITION_KEYS = {
    "$schema", "schema", "skillId", "version", "title", "description", "match", "routing",
    "authority", "operation", "agents", "completionCriteria", "llmAuthority",
}
AUTHORITY_BINDINGS = {
    "findingDigest", "targetRepository", "exactBaseSha", "catalogDigest",
    "skillDigest", "policyDigest", "decisionRef",
}
EXECUTORS = {
    "doctor-agent", "repair-agent", "validator-agent", "skills-agent", "human", "secret-intake"
}


class Contracts:
    def __init__(self) -> None:
        self.schema = _pr.load_strict_json(SCHEMA_PATH)
        self.grammar = _pr.read_regular_utf8(GRAMMAR_PATH)
        if not isinstance(self.schema, dict) or not isinstance(self.schema.get("$defs"), dict):
            raise ContractError("schema definitions missing")
        defs = self.schema["$defs"]
        names = (
            "identifier", "skillId", "semver", "sha256", "commit",
            "repository", "relativePath", "diagnosticCode",
        )
        self.patterns = {name: re.compile(defs[name]["pattern"]) for name in names}
        self.max_lengths: dict[str, int | None] = {
            name: defs[name].get("maxLength") for name in names
        }

    def ref(self, name: str, value: Any) -> str:
        if name == "repository":
            return _pr.validate_safe_repository(value, self.patterns["repository"], "repository")
        max_len = self.max_lengths.get(name)
        if (
            not isinstance(value, str)
            or (max_len is not None and len(value) > max_len)
            or self.patterns[name].fullmatch(value) is None
        ):
            raise ContractError(f"invalid {name}")
        return value

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("schema dialect mismatch")
        if self.schema.get("$id") != SCHEMA_URI:
            raise ContractError("schema identity mismatch")
        one_of = self.schema.get("oneOf")
        if not isinstance(one_of, list) or any(
            not isinstance(entry, dict) or not isinstance(entry.get("$ref"), str)
            for entry in one_of
        ):
            raise ContractError("document variants incomplete")
        variants = {entry["$ref"] for entry in one_of}
        expected_variants = {
            "#/$defs/definition", "#/$defs/catalog",
            "#/$defs/selectionRequest", "#/$defs/selectionProposal",
        }
        if variants != expected_variants:
            raise ContractError("document variants incomplete")
        if digest(canonical(self.schema)) != SCHEMA_DIGEST:
            raise ContractError("schema digest mismatch")
        if digest(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("grammar digest mismatch")
        required_fragments = (
            "root ::= proposal", "propose-only", "skill-id ::=",
            "priorityAdjustment", "requestDigest",
        )
        if any(fragment not in self.grammar for fragment in required_fragments):
            raise ContractError("grammar incomplete")
        forbidden_fields = (
            "authority", "grantRef", "credential", "shell", "argv", "targetRepository"
        )
        if any(f'\\"{field}\\"' in self.grammar for field in forbidden_fields):
            raise ContractError("grammar exposes forbidden output field")
        _pr.assert_closed_schema(self.schema)


def _validate_skill_header(value: dict[str, Any], document_schema: str) -> None:
    if value["$schema"] != SCHEMA_URI or value["schema"] != document_schema:
        raise ContractError("unsupported document")


def _validate_skill_artifact(c: Contracts, value: Any) -> None:
    value = exact(value, {"repository", "revision", "path", "sha256"})
    c.ref("repository", value["repository"])
    c.ref("commit", value["revision"])
    _pr.validate_safe_relative_path(value["path"], c.patterns["relativePath"], "relativePath")
    c.ref("sha256", value["sha256"])


def _validate_agent_phase(c: Contracts, value: Any) -> None:
    value = exact(value, {"consumes", "produces", "requires", "prohibits"})
    for field in ("consumes", "produces", "requires", "prohibits"):
        for item in unique_strings(value[field], 1):
            c.ref("identifier", item)


def _validate_skill_authority(c: Contracts, value: Any) -> tuple[str, set[str]]:
    value = exact(value, {"mode", "requiredBindings", "whenMissing"})
    mode = enum(
        value["mode"], {"standing-policy", "digest-bound", "human-decision", "secret-intake"}
    )
    bindings = set(unique_strings(value["requiredBindings"], 3))
    if not bindings <= AUTHORITY_BINDINGS:
        raise ContractError("unknown authority binding")
    if not {"findingDigest", "targetRepository", "catalogDigest", "skillDigest"} <= bindings:
        raise ContractError("authority is not evidence-bound")
    if mode == "standing-policy" and "policyDigest" not in bindings:
        raise ContractError("standing policy is not digest-bound")
    if mode in {"human-decision", "secret-intake"} and "decisionRef" not in bindings:
        raise ContractError("decision route lacks decision binding")
    enum(value["whenMissing"], {"block", "escalate", "plan-only"})
    return mode, bindings


def validate_definition(c: Contracts, value: Any) -> None:
    value = exact(value, DEFINITION_KEYS)
    _validate_skill_header(value, "wellmanifest.skill-definition/v1")
    c.ref("skillId", value["skillId"])
    c.ref("semver", value["version"])
    string(value["title"], 3, 160)
    string(value["description"], 3, 1000)

    match = exact(value["match"], {"diagnosticCodes", "errorClasses", "fallback"})
    codes = unique_strings(match["diagnosticCodes"], 0)
    for code in codes:
        c.ref("diagnosticCode", code)
    classes = unique_strings(match["errorClasses"], 1)
    if not set(classes) <= ERROR_CLASSES or not isinstance(match["fallback"], bool):
        raise ContractError("invalid diagnostic match")
    if not match["fallback"] and not codes:
        raise ContractError("non-fallback skill lacks diagnostic code")

    routing = exact(value["routing"], {"safetyClass", "basePriority", "deduplication"})
    safety = enum(routing["safetyClass"], {"routine", *PROTECTED_HUMAN, "secret"})
    enum(routing["basePriority"], {"P0", "P1", "P2", "P3"})
    dedupe = exact(routing["deduplication"], {"key", "scope"})
    if dedupe != {"key": "fingerprint", "scope": "target-repository"}:
        raise ContractError("invalid deduplication boundary")

    mode, bindings = _validate_skill_authority(c, value["authority"])
    operation = exact(value["operation"], {"capability", "executor", "effect", "maxChangedFiles"})
    c.ref("identifier", operation["capability"])
    executor = enum(operation["executor"], EXECUTORS)
    effect = enum(operation["effect"], {"none", "pull-request"})
    changed = integer(operation["maxChangedFiles"], 0, 1000)

    if safety == "routine" and mode not in {"standing-policy", "digest-bound"}:
        raise ContractError("routine skill has non-routine authority")
    if safety in PROTECTED_HUMAN and mode != "human-decision":
        raise ContractError("protected change lacks human decision")
    if safety == "secret" and (mode != "secret-intake" or executor != "secret-intake"):
        raise ContractError("secret finding bypasses secret intake")
    if safety in {"stash", "destructive"} and (effect != "none" or executor != "human"):
        raise ContractError("local or destructive user state cannot be agent-mutated")
    if safety == "secret" and (effect != "none" or changed != 0):
        raise ContractError("secret intake cannot change repository files")
    if effect == "pull-request":
        if executor != "repair-agent" or changed < 1 or "exactBaseSha" not in bindings:
            raise ContractError("pull-request repair lacks exact repair boundary")
    elif changed != 0:
        raise ContractError("non-mutating skill declares changed files")

    agents = value["agents"]
    if not isinstance(agents, dict) or not agents or any(not isinstance(k, str) for k in agents):
        raise ContractError("agent phase contract missing")
    if set(agents) - {"doctor-agent", "repair-agent", "validator-agent", "skills-agent"}:
        raise ContractError("unknown agent phase")
    for agent_phase in agents.values():
        _validate_agent_phase(c, agent_phase)
    if effect == "pull-request" and not {"repair-agent", "validator-agent"} <= set(agents):
        raise ContractError("repair skill lacks independent validation phase")
    for criterion in unique_strings(value["completionCriteria"], 1):
        c.ref("identifier", criterion)
    if value["llmAuthority"] != "propose-only":
        raise ContractError("LLM authority is not propose-only")
    _pr.reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=False)


def _validate_catalog_entry(c: Contracts, value: Any) -> str:
    value = exact(value, {"skillId", "definition", "safetyClass", "diagnosticCodes"})
    skill_id = c.ref("skillId", value["skillId"])
    _validate_skill_artifact(c, value["definition"])
    enum(value["safetyClass"], {"routine", *PROTECTED_HUMAN, "secret"})
    for code in unique_strings(value["diagnosticCodes"], 0):
        c.ref("diagnosticCode", code)
    return skill_id


def validate_catalog(c: Contracts, value: Any) -> None:
    value = exact(
        value, {"$schema", "schema", "catalogId", "version", "entries", "defaultRoute"}
    )
    _validate_skill_header(value, "wellmanifest.skill-catalog/v1")
    c.ref("identifier", value["catalogId"])
    c.ref("semver", value["version"])
    if not isinstance(value["entries"], list) or not value["entries"]:
        raise ContractError("empty catalog")
    ids = [_validate_catalog_entry(c, entry) for entry in value["entries"]]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate catalog skill")
    if value["defaultRoute"] != "block":
        raise ContractError("catalog fallback must block")
    _pr.reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=False)


def _validate_selection_finding(c: Contracts, value: Any) -> tuple[str, set[str]]:
    keys = {
        "fingerprint", "targetRepository", "diagnosticCode", "errorClass",
        "severity", "occurrences", "eligibleSkills", "deterministicPriority",
    }
    value = exact(value, keys)
    fingerprint = c.ref("sha256", value["fingerprint"])
    c.ref("repository", value["targetRepository"])
    c.ref("diagnosticCode", value["diagnosticCode"])
    enum(value["errorClass"], ERROR_CLASSES)
    enum(value["severity"], {"critical", "high", "medium", "low", "info"})
    integer(value["occurrences"], 1, 1000000)
    skills = set(unique_strings(value["eligibleSkills"], 1))
    for skill_id in skills:
        c.ref("skillId", skill_id)
    enum(value["deterministicPriority"], {"P0", "P1", "P2", "P3"})
    return fingerprint, skills


def validate_selection_request(c: Contracts, value: Any) -> dict[str, set[str]]:
    keys = {
        "$schema", "schema", "requestId", "catalogDigest",
        "policyDigest", "priorityProfileDigest", "findings",
    }
    value = exact(value, keys)
    _validate_skill_header(value, "wellmanifest.skill-selection-request/v1")
    c.ref("identifier", value["requestId"])
    for field in ("catalogDigest", "policyDigest", "priorityProfileDigest"):
        c.ref("sha256", value[field])
    findings = value["findings"]
    if not isinstance(findings, list) or not 1 <= len(findings) <= 100:
        raise ContractError("invalid finding batch")
    result: dict[str, set[str]] = {}
    for finding in findings:
        fingerprint, candidates = _validate_selection_finding(c, finding)
        if fingerprint in result:
            raise ContractError("duplicate finding fingerprint")
        result[fingerprint] = candidates
    _pr.reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=False)
    return result


def validate_selection_proposal(c: Contracts, value: Any) -> list[tuple[str, str]]:
    keys = {"$schema", "schema", "catalogDigest", "requestDigest", "effect", "selections"}
    value = exact(value, keys)
    _validate_skill_header(value, "wellmanifest.skill-selection-proposal/v1")
    c.ref("sha256", value["catalogDigest"])
    c.ref("sha256", value["requestDigest"])
    if value["effect"] != "propose-only":
        raise ContractError("selection has an effect")
    selections = value["selections"]
    if not isinstance(selections, list) or len(selections) > 100:
        raise ContractError("invalid selections")
    reasons = {
        "blast-radius", "dependency-order", "freshness", "operator-impact", "recurrence"
    }
    result: list[tuple[str, str]] = []
    for item in selections:
        item = exact(
            item, {"fingerprint", "skillId", "priorityAdjustment", "reasonCode", "rationale"}
        )
        fingerprint = c.ref("sha256", item["fingerprint"])
        skill_id = c.ref("skillId", item["skillId"])
        integer(item["priorityAdjustment"], -25, 25)
        enum(item["reasonCode"], reasons)
        string(item["rationale"], 1, 300)
        result.append((fingerprint, skill_id))
    if len(result) != len(set(result)):
        raise ContractError("duplicate selection")
    _pr.reject_sensitive_tree(value, allowed_schema_uris={SCHEMA_URI}, check_keys=False)
    return result


def validate_document(c: Contracts, value: Any) -> None:
    if not isinstance(value, dict):
        raise ContractError("document must be an object")
    validators: dict[str, Callable[[Contracts, Any], Any]] = {
        "wellmanifest.skill-definition/v1": validate_definition,
        "wellmanifest.skill-catalog/v1": validate_catalog,
        "wellmanifest.skill-selection-request/v1": validate_selection_request,
        "wellmanifest.skill-selection-proposal/v1": validate_selection_proposal,
    }
    schema_name = value.get("schema")
    validator = validators.get(schema_name) if isinstance(schema_name, str) else None
    if validator is None:
        raise ContractError("unknown document schema")
    validator(c, value)


def validate_pair(c: Contracts, request: Any, proposal: Any) -> None:
    candidates = validate_selection_request(c, request)
    selections = validate_selection_proposal(c, proposal)
    if proposal["catalogDigest"] != request["catalogDigest"]:
        raise ContractError("catalog digest mismatch")
    if proposal["requestDigest"] != digest(canonical(request)):
        raise ContractError("request digest mismatch")
    for fingerprint, skill_id in selections:
        if fingerprint not in candidates or skill_id not in candidates[fingerprint]:
            raise ContractError("proposal escaped deterministic candidates")


def expect_rejected(c: Contracts, value: Any, request: Any | None = None) -> None:
    if request is None:
        _pr.expect_rejected(lambda: validate_document(c, value))
    else:
        _pr.expect_rejected(lambda: validate_pair(c, request, value))


def run_all(c: Contracts) -> None:
    c.integrity()
    safeties = ("routine", "stash", "license", "secret", "ambiguous", "destructive")
    valid = [definition_example(safety) for safety in safeties]
    valid.append(catalog_example())
    request = request_example()
    proposal = proposal_example(request)
    valid.extend([request, proposal])
    for document in valid:
        validate_document(c, document)
    validate_pair(c, request, proposal)

    adversarial = _fx.build_adversarial_skill_cases(
        lambda doc: validate_document(c, doc),
        lambda req, prop: validate_pair(c, req, prop),
        request,
    )
    for case in adversarial:
        _pr.expect_rejected(case)
    print(f"PASS: {len(valid)} valid documents, {len(adversarial)} adversarial cases")

    execution_mod = _pr.load_sibling_module(
        __file__, "execution_conformance.py", "wellmanifest_execution_conformance"
    )
    execution_mod.run_all()
    profile_mod = _pr.load_sibling_module(
        __file__, "operation_profile_conformance.py", "wellmanifest_operation_profile_conformance"
    )
    profile_mod.run_all()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--all", action="store_true", help="run bundled positive and adversarial fixtures"
    )
    parser.add_argument("--file", type=Path, help="validate one JSON document")
    parser.add_argument(
        "--proposal-with-request", nargs=2, type=Path, metavar=("REQUEST", "PROPOSAL")
    )
    args = parser.parse_args()
    c = Contracts()
    try:
        if args.all:
            run_all(c)
        elif args.file:
            c.integrity()
            validate_document(c, _pr.load_strict_json(args.file))
            print("PASS: document conforms")
        elif args.proposal_with_request:
            c.integrity()
            request, proposal = (_pr.load_strict_json(p) for p in args.proposal_with_request)
            validate_pair(c, request, proposal)
            print("PASS: proposal is candidate-bound")
        else:
            parser.error("choose --all, --file or --proposal-with-request")
    except (ContractError, json.JSONDecodeError, OSError) as error:
        print(f"FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
