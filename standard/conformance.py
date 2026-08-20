#!/usr/bin/env python3
"""Dependency-free conformance checks for Wellmanifest governed skills v1."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "skill.schema.json"
GRAMMAR_PATH = ROOT / "skill.v1.gbnf"
SCHEMA_URI = "https://wellmanifest.dev/schemas/skills/v1"
SCHEMA_DIGEST = "4e59a6c771958afe17057d42469130a5abd9071042e763f76136f6c72c0705c0"
GRAMMAR_DIGEST = "c01fbcbcd004ac955b700fdfe1b8bb538119159d02b48e93d9823278c058c835"
PROTECTED_HUMAN = {"stash", "license", "ambiguous", "destructive"}
EXECUTABLE_TEXT = re.compile(
    r"(?:https?://|bearer\s|-----BEGIN|\b(?:ba)?sh\s+-c\b|\bgit\s+(?:merge|push|reset)\b|"
    r"\bcurl\s|\bwget\s|\$\(|`)",
    re.I,
)


class ContractError(ValueError):
    """A bounded conformance failure that does not echo untrusted content."""


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError("expected object")
    optional = optional or set()
    if set(value) - required - optional:
        raise ContractError("undeclared field")
    if required - set(value):
        raise ContractError("missing field")
    return value


def string(value: Any, minimum: int = 1, maximum: int = 1000) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ContractError("invalid string")
    if EXECUTABLE_TEXT.search(value):
        raise ContractError("executable or transport text is forbidden")
    return value


def integer(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ContractError("invalid integer")
    return value


def enum(value: Any, accepted: set[str]) -> str:
    if not isinstance(value, str) or value not in accepted:
        raise ContractError("invalid enum")
    return value


def unique_strings(value: Any, minimum: int, maximum: int = 100) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContractError("invalid list")
    if any(not isinstance(item, str) for item in value) or len(value) != len(set(value)):
        raise ContractError("list must contain unique strings")
    return value


class Contracts:
    def __init__(self) -> None:
        self.schema = json.loads(SCHEMA_PATH.read_text("utf-8"))
        self.grammar = GRAMMAR_PATH.read_text("utf-8")
        defs = self.schema["$defs"]
        self.patterns = {
            name: re.compile(defs[name]["pattern"])
            for name in (
                "identifier",
                "skillId",
                "semver",
                "sha256",
                "commit",
                "repository",
                "relativePath",
                "diagnosticCode",
            )
        }

    def ref(self, name: str, value: Any) -> str:
        if not isinstance(value, str) or self.patterns[name].fullmatch(value) is None:
            raise ContractError(f"invalid {name}")
        return value

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("schema dialect mismatch")
        if self.schema.get("$id") != SCHEMA_URI:
            raise ContractError("schema identity mismatch")
        variants = {entry.get("$ref") for entry in self.schema.get("oneOf", [])}
        if variants != {
            "#/$defs/definition",
            "#/$defs/catalog",
            "#/$defs/selectionRequest",
            "#/$defs/selectionProposal",
        }:
            raise ContractError("document variants incomplete")
        if digest(canonical(self.schema)) != SCHEMA_DIGEST:
            raise ContractError("schema digest mismatch")
        if digest(self.grammar) != GRAMMAR_DIGEST:
            raise ContractError("grammar digest mismatch")
        for fragment in (
            "root ::= proposal",
            "propose-only",
            "skill-id ::=",
            "priorityAdjustment",
            "requestDigest",
        ):
            if fragment not in self.grammar:
                raise ContractError("grammar incomplete")
        for forbidden in ("authority", "grantRef", "credential", "shell", "argv", "targetRepository"):
            if f'\\"{forbidden}\\"' in self.grammar:
                raise ContractError("grammar exposes forbidden output field")
        self._closed(self.schema)

    def _closed(self, value: Any) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object" and value.get("additionalProperties") is not False:
                raise ContractError("open object schema")
            for child in value.values():
                self._closed(child)
        elif isinstance(value, list):
            for child in value:
                self._closed(child)


def validate_header(value: dict[str, Any], document_schema: str) -> None:
    if value["$schema"] != SCHEMA_URI or value["schema"] != document_schema:
        raise ContractError("unsupported document")


def validate_artifact(c: Contracts, value: Any) -> None:
    value = exact(value, {"repository", "revision", "path", "sha256"})
    c.ref("repository", value["repository"])
    c.ref("commit", value["revision"])
    c.ref("relativePath", value["path"])
    c.ref("sha256", value["sha256"])


def validate_phase(c: Contracts, value: Any) -> None:
    value = exact(value, {"consumes", "produces", "requires", "prohibits"})
    for field in ("consumes", "produces", "requires", "prohibits"):
        for item in unique_strings(value[field], 1):
            c.ref("identifier", item)


def validate_authority(c: Contracts, value: Any) -> tuple[str, set[str]]:
    value = exact(value, {"mode", "requiredBindings", "whenMissing"})
    mode = enum(
        value["mode"],
        {"standing-policy", "digest-bound", "human-decision", "secret-intake"},
    )
    bindings = set(unique_strings(value["requiredBindings"], 3))
    accepted = {
        "findingDigest",
        "targetRepository",
        "exactBaseSha",
        "catalogDigest",
        "skillDigest",
        "policyDigest",
        "decisionRef",
    }
    if not bindings <= accepted:
        raise ContractError("unknown authority binding")
    required = {"findingDigest", "targetRepository", "catalogDigest", "skillDigest"}
    if not required <= bindings:
        raise ContractError("authority is not evidence-bound")
    if mode == "standing-policy" and "policyDigest" not in bindings:
        raise ContractError("standing policy is not digest-bound")
    if mode in {"human-decision", "secret-intake"} and "decisionRef" not in bindings:
        raise ContractError("decision route lacks decision binding")
    enum(value["whenMissing"], {"block", "escalate", "plan-only"})
    return mode, bindings


def validate_definition(c: Contracts, value: Any) -> None:
    value = exact(
        value,
        {
            "$schema",
            "schema",
            "skillId",
            "version",
            "title",
            "description",
            "match",
            "routing",
            "authority",
            "operation",
            "agents",
            "completionCriteria",
            "llmAuthority",
        },
    )
    validate_header(value, "wellmanifest.skill-definition/v1")
    c.ref("skillId", value["skillId"])
    c.ref("semver", value["version"])
    string(value["title"], 3, 160)
    string(value["description"], 3, 1000)

    match = exact(value["match"], {"diagnosticCodes", "errorClasses", "fallback"})
    codes = unique_strings(match["diagnosticCodes"], 0)
    for code in codes:
        c.ref("diagnosticCode", code)
    classes = unique_strings(match["errorClasses"], 1)
    accepted_classes = {
        "availability", "configuration", "integrity", "policy", "security", "state", "unknown"
    }
    if not set(classes) <= accepted_classes or not isinstance(match["fallback"], bool):
        raise ContractError("invalid diagnostic match")
    if not match["fallback"] and not codes:
        raise ContractError("non-fallback skill lacks diagnostic code")

    routing = exact(value["routing"], {"safetyClass", "basePriority", "deduplication"})
    safety = enum(routing["safetyClass"], {"routine", *PROTECTED_HUMAN, "secret"})
    enum(routing["basePriority"], {"P0", "P1", "P2", "P3"})
    dedupe = exact(routing["deduplication"], {"key", "scope"})
    if dedupe != {"key": "fingerprint", "scope": "target-repository"}:
        raise ContractError("invalid deduplication boundary")

    mode, bindings = validate_authority(c, value["authority"])
    operation = exact(value["operation"], {"capability", "executor", "effect", "maxChangedFiles"})
    c.ref("identifier", operation["capability"])
    executor = enum(
        operation["executor"],
        {"doctor-agent", "repair-agent", "validator-agent", "skills-agent", "human", "secret-intake"},
    )
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
    if not isinstance(agents, dict) or not agents:
        raise ContractError("agent phase contract missing")
    if set(agents) - {"doctor-agent", "repair-agent", "validator-agent", "skills-agent"}:
        raise ContractError("unknown agent phase")
    for phase in agents.values():
        validate_phase(c, phase)
    if effect == "pull-request" and not {"repair-agent", "validator-agent"} <= set(agents):
        raise ContractError("repair skill lacks independent validation phase")
    for criterion in unique_strings(value["completionCriteria"], 1):
        c.ref("identifier", criterion)
    if value["llmAuthority"] != "propose-only":
        raise ContractError("LLM authority is not propose-only")


def validate_catalog_entry(c: Contracts, value: Any) -> str:
    value = exact(value, {"skillId", "definition", "safetyClass", "diagnosticCodes"})
    skill_id = c.ref("skillId", value["skillId"])
    validate_artifact(c, value["definition"])
    enum(value["safetyClass"], {"routine", *PROTECTED_HUMAN, "secret"})
    for code in unique_strings(value["diagnosticCodes"], 0):
        c.ref("diagnosticCode", code)
    return skill_id


def validate_catalog(c: Contracts, value: Any) -> None:
    value = exact(value, {"$schema", "schema", "catalogId", "version", "entries", "defaultRoute"})
    validate_header(value, "wellmanifest.skill-catalog/v1")
    c.ref("identifier", value["catalogId"])
    c.ref("semver", value["version"])
    if not isinstance(value["entries"], list) or not value["entries"]:
        raise ContractError("empty catalog")
    ids = [validate_catalog_entry(c, entry) for entry in value["entries"]]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate catalog skill")
    if value["defaultRoute"] != "block":
        raise ContractError("catalog fallback must block")


def validate_finding(c: Contracts, value: Any) -> tuple[str, set[str]]:
    value = exact(
        value,
        {
            "fingerprint",
            "targetRepository",
            "diagnosticCode",
            "errorClass",
            "severity",
            "occurrences",
            "eligibleSkills",
            "deterministicPriority",
        },
    )
    fingerprint = c.ref("sha256", value["fingerprint"])
    c.ref("repository", value["targetRepository"])
    c.ref("diagnosticCode", value["diagnosticCode"])
    enum(value["errorClass"], {"availability", "configuration", "integrity", "policy", "security", "state", "unknown"})
    enum(value["severity"], {"critical", "high", "medium", "low", "info"})
    integer(value["occurrences"], 1, 1000000)
    skills = set(unique_strings(value["eligibleSkills"], 1))
    for skill_id in skills:
        c.ref("skillId", skill_id)
    enum(value["deterministicPriority"], {"P0", "P1", "P2", "P3"})
    return fingerprint, skills


def validate_selection_request(c: Contracts, value: Any) -> dict[str, set[str]]:
    value = exact(
        value,
        {"$schema", "schema", "requestId", "catalogDigest", "policyDigest", "priorityProfileDigest", "findings"},
    )
    validate_header(value, "wellmanifest.skill-selection-request/v1")
    c.ref("identifier", value["requestId"])
    for field in ("catalogDigest", "policyDigest", "priorityProfileDigest"):
        c.ref("sha256", value[field])
    findings = value["findings"]
    if not isinstance(findings, list) or not 1 <= len(findings) <= 100:
        raise ContractError("invalid finding batch")
    result: dict[str, set[str]] = {}
    for finding in findings:
        fingerprint, candidates = validate_finding(c, finding)
        if fingerprint in result:
            raise ContractError("duplicate finding fingerprint")
        result[fingerprint] = candidates
    return result


def validate_selection_proposal(c: Contracts, value: Any) -> list[tuple[str, str]]:
    value = exact(value, {"$schema", "schema", "catalogDigest", "requestDigest", "effect", "selections"})
    validate_header(value, "wellmanifest.skill-selection-proposal/v1")
    c.ref("sha256", value["catalogDigest"])
    c.ref("sha256", value["requestDigest"])
    if value["effect"] != "propose-only":
        raise ContractError("selection has an effect")
    selections = value["selections"]
    if not isinstance(selections, list) or len(selections) > 100:
        raise ContractError("invalid selections")
    result: list[tuple[str, str]] = []
    for item in selections:
        item = exact(item, {"fingerprint", "skillId", "priorityAdjustment", "reasonCode", "rationale"})
        fingerprint = c.ref("sha256", item["fingerprint"])
        skill_id = c.ref("skillId", item["skillId"])
        integer(item["priorityAdjustment"], -25, 25)
        enum(item["reasonCode"], {"blast-radius", "dependency-order", "freshness", "operator-impact", "recurrence"})
        string(item["rationale"], 1, 300)
        result.append((fingerprint, skill_id))
    if len(result) != len(set(result)):
        raise ContractError("duplicate selection")
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
    validator = validators.get(value.get("schema"))
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
        "authority": {"mode": modes[safety], "requiredBindings": bindings, "whenMissing": "block"},
        "operation": {
            "capability": f"repository.{safety}.remediate",
            "executor": executor,
            "effect": effect,
            "maxChangedFiles": 3 if effect == "pull-request" else 0,
        },
        "agents": {
            "doctor-agent": phase("doctor"),
            **({"repair-agent": phase("repair"), "validator-agent": phase("validator")} if effect == "pull-request" else {}),
            "skills-agent": phase("skills"),
        },
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
        "requestDigest": digest(canonical(request)),
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


def expect_rejected(c: Contracts, value: Any, request: Any | None = None) -> None:
    try:
        if request is None:
            validate_document(c, value)
        else:
            validate_pair(c, request, value)
    except ContractError:
        return
    raise ContractError("adversarial fixture accepted")


def run_all(c: Contracts) -> None:
    c.integrity()
    valid = [definition_example(safety) for safety in ("routine", "stash", "license", "secret", "ambiguous", "destructive")]
    valid.append(catalog_example())
    request = request_example()
    proposal = proposal_example(request)
    valid.extend([request, proposal])
    for document in valid:
        validate_document(c, document)
    validate_pair(c, request, proposal)

    invalid: list[Any] = []
    bad = definition_example("stash")
    bad["authority"]["mode"] = "standing-policy"
    invalid.append(bad)
    bad = definition_example("license")
    bad["authority"]["mode"] = "digest-bound"
    invalid.append(bad)
    bad = definition_example("secret")
    bad["operation"] = {"capability": "repository.secret.repair", "executor": "repair-agent", "effect": "pull-request", "maxChangedFiles": 1}
    bad["authority"]["requiredBindings"].append("exactBaseSha")
    invalid.append(bad)
    bad = definition_example("ambiguous")
    bad["authority"]["requiredBindings"].remove("decisionRef")
    invalid.append(bad)
    bad = definition_example("routine")
    bad["operation"]["shell"] = "ignored"
    invalid.append(bad)
    bad = catalog_example()
    bad["entries"].append(copy.deepcopy(bad["entries"][0]))
    invalid.append(bad)
    bad = proposal_example(request)
    bad["authority"] = "approved"
    invalid.append(bad)
    bad = proposal_example(request)
    bad["selections"][0]["priorityAdjustment"] = 26
    invalid.append(bad)
    for document in invalid:
        expect_rejected(c, document)
    escaped = proposal_example(request)
    escaped["selections"][0]["skillId"] = "skill.repository.other-remediation.v1"
    expect_rejected(c, escaped, request)
    print(f"PASS: {len(valid)} valid documents, {len(invalid) + 1} adversarial cases")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true", help="run bundled positive and adversarial fixtures")
    parser.add_argument("--file", type=Path, help="validate one JSON document")
    parser.add_argument("--proposal-with-request", nargs=2, type=Path, metavar=("REQUEST", "PROPOSAL"))
    args = parser.parse_args()
    c = Contracts()
    try:
        if args.all:
            run_all(c)
        elif args.file:
            c.integrity()
            validate_document(c, json.loads(args.file.read_text("utf-8")))
            print("PASS: document conforms")
        elif args.proposal_with_request:
            c.integrity()
            request, proposal = (json.loads(path.read_text("utf-8")) for path in args.proposal_with_request)
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
