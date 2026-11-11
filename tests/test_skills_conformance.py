#!/usr/bin/env python3
"""Standalone pytest and unittest suite for Wellmanifest governed skills conformance."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from standard import conformance, execution_conformance, operation_profile_conformance
from standard.skill_primitives import ContractError, parse_rfc3339_utc, strict_loads

REPO_ROOT = Path(__file__).resolve().parents[1]


class SkillsConformanceTests(unittest.TestCase):
    def test_all_three_suites_pass_via_primary_runner(self) -> None:
        contracts = conformance.Contracts()
        conformance.run_all(contracts)

    def test_strict_loads_rejects_duplicate_json_keys_at_any_depth(self) -> None:
        with self.assertRaises(ContractError):
            strict_loads('{"effect":"propose-only","effect":"execute"}')
        with self.assertRaises(ContractError):
            strict_loads('{"nested":{"singleUse":true,"singleUse":false}}')

    def test_skill_definition_rejects_inline_secrets_and_bool_for_int(self) -> None:
        contracts = conformance.Contracts()
        bad_secret = conformance.definition_example("routine")
        bad_secret["description"] = "Leak " + "ghp_" + ("a" * 30) + " placeholder."
        with self.assertRaises(ContractError):
            conformance.validate_definition(contracts, bad_secret)

        bad_bool = conformance.definition_example("routine")
        bad_bool["operation"]["maxChangedFiles"] = True
        with self.assertRaises(ContractError):
            conformance.validate_definition(contracts, bad_bool)

    def test_catalog_rejects_relative_path_traversal_and_dot_segments(self) -> None:
        contracts = conformance.Contracts()
        for unsafe_path in (
            "SKILLS/../escape/skill.json",
            "SKILLS/./routine/skill.json",
            "SKILLS//routine/skill.json",
            "/SKILLS/routine/skill.json",
        ):
            catalog = conformance.catalog_example()
            catalog["entries"][0]["definition"]["path"] = unsafe_path
            with self.subTest(path=unsafe_path), self.assertRaises(ContractError):
                conformance.validate_catalog(contracts, catalog)

    def test_selection_proposal_must_match_request_digest_and_candidates(self) -> None:
        contracts = conformance.Contracts()
        request = conformance.request_example()
        proposal = conformance.proposal_example(request)
        conformance.validate_pair(contracts, request, proposal)

        tampered = conformance.proposal_example(request)
        tampered["requestDigest"] = "0" * 64
        with self.assertRaises(ContractError):
            conformance.validate_pair(contracts, request, tampered)

    def test_execution_grant_enforces_strict_rfc3339_and_expiry(self) -> None:
        parsed = parse_rfc3339_utc("2099-01-01T00:00:00Z")
        self.assertEqual(parsed.tzinfo, UTC)
        for malformed in ("2099-01-01 00:00:00Z", "2099-01-01", "2099-01-01T00:00:00"):
            with self.subTest(ts=malformed), self.assertRaises(ContractError):
                parse_rfc3339_utc(malformed)

        plan = execution_conformance.plan_example("repository:repair")
        grant = execution_conformance.grant_example(plan)
        execution_conformance.validate_grant_pair(
            plan, grant, now=datetime(2026, 11, 11, tzinfo=UTC)
        )

        grant_space = execution_conformance.grant_example(plan)
        grant_space["expiresAt"] = "2099-01-01 00:00:00+00:00"
        with self.assertRaises(ContractError):
            execution_conformance.validate_grant(grant_space)

    def test_execution_receipt_and_error_reject_inline_secret_values(self) -> None:
        plan = execution_conformance.plan_example("repository:repair")
        grant = execution_conformance.grant_example(plan)
        receipt = execution_conformance.receipt_example(plan, grant)
        execution_conformance.validate_receipt_pair(
            plan, receipt, grant, now=datetime(2026, 11, 11, tzinfo=UTC)
        )

        leaked_error = execution_conformance.error_example()
        leaked_error["evidenceRefs"] = ["evidence://subactor/" + "sk-" + ("a" * 26)]
        with self.assertRaises(ContractError):
            execution_conformance.validate_error(leaked_error)

    def test_operation_profile_conformance_validates_and_rejects_tampering(self) -> None:
        operation_profile_conformance.schema_integrity()
        profile = json.loads(operation_profile_conformance.PROFILE_PATH.read_text(encoding="utf-8"))
        operation_profile_conformance.validate_profile(profile)
        profile["authority"]["singleUse"] = False
        with self.assertRaises(ContractError):
            operation_profile_conformance.validate_profile(profile)

    def test_cli_file_modes_accept_valid_and_reject_duplicate_key_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            valid_def = tmp_dir / "skill.json"
            valid_def.write_text(
                json.dumps(conformance.definition_example("routine")), encoding="utf-8"
            )
            ok = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "standard/conformance.py"),
                    "--file",
                    str(valid_def),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)

            dup_file = tmp_dir / "dup.json"
            dup_file.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            bad = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "standard/conformance.py"),
                    "--file",
                    str(dup_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(bad.returncode, 1)
            self.assertIn("FAIL:", bad.stdout)


if __name__ == "__main__":
    unittest.main()
