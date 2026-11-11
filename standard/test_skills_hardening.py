#!/usr/bin/env python3
"""Regression tests for Wellmanifest governed skills security and modular hardening."""

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from standard import conformance, execution_conformance, execution_errors
from standard import operation_profile_conformance as profile_conformance
from standard import skill_primitives as primitives
from standard.skill_primitives import (
    MAX_JSON_DEPTH,
    ContractError,
    assert_closed_schema,
    canonical,
    exact,
    load_strict_json,
    read_regular_utf8,
    reject_sensitive_tree,
    strict_loads,
)


class SkillsHardeningTests(unittest.TestCase):
    def test_strict_loads_and_canonical_reject_non_finite_and_deep_json(self) -> None:
        for bad_json in ("NaN", "Infinity", "-Infinity", '{"x": NaN}', "[Infinity]"):
            with self.subTest(payload=bad_json), self.assertRaises(ContractError):
                strict_loads(bad_json)

        with self.assertRaises(ContractError):
            canonical({"bad": float("nan")})
        with self.assertRaises(ContractError):
            canonical({"bad": float("inf")})

        deep_raw = "[" * (MAX_JSON_DEPTH + 2) + "1" + "]" * (MAX_JSON_DEPTH + 2)
        with self.assertRaises(ContractError):
            strict_loads(deep_raw)

        deep_obj: Any = 1
        for _ in range(MAX_JSON_DEPTH + 3):
            deep_obj = {"nested": deep_obj}
        with self.assertRaises(ContractError):
            canonical(deep_obj)
        with self.assertRaises(ContractError):
            reject_sensitive_tree(deep_obj)
        with self.assertRaises(ContractError):
            assert_closed_schema(deep_obj)

    def test_load_strict_json_rejects_symlinks_directories_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "real.json"
            target.write_text('{"ok": true}', encoding="utf-8")
            self.assertEqual(load_strict_json(target), {"ok": True})

            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(ContractError):
                load_strict_json(link)

            with self.assertRaises(ContractError):
                load_strict_json(root)

    def test_unhashable_fields_and_non_string_keys_raise_contract_error(self) -> None:
        contracts = conformance.Contracts()

        with self.assertRaises(ContractError):
            exact({1: "bad"}, {"1"})  # type: ignore[dict-item]
        with self.assertRaises(ContractError):
            reject_sensitive_tree({1: "bad"})
        reject_sensitive_tree({"$schema": ["benign"]}, allowed_schema_uris={"urn:ok"})
        with self.assertRaises(ContractError):
            reject_sensitive_tree(
                {"$schema": [conformance.SCHEMA_URI]},
                allowed_schema_uris={conformance.SCHEMA_URI},
            )

        with self.assertRaises(ContractError):
            conformance.validate_document(contracts, {"schema": ["unhashable"]})
        with self.assertRaises(ContractError):
            execution_conformance.validate_document({"schema": ["unhashable"]})

        bad_err = execution_conformance.error_example()
        bad_err["code"] = ["unhashable"]
        with self.assertRaises(ContractError):
            execution_errors.validate_error(bad_err)

        profile = load_strict_json(profile_conformance.PROFILE_PATH)
        bad_bindings = copy.deepcopy(profile)
        bad_bindings["authority"]["requiredBindings"] = [["unhashable"]] * 6
        with self.assertRaises(ContractError):
            profile_conformance.validate_profile(bad_bindings)

        bad_owner = copy.deepcopy(profile)
        bad_owner["runtimeOwnership"]["executor"] = ["unhashable"]
        with self.assertRaises(ContractError):
            profile_conformance.validate_profile(bad_owner)

    def test_repository_organization_and_reference_traversal_rejected(self) -> None:
        contracts = conformance.Contracts()
        for bad_repo in ("../..", "./subactor", "subactor/..", "subactor/."):
            cat = conformance.catalog_example()
            cat["entries"][0]["definition"]["repository"] = bad_repo
            with self.subTest(repo=bad_repo), self.assertRaises(ContractError):
                conformance.validate_catalog(contracts, cat)

            req = conformance.request_example()
            req["findings"][0]["targetRepository"] = bad_repo
            with self.subTest(req_repo=bad_repo), self.assertRaises(ContractError):
                conformance.validate_selection_request(contracts, req)

        bad_plan = execution_conformance.plan_example("repository:repair")
        bad_plan["target"]["organization"] = ".."
        bad_plan["target"]["repository"] = "../example"
        bad_plan["idempotencyKey"] = execution_conformance.idempotency_digest(bad_plan)
        bad_plan["planDigest"] = execution_conformance.plan_digest(bad_plan)
        with self.assertRaises(ContractError):
            execution_conformance.validate_plan(bad_plan)

        for bad_ref in (
            "grant://..",
            "grant:///empty",
            "grant://subactor/../escape",
            "grant://subactor//double",
            "grant://subactor/trailing/",
            "grant://subactor/bad space",
            "grant://subactor/bad\nline",
        ):
            grant = execution_conformance.grant_example(
                execution_conformance.plan_example("repository:repair")
            )
            grant["grantRef"] = bad_ref
            with self.subTest(ref=bad_ref), self.assertRaises(ContractError):
                execution_conformance.validate_grant(grant)

    def test_numeric_overflow_schema_maxlength_and_closed_schema_predicates(self) -> None:
        for bad_num in ("1e999", "-1e999", '{"x": 1e999}', f'{{"n": {"9" * 400}}}'):
            with self.subTest(payload=bad_num), self.assertRaises(ContractError):
                strict_loads(bad_num)

        with self.assertRaises(ContractError):
            canonical({"huge": 10**400})

        contracts = conformance.Contracts()
        bad_def = conformance.definition_example("routine")
        bad_def["skillId"] = f"skill.{'a' * 160}.repair.v1"
        with self.assertRaises(ContractError):
            conformance.validate_definition(contracts, bad_def)

        bad_cat = conformance.catalog_example()
        bad_cat["catalogId"] = "c" * 161
        with self.assertRaises(ContractError):
            conformance.validate_catalog(contracts, bad_cat)

        bad_req = conformance.request_example()
        bad_req["findings"][0]["diagnosticCode"] = "D" * 81
        with self.assertRaises(ContractError):
            conformance.validate_selection_request(contracts, bad_req)

        assert_closed_schema(
            {
                "type": "object",
                "additionalProperties": False,
                "properties": {"mode": {"type": "string"}},
                "if": {"type": "object", "properties": {"mode": {"const": "strict"}}},
                "then": {"properties": {"mode": {"const": "strict"}}},
            }
        )
        with self.assertRaises(ContractError):
            assert_closed_schema(
                {"$defs": {"openDef": {"properties": {"mode": {"type": "string"}}}}}
            )

    def test_regular_file_inode_swap_ancestor_symlinks_and_max_bytes_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_dir"
            real_dir.mkdir()
            target = real_dir / "payload.json"
            target.write_text('{"ok": 1}', encoding="utf-8")

            for bad_max in (True, False, 0, -5):
                with self.subTest(max_bytes=bad_max), self.assertRaises(ContractError):
                    read_regular_utf8(target, max_bytes=bad_max)  # type: ignore[arg-type]

            with self.assertRaises(ContractError):
                read_regular_utf8(target, max_bytes=4)
            with self.assertRaises(ContractError):
                read_regular_utf8(root / "missing.json")

            link_dir = root / "link_dir"
            link_dir.symlink_to(real_dir)
            prev_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaises(ContractError):
                    read_regular_utf8(Path("link_dir/payload.json"))
            finally:
                os.chdir(prev_cwd)

            real_fstat = os.fstat

            def swapped_fstat(fd: int) -> os.stat_result:
                st = real_fstat(fd)
                return os.stat_result(
                    (
                        st.st_mode,
                        st.st_ino + 999999,
                        st.st_dev,
                        st.st_nlink,
                        st.st_uid,
                        st.st_gid,
                        st.st_size,
                        st.st_atime,
                        st.st_mtime,
                        st.st_ctime,
                    )
                )

            with (
                patch("standard.skill_primitives.os.fstat", side_effect=swapped_fstat),
                self.assertRaises(ContractError),
            ):
                read_regular_utf8(target)

    def test_reference_colon_delimiters_and_strict_regex_anchors(self) -> None:
        plan = execution_conformance.plan_example("repository:repair")
        for bad_ref in (
            "grant://subactor:..",
            "grant://subactor/foo:..:bar",
            "grant://:subactor/001",
            "grant://subactor/001:",
            "grant://subactor::001",
            r"grant://subactor\001",
            "grant://subactor/001?query=1",
            "grant://subactor/001#frag",
        ):
            grant = execution_conformance.grant_example(plan)
            grant["grantRef"] = bad_ref
            with self.subTest(ref=bad_ref), self.assertRaises(ContractError):
                execution_conformance.validate_grant(grant)

        contracts = conformance.Contracts()
        samples = [
            (primitives.COMMIT, "a" * 40),
            (primitives.SHA256, "b" * 64),
            (primitives.IDENTIFIER, "plan.repository-001"),
            (primitives.SKILL_ID, "skill.repository.repair.v1"),
            (primitives.REPOSITORY, "subactor/example"),
            (primitives.RELATIVE_PATH, "standard/skill.schema.json"),
            (primitives.ORGANIZATION, "subactor"),
            (primitives.REFERENCE, "grant://subactor/repository/001"),
            (primitives.DIAGNOSTIC_CODE, "DETACHED_HEAD"),
            (primitives.DIAGNOSTIC_ID, "DIAGIT-GIT-002"),
            (primitives.RFC3339_TIMESTAMP, "2099-01-01T00:00:00Z"),
            (contracts.patterns["semver"], "1.2.3"),
            (contracts.patterns["relativePath"], "standard/skill.schema.json"),
        ]
        for pattern, valid_text in samples:
            with self.subTest(pattern=pattern.pattern):
                self.assertIsNotNone(pattern.match(valid_text))
                self.assertIsNone(pattern.match(valid_text + "\n"))

    def test_4300_digit_ints_surrogates_key_secrets_abs_symlinks_and_win_drives(self) -> None:
        for bad_json in (
            '{"n": ' + ("9" * 5000) + "}",
            '{"a": "\\ud800"}',
            '{"\\udfff": 1}',
            '{"a": "\ud800"}',
        ):
            with self.subTest(sample=bad_json[:24]), self.assertRaises(ContractError):
                strict_loads(bad_json)

        for bad_obj in ({"a": "\ud800"}, {"\udfff": 1}):
            with self.assertRaises(ContractError):
                canonical(bad_obj)
            with self.assertRaises(ContractError):
                reject_sensitive_tree(bad_obj)
        with self.assertRaises(ContractError):
            primitives.sha256_text("bad-\ud800")
        with self.assertRaises(ContractError):
            primitives.bounded_text("bad-\ud800")
        with self.assertRaises(ContractError):
            reject_sensitive_tree({"https://remote.example/key": 1}, check_keys=False)
        with self.assertRaises(ContractError):
            primitives.validate_safe_relative_path("C:foo/bar", primitives.RELATIVE_PATH)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_dir" / "nested"
            real_dir.mkdir(parents=True)
            doc_file = real_dir / "skill.json"
            doc_file.write_text('{"ok": 1}', encoding="utf-8")
            sym_dir = root / "sym_dir"
            sym_dir.symlink_to(root / "real_dir")
            with self.assertRaises(ContractError):
                read_regular_utf8(sym_dir / "nested" / "skill.json")


if __name__ == "__main__":
    unittest.main()
