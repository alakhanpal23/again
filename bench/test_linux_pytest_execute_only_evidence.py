#!/usr/bin/env python3
"""Unit tests for the pure Gate 3 execute-only evidence oracle."""

from __future__ import annotations

import copy
import importlib.util
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("linux_pytest_execute_only_evidence.py")
SPEC = importlib.util.spec_from_file_location("linux_pytest_execute_only_evidence", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
oracle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oracle
SPEC.loader.exec_module(oracle)


class ExecuteOnlyEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-gate3-oracle-test-")
        self.root = pathlib.Path(self.temporary.name)
        self.copy_index = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def copied_fixture(self) -> pathlib.Path:
        self.copy_index += 1
        destination = self.root / f"fixture-{self.copy_index}"
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, destination)
        return destination

    def assert_fixture_refusal(self, root: pathlib.Path, code: str) -> None:
        with self.assertRaises(oracle.EvidenceRefusal) as refused:
            oracle.validate_fixture(root)
        self.assertEqual(refused.exception.code, code)

    def test_committed_fixture_has_exact_path_bytes_length_and_sha256(self) -> None:
        identity = oracle.validate_fixture()

        self.assertEqual(identity.selector, "tests/test_smoke.py::test_smoke")
        self.assertEqual(identity.path, "tests/test_smoke.py")
        self.assertEqual(identity.length, 96)
        self.assertEqual(
            identity.sha256,
            "6c29f0960cc8ade5d57f147d7e9921d619ec9404dfd235377b3fe2d9a3ae7f72",
        )
        fixture = oracle.DEFAULT_FIXTURE_ROOT / identity.path
        self.assertEqual(fixture.read_bytes(), oracle.FIXTURE_BYTES)
        self.assertEqual(oracle.sha256_bytes(fixture.read_bytes()), identity.sha256)
        manifest = (oracle.DEFAULT_FIXTURE_ROOT / "manifest.json").read_bytes()
        self.assertEqual(manifest, oracle.canonical_json_bytes(oracle.EXPECTED_MANIFEST))

    def test_fixture_byte_and_manifest_drift_are_rejected(self) -> None:
        changed_file = self.copied_fixture()
        fixture = changed_file / oracle.FIXTURE_PATH
        changed = bytearray(fixture.read_bytes())
        changed[-2] ^= 1
        fixture.write_bytes(changed)
        self.assert_fixture_refusal(changed_file, "fixture_content_drift")

        changed_manifest = self.copied_fixture()
        manifest_path = changed_manifest / "manifest.json"
        manifest_path.write_bytes(manifest_path.read_bytes() + b" ")
        self.assert_fixture_refusal(changed_manifest, "fixture_manifest_drift")

        jointly_changed = self.copied_fixture()
        fixture_path = jointly_changed / oracle.FIXTURE_PATH
        replacement = fixture_path.read_bytes().replace(b"True", b"None")
        fixture_path.write_bytes(replacement)
        manifest = copy.deepcopy(oracle.EXPECTED_MANIFEST)
        manifest["files"][0]["bytes_base64"] = __import__("base64").b64encode(
            replacement
        ).decode("ascii")
        manifest["files"][0]["length"] = len(replacement)
        manifest["files"][0]["sha256"] = oracle.sha256_bytes(replacement)
        (jointly_changed / "manifest.json").write_bytes(oracle.canonical_json_bytes(manifest))
        self.assert_fixture_refusal(jointly_changed, "fixture_manifest_drift")

    def test_extra_missing_and_renamed_entries_are_rejected(self) -> None:
        extra = self.copied_fixture()
        (extra / "extra.txt").write_bytes(b"extra")
        self.assert_fixture_refusal(extra, "fixture_extra_entry")

        missing = self.copied_fixture()
        (missing / oracle.FIXTURE_PATH).unlink()
        self.assert_fixture_refusal(missing, "fixture_extra_entry")

        renamed = self.copied_fixture()
        (renamed / oracle.FIXTURE_PATH).rename(renamed / "tests" / "other.py")
        self.assert_fixture_refusal(renamed, "fixture_extra_entry")

    def test_symlinks_and_special_files_are_rejected(self) -> None:
        symlink = self.copied_fixture()
        fixture = symlink / oracle.FIXTURE_PATH
        fixture.unlink()
        os.symlink("../manifest.json", fixture)
        self.assert_fixture_refusal(symlink, "fixture_symlink")

        directory_symlink = self.root / "fixture-root-link"
        os.symlink(oracle.DEFAULT_FIXTURE_ROOT, directory_symlink)
        self.assert_fixture_refusal(directory_symlink, "fixture_symlink")

        if hasattr(os, "mkfifo"):
            special = self.copied_fixture()
            special_file = special / oracle.FIXTURE_PATH
            special_file.unlink()
            os.mkfifo(special_file)
            self.assert_fixture_refusal(special, "fixture_special_file")

    def test_sparse_and_oversized_inputs_are_rejected(self) -> None:
        oversized = self.copied_fixture()
        (oversized / oracle.FIXTURE_PATH).write_bytes(b"x" * (oracle.MAX_FIXTURE_BYTES + 1))
        self.assert_fixture_refusal(oversized, "fixture_oversized")

        sparse = self.copied_fixture()
        with mock.patch.object(
            oracle,
            "_is_sparse",
            side_effect=lambda metadata: metadata.st_size == oracle.FIXTURE_LENGTH,
        ):
            self.assert_fixture_refusal(sparse, "fixture_sparse_file")

    def test_consistent_diagnostic_is_non_authoritative(self) -> None:
        diagnostic = oracle.build_diagnostic_for_test()
        result = oracle.validate_execute_only_evidence(diagnostic)

        self.assertEqual(result.outcome, "diagnostic_consistent")
        self.assertEqual(result.reasons, ())
        rendered = result.to_dict()
        self.assertEqual(
            rendered["authority"],
            {"pass": False, "qualification": False, "execution": False, "reuse": False},
        )
        self.assertNotIn(result.outcome, {"pass", "qualified", "authorized"})

    def test_exact_inner_argv_and_fixture_hash_are_required(self) -> None:
        for index in range(len(oracle.EXACT_ARGV)):
            with self.subTest(index=index):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["argv"][index] += "-changed"
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertEqual(result.outcome, "non_pass")
                self.assertIn("argv_mismatch", result.reasons)

        extra = oracle.build_diagnostic_for_test()
        extra["argv"].append("-q")
        self.assertIn(
            "argv_mismatch", oracle.validate_execute_only_evidence(extra).reasons
        )

        wrong_fixture = oracle.build_diagnostic_for_test()
        wrong_fixture["hashes"]["fixture_sha256"] = "0" * 64
        self.assertIn(
            "fixture_hash_mismatch",
            oracle.validate_execute_only_evidence(wrong_fixture).reasons,
        )

    def test_all_hashes_and_qualified_tuple_reference_are_required(self) -> None:
        cases = [
            (("hashes", "binary_sha256"), "binary"),
            (("hashes", "source_sha256"), "source"),
            (("qualified_tuple_evidence", "sha256"), "tuple"),
        ]
        for path, value in cases:
            with self.subTest(path=path):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic[path[0]][path[1]] = value
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertEqual(result.outcome, "non_pass")

        missing_reference = oracle.build_diagnostic_for_test()
        missing_reference["qualified_tuple_evidence"]["reference"] = ""
        self.assertIn(
            "qualified_tuple_reference_malformed",
            oracle.validate_execute_only_evidence(missing_reference).reasons,
        )

    def test_captured_and_delivered_stream_evidence_must_match(self) -> None:
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream, field="length"):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["streams"][stream]["delivered_length"] = 1
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertIn(f"{stream}_delivery_mismatch", result.reasons)
            with self.subTest(stream=stream, field="hash"):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["streams"][stream]["delivered_sha256"] = "f" * 64
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertIn(f"{stream}_delivery_mismatch", result.reasons)

    def test_wait_status_host_manifest_and_cleanup_canaries_fail_closed(self) -> None:
        wait = oracle.build_diagnostic_for_test()
        wait["raw_final_wait_status"] = 256
        self.assertIn(
            "foreground_wait_status_nonzero",
            oracle.validate_execute_only_evidence(wait).reasons,
        )

        host = oracle.build_diagnostic_for_test()
        host["host_manifest"]["after_sha256"] = "1" * 64
        host["host_manifest"]["unchanged"] = False
        self.assertIn("host_manifest_changed", oracle.validate_execute_only_evidence(host).reasons)

        for canary in ("network", "fd", "mount", "namespace", "task", "branch"):
            with self.subTest(canary=canary):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["cleanup_canaries"][canary] = False
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertIn("cleanup_canary_failed", result.reasons)

    def test_terminal_reap_final_echild_reason_and_zero_counts_are_required(self) -> None:
        reap = oracle.build_diagnostic_for_test()
        reap["descendant_reap"]["all_descendants_terminally_reaped"] = False
        reap["descendant_reap"]["final_wait_error"] = "ESRCH"
        result = oracle.validate_execute_only_evidence(reap)
        self.assertIn("terminal_descendant_reap_incomplete", result.reasons)
        self.assertIn("final_echild_missing", result.reasons)

        reason = oracle.build_diagnostic_for_test()
        reason["execute_only_reason"] = ""
        self.assertIn(
            "execute_only_reason_malformed",
            oracle.validate_execute_only_evidence(reason).reasons,
        )

        for count in ("candidate", "shadow", "promotion", "replay"):
            with self.subTest(count=count):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["counts"][count] = 1
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertIn("forbidden_record_count", result.reasons)

    def test_pass_qualification_execution_and_reuse_claims_are_impossible(self) -> None:
        forbidden_outcomes = ("pass", "qualified", "executed", "reused")
        for outcome in forbidden_outcomes:
            with self.subTest(outcome=outcome):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["outcome"] = outcome
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertEqual(result.outcome, "non_pass")
                self.assertIn("forbidden_outcome", result.reasons)

        for claim in (
            "pass_claimed",
            "qualification_claimed",
            "execution_authority_claimed",
            "reuse_authority_claimed",
        ):
            with self.subTest(claim=claim):
                diagnostic = oracle.build_diagnostic_for_test()
                diagnostic["authority_claims"][claim] = True
                result = oracle.validate_execute_only_evidence(diagnostic)
                self.assertEqual(result.outcome, "non_pass")
                self.assertIn("forbidden_authority_claim", result.reasons)

        reported_non_pass = oracle.build_diagnostic_for_test(outcome="non_pass")
        self.assertEqual(
            oracle.validate_execute_only_evidence(reported_non_pass).outcome, "non_pass"
        )

    def test_schema_and_every_object_shape_are_closed(self) -> None:
        paths = [
            (),
            ("hashes",),
            ("qualified_tuple_evidence",),
            ("streams",),
            ("streams", "stdout"),
            ("streams", "stderr"),
            ("host_manifest",),
            ("cleanup_canaries",),
            ("descendant_reap",),
            ("counts",),
            ("authority_claims",),
        ]
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                diagnostic = oracle.build_diagnostic_for_test()
                target = diagnostic
                for component in path:
                    target = target[component]
                target[f"unknown_{index}"] = True
                self.assertEqual(
                    oracle.validate_execute_only_evidence(diagnostic).outcome,
                    "non_pass",
                )

        wrong_version = oracle.build_diagnostic_for_test()
        wrong_version["schema"] = "again.linux-pytest.execute-only-evidence.v2"
        self.assertIn(
            "schema_mismatch", oracle.validate_execute_only_evidence(wrong_version).reasons
        )

    def test_bounded_strict_json_has_only_two_outcomes(self) -> None:
        raw = oracle.canonical_json_bytes(oracle.build_diagnostic_for_test())
        self.assertEqual(
            oracle.validate_execute_only_evidence_bytes(raw).outcome,
            "diagnostic_consistent",
        )

        duplicate = b'{"schema":"a","schema":"b"}\n'
        duplicate_result = oracle.validate_execute_only_evidence_bytes(duplicate)
        self.assertEqual(duplicate_result.outcome, "non_pass")
        self.assertIn("json_duplicate_key", duplicate_result.reasons)

        oversized = b" " * (oracle.MAX_DIAGNOSTIC_BYTES + 1)
        oversized_result = oracle.validate_execute_only_evidence_bytes(oversized)
        self.assertEqual(oversized_result.outcome, "non_pass")
        self.assertIn("diagnostic_oversized", oversized_result.reasons)

        for value in (None, [], "text", 1, True):
            with self.subTest(value=value):
                result = oracle.validate_execute_only_evidence(value)
                self.assertEqual(result.outcome, "non_pass")
                self.assertEqual(result.reasons, ("diagnostic_shape_malformed",))

        self.assertEqual(
            {result.outcome for result in (duplicate_result, oversized_result)},
            {"non_pass"},
        )

    def test_validation_does_not_mutate_the_fixture(self) -> None:
        before = {
            path.relative_to(oracle.DEFAULT_FIXTURE_ROOT).as_posix(): path.read_bytes()
            for path in oracle.DEFAULT_FIXTURE_ROOT.rglob("*")
            if path.is_file()
        }
        oracle.validate_fixture()
        oracle.validate_execute_only_evidence(oracle.build_diagnostic_for_test())
        after = {
            path.relative_to(oracle.DEFAULT_FIXTURE_ROOT).as_posix(): path.read_bytes()
            for path in oracle.DEFAULT_FIXTURE_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
