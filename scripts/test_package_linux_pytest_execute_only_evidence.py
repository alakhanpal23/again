#!/usr/bin/env python3
"""Adversarial tests for deterministic Gate 3 evidence packaging."""

from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

from scripts import package_linux_pytest_execute_only_evidence as assembler
from scripts import verify_linux_pytest_execute_only_evidence as verifier


SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567"
BINARY_SHA256 = hashlib.sha256(b"reviewed again binary").hexdigest()
SOURCE_SHA256 = hashlib.sha256(b"reviewed source tree").hexdigest()
TUPLE_REFERENCE = "qualified-tuples/linux-x86_64-v1.json"
TUPLE_SHA256 = hashlib.sha256(b"reviewed qualified tuple").hexdigest()
STDOUT = b"tests/test_smoke.py::test_smoke PASSED\n1 passed\n"
STDERR = b""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def fixture_manifest() -> dict[str, object]:
    return {
        "schema": verifier.FIXTURE_SCHEMA,
        "selector": verifier.SELECTOR,
        "files": [
            {
                "path": verifier.FIXTURE_PATH,
                "bytes_base64": base64.b64encode(verifier.FIXTURE_BYTES).decode("ascii"),
                "length": len(verifier.FIXTURE_BYTES),
                "sha256": verifier.FIXTURE_SHA256,
            }
        ],
    }


def stream_record(data: bytes) -> dict[str, object]:
    digest = hashlib.sha256(data).hexdigest()
    return {
        "captured_length": len(data),
        "captured_sha256": digest,
        "delivered_length": len(data),
        "delivered_sha256": digest,
    }


def execution_record(manifest_sha256: str) -> dict[str, object]:
    workspace_sha256 = hashlib.sha256(b"unchanged host workspace manifest").hexdigest()
    return {
        "schema": verifier.RECORD_SCHEMA,
        "outcome": "executed_only",
        "selector": verifier.SELECTOR,
        "argv": list(verifier.EXACT_ARGV),
        "hashes": {
            "binary_sha256": BINARY_SHA256,
            "source_sha256": SOURCE_SHA256,
            "fixture_sha256": verifier.FIXTURE_SHA256,
            "fixture_manifest_sha256": manifest_sha256,
        },
        "qualified_tuple_evidence": {
            "schema": verifier.TUPLE_SCHEMA,
            "reference": TUPLE_REFERENCE,
            "sha256": TUPLE_SHA256,
        },
        "streams": {
            "stdout": stream_record(STDOUT),
            "stderr": stream_record(STDERR),
        },
        "raw_final_wait_status": 0,
        "host_manifest": {
            "before_sha256": workspace_sha256,
            "after_sha256": workspace_sha256,
            "unchanged": True,
        },
        "cleanup_canaries": {key: True for key in verifier.CLEANUP_KEYS},
        "descendant_reap": {
            "all_descendants_terminally_reaped": True,
            "final_wait_error": "ECHILD",
        },
        "execute_only_reason": verifier.EXECUTE_ONLY_REASON,
        "counts": {key: 0 for key in verifier.COUNT_KEYS},
        "authority_claims": {key: False for key in verifier.AUTHORITY_KEYS},
    }


def report(
    record: dict[str, object],
    record_sha256: str,
    manifest_sha256: str,
) -> dict[str, object]:
    return {
        "schema": verifier.REPORT_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "execution_record_sha256": record_sha256,
        "fixture_manifest_sha256": manifest_sha256,
        "outcome": record["outcome"],
        "selector": record["selector"],
        "argv": copy.deepcopy(record["argv"]),
        "hashes": copy.deepcopy(record["hashes"]),
        "qualified_tuple_evidence": copy.deepcopy(record["qualified_tuple_evidence"]),
        "streams": {
            "stdout": {"length": len(STDOUT), "sha256": hashlib.sha256(STDOUT).hexdigest()},
            "stderr": {"length": len(STDERR), "sha256": hashlib.sha256(STDERR).hexdigest()},
        },
        "raw_final_wait_status": record["raw_final_wait_status"],
        "host_manifest": copy.deepcopy(record["host_manifest"]),
        "cleanup_canaries": copy.deepcopy(record["cleanup_canaries"]),
        "descendant_reap": copy.deepcopy(record["descendant_reap"]),
        "execute_only_reason": record["execute_only_reason"],
        "counts": copy.deepcopy(record["counts"]),
        "authority_claims": copy.deepcopy(record["authority_claims"]),
    }


def valid_members() -> dict[str, bytes]:
    manifest_raw = canonical(fixture_manifest())
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    record = execution_record(manifest_sha256)
    record_raw = canonical(record)
    record_sha256 = hashlib.sha256(record_raw).hexdigest()
    return {
        verifier.FIXTURE_MANIFEST_MEMBER: manifest_raw,
        verifier.RECORD_MEMBER: record_raw,
        verifier.STDOUT_MEMBER: STDOUT,
        verifier.STDERR_MEMBER: STDERR,
        verifier.REPORT_MEMBER: canonical(report(record, record_sha256, manifest_sha256)),
    }


class EvidenceAssemblerTests(unittest.TestCase):
    def setUp(self) -> None:
        canonical_temporary_root = "/private/tmp" if Path("/private/tmp").is_dir() else None
        self.temporary = tempfile.TemporaryDirectory(
            prefix="again-gate3-assembler-test-", dir=canonical_temporary_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = self.root / "inputs"
        self.outputs = self.root / "outputs"
        self.inputs.mkdir()
        self.outputs.mkdir()
        self.write_members(valid_members())
        self.expectations = assembler.IndependentExpectations(
            source_commit=SOURCE_COMMIT,
            binary_sha256=BINARY_SHA256,
            source_sha256=SOURCE_SHA256,
            qualified_tuple_reference=TUPLE_REFERENCE,
            qualified_tuple_sha256=TUPLE_SHA256,
        )

    def write_members(self, members: dict[str, bytes]) -> None:
        for child in self.inputs.iterdir():
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        for name, raw in members.items():
            (self.inputs / name).write_bytes(raw)

    def package(self, name: str = "evidence.zip") -> dict[str, object]:
        return assembler.package_evidence(
            self.inputs,
            self.outputs,
            name,
            self.expectations,
        )

    def assert_refusal(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(assembler.AssemblyRefusal) as refused:
            function(*args, **kwargs)
        self.assertEqual(refused.exception.code, code)

    def assert_no_output(self, name: str = "evidence.zip") -> None:
        self.assertFalse((self.outputs / name).exists())

    def verify(self, path: Path) -> dict[str, object]:
        return verifier.verify_archive(
            path,
            SOURCE_COMMIT,
            BINARY_SHA256,
            SOURCE_SHA256,
            TUPLE_REFERENCE,
            TUPLE_SHA256,
        )

    def test_archive_is_byte_deterministic_and_accepted_by_existing_verifier(self) -> None:
        first_audit = self.package("first.zip")
        second_audit = self.package("second.zip")
        first = self.outputs / "first.zip"
        second = self.outputs / "second.zip"
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_audit, self.verify(first))
        self.assertEqual(second_audit, self.verify(second))
        self.assertEqual(first_audit["member_count"], 5)
        self.assertTrue(all(value is False for value in first_audit["authority"].values()))
        with zipfile.ZipFile(first) as archive:
            self.assertEqual([info.filename for info in archive.infolist()], list(assembler.MEMBER_ORDER))
            for info in archive.infolist():
                self.assertEqual(info.date_time, assembler.FIXED_ZIP_TIMESTAMP)
                self.assertEqual(info.compress_type, zipfile.ZIP_STORED)
                self.assertEqual(info.flag_bits, 0)
                self.assertEqual(info.external_attr >> 16, stat.S_IFREG | 0o600)
                self.assertEqual(info.extra, b"")
                self.assertEqual(info.comment, b"")
            self.assertEqual(archive.comment, b"")

    def test_missing_and_extra_inputs_refuse_before_output(self) -> None:
        for name in verifier.EXPECTED_MEMBERS:
            with self.subTest(missing=name):
                self.write_members(valid_members())
                (self.inputs / name).unlink()
                self.assert_refusal("input_member_set_mismatch", self.package)
                self.assert_no_output()
        self.write_members(valid_members())
        (self.inputs / "extra.json").write_bytes(b"{}\n")
        self.assert_refusal("input_member_set_mismatch", self.package)
        self.assert_no_output()

    def test_duplicate_malformed_nonfinite_and_nonobject_json_refuse(self) -> None:
        mutations = (
            (b'{"schema":"one","schema":"two"}\n', "json_duplicate_key"),
            (b"{not-json}\n", "json_malformed"),
            (b'{"value":NaN}\n', "json_nonfinite_number"),
            (b"[]\n", "json_object_required"),
        )
        for name in assembler.JSON_MEMBERS:
            for raw, code in mutations:
                with self.subTest(name=name, code=code):
                    self.write_members(valid_members())
                    (self.inputs / name).write_bytes(raw)
                    self.assert_refusal(code, self.package)
                    self.assert_no_output()

    def test_path_escapes_and_symlink_components_refuse(self) -> None:
        for output_name in ("../evidence.zip", "/evidence.zip", "dir/evidence.zip", "bad\\x.zip"):
            with self.subTest(output_name=output_name):
                self.assert_refusal("output_name_malformed", self.package, output_name)
        link = self.root / "inputs-link"
        os.symlink(self.inputs, link)
        self.assert_refusal(
            "symlink_or_directory_unavailable",
            assembler.package_evidence,
            link,
            self.outputs,
            "linked.zip",
            self.expectations,
        )
        self.assert_no_output("linked.zip")
        output_link = self.root / "outputs-link"
        os.symlink(self.outputs, output_link)
        self.assert_refusal(
            "symlink_or_directory_unavailable",
            assembler.package_evidence,
            self.inputs,
            output_link,
            "linked.zip",
            self.expectations,
        )
        self.assert_no_output("linked.zip")

        for escaped in (
            f"{self.root}/missing/../inputs",
            "./inputs",
        ):
            with self.subTest(escaped=escaped):
                self.assert_refusal(
                    "path_escape",
                    assembler.package_evidence,
                    escaped,
                    self.outputs,
                    "escaped.zip",
                    self.expectations,
                )

    def test_symlink_special_sparse_hardlinked_and_oversized_inputs_refuse(self) -> None:
        member = self.inputs / verifier.STDOUT_MEMBER
        member.unlink()
        os.symlink(verifier.STDERR_MEMBER, member)
        self.assert_refusal("input_symlink", self.package)

        self.write_members(valid_members())
        member = self.inputs / verifier.STDOUT_MEMBER
        if hasattr(os, "mkfifo"):
            member.unlink()
            os.mkfifo(member)
            self.assert_refusal("input_special_file", self.package)

        self.write_members(valid_members())
        member = self.inputs / verifier.STDOUT_MEMBER
        hardlink = self.root / "outside-hardlink"
        os.link(member, hardlink)
        self.assert_refusal("input_hardlinked", self.package)
        hardlink.unlink()

        self.write_members(valid_members())
        with mock.patch.object(
            assembler,
            "_is_sparse",
            side_effect=lambda metadata: metadata.st_size == len(STDOUT),
        ):
            self.assert_refusal("input_sparse", self.package)

        self.write_members(valid_members())
        member = self.inputs / verifier.STDOUT_MEMBER
        with member.open("wb") as output:
            output.truncate(verifier.MAX_STREAM_BYTES + 1)
        self.assert_refusal("input_oversized", self.package)
        self.assert_no_output()

    def test_change_during_read_refuses(self) -> None:
        target_inode = (self.inputs / verifier.STDOUT_MEMBER).stat().st_ino
        real_fstat = assembler.os.fstat
        observed = 0

        def changing_fstat(descriptor: int):
            nonlocal observed
            result = real_fstat(descriptor)
            if result.st_ino == target_inode:
                observed += 1
                if observed >= 2:
                    values = list(result)
                    values[8] = result.st_mtime + 1
                    return os.stat_result(values)
            return result

        with mock.patch.object(assembler.os, "fstat", side_effect=changing_fstat):
            self.assert_refusal("input_changed", self.package)
        self.assert_no_output()

    def test_semantically_invalid_archive_is_removed_after_verifier_refusal(self) -> None:
        members = valid_members()
        record = json.loads(members[verifier.RECORD_MEMBER])
        record["authority_claims"]["execution_authority_claimed"] = True
        members[verifier.RECORD_MEMBER] = canonical(record)
        self.write_members(members)
        self.assert_refusal("archive_verification_failed", self.package)
        self.assert_no_output()

    def test_overwrite_attempt_preserves_existing_bytes(self) -> None:
        existing = self.outputs / "evidence.zip"
        existing.write_bytes(b"existing")
        self.assert_refusal("output_exists", self.package)
        self.assertEqual(existing.read_bytes(), b"existing")

        existing.unlink()
        target = self.outputs / "target"
        target.write_bytes(b"target")
        os.symlink(target.name, existing)
        self.assert_refusal("output_exists", self.package)
        self.assertTrue(existing.is_symlink())
        self.assertEqual(target.read_bytes(), b"target")

    def test_partial_write_failure_removes_only_new_output(self) -> None:
        real_write = assembler.os.write
        calls = 0

        def failing_write(descriptor: int, value: bytes) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(descriptor, value[:17])
            raise OSError("injected write failure")

        with mock.patch.object(assembler.os, "write", side_effect=failing_write):
            self.assert_refusal("output_write_failed", self.package)
        self.assertGreaterEqual(calls, 2)
        self.assert_no_output()

    def test_source_directory_is_never_an_output_and_inputs_are_not_mutated(self) -> None:
        before = {path.name: path.read_bytes() for path in self.inputs.iterdir()}
        self.assert_refusal(
            "source_mutation_forbidden",
            assembler.package_evidence,
            self.inputs,
            self.inputs,
            "evidence.zip",
            self.expectations,
        )
        after = {path.name: path.read_bytes() for path in self.inputs.iterdir()}
        self.assertEqual(after, before)
        self.assertNotIn("evidence.zip", after)

    def test_independent_expectations_are_exact(self) -> None:
        cases = (
            {"source_commit": "A" * 40},
            {"binary_sha256": "f" * 63},
            {"source_sha256": "g" * 64},
            {"qualified_tuple_reference": "../tuple.json"},
            {"qualified_tuple_sha256": "f" * 65},
        )
        baseline = dataclass_values(self.expectations)
        for mutation in cases:
            with self.subTest(mutation=mutation):
                changed = {**baseline, **mutation}
                with self.assertRaises(assembler.AssemblyRefusal):
                    assembler.IndependentExpectations(**changed)

    def test_valid_but_mismatched_expectations_fail_verification_and_cleanup(self) -> None:
        changes = (
            {"source_commit": "f" * 40},
            {"binary_sha256": "f" * 64},
            {"source_sha256": "e" * 64},
            {"qualified_tuple_reference": "qualified-tuples/other.json"},
            {"qualified_tuple_sha256": "d" * 64},
        )
        baseline = dataclass_values(self.expectations)
        for change in changes:
            with self.subTest(change=change):
                expectations = assembler.IndependentExpectations(**{**baseline, **change})
                self.assert_refusal(
                    "archive_verification_failed",
                    assembler.package_evidence,
                    self.inputs,
                    self.outputs,
                    "mismatch.zip",
                    expectations,
                )
                self.assert_no_output("mismatch.zip")

    def test_cli_emits_audit_and_refuses_second_write(self) -> None:
        arguments = [
            str(self.inputs),
            str(self.outputs),
            "--expected-source-commit",
            SOURCE_COMMIT,
            "--expected-binary-sha256",
            BINARY_SHA256,
            "--expected-source-sha256",
            SOURCE_SHA256,
            "--expected-qualified-tuple-reference",
            TUPLE_REFERENCE,
            "--expected-qualified-tuple-sha256",
            TUPLE_SHA256,
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembler.main(arguments), 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["member_count"], 5)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembler.main(arguments), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("output_exists", stderr.getvalue())


def dataclass_values(expectations: assembler.IndependentExpectations) -> dict[str, str]:
    return {
        field.name: getattr(expectations, field.name)
        for field in assembler.dataclasses.fields(expectations)
    }


if __name__ == "__main__":
    unittest.main()
