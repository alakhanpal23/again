#!/usr/bin/env python3
"""Tests for the bounded Gate 3 snapshot reference oracle."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("linux_pytest_execute_only_snapshot.py")
SPEC = importlib.util.spec_from_file_location("linux_pytest_execute_only_snapshot", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
oracle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = oracle
SPEC.loader.exec_module(oracle)


class SnapshotOracleTests(unittest.TestCase):
    SOURCE_SHA = "b9872ce699c413e0d2d4dd4e568b74371e10e224"
    BINARY_BYTES = b"fixed non-executable python image bytes\n"

    def setUp(self) -> None:
        canonical_temporary_root = "/private/tmp" if pathlib.Path("/private/tmp").is_dir() else None
        self.temporary = tempfile.TemporaryDirectory(
            prefix="again-gate3-snapshot-test-", dir=canonical_temporary_root
        )
        self.root = pathlib.Path(self.temporary.name)
        self.fixture = self.root / "fixture"
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        self.binary = self.root / "python.bin"
        self.binary.write_bytes(self.BINARY_BYTES)
        self.tuple = self.root / "qualified-tuple.json"
        self.tuple_bytes = oracle.canonical_json_bytes(
            {
                "schema": oracle.QUALIFIED_TUPLE_SCHEMA,
                "authority": {
                    "execution_authority": False,
                    "reuse_authority": False,
                },
            }
        )
        self.tuple.write_bytes(self.tuple_bytes)
        self.request = oracle.build_request_for_test(
            binary_sha256=oracle.sha256_bytes(self.BINARY_BYTES),
            source_git_sha=self.SOURCE_SHA,
            qualified_tuple_sha256=oracle.sha256_bytes(self.tuple_bytes),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request_bytes(self, request: dict[str, object] | None = None) -> bytes:
        return oracle.canonical_json_bytes(self.request if request is None else request)

    def build(self, request_raw: bytes | None = None) -> bytes:
        return oracle.build_snapshot_evidence(
            self.request_bytes() if request_raw is None else request_raw,
            fixture_root=self.fixture,
            binary_path=self.binary,
            qualified_tuple_path=self.tuple,
            expected_source_git_sha=self.SOURCE_SHA,
        )

    def assert_refusal(self, code: str, function, *args, **kwargs) -> None:
        with self.assertRaises(oracle.SnapshotRefusal) as refused:
            function(*args, **kwargs)
        self.assertEqual(refused.exception.code, code)

    def test_consistent_output_is_canonical_deterministic_and_non_authoritative(self) -> None:
        first = self.build()
        second = self.build()
        self.assertEqual(first, second)
        self.assertEqual(first, oracle.canonical_json_bytes(json.loads(first)))

        evidence = json.loads(first)
        self.assertEqual(evidence["schema"], oracle.EVIDENCE_SCHEMA)
        self.assertEqual(evidence["oracle"], oracle.ORACLE_ID)
        self.assertEqual(evidence["authority"], oracle.AUTHORITY_FALSE)
        self.assertEqual(evidence["bindings"]["argv"], list(oracle.EXACT_ARGV))
        self.assertEqual(evidence["bindings"]["fixture"], oracle.EXPECTED_FIXTURE_IDENTITY)
        self.assertEqual(
            evidence["bindings"]["binary"]["sha256"],
            oracle.sha256_bytes(self.BINARY_BYTES),
        )
        self.assertEqual(evidence["bindings"]["source"]["git_sha"], self.SOURCE_SHA)
        self.assertEqual(
            evidence["bindings"]["qualified_tuple"]["sha256"],
            oracle.sha256_bytes(self.tuple_bytes),
        )
        committed = {
            "bindings": evidence["bindings"],
            "snapshot": evidence["snapshot"],
        }
        self.assertEqual(
            evidence["commitment_sha256"],
            oracle.sha256_bytes(oracle.canonical_json_bytes(committed)),
        )

    def test_request_duplicate_keys_malformed_shapes_and_oversize_refuse(self) -> None:
        self.assert_refusal(
            "json_duplicate_key",
            self.build,
            b'{"schema":"one","schema":"two"}\n',
        )
        self.assert_refusal("request_json_malformed", self.build, b"[] trailing")
        self.assert_refusal(
            "request_oversized",
            self.build,
            b" " * (oracle.MAX_REQUEST_BYTES + 1),
        )
        extra = copy.deepcopy(self.request)
        extra["extra"] = False
        self.assert_refusal("request_shape_malformed", self.build, self.request_bytes(extra))
        missing = copy.deepcopy(self.request)
        del missing["binary"]
        self.assert_refusal("request_shape_malformed", self.build, self.request_bytes(missing))

    def test_exact_argv_fixture_binary_source_and_tuple_bindings_are_required(self) -> None:
        for index in range(len(oracle.EXACT_ARGV)):
            changed = copy.deepcopy(self.request)
            changed["argv"][index] += "-changed"
            with self.subTest(argv=index):
                self.assert_refusal("argv_mismatch", self.build, self.request_bytes(changed))

        fixture = copy.deepcopy(self.request)
        fixture["fixture"]["sha256"] = "0" * 64
        self.assert_refusal(
            "fixture_identity_mismatch", self.build, self.request_bytes(fixture)
        )
        binary = copy.deepcopy(self.request)
        binary["binary"]["sha256"] = "1" * 64
        self.assert_refusal("binary_sha256_mismatch", self.build, self.request_bytes(binary))
        source = copy.deepcopy(self.request)
        source["source"]["git_sha"] = "2" * 40
        self.assert_refusal("source_git_sha_mismatch", self.build, self.request_bytes(source))
        qualified = copy.deepcopy(self.request)
        qualified["qualified_tuple"]["sha256"] = "3" * 64
        self.assert_refusal(
            "qualified_tuple_sha256_mismatch", self.build, self.request_bytes(qualified)
        )

    def test_path_escapes_and_type_loose_values_refuse(self) -> None:
        for path in (
            "../python",
            "/.venv/bin/python",
            ".venv//bin/python",
            ".venv/./bin/python",
            ".venv\\bin\\python",
        ):
            changed = copy.deepcopy(self.request)
            changed["binary"]["path"] = path
            with self.subTest(path=path):
                self.assert_refusal("path_escape", self.build, self.request_bytes(changed))
        changed = copy.deepcopy(self.request)
        changed["qualified_tuple"]["reference"] = "qualified-tuples/../tuple.json"
        self.assert_refusal("path_escape", self.build, self.request_bytes(changed))
        changed = copy.deepcopy(self.request)
        changed["fixture"]["length"] = True
        self.assert_refusal(
            "fixture_identity_mismatch", self.build, self.request_bytes(changed)
        )
        changed = copy.deepcopy(self.request)
        changed["fixture"]["length"] = float(oracle.FIXTURE_LENGTH)
        self.assert_refusal(
            "fixture_identity_mismatch", self.build, self.request_bytes(changed)
        )

    def test_every_authority_field_is_fixed_false(self) -> None:
        for field in oracle.AUTHORITY_FIELDS:
            changed = copy.deepcopy(self.request)
            changed["authority"][field] = True
            with self.subTest(field=field):
                self.assert_refusal("authority_claimed", self.build, self.request_bytes(changed))
        for claimed in (True, 1, "false"):
            tuple_claim = {
                "schema": oracle.QUALIFIED_TUPLE_SCHEMA,
                "nested": {"execution_authority_claimed": claimed},
            }
            self.tuple_bytes = oracle.canonical_json_bytes(tuple_claim)
            self.tuple.write_bytes(self.tuple_bytes)
            self.request["qualified_tuple"]["sha256"] = oracle.sha256_bytes(
                self.tuple_bytes
            )
            with self.subTest(tuple_authority=claimed):
                self.assert_refusal("qualified_tuple_authority_claimed", self.build)

    def test_fixture_missing_extra_changed_and_duplicate_manifest_refuse(self) -> None:
        (self.fixture / oracle.FIXTURE_PATH).unlink()
        self.assert_refusal("fixture_inputs_mismatch", self.build)

        shutil.rmtree(self.fixture)
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        (self.fixture / "extra").write_bytes(b"extra")
        self.assert_refusal("fixture_inputs_mismatch", self.build)

        shutil.rmtree(self.fixture)
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        (self.fixture / oracle.FIXTURE_PATH).write_bytes(b"changed")
        self.assert_refusal("fixture_content_drift", self.build)

        shutil.rmtree(self.fixture)
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        (self.fixture / "manifest.json").write_bytes(
            b'{"schema":"one","schema":"two"}\n'
        )
        self.assert_refusal("json_duplicate_key", self.build)

    def test_symlink_components_files_and_directories_never_follow(self) -> None:
        fixture_target = self.fixture
        fixture_link = self.root / "fixture-link"
        os.symlink(fixture_target, fixture_link)
        self.assert_refusal(
            "symlink_or_directory_unavailable",
            oracle.validate_fixture,
            fixture_link,
        )

        fixture_file = self.fixture / oracle.FIXTURE_PATH
        fixture_file.unlink()
        os.symlink("../manifest.json", fixture_file)
        self.assert_refusal("input_symlink", self.build)

        shutil.rmtree(self.fixture)
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        tests_target = self.root / "tests-target"
        (self.fixture / "tests").rename(tests_target)
        os.symlink(tests_target, self.fixture / "tests")
        self.assert_refusal("fixture_symlink_or_unavailable", self.build)

        shutil.rmtree(self.fixture)
        shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
        binary_target = self.binary
        binary_link = self.root / "binary-link"
        os.symlink(binary_target, binary_link)
        self.binary = binary_link
        self.assert_refusal("input_symlink", self.build)

    def test_special_sparse_hardlinked_and_oversized_inputs_refuse(self) -> None:
        if hasattr(os, "mkfifo"):
            self.binary.unlink()
            os.mkfifo(self.binary)
            self.assert_refusal("input_special_file", self.build)

        self.binary.unlink()
        self.binary.write_bytes(self.BINARY_BYTES)
        hardlink = self.root / "binary-hardlink"
        os.link(self.binary, hardlink)
        self.assert_refusal("input_hardlinked", self.build)
        hardlink.unlink()

        with mock.patch.object(
            oracle, "_is_sparse", side_effect=lambda metadata: metadata.st_size == len(self.BINARY_BYTES)
        ):
            self.assert_refusal("input_sparse", self.build)

        with self.binary.open("wb") as binary:
            binary.truncate(oracle.MAX_BINARY_BYTES + 1)
        self.request["binary"]["sha256"] = "4" * 64
        self.assert_refusal("input_oversized", self.build)

    def test_change_during_read_refuses(self) -> None:
        real_fstat = oracle.os.fstat
        binary_inode = self.binary.stat().st_ino
        seen = 0

        def changing_fstat(descriptor: int):
            nonlocal seen
            result = real_fstat(descriptor)
            if result.st_ino == binary_inode:
                seen += 1
                if seen >= 2:
                    values = list(result)
                    values[8] = result.st_mtime + 1
                    return os.stat_result(values)
            return result

        with mock.patch.object(oracle.os, "fstat", side_effect=changing_fstat):
            self.assert_refusal("input_changed", self.build)

    def test_tuple_duplicate_keys_and_oversize_refuse(self) -> None:
        duplicate = b'{"schema":"one","schema":"two"}\n'
        self.tuple.write_bytes(duplicate)
        self.request["qualified_tuple"]["sha256"] = oracle.sha256_bytes(duplicate)
        self.assert_refusal("json_duplicate_key", self.build)

        oversized = b" " * (oracle.MAX_QUALIFIED_TUPLE_BYTES + 1)
        self.tuple.write_bytes(oversized)
        self.request["qualified_tuple"]["sha256"] = oracle.sha256_bytes(oversized)
        self.assert_refusal("input_oversized", self.build)

    def test_exclusive_output_refuses_overwrite_escape_symlink_and_source_mutation(self) -> None:
        evidence = self.build()
        output = self.root / "output"
        output.mkdir()
        oracle.write_exclusive(output, "evidence.json", evidence)
        self.assertEqual((output / "evidence.json").read_bytes(), evidence)
        self.assertEqual(stat_mode(output / "evidence.json"), 0o600)
        self.assert_refusal(
            "output_exists", oracle.write_exclusive, output, "evidence.json", evidence
        )
        self.assertEqual((output / "evidence.json").read_bytes(), evidence)
        self.assert_refusal(
            "path_escape", oracle.write_exclusive, output, "../evidence.json", evidence
        )

        symlink = output / "linked.json"
        os.symlink(output / "evidence.json", symlink)
        self.assert_refusal(
            "output_exists", oracle.write_exclusive, output, "linked.json", evidence
        )
        fixture = oracle.validate_fixture(self.fixture)
        self.assert_refusal(
            "source_mutation_forbidden",
            oracle.write_exclusive,
            self.fixture,
            "evidence.json",
            evidence,
            forbidden_directory_identities=(fixture.root_identity, fixture.tests_identity),
        )

    def test_validation_does_not_mutate_source_bytes(self) -> None:
        before = {
            path.relative_to(self.fixture).as_posix(): path.read_bytes()
            for path in self.fixture.rglob("*")
            if path.is_file()
        }
        before_binary = self.binary.read_bytes()
        before_tuple = self.tuple.read_bytes()
        self.build()
        after = {
            path.relative_to(self.fixture).as_posix(): path.read_bytes()
            for path in self.fixture.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)
        self.assertEqual(self.binary.read_bytes(), before_binary)
        self.assertEqual(self.tuple.read_bytes(), before_tuple)

    def test_cli_reads_only_inputs_and_refuses_a_second_write(self) -> None:
        request_path = self.root / "request.json"
        request_path.write_bytes(self.request_bytes())
        output = self.root / "cli-output"
        output.mkdir()
        arguments = [
            "--request",
            str(request_path),
            "--fixture-root",
            str(self.fixture),
            "--binary",
            str(self.binary),
            "--qualified-tuple",
            str(self.tuple),
            "--expected-source-git-sha",
            self.SOURCE_SHA,
            "--output-directory",
            str(output),
        ]
        self.assertEqual(oracle.main(arguments), 0)
        written = output / "snapshot-evidence.json"
        self.assertEqual(written.read_bytes(), self.build())
        with mock.patch.object(oracle.sys, "stderr"):
            self.assertEqual(oracle.main(arguments), 2)
        self.assertEqual(written.read_bytes(), self.build())


def stat_mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
