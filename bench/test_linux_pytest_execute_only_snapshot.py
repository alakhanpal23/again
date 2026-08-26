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
            caller_reported_source_git_sha=self.SOURCE_SHA,
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
            evidence["bindings"]["binary_input"]["sha256"],
            oracle.sha256_bytes(self.BINARY_BYTES),
        )
        self.assertEqual(
            evidence["bindings"]["source_input"]["caller_reported_git_sha"],
            self.SOURCE_SHA,
        )
        self.assertEqual(
            evidence["bindings"]["qualified_tuple_input"]["sha256"],
            oracle.sha256_bytes(self.tuple_bytes),
        )
        self.assertEqual(
            evidence["bindings"]["argv_binary_relation"],
            oracle.ARGV_BINARY_RELATION_UNVERIFIED,
        )
        for field in ("binary_input", "source_input", "qualified_tuple_input"):
            self.assertEqual(
                evidence["bindings"][field]["provenance"],
                oracle.CALLER_SUPPLIED_UNVERIFIED,
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

        deeply_nested = (b"[" * (oracle.MAX_JSON_DEPTH + 1000)) + (
            b"]" * (oracle.MAX_JSON_DEPTH + 1000)
        )
        self.assert_refusal(
            "json_depth_oversized",
            oracle.decode_strict_json,
            deeply_nested,
            malformed_code="request_json_malformed",
        )
        too_many_nodes = oracle.canonical_json_bytes([0] * (oracle.MAX_JSON_NODES + 1))
        self.assert_refusal(
            "json_nodes_oversized",
            oracle.decode_strict_json,
            too_many_nodes,
            malformed_code="request_json_malformed",
        )

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
        binary["binary"]["content_sha256"] = "1" * 64
        self.assert_refusal("binary_sha256_mismatch", self.build, self.request_bytes(binary))
        source = copy.deepcopy(self.request)
        source["source"]["caller_reported_git_sha"] = "not-a-git-sha"
        self.assert_refusal("source_git_sha_malformed", self.build, self.request_bytes(source))
        qualified = copy.deepcopy(self.request)
        qualified["qualified_tuple"]["content_sha256"] = "3" * 64
        self.assert_refusal(
            "qualified_tuple_sha256_mismatch", self.build, self.request_bytes(qualified)
        )

    def test_caller_inputs_never_claim_fixed_logical_or_git_provenance(self) -> None:
        changed = copy.deepcopy(self.request)
        changed["source"]["caller_reported_git_sha"] = "2" * 40
        evidence = json.loads(self.build(self.request_bytes(changed)))
        bindings = evidence["bindings"]
        self.assertNotIn("path", bindings["binary_input"])
        self.assertEqual(
            bindings["argv_binary_relation"], oracle.ARGV_BINARY_RELATION_UNVERIFIED
        )
        self.assertEqual(
            bindings["source_input"],
            {
                "caller_reported_git_sha": "2" * 40,
                "provenance": oracle.CALLER_SUPPLIED_UNVERIFIED,
            },
        )
        self.assertEqual(
            bindings["qualified_tuple_input"]["caller_reported_reference"],
            oracle.QUALIFIED_TUPLE_REFERENCE,
        )
        self.assertEqual(
            bindings["qualified_tuple_input"]["provenance"],
            oracle.CALLER_SUPPLIED_UNVERIFIED,
        )

    def test_path_escapes_and_type_loose_values_refuse(self) -> None:
        changed = copy.deepcopy(self.request)
        changed["qualified_tuple"][
            "caller_reported_reference"
        ] = "qualified-tuples/../tuple.json"
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
            self.request["qualified_tuple"]["content_sha256"] = oracle.sha256_bytes(
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
            oracle,
            "_is_sparse",
            side_effect=lambda metadata: metadata.st_size == len(self.BINARY_BYTES),
        ):
            self.assert_refusal("input_sparse", self.build)

        with self.binary.open("wb") as binary:
            binary.truncate(oracle.MAX_BINARY_BYTES + 1)
        self.request["binary"]["content_sha256"] = "4" * 64
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
        self.request["qualified_tuple"]["content_sha256"] = oracle.sha256_bytes(duplicate)
        self.assert_refusal("json_duplicate_key", self.build)

        oversized = b" " * (oracle.MAX_QUALIFIED_TUPLE_BYTES + 1)
        self.tuple.write_bytes(oversized)
        self.request["qualified_tuple"]["content_sha256"] = oracle.sha256_bytes(oversized)
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

    def test_output_name_replacement_refuses_without_deleting_replacement(self) -> None:
        output = self.root / "output-race"
        output.mkdir()
        moved = output / "moved.json"
        replacement = b"attacker replacement"
        real_fsync = oracle.os.fsync
        replaced = False

        def replace_after_file_fsync(descriptor: int) -> None:
            nonlocal replaced
            real_fsync(descriptor)
            if not replaced:
                replaced = True
                (output / "evidence.json").rename(moved)
                (output / "evidence.json").write_bytes(replacement)

        with mock.patch.object(oracle.os, "fsync", side_effect=replace_after_file_fsync):
            self.assert_refusal(
                "output_changed",
                oracle.write_exclusive,
                output,
                "evidence.json",
                b"trusted",
            )
        self.assertEqual((output / "evidence.json").read_bytes(), replacement)
        self.assertEqual(moved.read_bytes(), b"trusted")

    def test_output_failure_cleanup_is_identity_checked_and_typed(self) -> None:
        output = self.root / "output-failure-race"
        output.mkdir()
        moved = output / "moved.json"
        replacement = b"replacement survives"
        real_fsync = oracle.os.fsync

        def replace_then_fail(descriptor: int) -> None:
            real_fsync(descriptor)
            (output / "evidence.json").rename(moved)
            (output / "evidence.json").write_bytes(replacement)
            raise OSError("injected file fsync failure")

        with mock.patch.object(oracle.os, "fsync", side_effect=replace_then_fail):
            self.assert_refusal(
                "output_fsync_failed",
                oracle.write_exclusive,
                output,
                "evidence.json",
                b"trusted",
            )
        self.assertEqual((output / "evidence.json").read_bytes(), replacement)
        self.assertEqual(moved.read_bytes(), b"trusted")

        clean_output = self.root / "output-write-failure"
        clean_output.mkdir()
        with mock.patch.object(oracle.os, "write", side_effect=OSError("injected write")):
            self.assert_refusal(
                "output_write_failed",
                oracle.write_exclusive,
                clean_output,
                "evidence.json",
                b"trusted",
            )
        self.assertFalse((clean_output / "evidence.json").exists())

    def test_output_directory_fsync_failure_is_typed_and_removes_only_owned_name(self) -> None:
        output = self.root / "output-directory-fsync"
        output.mkdir()
        real_fsync = oracle.os.fsync
        calls = 0

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                real_fsync(descriptor)
                return
            raise OSError("injected directory fsync failure")

        with mock.patch.object(oracle.os, "fsync", side_effect=fail_directory_fsync):
            self.assert_refusal(
                "output_directory_fsync_failed",
                oracle.write_exclusive,
                output,
                "evidence.json",
                b"trusted",
            )
        self.assertEqual(calls, 2)
        self.assertFalse((output / "evidence.json").exists())

    def test_output_directory_path_replacement_refuses_and_cleans_pinned_directory(self) -> None:
        output = self.root / "output-directory-race"
        moved = self.root / "moved-output-directory"
        output.mkdir()
        real_fsync = oracle.os.fsync
        calls = 0

        def replace_directory_after_its_fsync(descriptor: int) -> None:
            nonlocal calls
            calls += 1
            real_fsync(descriptor)
            if calls == 2:
                output.rename(moved)
                output.mkdir()

        with mock.patch.object(
            oracle.os, "fsync", side_effect=replace_directory_after_its_fsync
        ):
            self.assert_refusal(
                "output_directory_changed",
                oracle.write_exclusive,
                output,
                "evidence.json",
                b"trusted",
            )
        self.assertFalse((output / "evidence.json").exists())
        self.assertFalse((moved / "evidence.json").exists())

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
            "--output-directory",
            str(output),
        ]
        self.assertEqual(oracle.main(arguments), 0)
        written = output / "snapshot-evidence.json"
        self.assertEqual(written.read_bytes(), self.build())
        with mock.patch.object(oracle.sys, "stderr"):
            self.assertEqual(oracle.main(arguments), 2)
        self.assertEqual(written.read_bytes(), self.build())

    def test_cli_refuses_output_in_any_input_parent(self) -> None:
        request_path = self.root / "request-parent.json"
        request_path.write_bytes(self.request_bytes())
        arguments = [
            "--request",
            str(request_path),
            "--fixture-root",
            str(self.fixture),
            "--binary",
            str(self.binary),
            "--qualified-tuple",
            str(self.tuple),
            "--output-directory",
            str(self.root),
            "--output-name",
            "must-not-exist.json",
        ]
        with mock.patch.object(oracle.sys, "stderr"):
            self.assertEqual(oracle.main(arguments), 2)
        self.assertFalse((self.root / "must-not-exist.json").exists())

    def test_fixture_replacement_cannot_turn_fixture_path_into_output(self) -> None:
        request_path = self.root / "request-race.json"
        request_path.write_bytes(self.request_bytes())
        old_fixture = self.root / "old-fixture"
        real_build = oracle._build_snapshot_evidence

        def replace_after_observation(*args, **kwargs):
            built = real_build(*args, **kwargs)
            self.fixture.rename(old_fixture)
            shutil.copytree(oracle.DEFAULT_FIXTURE_ROOT, self.fixture)
            return built

        arguments = [
            "--request",
            str(request_path),
            "--fixture-root",
            str(self.fixture),
            "--binary",
            str(self.binary),
            "--qualified-tuple",
            str(self.tuple),
            "--output-directory",
            str(self.fixture),
            "--output-name",
            "must-not-exist.json",
        ]
        with mock.patch.object(
            oracle, "_build_snapshot_evidence", side_effect=replace_after_observation
        ), mock.patch.object(oracle.sys, "stderr"):
            self.assertEqual(oracle.main(arguments), 2)
        self.assertFalse((self.fixture / "must-not-exist.json").exists())

    def test_input_parent_replacement_cannot_turn_its_path_into_output(self) -> None:
        request_parent = self.root / "request-parent-race"
        old_request_parent = self.root / "old-request-parent"
        request_parent.mkdir()
        request_path = request_parent / "request.json"
        request_path.write_bytes(self.request_bytes())
        real_build = oracle._build_snapshot_evidence

        def replace_after_observation(*args, **kwargs):
            built = real_build(*args, **kwargs)
            request_parent.rename(old_request_parent)
            request_parent.mkdir()
            return built

        arguments = [
            "--request",
            str(request_path),
            "--fixture-root",
            str(self.fixture),
            "--binary",
            str(self.binary),
            "--qualified-tuple",
            str(self.tuple),
            "--output-directory",
            str(request_parent),
            "--output-name",
            "must-not-exist.json",
        ]
        with mock.patch.object(
            oracle, "_build_snapshot_evidence", side_effect=replace_after_observation
        ), mock.patch.object(oracle.sys, "stderr"):
            self.assertEqual(oracle.main(arguments), 2)
        self.assertFalse((request_parent / "must-not-exist.json").exists())


def stat_mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
