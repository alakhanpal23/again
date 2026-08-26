#!/usr/bin/env python3
"""Adversarial tests for the offline Gate 3 evidence verifier."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile

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
            "stdout": {
                "length": len(STDOUT),
                "sha256": hashlib.sha256(STDOUT).hexdigest(),
            },
            "stderr": {
                "length": len(STDERR),
                "sha256": hashlib.sha256(STDERR).hexdigest(),
            },
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


def replace_record(members: dict[str, bytes], record: dict[str, object]) -> None:
    record_raw = canonical(record)
    members[verifier.RECORD_MEMBER] = record_raw
    manifest_sha256 = hashlib.sha256(members[verifier.FIXTURE_MANIFEST_MEMBER]).hexdigest()
    members[verifier.REPORT_MEMBER] = canonical(
        report(record, hashlib.sha256(record_raw).hexdigest(), manifest_sha256)
    )


def write_zip(
    path: Path,
    members: dict[str, bytes],
    *,
    special: dict[str, int] | None = None,
    create_system: dict[str, int] | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
    duplicate: tuple[str, bytes] | None = None,
) -> None:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = create_system.get(name, 3) if create_system else 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = compression
            if special and name in special:
                info.external_attr = special[name] << 16
            archive.writestr(info, data)
        if duplicate is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(duplicate[0], duplicate[1])


def append_hidden_byte_to_last_member(path: Path) -> None:
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        last = max(infos, key=lambda info: info.header_offset)
        central_offset = archive.start_dir

    central_cursor = central_offset
    last_central_offset = None
    for info in infos:
        central = verifier.CENTRAL_DIRECTORY_HEADER.unpack_from(raw, central_cursor)
        name_size, extra_size, comment_size = central[10:13]
        if info.filename == last.filename:
            last_central_offset = central_cursor
        central_cursor += (
            verifier.CENTRAL_DIRECTORY_HEADER.size
            + name_size
            + extra_size
            + comment_size
        )
    if last_central_offset is None:
        raise AssertionError("last member must have a central header")

    local = list(verifier.LOCAL_FILE_HEADER.unpack_from(raw, last.header_offset))
    name_size, extra_size = local[9:11]
    data_end = (
        last.header_offset
        + verifier.LOCAL_FILE_HEADER.size
        + name_size
        + extra_size
        + last.compress_size
    )
    if data_end != central_offset:
        raise AssertionError("test ZIP must place the last payload before the central directory")
    raw[data_end:data_end] = b"X"
    local[7] += 1
    verifier.LOCAL_FILE_HEADER.pack_into(raw, last.header_offset, *local)

    shifted_central_offset = last_central_offset + 1
    central = list(verifier.CENTRAL_DIRECTORY_HEADER.unpack_from(raw, shifted_central_offset))
    central[8] += 1
    verifier.CENTRAL_DIRECTORY_HEADER.pack_into(raw, shifted_central_offset, *central)

    eocd_offset = len(raw) - verifier.END_OF_CENTRAL_DIRECTORY.size
    eocd = list(verifier.END_OF_CENTRAL_DIRECTORY.unpack_from(raw, eocd_offset))
    eocd[6] += 1
    verifier.END_OF_CENTRAL_DIRECTORY.pack_into(raw, eocd_offset, *eocd)
    path.write_bytes(raw)


def set_first_central_disk_start(path: Path, disk_start: int) -> None:
    raw = bytearray(path.read_bytes())
    with zipfile.ZipFile(path, "r") as archive:
        central_offset = archive.start_dir
    central = list(verifier.CENTRAL_DIRECTORY_HEADER.unpack_from(raw, central_offset))
    central[13] = disk_start
    verifier.CENTRAL_DIRECTORY_HEADER.pack_into(raw, central_offset, *central)
    path.write_bytes(raw)


def change_first_local_metadata(path: Path, field: int) -> None:
    raw = bytearray(path.read_bytes())
    local = list(verifier.LOCAL_FILE_HEADER.unpack_from(raw, 0))
    local[field] ^= 1
    verifier.LOCAL_FILE_HEADER.pack_into(raw, 0, *local)
    path.write_bytes(raw)


class ExecuteOnlyEvidenceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-gate3-verifier-")
        self.addCleanup(self.temporary.cleanup)
        self.archive = Path(self.temporary.name) / "evidence.zip"

    def verify(self, members: dict[str, bytes] | None = None) -> dict[str, object]:
        write_zip(self.archive, valid_members() if members is None else members)
        return self.verify_current_archive()

    def verify_current_archive(self) -> dict[str, object]:
        return verifier.verify_archive(
            self.archive,
            SOURCE_COMMIT,
            BINARY_SHA256,
            SOURCE_SHA256,
            TUPLE_REFERENCE,
            TUPLE_SHA256,
        )

    def assert_rejected(self, members: dict[str, bytes]) -> None:
        write_zip(self.archive, members)
        self.assert_current_archive_rejected()

    def assert_current_archive_rejected(self) -> None:
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(
                self.archive,
                SOURCE_COMMIT,
                BINARY_SHA256,
                SOURCE_SHA256,
                TUPLE_REFERENCE,
                TUPLE_SHA256,
            )

    def decoded_record(self, members: dict[str, bytes]) -> dict[str, object]:
        return json.loads(members[verifier.RECORD_MEMBER])

    def test_valid_archive_emits_deterministic_non_authoritative_audit(self) -> None:
        first = self.verify()
        second = verifier.verify_archive(
            self.archive,
            SOURCE_COMMIT,
            BINARY_SHA256,
            SOURCE_SHA256,
            TUPLE_REFERENCE,
            TUPLE_SHA256,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["member_count"], 5)
        self.assertEqual(first["source_commit"], SOURCE_COMMIT)
        self.assertEqual(len(first["archive_sha256"]), 64)
        self.assertEqual(len(first["member_manifest_sha256"]), 64)
        self.assertEqual(
            first["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest()
        )
        self.assertTrue(all(value == 0 for value in first["counts"].values()))
        self.assertTrue(all(value is False for value in first["authority"].values()))

    def test_cli_emits_exactly_one_canonical_audit_object(self) -> None:
        expected = self.verify()
        script = Path(__file__).with_name("verify_linux_pytest_execute_only_evidence.py")
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                str(self.archive),
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
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        self.assertEqual(json.loads(completed.stdout), expected)
        self.assertEqual(
            completed.stdout,
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        )

    def test_missing_extra_and_duplicate_members_are_rejected(self) -> None:
        for name in verifier.EXPECTED_MEMBERS:
            with self.subTest(missing=name):
                members = valid_members()
                del members[name]
                self.assert_rejected(members)
        members = valid_members()
        members["extra.json"] = b"{}\n"
        self.assert_rejected(members)
        members = valid_members()
        write_zip(
            self.archive,
            members,
            duplicate=(verifier.STDOUT_MEMBER, members[verifier.STDOUT_MEMBER]),
        )
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(
                self.archive,
                SOURCE_COMMIT,
                BINARY_SHA256,
                SOURCE_SHA256,
                TUPLE_REFERENCE,
                TUPLE_SHA256,
            )

    def test_absolute_traversal_and_noncanonical_names_are_rejected(self) -> None:
        for hostile in [
            "/stdout.raw",
            "../stdout.raw",
            "dir/../stdout.raw",
            "dir\\stdout.raw",
            "dir//stdout.raw",
            "C:/stdout.raw",
        ]:
            with self.subTest(hostile=hostile):
                members = valid_members()
                members[hostile] = members.pop(verifier.STDOUT_MEMBER)
                self.assert_rejected(members)

    def test_symlink_and_special_members_are_rejected(self) -> None:
        for mode in [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFDIR | 0o700]:
            with self.subTest(mode=mode):
                members = valid_members()
                write_zip(
                    self.archive,
                    members,
                    special={verifier.STDOUT_MEMBER: mode},
                )
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_archive(
                        self.archive,
                        SOURCE_COMMIT,
                        BINARY_SHA256,
                        SOURCE_SHA256,
                        TUPLE_REFERENCE,
                        TUPLE_SHA256,
                    )

    def test_oversized_and_high_ratio_compressed_members_are_rejected(self) -> None:
        members = valid_members()
        members[verifier.STDOUT_MEMBER] = b"A" * (verifier.MAX_STREAM_BYTES + 1)
        self.assert_rejected(members)
        members = valid_members()
        members[verifier.STDOUT_MEMBER] = b"A" * 100_000
        self.assert_rejected(members)

    def test_hidden_archive_prefix_and_trailer_are_rejected(self) -> None:
        for prefix, trailer in [(b"hidden-prefix", b""), (b"", b"hidden-trailer")]:
            with self.subTest(prefix=bool(prefix), trailer=bool(trailer)):
                write_zip(self.archive, valid_members())
                raw = self.archive.read_bytes()
                self.archive.write_bytes(prefix + raw + trailer)
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_archive(
                        self.archive,
                        SOURCE_COMMIT,
                        BINARY_SHA256,
                        SOURCE_SHA256,
                        TUPLE_REFERENCE,
                        TUPLE_SHA256,
                    )

    def test_hidden_bytes_inside_stored_and_deflated_members_are_rejected(self) -> None:
        for compression in [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED]:
            with self.subTest(compression=compression):
                write_zip(self.archive, valid_members(), compression=compression)
                self.verify_current_archive()
                append_hidden_byte_to_last_member(self.archive)
                self.assert_current_archive_rejected()

    def test_dos_origin_rejects_every_unix_file_type_encoding(self) -> None:
        for mode in [
            stat.S_IFREG | 0o600,
            stat.S_IFLNK | 0o777,
            stat.S_IFIFO | 0o600,
            stat.S_IFDIR | 0o700,
        ]:
            with self.subTest(mode=mode):
                write_zip(
                    self.archive,
                    valid_members(),
                    special={verifier.STDOUT_MEMBER: mode},
                    create_system={verifier.STDOUT_MEMBER: 0},
                )
                self.assert_current_archive_rejected()

        write_zip(
            self.archive,
            valid_members(),
            special={verifier.STDOUT_MEMBER: 0o600},
            create_system={verifier.STDOUT_MEMBER: 0},
        )
        self.verify_current_archive()

    def test_nonzero_central_member_disk_start_is_rejected(self) -> None:
        write_zip(self.archive, valid_members())
        set_first_central_disk_start(self.archive, 1)
        self.assert_current_archive_rejected()

    def test_local_version_time_and_date_must_match_central_metadata(self) -> None:
        for field in [1, 4, 5]:
            with self.subTest(field=field):
                write_zip(self.archive, valid_members())
                change_first_local_metadata(self.archive, field)
                self.assert_current_archive_rejected()

    def test_malformed_duplicate_key_trailing_and_non_object_json_are_rejected(self) -> None:
        for name in [
            verifier.RECORD_MEMBER,
            verifier.REPORT_MEMBER,
            verifier.FIXTURE_MANIFEST_MEMBER,
        ]:
            for mutation in [
                b"{not-json}\n",
                b'{"schema":1,"schema":2}\n',
                b"{}\n{}\n",
                b"[]\n",
                b'{"value":NaN}\n',
            ]:
                with self.subTest(name=name, mutation=mutation[:16]):
                    members = valid_members()
                    members[name] = mutation
                    self.assert_rejected(members)

    def test_exact_argv_and_selector_are_required(self) -> None:
        for index in range(len(verifier.EXACT_ARGV)):
            with self.subTest(index=index):
                members = valid_members()
                record = self.decoded_record(members)
                record["argv"][index] += "-changed"
                replace_record(members, record)
                self.assert_rejected(members)
        members = valid_members()
        record = self.decoded_record(members)
        record["argv"].append("-q")
        replace_record(members, record)
        self.assert_rejected(members)
        members = valid_members()
        record = self.decoded_record(members)
        record["selector"] = "tests/test_other.py::test_other"
        replace_record(members, record)
        self.assert_rejected(members)

    def test_all_trusted_and_member_hashes_are_bound(self) -> None:
        for field in verifier.HASH_KEYS:
            with self.subTest(field=field):
                members = valid_members()
                record = self.decoded_record(members)
                record["hashes"][field] = "f" * 64
                replace_record(members, record)
                self.assert_rejected(members)
        members = valid_members()
        record = self.decoded_record(members)
        record["qualified_tuple_evidence"]["sha256"] = "e" * 64
        replace_record(members, record)
        self.assert_rejected(members)

    def test_fixture_manifest_path_bytes_length_hash_and_shape_are_frozen(self) -> None:
        changes = [
            ("path", "tests/other.py"),
            ("bytes_base64", base64.b64encode(b"changed").decode()),
            ("length", 95),
            ("sha256", "f" * 64),
            ("extra", False),
        ]
        for field, value in changes:
            with self.subTest(field=field):
                members = valid_members()
                manifest = json.loads(members[verifier.FIXTURE_MANIFEST_MEMBER])
                manifest["files"][0][field] = value
                members[verifier.FIXTURE_MANIFEST_MEMBER] = canonical(manifest)
                self.assert_rejected(members)

    def test_stream_member_capture_and_delivery_mismatches_are_rejected(self) -> None:
        members = valid_members()
        members[verifier.STDOUT_MEMBER] += b"drift"
        self.assert_rejected(members)
        for stream in ("stdout", "stderr"):
            for field, value in [
                ("captured_length", 99),
                ("delivered_length", 99),
                ("captured_sha256", "f" * 64),
                ("delivered_sha256", "f" * 64),
            ]:
                with self.subTest(stream=stream, field=field):
                    members = valid_members()
                    record = self.decoded_record(members)
                    record["streams"][stream][field] = value
                    replace_record(members, record)
                    self.assert_rejected(members)

    def test_nonzero_or_noninteger_wait_status_is_rejected(self) -> None:
        for wait_status in [1, 256, -1, True, "0"]:
            with self.subTest(wait_status=wait_status):
                members = valid_members()
                record = self.decoded_record(members)
                record["raw_final_wait_status"] = wait_status
                replace_record(members, record)
                self.assert_rejected(members)

    def test_workspace_drift_is_rejected(self) -> None:
        mutations = [
            ("unchanged", False),
            ("after_sha256", "f" * 64),
            ("before_sha256", "not-a-hash"),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                members = valid_members()
                record = self.decoded_record(members)
                record["host_manifest"][field] = value
                replace_record(members, record)
                self.assert_rejected(members)

    def test_every_cleanup_canary_terminal_reap_and_final_echild_are_required(self) -> None:
        for canary in verifier.CLEANUP_KEYS:
            with self.subTest(canary=canary):
                members = valid_members()
                record = self.decoded_record(members)
                record["cleanup_canaries"][canary] = False
                replace_record(members, record)
                self.assert_rejected(members)
        members = valid_members()
        record = self.decoded_record(members)
        record["descendant_reap"]["all_descendants_terminally_reaped"] = False
        replace_record(members, record)
        self.assert_rejected(members)
        members = valid_members()
        record = self.decoded_record(members)
        record["descendant_reap"]["final_wait_error"] = "ESRCH"
        replace_record(members, record)
        self.assert_rejected(members)

    def test_candidate_shadow_promotion_replay_and_hit_counts_must_be_zero(self) -> None:
        for count in verifier.COUNT_KEYS:
            for value in [1, -1, True]:
                with self.subTest(count=count, value=value):
                    members = valid_members()
                    record = self.decoded_record(members)
                    record["counts"][count] = value
                    replace_record(members, record)
                    self.assert_rejected(members)

    def test_every_authority_claim_is_rejected(self) -> None:
        for claim in verifier.AUTHORITY_KEYS:
            for value in [True, 0, "false"]:
                with self.subTest(claim=claim, value=value):
                    members = valid_members()
                    record = self.decoded_record(members)
                    record["authority_claims"][claim] = value
                    replace_record(members, record)
                    self.assert_rejected(members)

    def test_outcome_reason_and_every_object_shape_are_closed(self) -> None:
        for field, value in [
            ("outcome", "candidate"),
            ("execute_only_reason", "other_reason"),
            ("schema", "again.linux-pytest.execute-only-execution-record.v2"),
        ]:
            with self.subTest(field=field):
                members = valid_members()
                record = self.decoded_record(members)
                record[field] = value
                replace_record(members, record)
                self.assert_rejected(members)
        for path in [
            (),
            ("hashes",),
            ("qualified_tuple_evidence",),
            ("streams",),
            ("streams", "stdout"),
            ("host_manifest",),
            ("cleanup_canaries",),
            ("descendant_reap",),
            ("counts",),
            ("authority_claims",),
        ]:
            with self.subTest(path=path):
                members = valid_members()
                record = self.decoded_record(members)
                target = record
                for component in path:
                    target = target[component]
                target["unknown"] = False
                replace_record(members, record)
                self.assert_rejected(members)

    def test_report_divergence_and_open_report_shape_are_rejected(self) -> None:
        for field, value in [
            ("source_commit", "f" * 40),
            ("execution_record_sha256", "f" * 64),
            ("outcome", "candidate"),
            ("raw_final_wait_status", True),
            ("extra", False),
        ]:
            with self.subTest(field=field):
                members = valid_members()
                changed = json.loads(members[verifier.REPORT_MEMBER])
                changed[field] = value
                members[verifier.REPORT_MEMBER] = canonical(changed)
                self.assert_rejected(members)
        members = valid_members()
        changed = json.loads(members[verifier.REPORT_MEMBER])
        changed["authority_claims"]["hit_authority_claimed"] = True
        members[verifier.REPORT_MEMBER] = canonical(changed)
        self.assert_rejected(members)

    def test_expected_metadata_must_be_exact_and_match(self) -> None:
        self.verify()
        cases = [
            ("A" * 40, BINARY_SHA256, SOURCE_SHA256, TUPLE_REFERENCE, TUPLE_SHA256),
            (SOURCE_COMMIT, "f" * 63, SOURCE_SHA256, TUPLE_REFERENCE, TUPLE_SHA256),
            (SOURCE_COMMIT, BINARY_SHA256, "f" * 64, TUPLE_REFERENCE, TUPLE_SHA256),
            (SOURCE_COMMIT, BINARY_SHA256, SOURCE_SHA256, "../tuple", TUPLE_SHA256),
            (SOURCE_COMMIT, BINARY_SHA256, SOURCE_SHA256, TUPLE_REFERENCE, "f" * 64),
        ]
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_archive(self.archive, *arguments)

    def test_archive_symlink_non_zip_and_oversized_file_are_rejected(self) -> None:
        target = Path(self.temporary.name) / "target.zip"
        write_zip(target, valid_members())
        symlink = Path(self.temporary.name) / "link.zip"
        symlink.symlink_to(target)
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(
                symlink,
                SOURCE_COMMIT,
                BINARY_SHA256,
                SOURCE_SHA256,
                TUPLE_REFERENCE,
                TUPLE_SHA256,
            )
        self.archive.write_bytes(b"not a zip")
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(
                self.archive,
                SOURCE_COMMIT,
                BINARY_SHA256,
                SOURCE_SHA256,
                TUPLE_REFERENCE,
                TUPLE_SHA256,
            )
        self.archive.write_bytes(b"x" * (verifier.MAX_ARCHIVE_BYTES + 1))
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(
                self.archive,
                SOURCE_COMMIT,
                BINARY_SHA256,
                SOURCE_SHA256,
                TUPLE_REFERENCE,
                TUPLE_SHA256,
            )


if __name__ == "__main__":
    unittest.main()
