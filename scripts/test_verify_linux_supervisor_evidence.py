#!/usr/bin/env python3
"""Adversarial tests for the offline Gate 2 evidence verifier."""

from __future__ import annotations

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

from scripts import verify_linux_supervisor_evidence as verifier


SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"


def compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def probe(order: str) -> dict[str, object]:
    return {
        "schema": "again.linux-pytest-supervisor-tree-probe.v1",
        "profile_id": "linux-pytest-v1",
        "scope": {
            "kind": "fixed_no_command_two_task_supervisor",
            "profile_qualification": False,
            "accepts_command": False,
            "effect_ir_authority": False,
            "execution_authority": False,
            "reuse_authority": False,
        },
        "status": "completed",
        "result": {
            "fork_delivery_order": order,
            "task_count": 2,
            "accepted_transition_count": 11,
            "fork_birth_count": 1,
            "seccomp_entry_count": 3,
            "syscall_exit_count": 1,
            "no_return_resolution_count": 2,
            "ptrace_exit_event_count": 2,
            "terminal_reap_count": 2,
            "cleanup_complete": True,
        },
        "refusal": None,
    }


def report(orders: list[str] | None = None) -> dict[str, object]:
    return {
        "schema": "again.linux-pytest-supervisor-qualification.v1",
        "validated_sample_count": 100,
        "source_commit": SOURCE_SHA,
        "platform": {
            "os": "linux",
            "architecture": "x86_64",
            "kernel_release": "6.17.0-test",
        },
        "first_iteration": 1,
        "last_iteration": 100,
        "fork_delivery_orders": orders
        if orders is not None
        else ["child_stop_first", "parent_event_first"],
        "scope": {
            "kind": "fixed_no_command_two_task_supervisor_qualification",
            "profile_qualification": False,
            "accepts_command": False,
            "effect_ir_authority": False,
            "execution_authority": False,
            "reuse_authority": False,
        },
    }


def valid_members() -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    validated = []
    for iteration in range(1, 101):
        order = "child_stop_first" if iteration % 2 else "parent_event_first"
        raw = probe(order)
        prefix = f"sample-{iteration:03d}"
        members[f"{prefix}/stdout.raw"] = compact(raw)
        members[f"{prefix}/stderr.raw"] = b""
        members[f"{prefix}/exit-status.txt"] = b"0\n"
        record = copy.deepcopy(raw)
        record["iteration"] = iteration
        validated.append(compact(record))
    members["validated.jsonl"] = b"".join(validated)
    members["report.json"] = compact(report())
    return members


def write_zip(
    path: Path,
    members: dict[str, bytes],
    *,
    special: dict[str, int] | None = None,
    duplicate: tuple[str, bytes] | None = None,
) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            if special and name in special:
                info.external_attr = special[name] << 16
            archive.writestr(info, data)
        if duplicate is not None:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(duplicate[0], duplicate[1])


class EvidenceVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.archive = Path(self.temporary.name) / "evidence.zip"

    def verify(self, members: dict[str, bytes] | None = None) -> dict[str, object]:
        write_zip(self.archive, valid_members() if members is None else members)
        return verifier.verify_archive(self.archive, SOURCE_SHA)

    def assert_rejected(self, members: dict[str, bytes]) -> None:
        write_zip(self.archive, members)
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(self.archive, SOURCE_SHA)

    def test_valid_archive_emits_deterministic_content_bound_audit(self) -> None:
        first = self.verify()
        second = verifier.verify_archive(self.archive, SOURCE_SHA)
        self.assertEqual(first, second)
        self.assertEqual(first["member_count"], 302)
        self.assertEqual(first["validated_sample_count"], 100)
        self.assertEqual(first["source_commit"], SOURCE_SHA)
        self.assertEqual(len(first["archive_sha256"]), 64)
        self.assertEqual(len(first["member_manifest_sha256"]), 64)
        self.assertEqual(
            first["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest()
        )

    def test_cli_emits_one_canonical_audit_object(self) -> None:
        self.verify()
        script = Path(__file__).with_name("verify_linux_supervisor_evidence.py")
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(script),
                str(self.archive),
                "--expected-source-sha",
                SOURCE_SHA,
            ],
            check=False,
            capture_output=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b"")
        parsed = json.loads(completed.stdout)
        self.assertEqual(parsed["member_count"], 302)
        self.assertEqual(
            completed.stdout,
            json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode() + b"\n",
        )

    def test_missing_and_extra_samples_are_rejected(self) -> None:
        members = valid_members()
        del members["sample-100/stdout.raw"]
        self.assert_rejected(members)
        members = valid_members()
        members["sample-101/stdout.raw"] = compact(probe("child_stop_first"))
        self.assert_rejected(members)

    def test_missing_and_extra_non_sample_members_are_rejected(self) -> None:
        members = valid_members()
        del members["report.json"]
        self.assert_rejected(members)
        members = valid_members()
        members["notes.txt"] = b"unreviewed"
        self.assert_rejected(members)

    def test_duplicate_member_is_rejected(self) -> None:
        members = valid_members()
        write_zip(
            self.archive,
            members,
            duplicate=("sample-001/stdout.raw", members["sample-001/stdout.raw"]),
        )
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(self.archive, SOURCE_SHA)

    def test_absolute_traversal_and_noncanonical_paths_are_rejected(self) -> None:
        for hostile in [
            "/sample-001/stdout.raw",
            "../sample-001/stdout.raw",
            "sample-001/../stdout.raw",
            "sample-001\\stdout.raw",
            "sample-001//stdout.raw",
            "C:/sample-001/stdout.raw",
        ]:
            with self.subTest(hostile=hostile):
                members = valid_members()
                del members["sample-001/stdout.raw"]
                members[hostile] = compact(probe("child_stop_first"))
                self.assert_rejected(members)

    def test_symlink_and_special_entries_are_rejected(self) -> None:
        for mode in [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFDIR | 0o700]:
            with self.subTest(mode=mode):
                members = valid_members()
                name = "sample-001/stdout.raw"
                write_zip(self.archive, members, special={name: mode})
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_archive(self.archive, SOURCE_SHA)

    def test_oversized_compressed_member_is_rejected_before_read(self) -> None:
        members = valid_members()
        members["sample-001/stdout.raw"] = b"A" * (verifier.MAX_STDOUT_BYTES + 1)
        self.assert_rejected(members)

    def test_compressed_bomb_ratio_is_rejected_before_read(self) -> None:
        members = valid_members()
        members["validated.jsonl"] = b"A" * 100_000
        self.assert_rejected(members)

    def test_nonzero_exit_and_stderr_bytes_are_rejected(self) -> None:
        members = valid_members()
        members["sample-017/exit-status.txt"] = b"1\n"
        self.assert_rejected(members)
        members = valid_members()
        members["sample-017/stderr.raw"] = b"warning\n"
        self.assert_rejected(members)

    def test_authority_escalation_and_counter_changes_are_rejected(self) -> None:
        for field in verifier.PROBE_SCOPE_KEYS - {"kind"}:
            with self.subTest(field=field):
                members = valid_members()
                raw = probe("child_stop_first")
                raw["scope"][field] = True
                members["sample-001/stdout.raw"] = compact(raw)
                self.assert_rejected(members)
        members = valid_members()
        raw = probe("child_stop_first")
        raw["result"]["task_count"] = 3
        members["sample-001/stdout.raw"] = compact(raw)
        self.assert_rejected(members)
        members = valid_members()
        raw = probe("child_stop_first")
        raw["result"]["cleanup_complete"] = False
        members["sample-001/stdout.raw"] = compact(raw)
        self.assert_rejected(members)

    def test_malformed_duplicate_key_and_trailing_json_are_rejected(self) -> None:
        mutations = [
            b"{not-json}\n",
            b'{"schema":1,"schema":2}\n',
            compact(probe("child_stop_first")) + b"{}\n",
            b"[]\n",
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation[:20]):
                members = valid_members()
                members["sample-001/stdout.raw"] = mutation
                self.assert_rejected(members)

    def test_validated_record_must_equal_raw_plus_only_iteration(self) -> None:
        for field, value in [("iteration", 2), ("extra", False)]:
            with self.subTest(field=field):
                members = valid_members()
                lines = members["validated.jsonl"].splitlines()
                changed = json.loads(lines[0])
                changed[field] = value
                lines[0] = compact(changed).rstrip(b"\n")
                members["validated.jsonl"] = b"\n".join(lines) + b"\n"
                self.assert_rejected(members)

    def test_missing_duplicate_and_out_of_range_iterations_are_rejected(self) -> None:
        for iteration in [0, 2, 101, True]:
            with self.subTest(iteration=iteration):
                members = valid_members()
                lines = members["validated.jsonl"].splitlines()
                changed = json.loads(lines[0])
                changed["iteration"] = iteration
                lines[0] = compact(changed).rstrip(b"\n")
                members["validated.jsonl"] = b"\n".join(lines) + b"\n"
                self.assert_rejected(members)

    def test_one_delivery_order_is_rejected(self) -> None:
        members = valid_members()
        validated = []
        for iteration in range(1, 101):
            raw = probe("child_stop_first")
            members[f"sample-{iteration:03d}/stdout.raw"] = compact(raw)
            raw["iteration"] = iteration
            validated.append(compact(raw))
        members["validated.jsonl"] = b"".join(validated)
        members["report.json"] = compact(report(["child_stop_first"]))
        self.assert_rejected(members)

    def test_report_raw_divergence_and_open_report_schema_are_rejected(self) -> None:
        mutations = [
            ("validated_sample_count", 99),
            ("source_commit", "f" * 40),
            ("extra", False),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                members = valid_members()
                changed = report()
                changed[field] = value
                members["report.json"] = compact(changed)
                self.assert_rejected(members)

    def test_report_authority_escalation_is_rejected(self) -> None:
        members = valid_members()
        changed = report()
        changed["scope"]["reuse_authority"] = True
        members["report.json"] = compact(changed)
        self.assert_rejected(members)

    def test_expected_source_sha_is_exact_and_must_match(self) -> None:
        self.verify()
        for source_sha in ["A" * 40, "0" * 39, "g" * 40, "f" * 40]:
            with self.subTest(source_sha=source_sha):
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_archive(self.archive, source_sha)

    def test_malformed_aggregate_json_is_rejected(self) -> None:
        for name in ["validated.jsonl", "report.json"]:
            with self.subTest(name=name):
                members = valid_members()
                members[name] = b'{"x":1,"x":2}\n'
                self.assert_rejected(members)

    def test_archive_symlink_and_non_zip_are_rejected(self) -> None:
        target = Path(self.temporary.name) / "target.zip"
        write_zip(target, valid_members())
        symlink = Path(self.temporary.name) / "link.zip"
        symlink.symlink_to(target)
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(symlink, SOURCE_SHA)
        self.archive.write_bytes(b"not a zip")
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_archive(self.archive, SOURCE_SHA)


if __name__ == "__main__":
    unittest.main()
