#!/usr/bin/env python3
"""Offline verifier for a Gate 2 Linux supervisor evidence artifact ZIP.

The archive is inspected in place and is never extracted.  The canonical
member manifest is the compact, key-sorted JSON encoding of a list ordered by
member name, where every item contains the member's name, uncompressed byte
size, and SHA-256 digest.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile


SAMPLE_COUNT = 100
EXPECTED_MEMBER_COUNT = SAMPLE_COUNT * 3 + 2
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_STDOUT_BYTES = 8 * 1024
MAX_VALIDATED_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

SOURCE_SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
KERNEL_RELEASE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,254}\Z")

PROBE_KEYS = {"profile_id", "refusal", "result", "schema", "scope", "status"}
PROBE_SCOPE_KEYS = {
    "accepts_command",
    "effect_ir_authority",
    "execution_authority",
    "kind",
    "profile_qualification",
    "reuse_authority",
}
PROBE_RESULT_KEYS = {
    "accepted_transition_count",
    "cleanup_complete",
    "fork_birth_count",
    "fork_delivery_order",
    "no_return_resolution_count",
    "ptrace_exit_event_count",
    "seccomp_entry_count",
    "syscall_exit_count",
    "task_count",
    "terminal_reap_count",
}
REPORT_KEYS = {
    "first_iteration",
    "fork_delivery_orders",
    "last_iteration",
    "platform",
    "schema",
    "scope",
    "source_commit",
    "validated_sample_count",
}
REPORT_PLATFORM_KEYS = {"architecture", "kernel_release", "os"}
REPORT_SCOPE_KEYS = PROBE_SCOPE_KEYS
DELIVERY_ORDERS = {"child_stop_first", "parent_event_first"}


class EvidenceError(ValueError):
    """The artifact does not satisfy the closed Gate 2 evidence contract."""


def _reject_duplicate_key(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise EvidenceError(f"non-finite JSON number: {value}")


def _strict_json(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"{label}: JSON is not UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"{label}: malformed JSON: {error}") from error
    if type(value) is not dict:
        raise EvidenceError(f"{label}: JSON value must be one object")
    return value


def _require_exact_keys(value: dict[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise EvidenceError(f"{label}: object keys do not match the closed schema")


def _require_exact_int(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise EvidenceError(f"{label}: expected integer {expected}")


def _require_false(value: object, label: str) -> None:
    if value is not False:
        raise EvidenceError(f"{label}: authority field must be false")


def _validate_probe(record: dict[str, object], label: str) -> None:
    _require_exact_keys(record, PROBE_KEYS, label)
    if record["schema"] != "again.linux-pytest-supervisor-tree-probe.v1":
        raise EvidenceError(f"{label}: wrong probe schema")
    if record["profile_id"] != "linux-pytest-v1":
        raise EvidenceError(f"{label}: wrong profile id")
    if record["status"] != "completed" or record["refusal"] is not None:
        raise EvidenceError(f"{label}: probe did not complete without refusal")

    scope = record["scope"]
    if type(scope) is not dict:
        raise EvidenceError(f"{label}: scope must be an object")
    _require_exact_keys(scope, PROBE_SCOPE_KEYS, f"{label}.scope")
    if scope["kind"] != "fixed_no_command_two_task_supervisor":
        raise EvidenceError(f"{label}: wrong scope kind")
    for field in PROBE_SCOPE_KEYS - {"kind"}:
        _require_false(scope[field], f"{label}.scope.{field}")

    result = record["result"]
    if type(result) is not dict:
        raise EvidenceError(f"{label}: result must be an object")
    _require_exact_keys(result, PROBE_RESULT_KEYS, f"{label}.result")
    expected_counters = {
        "task_count": 2,
        "accepted_transition_count": 11,
        "fork_birth_count": 1,
        "seccomp_entry_count": 3,
        "syscall_exit_count": 1,
        "no_return_resolution_count": 2,
        "ptrace_exit_event_count": 2,
        "terminal_reap_count": 2,
    }
    for field, expected in expected_counters.items():
        _require_exact_int(result[field], expected, f"{label}.result.{field}")
    if result["cleanup_complete"] is not True:
        raise EvidenceError(f"{label}: cleanup_complete must be true")
    if result["fork_delivery_order"] not in DELIVERY_ORDERS:
        raise EvidenceError(f"{label}: unknown fork delivery order")


def _expected_member_names() -> set[str]:
    names = {"validated.jsonl", "report.json"}
    for iteration in range(1, SAMPLE_COUNT + 1):
        prefix = f"sample-{iteration:03d}"
        names.update(
            {
                f"{prefix}/stdout.raw",
                f"{prefix}/stderr.raw",
                f"{prefix}/exit-status.txt",
            }
        )
    return names


def _member_limit(name: str) -> int:
    if name.endswith("/stdout.raw"):
        return MAX_STDOUT_BYTES
    if name.endswith("/stderr.raw"):
        return 0
    if name.endswith("/exit-status.txt"):
        return 2
    if name == "validated.jsonl":
        return MAX_VALIDATED_BYTES
    if name == "report.json":
        return MAX_REPORT_BYTES
    raise EvidenceError(f"unexpected archive member: {name}")


def _validate_member_metadata(info: zipfile.ZipInfo) -> None:
    original = info.orig_filename
    if "\x00" in original:
        raise EvidenceError("archive member name contains NUL")
    if "\\" in original:
        raise EvidenceError(f"archive member uses a backslash path: {original}")
    path = PurePosixPath(original)
    if (
        path.is_absolute()
        or original.startswith("/")
        or re.match(r"[A-Za-z]:", original) is not None
    ):
        raise EvidenceError(f"absolute archive member path: {original}")
    if any(part in {"", ".", ".."} for part in original.split("/")):
        raise EvidenceError(f"non-canonical or traversal archive path: {original}")
    if info.is_dir() or info.filename.endswith("/"):
        raise EvidenceError(f"archive member is not a regular file: {original}")
    if info.flag_bits & 0x1:
        raise EvidenceError(f"encrypted archive member: {original}")
    if info.compress_type not in ALLOWED_COMPRESSION:
        raise EvidenceError(f"unsupported compression method: {original}")

    mode = info.external_attr >> 16
    dos_directory = bool(info.external_attr & 0x10)
    if info.create_system == 3:
        regular = stat.S_ISREG(mode)
    elif info.create_system == 0:
        regular = not dos_directory
    else:
        regular = False
    if not regular:
        raise EvidenceError(f"symlink or special archive member: {original}")

    limit = _member_limit(info.filename)
    if info.file_size < 0 or info.file_size > limit:
        raise EvidenceError(f"oversized archive member: {original}")
    if info.compress_size < 0:
        raise EvidenceError(f"invalid compressed size: {original}")
    if info.file_size > 0:
        if info.compress_size == 0:
            raise EvidenceError(f"impossible compression ratio: {original}")
        if info.file_size > info.compress_size * MAX_COMPRESSION_RATIO:
            raise EvidenceError(f"compressed-bomb ratio: {original}")


def _read_members(archive: Path) -> tuple[dict[str, bytes], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(archive, flags)
    except OSError as error:
        raise EvidenceError(f"cannot open archive without following symlinks: {error}") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            archive_info = os.fstat(source.fileno())
            if not stat.S_ISREG(archive_info.st_mode):
                raise EvidenceError("archive must be a regular non-symlink file")
            if archive_info.st_size <= 0 or archive_info.st_size > MAX_ARCHIVE_BYTES:
                raise EvidenceError("archive byte size is outside the allowed limit")
            archive_bytes = source.read(MAX_ARCHIVE_BYTES + 1)
    except OSError as error:
        raise EvidenceError(f"cannot read archive: {error}") from error
    if len(archive_bytes) != archive_info.st_size or len(archive_bytes) > MAX_ARCHIVE_BYTES:
        raise EvidenceError("archive changed while being read or exceeds the byte limit")
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()

    expected_names = _expected_member_names()
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as evidence:
            infos = evidence.infolist()
            if len(infos) != EXPECTED_MEMBER_COUNT:
                raise EvidenceError(
                    f"archive must contain exactly {EXPECTED_MEMBER_COUNT} members"
                )
            names = [info.filename for info in infos]
            if len(set(names)) != len(names):
                raise EvidenceError("archive contains duplicate member names")
            if set(names) != expected_names:
                raise EvidenceError("archive member set does not match the exact allowlist")

            total_size = 0
            for info in infos:
                _validate_member_metadata(info)
                total_size += info.file_size
                if total_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise EvidenceError("archive uncompressed size exceeds the total limit")

            for info in infos:
                limit = _member_limit(info.filename)
                with evidence.open(info, "r") as member:
                    data = member.read(limit + 1)
                    if member.read(1):
                        raise EvidenceError(f"oversized decompressed member: {info.filename}")
                if len(data) != info.file_size or len(data) > limit:
                    raise EvidenceError(f"member size mismatch: {info.filename}")
                contents[info.filename] = data
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise EvidenceError(f"invalid ZIP archive: {error}") from error

    return contents, archive_sha256


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def verify_archive(archive: Path, expected_source_sha: str) -> dict[str, object]:
    """Verify *archive* and return its deterministic audit record."""
    if SOURCE_SHA_RE.fullmatch(expected_source_sha) is None:
        raise EvidenceError("expected source SHA must be 40 lowercase hexadecimal characters")

    contents, archive_sha256 = _read_members(archive)
    raw_records: list[dict[str, object]] = []
    for iteration in range(1, SAMPLE_COUNT + 1):
        prefix = f"sample-{iteration:03d}"
        if contents[f"{prefix}/exit-status.txt"] != b"0\n":
            raise EvidenceError(f"{prefix}: exit status must equal exactly 0\\n")
        if contents[f"{prefix}/stderr.raw"] != b"":
            raise EvidenceError(f"{prefix}: stderr must be empty")
        record = _strict_json(contents[f"{prefix}/stdout.raw"], f"{prefix}/stdout.raw")
        _validate_probe(record, f"{prefix}/stdout.raw")
        raw_records.append(record)

    validated_bytes = contents["validated.jsonl"]
    if not validated_bytes.endswith(b"\n") or b"\r" in validated_bytes:
        raise EvidenceError("validated.jsonl must use newline-terminated LF records")
    validated_lines = validated_bytes[:-1].split(b"\n")
    if len(validated_lines) != SAMPLE_COUNT or any(not line for line in validated_lines):
        raise EvidenceError("validated.jsonl must contain exactly 100 nonempty records")

    validated_records: list[dict[str, object]] = []
    observed_orders: set[str] = set()
    for iteration, (line, raw) in enumerate(zip(validated_lines, raw_records), start=1):
        record = _strict_json(line, f"validated.jsonl line {iteration}")
        _require_exact_keys(record, PROBE_KEYS | {"iteration"}, f"validated line {iteration}")
        _require_exact_int(record["iteration"], iteration, f"validated line {iteration}.iteration")
        expected = dict(raw)
        expected["iteration"] = iteration
        if record != expected:
            raise EvidenceError(
                f"validated line {iteration} does not equal its raw record plus iteration"
            )
        result = record["result"]
        assert type(result) is dict
        observed_orders.add(result["fork_delivery_order"])
        validated_records.append(record)
    if observed_orders != DELIVERY_ORDERS:
        raise EvidenceError("evidence must contain both fork delivery orders")

    report = _strict_json(contents["report.json"], "report.json")
    _require_exact_keys(report, REPORT_KEYS, "report.json")
    platform = report["platform"]
    if type(platform) is not dict:
        raise EvidenceError("report.json.platform must be an object")
    _require_exact_keys(platform, REPORT_PLATFORM_KEYS, "report.json.platform")
    kernel_release = platform["kernel_release"]
    if type(kernel_release) is not str or KERNEL_RELEASE_RE.fullmatch(kernel_release) is None:
        raise EvidenceError("report.json contains an invalid kernel release")

    expected_report = {
        "schema": "again.linux-pytest-supervisor-qualification.v1",
        "validated_sample_count": SAMPLE_COUNT,
        "source_commit": expected_source_sha,
        "platform": {
            "os": "linux",
            "architecture": "x86_64",
            "kernel_release": kernel_release,
        },
        "first_iteration": 1,
        "last_iteration": SAMPLE_COUNT,
        "fork_delivery_orders": sorted(observed_orders),
        "scope": {
            "kind": "fixed_no_command_two_task_supervisor_qualification",
            "profile_qualification": False,
            "accepts_command": False,
            "effect_ir_authority": False,
            "execution_authority": False,
            "reuse_authority": False,
        },
    }
    if report != expected_report:
        raise EvidenceError("report.json does not equal the independently reconstructed report")

    manifest = [
        {
            "name": name,
            "sha256": hashlib.sha256(contents[name]).hexdigest(),
            "size": len(contents[name]),
        }
        for name in sorted(contents)
    ]
    manifest_sha256 = hashlib.sha256(_canonical_json_bytes(manifest)).hexdigest()
    return {
        "archive_sha256": archive_sha256,
        "fork_delivery_orders": sorted(observed_orders),
        "member_count": len(contents),
        "member_manifest_sha256": manifest_sha256,
        "schema": "again.linux-pytest-supervisor-evidence-audit.v1",
        "source_commit": expected_source_sha,
        "validated_sample_count": len(validated_records),
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline verification of a Gate 2 supervisor evidence ZIP"
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-source-sha", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        audit = verify_archive(args.archive, args.expected_source_sha)
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    os.write(sys.stdout.fileno(), _canonical_json_bytes(audit) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
