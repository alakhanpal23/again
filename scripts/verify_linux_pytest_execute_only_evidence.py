#!/usr/bin/env python3
"""Bounded offline verifier for future Gate 3 execute-only evidence.

The verifier reads one regular non-symlink ZIP through a no-follow descriptor,
never extracts a member, never executes a command, and never accesses a
network.  Its successful output is an integrity audit only and grants no pass,
qualification, execution, candidate, replay, hit, or reuse authority.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import zipfile


REPORT_MEMBER = "report.json"
RECORD_MEMBER = "execution-record.json"
FIXTURE_MANIFEST_MEMBER = "fixture-manifest.json"
STDOUT_MEMBER = "stdout.raw"
STDERR_MEMBER = "stderr.raw"
EXPECTED_MEMBERS = frozenset(
    {
        REPORT_MEMBER,
        RECORD_MEMBER,
        FIXTURE_MANIFEST_MEMBER,
        STDOUT_MEMBER,
        STDERR_MEMBER,
    }
)

MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_FIXTURE_MANIFEST_BYTES = 16 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 3 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MEMBER_LIMITS = {
    REPORT_MEMBER: MAX_REPORT_BYTES,
    RECORD_MEMBER: MAX_RECORD_BYTES,
    FIXTURE_MANIFEST_MEMBER: MAX_FIXTURE_MANIFEST_BYTES,
    STDOUT_MEMBER: MAX_STREAM_BYTES,
    STDERR_MEMBER: MAX_STREAM_BYTES,
}

ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
ALLOWED_DOS_FILE_ATTRIBUTES = 0x01 | 0x02 | 0x04 | 0x20
LOCAL_FILE_HEADER_SIGNATURE = 0x04034B50
CENTRAL_DIRECTORY_HEADER_SIGNATURE = 0x02014B50
DATA_DESCRIPTOR_SIGNATURE = 0x08074B50
END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054B50
LOCAL_FILE_HEADER = struct.Struct("<IHHHHHIIIHH")
CENTRAL_DIRECTORY_HEADER = struct.Struct("<IHHHHHHIIIHHHHHII")
DATA_DESCRIPTOR = struct.Struct("<IIII")
END_OF_CENTRAL_DIRECTORY = struct.Struct("<IHHHHIIH")

SOURCE_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
REFERENCE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+~-]{0,1023}\Z")

FIXTURE_SCHEMA = "again.linux-pytest.execute-only-fixture.v1"
RECORD_SCHEMA = "again.linux-pytest.execute-only-execution-record.v1"
REPORT_SCHEMA = "again.linux-pytest.execute-only-evidence-report.v1"
TUPLE_SCHEMA = "again.linux-pytest.qualified-tuple-evidence.v1"
AUDIT_SCHEMA = "again.linux-pytest.execute-only-evidence-audit.v1"
SELECTOR = "tests/test_smoke.py::test_smoke"
FIXTURE_PATH = "tests/test_smoke.py"
EXACT_ARGV = [
    ".venv/bin/python",
    "-I",
    "-m",
    "pytest",
    SELECTOR,
]
FIXTURE_BYTES = (
    b'"""Fixed Gate 3 execute-only acceptance fixture."""\n'
    b"\n"
    b"\n"
    b"def test_smoke() -> None:\n"
    b"    assert True\n"
)
FIXTURE_SHA256 = "6c29f0960cc8ade5d57f147d7e9921d619ec9404dfd235377b3fe2d9a3ae7f72"
EXECUTE_ONLY_REASON = "gate3_execute_only"

RECORD_KEYS = {
    "argv",
    "authority_claims",
    "cleanup_canaries",
    "counts",
    "descendant_reap",
    "execute_only_reason",
    "hashes",
    "host_manifest",
    "outcome",
    "qualified_tuple_evidence",
    "raw_final_wait_status",
    "schema",
    "selector",
    "streams",
}
HASH_KEYS = {
    "binary_sha256",
    "fixture_manifest_sha256",
    "fixture_sha256",
    "source_sha256",
}
TUPLE_KEYS = {"reference", "schema", "sha256"}
STREAMS_KEYS = {"stderr", "stdout"}
STREAM_KEYS = {
    "captured_length",
    "captured_sha256",
    "delivered_length",
    "delivered_sha256",
}
HOST_MANIFEST_KEYS = {"after_sha256", "before_sha256", "unchanged"}
CLEANUP_KEYS = {"branch", "fd", "mount", "namespace", "network", "task"}
REAP_KEYS = {"all_descendants_terminally_reaped", "final_wait_error"}
COUNT_KEYS = {"candidate", "hit", "promotion", "replay", "shadow"}
AUTHORITY_KEYS = {
    "candidate_authority_claimed",
    "execution_authority_claimed",
    "hit_authority_claimed",
    "pass_claimed",
    "promotion_authority_claimed",
    "qualification_claimed",
    "replay_authority_claimed",
    "reuse_authority_claimed",
    "shadow_authority_claimed",
}
FIXTURE_MANIFEST_KEYS = {"files", "schema", "selector"}
FIXTURE_FILE_KEYS = {"bytes_base64", "length", "path", "sha256"}
REPORT_KEYS = {
    "argv",
    "authority_claims",
    "cleanup_canaries",
    "counts",
    "descendant_reap",
    "execute_only_reason",
    "execution_record_sha256",
    "fixture_manifest_sha256",
    "hashes",
    "host_manifest",
    "outcome",
    "qualified_tuple_evidence",
    "raw_final_wait_status",
    "schema",
    "selector",
    "source_commit",
    "streams",
}
REPORT_STREAM_KEYS = {"length", "sha256"}


class EvidenceError(ValueError):
    """The archive violates the closed Gate 3 evidence contract."""


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
        raise EvidenceError(f"{label}: JSON is not strict UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, EvidenceError, RecursionError) as error:
        raise EvidenceError(f"{label}: malformed JSON: {error}") from error
    if type(value) is not dict:
        raise EvidenceError(f"{label}: JSON value must be exactly one object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _type_exact_equal(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        left_dict = left
        right_dict = right
        return set(left_dict) == set(right_dict) and all(
            _type_exact_equal(left_dict[key], right_dict[key]) for key in left_dict
        )
    if type(left) is list:
        left_list = left
        right_list = right
        return len(left_list) == len(right_list) and all(
            _type_exact_equal(a, b) for a, b in zip(left_list, right_list)
        )
    return left == right


def _require_exact_keys(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise EvidenceError(f"{label}: object keys do not match the closed schema")
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label}: expected lowercase SHA-256")
    return value


def _require_reference(value: object, label: str) -> str:
    if type(value) is not str or REFERENCE_RE.fullmatch(value) is None or "\\" in value:
        raise EvidenceError(f"{label}: malformed relative reference")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise EvidenceError(f"{label}: malformed relative reference")
    return value


def _require_exact_int(value: object, expected: int, label: str) -> None:
    if type(value) is not int or value != expected:
        raise EvidenceError(f"{label}: expected integer {expected}")


def _member_limit(name: str) -> int:
    try:
        return MEMBER_LIMITS[name]
    except KeyError as error:
        raise EvidenceError(f"unexpected archive member: {name}") from error


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
    if info.flag_bits & 0x1 or info.flag_bits & ~(0x08 | 0x800):
        raise EvidenceError(f"encrypted or unsupported ZIP member flags: {original}")
    if info.compress_type not in ALLOWED_COMPRESSION:
        raise EvidenceError(f"unsupported compression method: {original}")

    mode = info.external_attr >> 16
    dos_attributes = info.external_attr & 0xFF
    if dos_attributes & ~ALLOWED_DOS_FILE_ATTRIBUTES:
        raise EvidenceError(f"DOS special archive member: {original}")
    if info.create_system == 3:
        regular = stat.S_ISREG(mode)
    elif info.create_system == 0:
        regular = True
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


def _require_slice(data: bytes, offset: int, size: int, label: str) -> bytes:
    end = offset + size
    if offset < 0 or size < 0 or end > len(data):
        raise EvidenceError(f"truncated ZIP {label}")
    return data[offset:end]


def _validate_data_descriptor(
    archive_bytes: bytes,
    start: int,
    end: int,
    info: zipfile.ZipInfo,
) -> None:
    descriptor = _require_slice(
        archive_bytes, start, DATA_DESCRIPTOR.size, f"data descriptor for {info.filename}"
    )
    if start + DATA_DESCRIPTOR.size != end:
        raise EvidenceError(f"non-canonical ZIP data descriptor: {info.filename}")
    signature, crc, compressed_size, file_size = DATA_DESCRIPTOR.unpack(descriptor)
    if signature != DATA_DESCRIPTOR_SIGNATURE:
        raise EvidenceError(f"unsigned ZIP data descriptor: {info.filename}")
    if (crc, compressed_size, file_size) != (
        info.CRC,
        info.compress_size,
        info.file_size,
    ):
        raise EvidenceError(f"ZIP data descriptor mismatch: {info.filename}")


def _validate_exact_zip_layout(
    archive_bytes: bytes,
    evidence: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> None:
    """Reject hidden prefixes, trailers, gaps, comments, and extra fields."""
    if evidence.comment != b"" or len(archive_bytes) < END_OF_CENTRAL_DIRECTORY.size:
        raise EvidenceError("ZIP comment or truncated end record")
    eocd_offset = len(archive_bytes) - END_OF_CENTRAL_DIRECTORY.size
    fields = END_OF_CENTRAL_DIRECTORY.unpack(
        _require_slice(
            archive_bytes, eocd_offset, END_OF_CENTRAL_DIRECTORY.size, "end record"
        )
    )
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = fields
    if signature != END_OF_CENTRAL_DIRECTORY_SIGNATURE or comment_size != 0:
        raise EvidenceError("ZIP end record must end exactly at EOF")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise EvidenceError("multi-disk ZIP archives are unsupported")
    if total_entries != len(infos):
        raise EvidenceError("ZIP end record member count mismatch")
    if central_offset != evidence.start_dir or central_offset + central_size != eocd_offset:
        raise EvidenceError("ZIP central directory does not cover the archive exactly")

    ordered = sorted(infos, key=lambda info: info.header_offset)
    if not ordered or ordered[0].header_offset != 0:
        raise EvidenceError("ZIP contains a hidden prefix")
    for index, info in enumerate(ordered):
        fixed = _require_slice(
            archive_bytes,
            info.header_offset,
            LOCAL_FILE_HEADER.size,
            f"local header for {info.filename}",
        )
        local = LOCAL_FILE_HEADER.unpack(fixed)
        if local[0] != LOCAL_FILE_HEADER_SIGNATURE:
            raise EvidenceError(f"invalid ZIP local header: {info.filename}")
        local_flags = local[2]
        local_compression = local[3]
        local_crc, local_compressed_size, local_file_size = local[6:9]
        name_size, extra_size = local[9:11]
        name_start = info.header_offset + LOCAL_FILE_HEADER.size
        name = _require_slice(archive_bytes, name_start, name_size, "local member name")
        if extra_size != 0:
            raise EvidenceError(f"ZIP local extra fields are unsupported: {info.filename}")
        try:
            expected_name = info.orig_filename.encode("utf-8")
        except UnicodeEncodeError as error:
            raise EvidenceError(f"non-UTF-8 ZIP member name: {info.orig_filename}") from error
        if name != expected_name:
            raise EvidenceError(f"ZIP local member name mismatch: {info.filename}")
        if local_flags != info.flag_bits or local_compression != info.compress_type:
            raise EvidenceError(f"ZIP local metadata mismatch: {info.filename}")
        data_start = name_start + name_size
        data_end = data_start + info.compress_size
        next_offset = (
            ordered[index + 1].header_offset
            if index + 1 < len(ordered)
            else evidence.start_dir
        )
        _require_slice(archive_bytes, data_start, info.compress_size, "compressed member data")
        if local_flags & 0x08:
            if (local_crc, local_compressed_size, local_file_size) != (0, 0, 0):
                raise EvidenceError(f"non-canonical deferred ZIP sizes: {info.filename}")
            _validate_data_descriptor(archive_bytes, data_end, next_offset, info)
        else:
            if (local_crc, local_compressed_size, local_file_size) != (
                info.CRC,
                info.compress_size,
                info.file_size,
            ):
                raise EvidenceError(f"ZIP local size or CRC mismatch: {info.filename}")
            if data_end != next_offset:
                raise EvidenceError(f"unreferenced bytes after ZIP member: {info.filename}")

    cursor = evidence.start_dir
    for info in infos:
        fixed = _require_slice(
            archive_bytes,
            cursor,
            CENTRAL_DIRECTORY_HEADER.size,
            f"central header for {info.filename}",
        )
        central = CENTRAL_DIRECTORY_HEADER.unpack(fixed)
        if central[0] != CENTRAL_DIRECTORY_HEADER_SIGNATURE:
            raise EvidenceError(f"invalid ZIP central header: {info.filename}")
        name_size, extra_size, comment_size = central[10:13]
        local_offset = central[16]
        name_start = cursor + CENTRAL_DIRECTORY_HEADER.size
        name = _require_slice(archive_bytes, name_start, name_size, "central member name")
        if name != info.orig_filename.encode("utf-8") or local_offset != info.header_offset:
            raise EvidenceError(f"ZIP central member mismatch: {info.filename}")
        if extra_size != 0 or comment_size != 0:
            raise EvidenceError(f"ZIP central extras/comments unsupported: {info.filename}")
        cursor = name_start + name_size
    if cursor != eocd_offset:
        raise EvidenceError("ZIP contains a hidden trailer or central-directory gap")


def _read_members(archive: Path) -> tuple[dict[str, bytes], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(archive, flags)
    except OSError as error:
        raise EvidenceError(f"cannot open archive without following symlinks: {error}") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError("archive must be a regular non-symlink file")
            if before.st_size <= 0 or before.st_size > MAX_ARCHIVE_BYTES:
                raise EvidenceError("archive byte size is outside the allowed limit")
            archive_bytes = source.read(MAX_ARCHIVE_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise EvidenceError(f"cannot read archive: {error}") from error
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        len(archive_bytes) != before.st_size
        or len(archive_bytes) > MAX_ARCHIVE_BYTES
        or identity(before) != identity(after)
    ):
        raise EvidenceError("archive changed while being read or exceeds the byte limit")
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()

    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as evidence:
            infos = evidence.infolist()
            names = [info.filename for info in infos]
            if len(infos) != len(EXPECTED_MEMBERS):
                raise EvidenceError("archive member count is not exactly five")
            if len(set(names)) != len(names):
                raise EvidenceError("archive contains duplicate member names")
            if set(names) != EXPECTED_MEMBERS:
                raise EvidenceError("archive member set does not match the exact allowlist")
            _validate_exact_zip_layout(archive_bytes, evidence, infos)

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


def _validate_fixture_manifest(raw: bytes) -> tuple[dict[str, object], str]:
    manifest = _strict_json(raw, FIXTURE_MANIFEST_MEMBER)
    _require_exact_keys(manifest, FIXTURE_MANIFEST_KEYS, FIXTURE_MANIFEST_MEMBER)
    files = manifest["files"]
    if type(files) is not list or len(files) != 1:
        raise EvidenceError("fixture manifest must contain exactly one file")
    file_record = _require_exact_keys(files[0], FIXTURE_FILE_KEYS, "fixture file")
    expected_encoded = base64.b64encode(FIXTURE_BYTES).decode("ascii")
    expected_manifest = {
        "schema": FIXTURE_SCHEMA,
        "selector": SELECTOR,
        "files": [
            {
                "path": FIXTURE_PATH,
                "bytes_base64": expected_encoded,
                "length": len(FIXTURE_BYTES),
                "sha256": FIXTURE_SHA256,
            }
        ],
    }
    if not _type_exact_equal(manifest, expected_manifest):
        raise EvidenceError("fixture manifest differs from the exact frozen fixture")
    try:
        decoded = base64.b64decode(file_record["bytes_base64"], validate=True)
    except (binascii.Error, TypeError, ValueError) as error:
        raise EvidenceError("fixture manifest bytes are not strict base64") from error
    if decoded != FIXTURE_BYTES or hashlib.sha256(decoded).hexdigest() != FIXTURE_SHA256:
        raise EvidenceError("fixture manifest content hash mismatch")
    if raw != _canonical_json_bytes(expected_manifest) + b"\n":
        raise EvidenceError("fixture manifest bytes are not the canonical frozen manifest")
    return manifest, hashlib.sha256(raw).hexdigest()


def _validate_stream(
    name: str,
    value: object,
    actual: bytes,
) -> None:
    stream = _require_exact_keys(value, STREAM_KEYS, f"record streams.{name}")
    length = len(actual)
    digest = hashlib.sha256(actual).hexdigest()
    for field in ("captured_length", "delivered_length"):
        _require_exact_int(stream[field], length, f"record streams.{name}.{field}")
    for field in ("captured_sha256", "delivered_sha256"):
        if stream[field] != digest:
            raise EvidenceError(f"record streams.{name}.{field}: stream hash mismatch")


def _validate_execution_record(
    record: dict[str, object],
    contents: dict[str, bytes],
    fixture_manifest_sha256: str,
    expected_binary_sha256: str,
    expected_source_sha256: str,
    expected_tuple_reference: str,
    expected_tuple_sha256: str,
) -> None:
    _require_exact_keys(record, RECORD_KEYS, RECORD_MEMBER)
    if record["schema"] != RECORD_SCHEMA or record["outcome"] != "executed_only":
        raise EvidenceError("execution record schema or outcome mismatch")
    if record["selector"] != SELECTOR or not _type_exact_equal(record["argv"], EXACT_ARGV):
        raise EvidenceError("execution record selector or argv mismatch")

    hashes = _require_exact_keys(record["hashes"], HASH_KEYS, "record hashes")
    expected_hashes = {
        "binary_sha256": expected_binary_sha256,
        "source_sha256": expected_source_sha256,
        "fixture_sha256": FIXTURE_SHA256,
        "fixture_manifest_sha256": fixture_manifest_sha256,
    }
    if not _type_exact_equal(hashes, expected_hashes):
        raise EvidenceError("execution record hashes do not match trusted/member hashes")

    tuple_evidence = _require_exact_keys(
        record["qualified_tuple_evidence"], TUPLE_KEYS, "qualified tuple evidence"
    )
    expected_tuple = {
        "schema": TUPLE_SCHEMA,
        "reference": expected_tuple_reference,
        "sha256": expected_tuple_sha256,
    }
    if not _type_exact_equal(tuple_evidence, expected_tuple):
        raise EvidenceError("qualified tuple evidence does not match trusted metadata")

    streams = _require_exact_keys(record["streams"], STREAMS_KEYS, "record streams")
    _validate_stream("stdout", streams["stdout"], contents[STDOUT_MEMBER])
    _validate_stream("stderr", streams["stderr"], contents[STDERR_MEMBER])
    _require_exact_int(record["raw_final_wait_status"], 0, "raw final wait status")

    host = _require_exact_keys(record["host_manifest"], HOST_MANIFEST_KEYS, "host manifest")
    before = _require_sha256(host["before_sha256"], "host manifest before")
    after = _require_sha256(host["after_sha256"], "host manifest after")
    if host["unchanged"] is not True or before != after:
        raise EvidenceError("host workspace manifest changed")

    cleanup = _require_exact_keys(record["cleanup_canaries"], CLEANUP_KEYS, "cleanup canaries")
    for key in CLEANUP_KEYS:
        if cleanup[key] is not True:
            raise EvidenceError(f"cleanup canary failed: {key}")
    reap = _require_exact_keys(record["descendant_reap"], REAP_KEYS, "descendant reap")
    if reap["all_descendants_terminally_reaped"] is not True:
        raise EvidenceError("terminal descendant reap is incomplete")
    if reap["final_wait_error"] != "ECHILD":
        raise EvidenceError("final ECHILD is missing")
    if record["execute_only_reason"] != EXECUTE_ONLY_REASON:
        raise EvidenceError("execute-only reason mismatch")

    counts = _require_exact_keys(record["counts"], COUNT_KEYS, "record counts")
    for key in COUNT_KEYS:
        _require_exact_int(counts[key], 0, f"record counts.{key}")
    authority = _require_exact_keys(
        record["authority_claims"], AUTHORITY_KEYS, "record authority claims"
    )
    for key in AUTHORITY_KEYS:
        if authority[key] is not False:
            raise EvidenceError(f"forbidden authority claim: {key}")


def _expected_report(
    record: dict[str, object],
    contents: dict[str, bytes],
    source_commit: str,
    record_sha256: str,
    fixture_manifest_sha256: str,
) -> dict[str, object]:
    return {
        "schema": REPORT_SCHEMA,
        "source_commit": source_commit,
        "execution_record_sha256": record_sha256,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "outcome": record["outcome"],
        "selector": record["selector"],
        "argv": record["argv"],
        "hashes": record["hashes"],
        "qualified_tuple_evidence": record["qualified_tuple_evidence"],
        "streams": {
            "stdout": {
                "length": len(contents[STDOUT_MEMBER]),
                "sha256": hashlib.sha256(contents[STDOUT_MEMBER]).hexdigest(),
            },
            "stderr": {
                "length": len(contents[STDERR_MEMBER]),
                "sha256": hashlib.sha256(contents[STDERR_MEMBER]).hexdigest(),
            },
        },
        "raw_final_wait_status": record["raw_final_wait_status"],
        "host_manifest": record["host_manifest"],
        "cleanup_canaries": record["cleanup_canaries"],
        "descendant_reap": record["descendant_reap"],
        "execute_only_reason": record["execute_only_reason"],
        "counts": record["counts"],
        "authority_claims": record["authority_claims"],
    }


def verify_archive(
    archive: Path,
    expected_source_commit: str,
    expected_binary_sha256: str,
    expected_source_sha256: str,
    expected_tuple_reference: str,
    expected_tuple_sha256: str,
) -> dict[str, object]:
    """Verify one Gate 3 ZIP and return a deterministic non-authoritative audit."""
    if type(expected_source_commit) is not str or SOURCE_COMMIT_RE.fullmatch(
        expected_source_commit
    ) is None:
        raise EvidenceError("expected source commit must be 40 lowercase hexadecimal characters")
    expected_binary_sha256 = _require_sha256(expected_binary_sha256, "expected binary hash")
    expected_source_sha256 = _require_sha256(expected_source_sha256, "expected source hash")
    expected_tuple_sha256 = _require_sha256(expected_tuple_sha256, "expected tuple hash")
    expected_tuple_reference = _require_reference(
        expected_tuple_reference, "expected qualified tuple reference"
    )

    contents, archive_sha256 = _read_members(archive)
    _, fixture_manifest_sha256 = _validate_fixture_manifest(
        contents[FIXTURE_MANIFEST_MEMBER]
    )
    record = _strict_json(contents[RECORD_MEMBER], RECORD_MEMBER)
    _validate_execution_record(
        record,
        contents,
        fixture_manifest_sha256,
        expected_binary_sha256,
        expected_source_sha256,
        expected_tuple_reference,
        expected_tuple_sha256,
    )
    record_sha256 = hashlib.sha256(contents[RECORD_MEMBER]).hexdigest()
    report = _strict_json(contents[REPORT_MEMBER], REPORT_MEMBER)
    _require_exact_keys(report, REPORT_KEYS, REPORT_MEMBER)
    expected_report = _expected_report(
        record,
        contents,
        expected_source_commit,
        record_sha256,
        fixture_manifest_sha256,
    )
    if not _type_exact_equal(report, expected_report):
        raise EvidenceError("report does not equal the independently reconstructed report")
    report_streams = _require_exact_keys(report["streams"], STREAMS_KEYS, "report streams")
    for name in STREAMS_KEYS:
        _require_exact_keys(report_streams[name], REPORT_STREAM_KEYS, f"report streams.{name}")

    member_manifest = [
        {
            "name": name,
            "sha256": hashlib.sha256(contents[name]).hexdigest(),
            "size": len(contents[name]),
        }
        for name in sorted(contents)
    ]
    member_manifest_sha256 = hashlib.sha256(
        _canonical_json_bytes(member_manifest)
    ).hexdigest()
    return {
        "schema": AUDIT_SCHEMA,
        "archive_sha256": archive_sha256,
        "member_manifest_sha256": member_manifest_sha256,
        "member_count": len(contents),
        "source_commit": expected_source_commit,
        "execution_record_sha256": record_sha256,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "hashes": record["hashes"],
        "qualified_tuple_evidence": record["qualified_tuple_evidence"],
        "streams": expected_report["streams"],
        "counts": {key: 0 for key in sorted(COUNT_KEYS)},
        "authority": {key: False for key in sorted(AUTHORITY_KEYS)},
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline verification of a Gate 3 execute-only evidence ZIP"
    )
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--expected-qualified-tuple-reference", required=True)
    parser.add_argument("--expected-qualified-tuple-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        audit = verify_archive(
            args.archive,
            args.expected_source_commit,
            args.expected_binary_sha256,
            args.expected_source_sha256,
            args.expected_qualified_tuple_reference,
            args.expected_qualified_tuple_sha256,
        )
    except EvidenceError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    os.write(sys.stdout.fileno(), _canonical_json_bytes(audit) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
