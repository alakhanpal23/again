#!/usr/bin/env python3
"""Pure, non-authoritative oracle for the first Gate 3 pytest fixture.

This module only reads and validates caller-supplied bytes and the fixed local
fixture.  It never starts a process, opens a network endpoint, creates an
environment, invokes pytest, or mutates a repository.  A consistent result is
diagnostic evidence only: it cannot grant pass, qualification, execution, or
reuse authority.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import stat
from typing import Any


FIXTURE_SCHEMA = "again.linux-pytest.execute-only-fixture.v1"
EVIDENCE_SCHEMA = "again.linux-pytest.execute-only-evidence.v1"
QUALIFIED_TUPLE_EVIDENCE_SCHEMA = "again.linux-pytest.qualified-tuple-evidence.v1"
ORACLE_RESULT_SCHEMA = "again.linux-pytest.execute-only-oracle-result.v1"
SELECTOR = "tests/test_smoke.py::test_smoke"
FIXTURE_PATH = "tests/test_smoke.py"
EXACT_ARGV = (
    ".venv/bin/python",
    "-I",
    "-m",
    "pytest",
    SELECTOR,
)
FIXTURE_BYTES = (
    b'"""Fixed Gate 3 execute-only acceptance fixture."""\n'
    b"\n"
    b"\n"
    b"def test_smoke() -> None:\n"
    b"    assert True\n"
)
FIXTURE_LENGTH = 96
FIXTURE_SHA256 = "6c29f0960cc8ade5d57f147d7e9921d619ec9404dfd235377b3fe2d9a3ae7f72"
DEFAULT_FIXTURE_ROOT = pathlib.Path(__file__).with_name("fixtures") / (
    "linux_pytest_execute_only_v1"
)

MAX_MANIFEST_BYTES = 16 * 1024
MAX_FIXTURE_BYTES = 4 * 1024
MAX_DIAGNOSTIC_BYTES = 1024 * 1024
MAX_TREE_ENTRIES = 3
EXPECTED_DIRECTORIES = frozenset({"tests"})
EXPECTED_FILES = frozenset({"manifest.json", FIXTURE_PATH})
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXECUTE_ONLY_REASON = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")


EXPECTED_MANIFEST: dict[str, Any] = {
    "schema": FIXTURE_SCHEMA,
    "selector": SELECTOR,
    "files": [
        {
            "path": FIXTURE_PATH,
            "bytes_base64": base64.b64encode(FIXTURE_BYTES).decode("ascii"),
            "length": FIXTURE_LENGTH,
            "sha256": FIXTURE_SHA256,
        }
    ],
}


class EvidenceRefusal(ValueError):
    """A typed fail-closed fixture or input refusal."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class FixtureIdentity:
    """Identity re-derived from the fixed fixture bytes."""

    selector: str
    path: str
    length: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class ValidationResult:
    """A non-authoritative, two-outcome diagnostic result."""

    outcome: str
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.outcome not in {"diagnostic_consistent", "non_pass"}:
            raise ValueError("oracle outcomes are closed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": ORACLE_RESULT_SCHEMA,
            "outcome": self.outcome,
            "reasons": list(self.reasons),
            "authority": {
                "pass": False,
                "qualification": False,
                "execution": False,
                "reuse": False,
            },
        }


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceRefusal("json_duplicate_key", f"duplicate JSON key: {key!r}")
        value[key] = item
    return value


def _decode_json(raw: bytes, *, code: str) -> Any:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except EvidenceRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceRefusal(code, "input is not strict UTF-8 JSON") from error


def _is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    return bool(metadata.st_size and blocks is not None and blocks * 512 < metadata.st_size)


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _require_regular(metadata: os.stat_result, relative: str, limit: int) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise EvidenceRefusal("fixture_symlink", f"fixture entry is a symlink: {relative}")
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceRefusal(
            "fixture_special_file", f"fixture entry is not a regular file: {relative}"
        )
    if metadata.st_size > limit:
        raise EvidenceRefusal("fixture_oversized", f"fixture input is oversized: {relative}")
    if _is_sparse(metadata):
        raise EvidenceRefusal("fixture_sparse_file", f"fixture input is sparse: {relative}")


def _read_stable_regular(path: pathlib.Path, relative: str, limit: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceRefusal("fixture_unavailable", f"cannot stat {relative}: {error}") from error
    _require_regular(before, relative, limit)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceRefusal("fixture_unavailable", f"cannot open {relative}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular(opened, relative, limit)
        if _stat_identity(opened) != _stat_identity(before):
            raise EvidenceRefusal("fixture_changed", f"fixture changed before read: {relative}")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > limit:
                raise EvidenceRefusal(
                    "fixture_oversized", f"fixture input is oversized: {relative}"
                )
        after = os.fstat(descriptor)
        if _stat_identity(after) != _stat_identity(opened):
            raise EvidenceRefusal("fixture_changed", f"fixture changed during read: {relative}")
        value = b"".join(chunks)
        if len(value) != opened.st_size:
            raise EvidenceRefusal("fixture_changed", f"fixture length changed: {relative}")
        return value
    finally:
        os.close(descriptor)


def _scan_fixture_tree(root: pathlib.Path) -> None:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise EvidenceRefusal("fixture_unavailable", f"fixture root is unavailable: {error}") from error
    if stat.S_ISLNK(root_metadata.st_mode):
        raise EvidenceRefusal("fixture_symlink", "fixture root must not be a symlink")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceRefusal("fixture_not_directory", "fixture root is not a directory")

    directories: set[str] = set()
    files: set[str] = set()
    pending = [(root, "")]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise EvidenceRefusal(
                "fixture_unavailable", f"cannot enumerate fixture directory: {error}"
            ) from error
        for child in children:
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise EvidenceRefusal("fixture_extra_entry", "fixture contains extra entries")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise EvidenceRefusal(
                    "fixture_unavailable", f"cannot stat fixture entry {relative}: {error}"
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                raise EvidenceRefusal(
                    "fixture_symlink", f"fixture entry is a symlink: {relative}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative)
                pending.append((pathlib.Path(child.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
                limit = MAX_MANIFEST_BYTES if relative == "manifest.json" else MAX_FIXTURE_BYTES
                _require_regular(metadata, relative, limit)
            else:
                raise EvidenceRefusal(
                    "fixture_special_file", f"fixture entry is special: {relative}"
                )

    if directories != EXPECTED_DIRECTORIES or files != EXPECTED_FILES:
        raise EvidenceRefusal("fixture_extra_entry", "fixture tree does not match the closed manifest")


def validate_fixture(
    fixture_root: os.PathLike[str] | str = DEFAULT_FIXTURE_ROOT,
) -> FixtureIdentity:
    """Validate the closed fixture tree and return its re-derived identity."""

    root = pathlib.Path(fixture_root)
    _scan_fixture_tree(root)
    manifest_raw = _read_stable_regular(root / "manifest.json", "manifest.json", MAX_MANIFEST_BYTES)
    manifest = _decode_json(manifest_raw, code="fixture_manifest_malformed")
    if type(manifest) is not dict or manifest != EXPECTED_MANIFEST:
        raise EvidenceRefusal(
            "fixture_manifest_drift", "fixture manifest differs from the compiled acceptance identity"
        )
    if manifest_raw != canonical_json_bytes(EXPECTED_MANIFEST):
        raise EvidenceRefusal(
            "fixture_manifest_drift", "fixture manifest is not the exact canonical byte sequence"
        )

    encoded = manifest["files"][0]["bytes_base64"]
    try:
        bound_bytes = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EvidenceRefusal("fixture_manifest_drift", "manifest bytes are not strict base64") from error
    fixture_bytes = _read_stable_regular(root / FIXTURE_PATH, FIXTURE_PATH, MAX_FIXTURE_BYTES)
    if (
        bound_bytes != FIXTURE_BYTES
        or fixture_bytes != bound_bytes
        or len(fixture_bytes) != FIXTURE_LENGTH
        or sha256_bytes(fixture_bytes) != FIXTURE_SHA256
    ):
        raise EvidenceRefusal(
            "fixture_content_drift", "fixture path, bytes, length, or SHA-256 changed"
        )
    return FixtureIdentity(SELECTOR, FIXTURE_PATH, FIXTURE_LENGTH, FIXTURE_SHA256)


def _plain_dict(value: Any) -> bool:
    return type(value) is dict


def _exact_keys(value: Any, expected: set[str], reason: str, reasons: list[str]) -> bool:
    if not _plain_dict(value):
        reasons.append(reason)
        return False
    if set(value) != expected:
        reasons.append(reason)
        return False
    return True


def _sha256(value: Any) -> bool:
    return type(value) is str and HEX_SHA256.fullmatch(value) is not None


def _bounded_count(value: Any) -> bool:
    return type(value) is int and 0 <= value <= (1 << 63) - 1


def _check_hash_object(value: Any, fixture: FixtureIdentity, reasons: list[str]) -> None:
    keys = {"binary_sha256", "source_sha256", "fixture_sha256"}
    if not _exact_keys(value, keys, "hashes_malformed", reasons):
        return
    if not all(_sha256(value[key]) for key in keys):
        reasons.append("hashes_malformed")
    elif value["fixture_sha256"] != fixture.sha256:
        reasons.append("fixture_hash_mismatch")


def _check_tuple_reference(value: Any, reasons: list[str]) -> None:
    keys = {"schema", "reference", "sha256"}
    if not _exact_keys(value, keys, "qualified_tuple_reference_malformed", reasons):
        return
    if value["schema"] != QUALIFIED_TUPLE_EVIDENCE_SCHEMA:
        reasons.append("qualified_tuple_schema_mismatch")
    reference = value["reference"]
    try:
        reference_bytes = reference.encode("utf-8") if type(reference) is str else b""
    except UnicodeEncodeError:
        reference_bytes = b""
    if (
        type(reference) is not str
        or not reference_bytes
        or len(reference_bytes) > 1024
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in reference)
    ):
        reasons.append("qualified_tuple_reference_malformed")
    if not _sha256(value["sha256"]):
        reasons.append("qualified_tuple_hash_malformed")


def _check_stream(name: str, value: Any, reasons: list[str]) -> None:
    keys = {
        "captured_length",
        "captured_sha256",
        "delivered_length",
        "delivered_sha256",
    }
    reason = f"{name}_stream_malformed"
    if not _exact_keys(value, keys, reason, reasons):
        return
    if not _bounded_count(value["captured_length"]) or not _bounded_count(
        value["delivered_length"]
    ):
        reasons.append(reason)
    if not _sha256(value["captured_sha256"]) or not _sha256(value["delivered_sha256"]):
        reasons.append(reason)
    if (
        value["captured_length"] != value["delivered_length"]
        or value["captured_sha256"] != value["delivered_sha256"]
    ):
        reasons.append(f"{name}_delivery_mismatch")


def _check_streams(value: Any, reasons: list[str]) -> None:
    if not _exact_keys(value, {"stdout", "stderr"}, "streams_malformed", reasons):
        return
    _check_stream("stdout", value["stdout"], reasons)
    _check_stream("stderr", value["stderr"], reasons)


def _check_host_manifest(value: Any, reasons: list[str]) -> None:
    keys = {"before_sha256", "after_sha256", "unchanged"}
    if not _exact_keys(value, keys, "host_manifest_malformed", reasons):
        return
    if not _sha256(value["before_sha256"]) or not _sha256(value["after_sha256"]):
        reasons.append("host_manifest_malformed")
    if type(value["unchanged"]) is not bool:
        reasons.append("host_manifest_malformed")
    if value["unchanged"] is not True or value["before_sha256"] != value["after_sha256"]:
        reasons.append("host_manifest_changed")


def _check_cleanup(value: Any, reasons: list[str]) -> None:
    keys = {"network", "fd", "mount", "namespace", "task", "branch"}
    if not _exact_keys(value, keys, "cleanup_canaries_malformed", reasons):
        return
    if any(type(value[key]) is not bool for key in keys):
        reasons.append("cleanup_canaries_malformed")
    if any(value[key] is not True for key in keys):
        reasons.append("cleanup_canary_failed")


def _check_reap(value: Any, reasons: list[str]) -> None:
    keys = {"all_descendants_terminally_reaped", "final_wait_error"}
    if not _exact_keys(value, keys, "descendant_reap_malformed", reasons):
        return
    if value["all_descendants_terminally_reaped"] is not True:
        reasons.append("terminal_descendant_reap_incomplete")
    if value["final_wait_error"] != "ECHILD":
        reasons.append("final_echild_missing")


def _check_counts(value: Any, reasons: list[str]) -> None:
    keys = {"candidate", "shadow", "promotion", "replay"}
    if not _exact_keys(value, keys, "counts_malformed", reasons):
        return
    if any(type(value[key]) is not int or value[key] != 0 for key in keys):
        reasons.append("forbidden_record_count")


def _check_authority(value: Any, reasons: list[str]) -> None:
    keys = {
        "pass_claimed",
        "qualification_claimed",
        "execution_authority_claimed",
        "reuse_authority_claimed",
    }
    if not _exact_keys(value, keys, "authority_claims_malformed", reasons):
        return
    if any(type(value[key]) is not bool for key in keys):
        reasons.append("authority_claims_malformed")
    if any(value[key] is not False for key in keys):
        reasons.append("forbidden_authority_claim")


def validate_execute_only_evidence(
    diagnostic: Any,
    *,
    fixture_root: os.PathLike[str] | str = DEFAULT_FIXTURE_ROOT,
) -> ValidationResult:
    """Validate one already-decoded V1 diagnostic without granting authority."""

    fixture = validate_fixture(fixture_root)
    reasons: list[str] = []
    top_keys = {
        "schema",
        "outcome",
        "selector",
        "argv",
        "hashes",
        "qualified_tuple_evidence",
        "streams",
        "raw_final_wait_status",
        "host_manifest",
        "cleanup_canaries",
        "descendant_reap",
        "execute_only_reason",
        "counts",
        "authority_claims",
    }
    if not _exact_keys(diagnostic, top_keys, "diagnostic_shape_malformed", reasons):
        return ValidationResult("non_pass", tuple(reasons))

    if diagnostic["schema"] != EVIDENCE_SCHEMA:
        reasons.append("schema_mismatch")
    reported_outcome = diagnostic["outcome"]
    if type(reported_outcome) is not str or reported_outcome not in {
        "diagnostic_consistent",
        "non_pass",
    }:
        reasons.append("forbidden_outcome")
    if diagnostic["selector"] != fixture.selector:
        reasons.append("selector_mismatch")
    argv = diagnostic["argv"]
    if type(argv) is not list or any(type(item) is not str for item in argv):
        reasons.append("argv_malformed")
    elif tuple(argv) != EXACT_ARGV:
        reasons.append("argv_mismatch")
    _check_hash_object(diagnostic["hashes"], fixture, reasons)
    _check_tuple_reference(diagnostic["qualified_tuple_evidence"], reasons)
    _check_streams(diagnostic["streams"], reasons)
    wait_status = diagnostic["raw_final_wait_status"]
    if type(wait_status) is not int or not 0 <= wait_status <= 0xFFFF_FFFF:
        reasons.append("raw_wait_status_malformed")
    elif wait_status != 0:
        reasons.append("foreground_wait_status_nonzero")
    _check_host_manifest(diagnostic["host_manifest"], reasons)
    _check_cleanup(diagnostic["cleanup_canaries"], reasons)
    _check_reap(diagnostic["descendant_reap"], reasons)
    execute_only_reason = diagnostic["execute_only_reason"]
    if (
        type(execute_only_reason) is not str
        or len(execute_only_reason) > 96
        or EXECUTE_ONLY_REASON.fullmatch(execute_only_reason) is None
    ):
        reasons.append("execute_only_reason_malformed")
    _check_counts(diagnostic["counts"], reasons)
    _check_authority(diagnostic["authority_claims"], reasons)

    deduplicated = tuple(dict.fromkeys(reasons))
    if deduplicated or reported_outcome != "diagnostic_consistent":
        return ValidationResult("non_pass", deduplicated)
    return ValidationResult("diagnostic_consistent", ())


def validate_execute_only_evidence_bytes(
    raw: bytes,
    *,
    fixture_root: os.PathLike[str] | str = DEFAULT_FIXTURE_ROOT,
) -> ValidationResult:
    """Decode and validate a bounded diagnostic JSON byte string."""

    if type(raw) is not bytes:
        return ValidationResult("non_pass", ("diagnostic_bytes_required",))
    if len(raw) > MAX_DIAGNOSTIC_BYTES:
        return ValidationResult("non_pass", ("diagnostic_oversized",))
    try:
        diagnostic = _decode_json(raw, code="diagnostic_json_malformed")
    except EvidenceRefusal as error:
        return ValidationResult("non_pass", (error.code,))
    return validate_execute_only_evidence(diagnostic, fixture_root=fixture_root)


def build_diagnostic_for_test(
    *,
    outcome: str = "diagnostic_consistent",
) -> dict[str, Any]:
    """Build deterministic synthetic input for oracle tests; it is not evidence."""

    empty_sha256 = sha256_bytes(b"")
    manifest_sha256 = sha256_bytes(b"fixed host manifest")
    return {
        "schema": EVIDENCE_SCHEMA,
        "outcome": outcome,
        "selector": SELECTOR,
        "argv": list(EXACT_ARGV),
        "hashes": {
            "binary_sha256": sha256_bytes(b"future again binary"),
            "source_sha256": sha256_bytes(b"future source tree"),
            "fixture_sha256": FIXTURE_SHA256,
        },
        "qualified_tuple_evidence": {
            "schema": QUALIFIED_TUPLE_EVIDENCE_SCHEMA,
            "reference": "qualified-tuples/linux-x86_64-v1.json",
            "sha256": sha256_bytes(b"qualified tuple evidence"),
        },
        "streams": {
            "stdout": {
                "captured_length": 0,
                "captured_sha256": empty_sha256,
                "delivered_length": 0,
                "delivered_sha256": empty_sha256,
            },
            "stderr": {
                "captured_length": 0,
                "captured_sha256": empty_sha256,
                "delivered_length": 0,
                "delivered_sha256": empty_sha256,
            },
        },
        "raw_final_wait_status": 0,
        "host_manifest": {
            "before_sha256": manifest_sha256,
            "after_sha256": manifest_sha256,
            "unchanged": True,
        },
        "cleanup_canaries": {
            "network": True,
            "fd": True,
            "mount": True,
            "namespace": True,
            "task": True,
            "branch": True,
        },
        "descendant_reap": {
            "all_descendants_terminally_reaped": True,
            "final_wait_error": "ECHILD",
        },
        "execute_only_reason": "gate3_execute_only",
        "counts": {"candidate": 0, "shadow": 0, "promotion": 0, "replay": 0},
        "authority_claims": {
            "pass_claimed": False,
            "qualification_claimed": False,
            "execution_authority_claimed": False,
            "reuse_authority_claimed": False,
        },
    }
