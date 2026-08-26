#!/usr/bin/env python3
"""Bounded reference oracle for the fixed Gate 3 snapshot fixture.

The oracle reads a closed fixture tree, one regular binary, one local
qualified-tuple reference, and a strict JSON request.  It never executes the
binary or pytest, accesses a network, follows a symlink, or writes into an
input tree.  Its output is deterministic diagnostic data only and cannot grant
pass, qualification, execution, or reuse authority.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import dataclasses
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any, Iterable


FIXTURE_SCHEMA = "again.linux-pytest.execute-only-fixture.v1"
REQUEST_SCHEMA = "again.linux-pytest.execute-only-snapshot-request.v1"
EVIDENCE_SCHEMA = "again.linux-pytest.execute-only-snapshot-evidence.v1"
QUALIFIED_TUPLE_SCHEMA = "again.linux-pytest.qualified-tuple-evidence.v1"
ORACLE_ID = "gate3-fixed-snapshot-reference-v1"

SELECTOR = "tests/test_smoke.py::test_smoke"
FIXTURE_PATH = "tests/test_smoke.py"
BINARY_ARGV_PATH = ".venv/bin/python"
QUALIFIED_TUPLE_REFERENCE = "qualified-tuples/linux-x86_64-v1.json"
EXACT_ARGV = (
    BINARY_ARGV_PATH,
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

MAX_REQUEST_BYTES = 16 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_FIXTURE_BYTES = 4 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_QUALIFIED_TUPLE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024
MAX_REFERENCE_BYTES = 1024
READ_CHUNK_BYTES = 64 * 1024

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
AUTHORITY_FIELDS = ("pass", "qualification", "execution", "reuse")
AUTHORITY_FALSE = {field: False for field in AUTHORITY_FIELDS}

EXPECTED_FIXTURE_IDENTITY: dict[str, Any] = {
    "schema": FIXTURE_SCHEMA,
    "selector": SELECTOR,
    "path": FIXTURE_PATH,
    "length": FIXTURE_LENGTH,
    "sha256": FIXTURE_SHA256,
}
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


class SnapshotRefusal(ValueError):
    """Stable fail-closed refusal from the reference oracle."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True)
class StableInput:
    length: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class FixtureObservation:
    manifest: StableInput
    selector: StableInput
    root_identity: tuple[int, int]
    tests_identity: tuple[int, int]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotRefusal("json_duplicate_key")
        result[key] = value
    return result


def decode_strict_json(raw: bytes, *, malformed_code: str) -> Any:
    if type(raw) is not bytes:
        raise SnapshotRefusal("input_bytes_required")
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_duplicate_keys)
    except SnapshotRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SnapshotRefusal(malformed_code) from error


def _exact_keys(value: Any, expected: Iterable[str], code: str) -> None:
    if type(value) is not dict or set(value) != set(expected):
        raise SnapshotRefusal(code)


def _is_sha256(value: Any) -> bool:
    return type(value) is str and SHA256_RE.fullmatch(value) is not None


def _is_git_sha(value: Any) -> bool:
    return type(value) is str and GIT_SHA_RE.fullmatch(value) is not None


def _require_canonical_relative_path(value: Any, *, exact: str | None = None) -> str:
    if type(value) is not str:
        raise SnapshotRefusal("path_malformed")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SnapshotRefusal("path_malformed") from error
    parts = value.split("/")
    if (
        not encoded
        or len(encoded) > MAX_REFERENCE_BYTES
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in parts)
        or any(byte < 0x20 or byte == 0x7F for byte in encoded)
        or (exact is not None and value != exact)
    ):
        raise SnapshotRefusal("path_escape")
    return value


def _false_authority(value: Any, code: str = "authority_malformed") -> None:
    _exact_keys(value, AUTHORITY_FIELDS, code)
    if any(type(value[field]) is not bool for field in AUTHORITY_FIELDS):
        raise SnapshotRefusal(code)
    if any(value[field] is not False for field in AUTHORITY_FIELDS):
        raise SnapshotRefusal("authority_claimed")


def _new_false_authority() -> dict[str, bool]:
    # Never derive emitted authority from caller-owned or mutable module data.
    return {field: False for field in AUTHORITY_FIELDS}


def _reject_nested_authority_claims(value: Any) -> None:
    if type(value) is dict:
        for key, child in value.items():
            normalized = key.lower()
            authority_leaf = (
                normalized in AUTHORITY_FIELDS
                or normalized.endswith("_authority")
                or normalized.endswith("_authority_claimed")
                or normalized.endswith("_claimed")
            )
            if authority_leaf and (type(child) is not bool or child is not False):
                raise SnapshotRefusal("qualified_tuple_authority_claimed")
            _reject_nested_authority_claims(child)
    elif type(value) is list:
        for child in value:
            _reject_nested_authority_claims(child)


def validate_request(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_REQUEST_BYTES:
        raise SnapshotRefusal("request_oversized")
    request = decode_strict_json(raw, malformed_code="request_json_malformed")
    _exact_keys(
        request,
        {
            "schema",
            "argv",
            "fixture",
            "binary",
            "source",
            "qualified_tuple",
            "authority",
        },
        "request_shape_malformed",
    )
    if request["schema"] != REQUEST_SCHEMA:
        raise SnapshotRefusal("request_schema_mismatch")
    if type(request["argv"]) is not list or tuple(request["argv"]) != EXACT_ARGV:
        raise SnapshotRefusal("argv_mismatch")
    _exact_keys(request["fixture"], EXPECTED_FIXTURE_IDENTITY, "fixture_identity_malformed")
    fixture = request["fixture"]
    if (
        type(fixture["schema"]) is not str
        or type(fixture["selector"]) is not str
        or type(fixture["path"]) is not str
        or type(fixture["length"]) is not int
        or type(fixture["sha256"]) is not str
        or fixture != EXPECTED_FIXTURE_IDENTITY
    ):
        raise SnapshotRefusal("fixture_identity_mismatch")

    _exact_keys(request["binary"], {"path", "sha256"}, "binary_binding_malformed")
    _require_canonical_relative_path(
        request["binary"]["path"], exact=BINARY_ARGV_PATH
    )
    if not _is_sha256(request["binary"]["sha256"]):
        raise SnapshotRefusal("binary_sha256_malformed")

    _exact_keys(request["source"], {"git_sha"}, "source_binding_malformed")
    if not _is_git_sha(request["source"]["git_sha"]):
        raise SnapshotRefusal("source_git_sha_malformed")

    _exact_keys(
        request["qualified_tuple"],
        {"schema", "reference", "sha256"},
        "qualified_tuple_binding_malformed",
    )
    if request["qualified_tuple"]["schema"] != QUALIFIED_TUPLE_SCHEMA:
        raise SnapshotRefusal("qualified_tuple_schema_mismatch")
    _require_canonical_relative_path(
        request["qualified_tuple"]["reference"],
        exact=QUALIFIED_TUPLE_REFERENCE,
    )
    if not _is_sha256(request["qualified_tuple"]["sha256"]):
        raise SnapshotRefusal("qualified_tuple_sha256_malformed")
    _false_authority(request["authority"])
    return request


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _regular_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _path_components(path: os.PathLike[str] | str) -> tuple[bool, tuple[str, ...]]:
    raw = os.fspath(path)
    if type(raw) is not str or not raw or "\x00" in raw:
        raise SnapshotRefusal("path_malformed")
    pure = pathlib.PurePath(raw)
    absolute = pure.is_absolute()
    parts = pure.parts[1:] if absolute else pure.parts
    if not parts or any(part in {"", ".", "..", "/"} for part in parts):
        raise SnapshotRefusal("path_escape")
    return absolute, tuple(parts)


def _open_directory_no_follow(path: os.PathLike[str] | str) -> int:
    if os.fspath(path) == ".":
        try:
            return os.open(".", _directory_flags())
        except OSError as error:
            raise SnapshotRefusal("directory_unavailable") from error
    absolute, parts = _path_components(path)
    try:
        descriptor = os.open("/" if absolute else ".", _directory_flags())
    except OSError as error:
        raise SnapshotRefusal("directory_unavailable") from error
    try:
        for part in parts:
            try:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise SnapshotRefusal("symlink_or_directory_unavailable") from error
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    return bool(metadata.st_size and blocks is not None and blocks * 512 < metadata.st_size)


def _require_regular(metadata: os.stat_result, limit: int) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise SnapshotRefusal("input_symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise SnapshotRefusal("input_special_file")
    if metadata.st_nlink != 1:
        raise SnapshotRefusal("input_hardlinked")
    if metadata.st_size > limit:
        raise SnapshotRefusal("input_oversized")
    if _is_sparse(metadata):
        raise SnapshotRefusal("input_sparse")


def _read_stable_regular_at(
    directory_fd: int,
    name: str,
    *,
    limit: int,
) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise SnapshotRefusal("input_unavailable") from error
    _require_regular(before, limit)
    try:
        descriptor = os.open(name, _regular_flags(), dir_fd=directory_fd)
    except OSError as error:
        raise SnapshotRefusal("input_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular(opened, limit)
        if _identity(opened) != _identity(before):
            raise SnapshotRefusal("input_changed")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > limit:
                raise SnapshotRefusal("input_oversized")
        after_open = os.fstat(descriptor)
        try:
            after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise SnapshotRefusal("input_changed") from error
        if (
            _identity(after_open) != _identity(opened)
            or _identity(after_path) != _identity(opened)
            or observed != opened.st_size
        ):
            raise SnapshotRefusal("input_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_stable_path(path: os.PathLike[str] | str, *, limit: int) -> bytes:
    absolute, parts = _path_components(path)
    if not parts:
        raise SnapshotRefusal("path_malformed")
    parent_parts, name = parts[:-1], parts[-1]
    parent = pathlib.Path("/" if absolute else ".")
    for part in parent_parts:
        parent /= part
    directory_fd = _open_directory_no_follow(parent)
    try:
        return _read_stable_regular_at(directory_fd, name, limit=limit)
    finally:
        os.close(directory_fd)


def _scan_names(directory_fd: int) -> list[str]:
    try:
        with os.scandir(directory_fd) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError as error:
        raise SnapshotRefusal("fixture_unavailable") from error
    if any(type(name) is not str for name in names):
        raise SnapshotRefusal("fixture_entry_name_malformed")
    return names


def validate_fixture(
    fixture_root: os.PathLike[str] | str = DEFAULT_FIXTURE_ROOT,
) -> FixtureObservation:
    root_fd = _open_directory_no_follow(fixture_root)
    try:
        root_before = os.fstat(root_fd)
        if not stat.S_ISDIR(root_before.st_mode):
            raise SnapshotRefusal("fixture_not_directory")
        if _scan_names(root_fd) != ["manifest.json", "tests"]:
            raise SnapshotRefusal("fixture_inputs_mismatch")
        try:
            tests_fd = os.open("tests", _directory_flags(), dir_fd=root_fd)
        except OSError as error:
            raise SnapshotRefusal("fixture_symlink_or_unavailable") from error
        try:
            tests_before = os.fstat(tests_fd)
            if not stat.S_ISDIR(tests_before.st_mode):
                raise SnapshotRefusal("fixture_not_directory")
            if _scan_names(tests_fd) != ["test_smoke.py"]:
                raise SnapshotRefusal("fixture_inputs_mismatch")
            fixture_raw = _read_stable_regular_at(
                tests_fd, "test_smoke.py", limit=MAX_FIXTURE_BYTES
            )
            tests_after = os.fstat(tests_fd)
            if _directory_identity(tests_after) != _directory_identity(tests_before):
                raise SnapshotRefusal("fixture_changed")
        finally:
            os.close(tests_fd)

        manifest_raw = _read_stable_regular_at(
            root_fd, "manifest.json", limit=MAX_MANIFEST_BYTES
        )
        root_after = os.fstat(root_fd)
        if _directory_identity(root_after) != _directory_identity(root_before):
            raise SnapshotRefusal("fixture_changed")
    finally:
        os.close(root_fd)

    manifest = decode_strict_json(manifest_raw, malformed_code="fixture_manifest_malformed")
    if manifest != EXPECTED_MANIFEST or manifest_raw != canonical_json_bytes(EXPECTED_MANIFEST):
        raise SnapshotRefusal("fixture_manifest_drift")
    try:
        encoded_fixture = base64.b64decode(
            manifest["files"][0]["bytes_base64"], validate=True
        )
    except (binascii.Error, KeyError, TypeError, ValueError) as error:
        raise SnapshotRefusal("fixture_manifest_drift") from error
    if (
        encoded_fixture != FIXTURE_BYTES
        or fixture_raw != FIXTURE_BYTES
        or len(fixture_raw) != FIXTURE_LENGTH
        or sha256_bytes(fixture_raw) != FIXTURE_SHA256
    ):
        raise SnapshotRefusal("fixture_content_drift")
    return FixtureObservation(
        manifest=StableInput(len(manifest_raw), sha256_bytes(manifest_raw)),
        selector=StableInput(len(fixture_raw), sha256_bytes(fixture_raw)),
        root_identity=(root_before.st_dev, root_before.st_ino),
        tests_identity=(tests_before.st_dev, tests_before.st_ino),
    )


def build_snapshot_evidence(
    request_raw: bytes,
    *,
    fixture_root: os.PathLike[str] | str,
    binary_path: os.PathLike[str] | str,
    qualified_tuple_path: os.PathLike[str] | str,
    expected_source_git_sha: str,
) -> bytes:
    """Return canonical non-authoritative evidence after stable input reads."""

    request = validate_request(request_raw)
    if not _is_git_sha(expected_source_git_sha):
        raise SnapshotRefusal("expected_source_git_sha_malformed")
    if request["source"]["git_sha"] != expected_source_git_sha:
        raise SnapshotRefusal("source_git_sha_mismatch")

    fixture = validate_fixture(fixture_root)
    binary = _read_stable_path(binary_path, limit=MAX_BINARY_BYTES)
    binary_sha256 = sha256_bytes(binary)
    if request["binary"]["sha256"] != binary_sha256:
        raise SnapshotRefusal("binary_sha256_mismatch")

    qualified_tuple = _read_stable_path(
        qualified_tuple_path, limit=MAX_QUALIFIED_TUPLE_BYTES
    )
    tuple_value = decode_strict_json(
        qualified_tuple, malformed_code="qualified_tuple_json_malformed"
    )
    if type(tuple_value) is not dict or tuple_value.get("schema") != QUALIFIED_TUPLE_SCHEMA:
        raise SnapshotRefusal("qualified_tuple_schema_mismatch")
    _reject_nested_authority_claims(tuple_value)
    tuple_sha256 = sha256_bytes(qualified_tuple)
    if request["qualified_tuple"]["sha256"] != tuple_sha256:
        raise SnapshotRefusal("qualified_tuple_sha256_mismatch")

    bindings = {
        "argv": list(EXACT_ARGV),
        "fixture": dict(EXPECTED_FIXTURE_IDENTITY),
        "binary": {"path": BINARY_ARGV_PATH, "length": len(binary), "sha256": binary_sha256},
        "source": {"git_sha": expected_source_git_sha},
        "qualified_tuple": dict(request["qualified_tuple"]),
    }
    snapshot = {
        "input_count": 3,
        "manifest": dataclasses.asdict(fixture.manifest),
        "selector": {
            "path": FIXTURE_PATH,
            **dataclasses.asdict(fixture.selector),
        },
    }
    commitment = sha256_bytes(
        canonical_json_bytes({"bindings": bindings, "snapshot": snapshot})
    )
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "oracle": ORACLE_ID,
        "bindings": bindings,
        "snapshot": snapshot,
        "commitment_sha256": commitment,
        "authority": _new_false_authority(),
    }
    rendered = canonical_json_bytes(evidence)
    if len(rendered) > MAX_OUTPUT_BYTES:
        raise SnapshotRefusal("output_oversized")
    return rendered


def write_exclusive(
    output_directory: os.PathLike[str] | str,
    output_name: str,
    value: bytes,
    *,
    forbidden_directory_identities: Iterable[tuple[int, int]] = (),
) -> None:
    """Create one output atomically enough to refuse every overwrite attempt."""

    _require_canonical_relative_path(output_name)
    if "/" in output_name or not output_name.endswith(".json"):
        raise SnapshotRefusal("output_name_malformed")
    if type(value) is not bytes or len(value) > MAX_OUTPUT_BYTES:
        raise SnapshotRefusal("output_oversized")
    directory_fd = _open_directory_no_follow(output_directory)
    descriptor: int | None = None
    created = False
    try:
        metadata = os.fstat(directory_fd)
        if (metadata.st_dev, metadata.st_ino) in set(forbidden_directory_identities):
            raise SnapshotRefusal("source_mutation_forbidden")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(output_name, flags, 0o600, dir_fd=directory_fd)
            created = True
        except FileExistsError as error:
            raise SnapshotRefusal("output_exists") from error
        except OSError as error:
            raise SnapshotRefusal("output_unavailable") from error
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise SnapshotRefusal("output_write_failed")
            offset += written
        os.fsync(descriptor)
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                os.unlink(output_name, dir_fd=directory_fd)
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory_fd)


def build_request_for_test(
    *,
    binary_sha256: str,
    source_git_sha: str,
    qualified_tuple_sha256: str,
) -> dict[str, Any]:
    """Construct deterministic synthetic input; this is never evidence."""

    return {
        "schema": REQUEST_SCHEMA,
        "argv": list(EXACT_ARGV),
        "fixture": dict(EXPECTED_FIXTURE_IDENTITY),
        "binary": {"path": BINARY_ARGV_PATH, "sha256": binary_sha256},
        "source": {"git_sha": source_git_sha},
        "qualified_tuple": {
            "schema": QUALIFIED_TUPLE_SCHEMA,
            "reference": QUALIFIED_TUPLE_REFERENCE,
            "sha256": qualified_tuple_sha256,
        },
        "authority": _new_false_authority(),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=pathlib.Path)
    parser.add_argument("--fixture-root", required=True, type=pathlib.Path)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--qualified-tuple", required=True, type=pathlib.Path)
    parser.add_argument("--expected-source-git-sha", required=True)
    parser.add_argument("--output-directory", required=True, type=pathlib.Path)
    parser.add_argument("--output-name", default="snapshot-evidence.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        request_raw = _read_stable_path(arguments.request, limit=MAX_REQUEST_BYTES)
        fixture = validate_fixture(arguments.fixture_root)
        evidence = build_snapshot_evidence(
            request_raw,
            fixture_root=arguments.fixture_root,
            binary_path=arguments.binary,
            qualified_tuple_path=arguments.qualified_tuple,
            expected_source_git_sha=arguments.expected_source_git_sha,
        )
        write_exclusive(
            arguments.output_directory,
            arguments.output_name,
            evidence,
            forbidden_directory_identities=(fixture.root_identity, fixture.tests_identity),
        )
    except SnapshotRefusal as refusal:
        print(f"snapshot oracle refused: {refusal.code}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
