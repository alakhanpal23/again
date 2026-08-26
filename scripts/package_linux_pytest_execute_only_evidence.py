#!/usr/bin/env python3
"""Deterministically package non-authoritative Gate 3 evidence.

The assembler reads one closed five-file input directory, writes one new ZIP,
and retains it only after the existing offline verifier accepts it against
independently supplied expectations.  It never executes pytest or any other
command, accesses a network, follows a symlink, overwrites an output, or writes
inside the input directory.  A retained archive is evidence data only and
creates no pass, qualification, execution, candidate, hit, replay, or reuse
authority.
"""

from __future__ import annotations

import argparse
import dataclasses
import errno
import hashlib
import io
import json
import os
from pathlib import Path, PurePath, PurePosixPath
import re
import secrets
import stat
import sys
from typing import Any
import zipfile

try:
    from scripts import verify_linux_pytest_execute_only_evidence as verifier
except ModuleNotFoundError:  # Direct `python scripts/package_...py` invocation.
    import verify_linux_pytest_execute_only_evidence as verifier


MEMBER_ORDER = (
    verifier.RECORD_MEMBER,
    verifier.FIXTURE_MANIFEST_MEMBER,
    verifier.REPORT_MEMBER,
    verifier.STDOUT_MEMBER,
    verifier.STDERR_MEMBER,
)
JSON_MEMBERS = frozenset(
    {
        verifier.RECORD_MEMBER,
        verifier.FIXTURE_MANIFEST_MEMBER,
        verifier.REPORT_MEMBER,
    }
)
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
OUTPUT_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip\Z")
SOURCE_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class AssemblyRefusal(ValueError):
    """Stable fail-closed refusal from the evidence assembler."""

    def __init__(self, code: str, *, cleanup_complete: bool = True):
        super().__init__(code)
        self.code = code
        self.cleanup_complete = cleanup_complete


@dataclasses.dataclass(frozen=True)
class IndependentExpectations:
    source_commit: str
    binary_sha256: str
    source_sha256: str
    qualified_tuple_reference: str
    qualified_tuple_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.source_commit) is not str
            or SOURCE_COMMIT_RE.fullmatch(self.source_commit) is None
        ):
            raise AssemblyRefusal("source_commit_malformed")
        for value, code in (
            (self.binary_sha256, "binary_sha256_malformed"),
            (self.source_sha256, "source_sha256_malformed"),
            (self.qualified_tuple_sha256, "qualified_tuple_sha256_malformed"),
        ):
            if type(value) is not str or SHA256_RE.fullmatch(value) is None:
                raise AssemblyRefusal(code)
        _require_reference(self.qualified_tuple_reference)


def _require_reference(value: Any) -> str:
    if (
        type(value) is not str
        or verifier.REFERENCE_RE.fullmatch(value) is None
        or "\\" in value
    ):
        raise AssemblyRefusal("qualified_tuple_reference_malformed")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in value.split("/")):
        raise AssemblyRefusal("qualified_tuple_reference_malformed")
    return value


def _reject_duplicate_key(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssemblyRefusal("json_duplicate_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise AssemblyRefusal("json_nonfinite_number")


def _validate_json_member(name: str, raw: bytes) -> None:
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_key,
            parse_constant=_reject_json_constant,
        )
    except AssemblyRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise AssemblyRefusal("json_malformed") from error
    if type(value) is not dict:
        raise AssemblyRefusal("json_object_required")
    if name not in JSON_MEMBERS:
        raise AssemblyRefusal("internal_member_classification_error")


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _regular_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _regular_audit_flags() -> int:
    return _regular_read_flags() | getattr(os, "O_NONBLOCK", 0)


def _path_components(path: os.PathLike[str] | str) -> tuple[bool, tuple[str, ...]]:
    raw = os.fspath(path)
    if type(raw) is not str or not raw or "\x00" in raw or "\\" in raw:
        raise AssemblyRefusal("path_malformed")
    lexical_parts = raw[1:].split("/") if raw.startswith("/") else raw.split("/")
    if any(part in {"", ".", ".."} for part in lexical_parts):
        raise AssemblyRefusal("path_escape")
    pure = PurePath(raw)
    absolute = pure.is_absolute()
    parts = pure.parts[1:] if absolute else pure.parts
    if not parts or any(part in {"", ".", "..", "/"} for part in parts):
        raise AssemblyRefusal("path_escape")
    return absolute, tuple(parts)


def _open_directory_no_follow(path: os.PathLike[str] | str) -> int:
    if os.fspath(path) == ".":
        try:
            return os.open(".", _directory_flags())
        except OSError as error:
            raise AssemblyRefusal("directory_unavailable") from error
    absolute, parts = _path_components(path)
    try:
        descriptor = os.open("/" if absolute else ".", _directory_flags())
    except OSError as error:
        raise AssemblyRefusal("directory_unavailable") from error
    try:
        for part in parts:
            try:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise AssemblyRefusal("symlink_or_directory_unavailable") from error
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _require_regular_input(metadata: os.stat_result, limit: int) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise AssemblyRefusal("input_symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise AssemblyRefusal("input_special_file")
    if metadata.st_nlink != 1:
        raise AssemblyRefusal("input_hardlinked")
    if metadata.st_size > limit:
        raise AssemblyRefusal("input_oversized")
    if _is_sparse(metadata):
        raise AssemblyRefusal("input_sparse")


def _read_stable_member(directory_fd: int, name: str, limit: int) -> bytes:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError as error:
        raise AssemblyRefusal("input_unavailable") from error
    _require_regular_input(before, limit)
    try:
        descriptor = os.open(name, _regular_read_flags(), dir_fd=directory_fd)
    except OSError as error:
        raise AssemblyRefusal("input_unavailable") from error
    try:
        opened = os.fstat(descriptor)
        _require_regular_input(opened, limit)
        if _file_identity(opened) != _file_identity(before):
            raise AssemblyRefusal("input_changed")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > limit:
                raise AssemblyRefusal("input_oversized")
        after_open = os.fstat(descriptor)
        try:
            after_path = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise AssemblyRefusal("input_changed") from error
        if (
            _file_identity(after_open) != _file_identity(opened)
            or _file_identity(after_path) != _file_identity(opened)
            or observed != opened.st_size
        ):
            raise AssemblyRefusal("input_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def read_closed_input_directory(
    input_directory: os.PathLike[str] | str,
) -> tuple[dict[str, bytes], tuple[int, int]]:
    """Read the exact five stable inputs without following any component."""

    directory_fd = _open_directory_no_follow(input_directory)
    try:
        before = os.fstat(directory_fd)
        if not stat.S_ISDIR(before.st_mode):
            raise AssemblyRefusal("input_not_directory")
        try:
            with os.scandir(directory_fd) as entries:
                names = sorted(entry.name for entry in entries)
        except OSError as error:
            raise AssemblyRefusal("input_directory_unavailable") from error
        if names != sorted(verifier.EXPECTED_MEMBERS):
            raise AssemblyRefusal("input_member_set_mismatch")

        contents: dict[str, bytes] = {}
        total = 0
        for name in MEMBER_ORDER:
            raw = _read_stable_member(directory_fd, name, verifier.MEMBER_LIMITS[name])
            total += len(raw)
            if total > verifier.MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise AssemblyRefusal("input_total_oversized")
            if name in JSON_MEMBERS:
                _validate_json_member(name, raw)
            contents[name] = raw
        after = os.fstat(directory_fd)
        if _directory_identity(after) != _directory_identity(before):
            raise AssemblyRefusal("input_changed")
        return contents, (before.st_dev, before.st_ino)
    finally:
        os.close(directory_fd)


def build_deterministic_archive(contents: dict[str, bytes]) -> bytes:
    """Build the one canonical stored ZIP representation in memory."""

    if type(contents) is not dict or set(contents) != verifier.EXPECTED_MEMBERS:
        raise AssemblyRefusal("input_member_set_mismatch")
    total = 0
    for name in MEMBER_ORDER:
        raw = contents[name]
        if type(raw) is not bytes or len(raw) > verifier.MEMBER_LIMITS[name]:
            raise AssemblyRefusal("input_oversized")
        total += len(raw)
        if total > verifier.MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise AssemblyRefusal("input_total_oversized")
    output = io.BytesIO()
    try:
        with zipfile.ZipFile(
            output,
            mode="w",
            compression=zipfile.ZIP_STORED,
            allowZip64=False,
            strict_timestamps=True,
        ) as archive:
            archive.comment = b""
            for name in MEMBER_ORDER:
                raw = contents[name]
                info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.create_version = 20
                info.extract_version = 20
                info.flag_bits = 0
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.internal_attr = 0
                info.extra = b""
                info.comment = b""
                archive.writestr(info, raw)
    except (OSError, RuntimeError, ValueError, zipfile.LargeZipFile) as error:
        if isinstance(error, AssemblyRefusal):
            raise
        raise AssemblyRefusal("archive_construction_failed") from error
    rendered = output.getvalue()
    if not rendered or len(rendered) > verifier.MAX_ARCHIVE_BYTES:
        raise AssemblyRefusal("archive_oversized")
    return rendered


def _require_output_name(output_name: Any) -> str:
    if type(output_name) is not str or OUTPUT_NAME_RE.fullmatch(output_name) is None:
        raise AssemblyRefusal("output_name_malformed")
    if "/" in output_name or "\\" in output_name or output_name in {".", ".."}:
        raise AssemblyRefusal("path_escape")
    return output_name


def _same_created_file(
    directory_fd: int,
    output_name: str,
    identity: tuple[int, int],
) -> bool:
    try:
        current = os.stat(output_name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == identity


def _unlink_created_file(
    directory_fd: int,
    name: str,
    identity: tuple[int, int] | None,
) -> bool:
    """Remove only the exact inode created by this invocation."""

    if identity is None:
        return True
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != identity:
        return False
    try:
        os.unlink(name, dir_fd=directory_fd)
    except OSError:
        return False
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


MAX_STAGING_CREATE_ATTEMPTS = 16
STAGING_TOKEN_BYTES = 16


def _create_staging_file(directory_fd: int) -> tuple[str, int, tuple[int, int]]:
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _ in range(MAX_STAGING_CREATE_ATTEMPTS):
        name = f".again-evidence-stage-{secrets.token_hex(STAGING_TOKEN_BYTES)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
        except OSError as error:
            raise AssemblyRefusal("staging_unavailable") from error
        identity: tuple[int, int] | None = None
        try:
            initial = os.fstat(descriptor)
            identity = (initial.st_dev, initial.st_ino)
            os.fchmod(descriptor, 0o600)
            metadata = os.fstat(descriptor)
        except OSError as error:
            cleanup_complete = True
            try:
                os.close(descriptor)
            except OSError:
                cleanup_complete = False
            if identity is None:
                cleanup_complete = False
            else:
                cleanup_complete = (
                    _unlink_created_file(directory_fd, name, identity) and cleanup_complete
                )
            try:
                os.fsync(directory_fd)
            except OSError:
                cleanup_complete = False
            raise AssemblyRefusal(
                "staging_unavailable", cleanup_complete=cleanup_complete
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
        ):
            try:
                os.close(descriptor)
            except OSError:
                cleanup_complete = False
            else:
                cleanup_complete = True
            cleanup_complete = (
                _unlink_created_file(directory_fd, name, identity) and cleanup_complete
            )
            try:
                os.fsync(directory_fd)
            except OSError:
                cleanup_complete = False
            raise AssemblyRefusal(
                "staging_identity_changed", cleanup_complete=cleanup_complete
            )
        return name, descriptor, (metadata.st_dev, metadata.st_ino)
    raise AssemblyRefusal("staging_name_exhausted")


def _read_descriptor_bytes(descriptor: int, limit: int) -> tuple[bytes, os.stat_result]:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > limit
        ):
            raise AssemblyRefusal("output_identity_changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, limit + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > limit:
                raise AssemblyRefusal("output_identity_changed")
        after = os.fstat(descriptor)
    except AssemblyRefusal:
        raise
    except OSError as error:
        raise AssemblyRefusal("output_identity_changed") from error
    if _file_identity(before) != _file_identity(after) or observed != before.st_size:
        raise AssemblyRefusal("output_identity_changed")
    return b"".join(chunks), after


def _cleanup_failed_assembly(
    directory_fd: int,
    staging_name: str | None,
    created_identity: tuple[int, int] | None,
    output_name: str,
    final_identity: tuple[int, int] | None,
    cleanup_complete: bool,
) -> bool:
    complete = cleanup_complete
    if final_identity is not None:
        complete = _unlink_created_file(directory_fd, output_name, final_identity) and complete
    if staging_name is not None:
        complete = _unlink_created_file(directory_fd, staging_name, created_identity) and complete
    try:
        os.fsync(directory_fd)
    except OSError:
        complete = False
    return complete


def package_evidence(
    input_directory: os.PathLike[str] | str,
    output_directory: os.PathLike[str] | str,
    output_name: str,
    expectations: IndependentExpectations,
) -> dict[str, object]:
    """Package, independently verify, and retain one new evidence archive."""

    if type(expectations) is not IndependentExpectations:
        raise AssemblyRefusal("expectations_required")
    output_name = _require_output_name(output_name)
    contents, input_identity = read_closed_input_directory(input_directory)
    archive_bytes = build_deterministic_archive(contents)
    expected_archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()

    output_fd = _open_directory_no_follow(output_directory)
    staging_name: str | None = None
    archive_fd: int | None = None
    final_audit_fd: int | None = None
    created_identity: tuple[int, int] | None = None
    final_identity: tuple[int, int] | None = None
    output_directory_identity: tuple[int, int] | None = None
    primary: BaseException | None = None
    audit: dict[str, object] | None = None
    cleanup_complete = True
    try:
        try:
            output_metadata = os.fstat(output_fd)
        except OSError as error:
            raise AssemblyRefusal("output_unavailable") from error
        output_directory_identity = (output_metadata.st_dev, output_metadata.st_ino)
        if (output_metadata.st_dev, output_metadata.st_ino) == input_identity:
            raise AssemblyRefusal("source_mutation_forbidden")
        staging_name, archive_fd, created_identity = _create_staging_file(output_fd)
        offset = 0
        try:
            while offset < len(archive_bytes):
                written = os.write(archive_fd, archive_bytes[offset:])
                if written <= 0:
                    raise OSError("zero-length output write")
                offset += written
            os.fsync(archive_fd)
        except OSError as error:
            raise AssemblyRefusal("output_write_failed") from error

        try:
            written = os.fstat(archive_fd)
        except OSError as error:
            raise AssemblyRefusal("output_identity_changed") from error
        if (
            not stat.S_ISREG(written.st_mode)
            or stat.S_IMODE(written.st_mode) != 0o600
            or written.st_nlink != 1
            or written.st_size != len(archive_bytes)
        ):
            raise AssemblyRefusal("output_identity_changed")
        staging_path = Path(output_directory) / staging_name
        try:
            audit = verifier.verify_archive(
                staging_path,
                expectations.source_commit,
                expectations.binary_sha256,
                expectations.source_sha256,
                expectations.qualified_tuple_reference,
                expectations.qualified_tuple_sha256,
            )
        except verifier.EvidenceError as error:
            raise AssemblyRefusal("archive_verification_failed") from error
        try:
            after_verify = os.fstat(archive_fd)
        except OSError as error:
            raise AssemblyRefusal("output_identity_changed") from error
        if (
            _file_identity(after_verify) != _file_identity(written)
            or not _same_created_file(output_fd, staging_name, created_identity)
            or audit.get("archive_sha256") != expected_archive_sha256
        ):
            raise AssemblyRefusal("output_identity_changed")

        staged_bytes, staged_metadata = _read_descriptor_bytes(
            archive_fd, verifier.MAX_ARCHIVE_BYTES
        )
        if (
            staged_bytes != archive_bytes
            or hashlib.sha256(staged_bytes).hexdigest() != expected_archive_sha256
            or stat.S_IMODE(staged_metadata.st_mode) != 0o600
            or staged_metadata.st_nlink != 1
        ):
            raise AssemblyRefusal("output_identity_changed")
        try:
            os.close(archive_fd)
        except OSError as error:
            cleanup_complete = False
            raise AssemblyRefusal("output_close_failed", cleanup_complete=False) from error
        archive_fd = None

        try:
            os.link(
                staging_name,
                output_name,
                src_dir_fd=output_fd,
                dst_dir_fd=output_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise AssemblyRefusal("output_exists") from error
        except (NotImplementedError, TypeError) as error:
            raise AssemblyRefusal("publication_unsupported") from error
        except OSError as error:
            if error.errno in {errno.ENOSYS, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise AssemblyRefusal("publication_unsupported") from error
            raise AssemblyRefusal("publication_failed") from error
        final_identity = created_identity
        try:
            published = os.stat(output_name, dir_fd=output_fd, follow_symlinks=False)
        except OSError as error:
            raise AssemblyRefusal("publication_identity_changed") from error
        if (
            not stat.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino) != created_identity
            or stat.S_IMODE(published.st_mode) != 0o600
            or published.st_nlink != 2
            or published.st_size != len(archive_bytes)
        ):
            raise AssemblyRefusal("publication_identity_changed")
        if not _unlink_created_file(output_fd, staging_name, created_identity):
            raise AssemblyRefusal("staging_unlink_failed")
        staging_name = None

        try:
            os.fsync(output_fd)
        except OSError as error:
            raise AssemblyRefusal("publication_fsync_failed") from error

        try:
            final_audit_fd = os.open(output_name, _regular_audit_flags(), dir_fd=output_fd)
        except OSError as error:
            raise AssemblyRefusal("output_identity_changed") from error
        final_bytes, final_metadata = _read_descriptor_bytes(
            final_audit_fd, verifier.MAX_ARCHIVE_BYTES
        )
        try:
            final_path_metadata = os.stat(
                output_name, dir_fd=output_fd, follow_symlinks=False
            )
        except OSError as error:
            raise AssemblyRefusal("output_identity_changed") from error
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or (final_metadata.st_dev, final_metadata.st_ino) != created_identity
            or _file_identity(final_path_metadata) != _file_identity(final_metadata)
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
            or final_metadata.st_nlink != 1
            or final_metadata.st_size != len(archive_bytes)
            or final_bytes != archive_bytes
            or hashlib.sha256(final_bytes).hexdigest() != expected_archive_sha256
        ):
            raise AssemblyRefusal("output_identity_changed")
        try:
            os.close(final_audit_fd)
        except OSError as error:
            cleanup_complete = False
            raise AssemblyRefusal("output_close_failed", cleanup_complete=False) from error
        final_audit_fd = None
    except BaseException as error:
        primary = error

    if primary is None:
        try:
            os.close(output_fd)
        except OSError as error:
            recovery_fd: int | None = None
            try:
                recovery_fd = _open_directory_no_follow(output_directory)
                recovered = os.fstat(recovery_fd)
                if (recovered.st_dev, recovered.st_ino) == output_directory_identity:
                    _cleanup_failed_assembly(
                        recovery_fd,
                        staging_name,
                        created_identity,
                        output_name,
                        final_identity,
                        False,
                    )
            except (AssemblyRefusal, OSError):
                pass
            finally:
                if recovery_fd is not None:
                    try:
                        os.close(recovery_fd)
                    except OSError:
                        pass
            raise AssemblyRefusal("output_close_failed", cleanup_complete=False) from error
        if audit is None:
            raise AssemblyRefusal("internal_audit_missing")
        return audit

    for descriptor_name in ("final_audit_fd", "archive_fd"):
        descriptor = final_audit_fd if descriptor_name == "final_audit_fd" else archive_fd
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError:
            cleanup_complete = False
        if descriptor_name == "final_audit_fd":
            final_audit_fd = None
        else:
            archive_fd = None

    if isinstance(primary, AssemblyRefusal):
        cleanup_complete = primary.cleanup_complete and cleanup_complete
    cleanup_complete = _cleanup_failed_assembly(
        output_fd,
        staging_name,
        created_identity,
        output_name,
        final_identity,
        cleanup_complete,
    )
    try:
        os.close(output_fd)
    except OSError:
        cleanup_complete = False

    if isinstance(primary, AssemblyRefusal):
        raise AssemblyRefusal(primary.code, cleanup_complete=cleanup_complete) from primary
    raise primary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--output-name", default="execute-only-evidence.zip")
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--expected-source-sha256", required=True)
    parser.add_argument("--expected-qualified-tuple-reference", required=True)
    parser.add_argument("--expected-qualified-tuple-sha256", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        expectations = IndependentExpectations(
            source_commit=args.expected_source_commit,
            binary_sha256=args.expected_binary_sha256,
            source_sha256=args.expected_source_sha256,
            qualified_tuple_reference=args.expected_qualified_tuple_reference,
            qualified_tuple_sha256=args.expected_qualified_tuple_sha256,
        )
        audit = package_evidence(
            args.input_directory,
            args.output_directory,
            args.output_name,
            expectations,
        )
    except AssemblyRefusal as refusal:
        print(f"error: evidence assembly refused: {refusal.code}", file=sys.stderr)
        return 1
    print(json.dumps(audit, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
