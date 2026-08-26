#!/usr/bin/env python3
"""Validate Again against copied tracked inputs from four real repositories.

The harness itself has no clone, download, or network-client code path and
never executes source-repository code. It reads explicit local Git worktrees,
copies two deterministic tracked regular files per language into private
temporary workspaces, and exercises only the fixed read-only command corpus
declared below through a private pinned copy of the supplied Again binary.

This is not a network or hostile-process sandbox. Inherited descriptors are
closed except for one harness-owned descendant sentinel, and surviving
sentinel holders fail the run, but a hostile executable can deliberately close
that sentinel or create a separately contained process. The evidence therefore
depends on the closed trusted argv corpus and the exact pinned Again bytes.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import select
import selectors
import signal
import stat
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from typing import Any


SCHEMA = "again.real-repository-corpus.v1"
HARNESS_VERSION = "1.1.0"
COMMAND_CORPUS_VERSION = "strict-read-real-repositories.v1"
LANGUAGE_SUFFIXES: dict[str, tuple[str, ...]] = {
    "rust": (".rs",),
    "python": (".py",),
    "go": (".go",),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
}
LANGUAGE_ARGUMENTS: tuple[tuple[str, str], ...] = (
    ("rust", "--rust-repo"),
    ("python", "--python-repo"),
    ("go", "--go-repo"),
    ("typescript", "--typescript-repo"),
)
HEX_OBJECT_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS = 2.0
PROCESS_SESSION_DRAIN_TIMEOUT_SECONDS = 0.25
PROCESS_CAPTURE_POLL_SECONDS = 0.05
PROCESS_CAPTURE_CHUNK_BYTES = 64 * 1024


@dataclasses.dataclass(frozen=True)
class Limits:
    max_tracked_files: int = 100_000
    max_manifest_bytes: int = 32 * 1024 * 1024
    max_status_bytes: int = 4 * 1024 * 1024
    max_repository_logical_bytes: int = 8 * 1024 * 1024 * 1024
    max_selected_file_bytes: int = 8 * 1024 * 1024
    max_binary_bytes: int = 256 * 1024 * 1024
    selected_files: int = 2
    stream_bytes: int = 16 * 1024 * 1024
    timeout_seconds: float = 60.0


DEFAULT_LIMITS = Limits()


class HarnessRefusal(RuntimeError):
    """A typed fail-closed harness outcome."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class Completed:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float


@dataclasses.dataclass(frozen=True)
class TrackedEntry:
    mode: str
    object_id: str
    path: str
    path_bytes: bytes


@dataclasses.dataclass(frozen=True)
class SelectedFile:
    path: str
    size: int
    sha256: str
    executable: bool
    stat_fingerprint: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class RepositorySnapshot:
    language: str
    root: pathlib.Path
    git_sha: str
    dirty: bool
    dirty_status_sha256: str
    tracked_manifest_sha256: str
    tracked_worktree_stat_sha256: str
    tracked_files: int
    repository_logical_bytes: int
    selected: tuple[SelectedFile, ...]


@dataclasses.dataclass(frozen=True)
class PinnedBinary:
    source: pathlib.Path
    executable: pathlib.Path
    sha256: str
    size: int
    source_fingerprint: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str, ...]


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as error:
        raise HarnessRefusal(
            "process_tree_cleanup_failed",
            f"cannot inspect owned process group {process_group}",
        ) from error
    return True


def _cleanup_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill the owned process group and report whether a survivor was present."""

    process_group = process.pid
    survivor_present = _process_group_exists(process_group)
    if survivor_present:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise HarnessRefusal(
            "process_tree_cleanup_failed",
            f"process-group leader {process.pid} did not reap after SIGKILL",
        ) from error

    deadline = time.monotonic() + PROCESS_GROUP_CLEANUP_TIMEOUT_SECONDS
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            raise HarnessRefusal(
                "process_tree_cleanup_failed",
                f"owned process group {process_group} survived SIGKILL",
            )
        time.sleep(0.01)
    return survivor_present


def _sentinel_reached_eof(descriptor: int) -> bool:
    readable, _writable, _exceptional = select.select(
        [descriptor], [], [], PROCESS_SESSION_DRAIN_TIMEOUT_SECONDS
    )
    return bool(readable) and os.read(descriptor, 1) == b""


def _capture_ready_streams(
    stream_selector: selectors.BaseSelector,
    buffers: dict[int, bytearray],
    stream_limit_bytes: int,
    timeout_seconds: float,
) -> bool:
    """Capture ready pipe bytes and report whether either bound was exceeded."""

    for key, _mask in stream_selector.select(timeout_seconds):
        descriptor = key.fd
        while True:
            try:
                retained_room = stream_limit_bytes + 1 - len(buffers[descriptor])
                chunk = os.read(
                    descriptor,
                    min(PROCESS_CAPTURE_CHUNK_BYTES, max(1, retained_room)),
                )
            except BlockingIOError:
                break
            if not chunk:
                stream_selector.unregister(descriptor)
                break
            buffers[descriptor].extend(chunk)
            if len(buffers[descriptor]) > stream_limit_bytes:
                return True
    return False


def _discard_ready_streams(
    stream_selector: selectors.BaseSelector, timeout_seconds: float
) -> None:
    """Drain killed-process pipes without retaining bytes beyond the evidence cap."""

    for key, _mask in stream_selector.select(timeout_seconds):
        descriptor = key.fd
        while True:
            try:
                chunk = os.read(descriptor, PROCESS_CAPTURE_CHUNK_BYTES)
            except BlockingIOError:
                break
            if not chunk:
                stream_selector.unregister(descriptor)
                break


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    timeout_seconds: float,
    stream_limit_bytes: int,
) -> Completed:
    """Run a noninteractive process with bounded captured streams."""

    if timeout_seconds <= 0 or stream_limit_bytes < 0:
        raise ValueError("process bounds must be nonnegative and timeout must be positive")

    sentinel_read, sentinel_write = os.pipe()
    started = time.perf_counter_ns()
    try:
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(sentinel_write,),
            start_new_session=True,
        )
    except BaseException:
        os.close(sentinel_read)
        os.close(sentinel_write)
        raise
    os.close(sentinel_write)
    assert process.stdout is not None and process.stderr is not None
    streams = (process.stdout, process.stderr)
    stream_selector = selectors.DefaultSelector()
    buffers: dict[int, bytearray] = {}
    for stream in streams:
        descriptor = stream.fileno()
        os.set_blocking(descriptor, False)
        buffers[descriptor] = bytearray()
        stream_selector.register(descriptor, selectors.EVENT_READ)
    stdout_descriptor, stderr_descriptor = (stream.fileno() for stream in streams)

    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    stream_limit_exceeded = False
    try:
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if _capture_ready_streams(
                stream_selector,
                buffers,
                stream_limit_bytes,
                min(PROCESS_CAPTURE_POLL_SECONDS, remaining),
            ):
                stream_limit_exceeded = True
                break

        survivor_present = _cleanup_process_group(process)
        drain_deadline = time.monotonic() + PROCESS_SESSION_DRAIN_TIMEOUT_SECONDS
        while stream_selector.get_map() and time.monotonic() < drain_deadline:
            remaining = max(0.0, drain_deadline - time.monotonic())
            if stream_limit_exceeded:
                _discard_ready_streams(stream_selector, remaining)
            elif _capture_ready_streams(
                stream_selector, buffers, stream_limit_bytes, remaining
            ):
                stream_limit_exceeded = True
        streams_closed = not stream_selector.get_map()
        sentinel_closed = _sentinel_reached_eof(sentinel_read)
    except BaseException:
        _cleanup_process_group(process)
        raise
    finally:
        stream_selector.close()
        for stream in streams:
            stream.close()
        os.close(sentinel_read)

    if not sentinel_closed or not streams_closed:
        raise HarnessRefusal(
            "process_session_escape_detected",
            f"a descendant retained a harness channel after command exit: {argv!r}",
        )
    if timed_out:
        raise HarnessRefusal(
            "command_timeout", f"command exceeded {timeout_seconds:g}s: {argv!r}"
        )
    if stream_limit_exceeded:
        raise HarnessRefusal(
            "stream_limit_exceeded",
            f"command exceeded the {stream_limit_bytes}-byte stream limit: {argv!r}",
        )
    if survivor_present:
        raise HarnessRefusal(
            "unexpected_descendant",
            f"a descendant outlived the command leader: {argv!r}",
        )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return Completed(
        argv=tuple(argv),
        returncode=process.returncode,
        stdout=bytes(buffers[stdout_descriptor]),
        stderr=bytes(buffers[stderr_descriptor]),
        elapsed_ms=elapsed_ms,
    )


def _git_environment() -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def run_git(
    root: pathlib.Path,
    arguments: Sequence[str],
    *,
    limit_bytes: int,
) -> bytes:
    completed = run_bounded(
        ("git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *arguments),
        cwd=root,
        environment=_git_environment(),
        timeout_seconds=30.0,
        stream_limit_bytes=limit_bytes,
    )
    if completed.returncode != 0:
        raise HarnessRefusal(
            "git_inspection_failed",
            f"read-only git inspection failed for {root}: "
            f"{completed.stderr[:512].decode(errors='replace')}",
        )
    return completed.stdout


def require_absolute_directory(path: pathlib.Path, label: str) -> pathlib.Path:
    if not path.is_absolute():
        raise HarnessRefusal("path_not_absolute", f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise HarnessRefusal("path_unavailable", f"{label} is unavailable: {error}") from error
    if resolved != path:
        raise HarnessRefusal("path_not_canonical", f"{label} must be canonical and symlink-free")
    if not resolved.is_dir():
        raise HarnessRefusal("path_not_directory", f"{label} is not a directory")
    prefix = run_git(
        resolved,
        ("rev-parse", "--show-prefix"),
        limit_bytes=4096,
    )
    if prefix != b"\n":
        raise HarnessRefusal("not_repository_root", f"{label} must name the Git worktree root")
    return resolved


def parse_tracked_manifest(raw: bytes, limits: Limits) -> tuple[TrackedEntry, ...]:
    if len(raw) > limits.max_manifest_bytes:
        raise HarnessRefusal("repository_oversized", "tracked manifest exceeds its byte bound")
    records = raw.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > limits.max_tracked_files:
        raise HarnessRefusal("repository_oversized", "tracked file count exceeds its bound")
    entries: list[TrackedEntry] = []
    seen: set[bytes] = set()
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_bytes, object_bytes, stage_bytes = header.split(b" ")
            mode = mode_bytes.decode("ascii")
            object_id = object_bytes.decode("ascii")
            stage = stage_bytes.decode("ascii")
            path = os.fsdecode(raw_path)
        except (ValueError, UnicodeDecodeError) as error:
            raise HarnessRefusal("tracked_manifest_malformed", "malformed tracked entry") from error
        path_parts = pathlib.PurePosixPath(path).parts
        if (
            not raw_path
            or pathlib.PurePosixPath(path).is_absolute()
            or ".." in path_parts
            or any(part.lower() == ".git" for part in path_parts)
            or stage != "0"
            or not HEX_OBJECT_RE.fullmatch(object_id)
            or mode not in {"100644", "100755", "120000", "160000"}
            or raw_path in seen
        ):
            raise HarnessRefusal("tracked_manifest_malformed", f"unsafe tracked entry: {path!r}")
        if os.fsencode(path) != raw_path:
            raise HarnessRefusal(
                "tracked_filename_unsupported",
                "tracked filename is not losslessly representable on this host",
            )
        seen.add(raw_path)
        entries.append(
            TrackedEntry(mode=mode, object_id=object_id, path=path, path_bytes=raw_path)
        )
    return tuple(sorted(entries, key=lambda entry: entry.path_bytes))


def _stat_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def is_sparse(metadata: os.stat_result) -> bool:
    blocks = getattr(metadata, "st_blocks", None)
    return metadata.st_size > 0 and blocks is not None and blocks * 512 < metadata.st_size


def _directory_open_flags() -> int:
    required = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if required is None or nofollow is None:
        raise HarnessRefusal(
            "descriptor_walk_unsupported",
            "host lacks O_DIRECTORY or O_NOFOLLOW for source-safe inspection",
        )
    return os.O_RDONLY | required | nofollow | getattr(os, "O_CLOEXEC", 0)


def _open_parent_directory(root: pathlib.Path, relative: str) -> tuple[int, str]:
    parts = pathlib.PurePosixPath(relative).parts
    if not parts:
        raise HarnessRefusal("tracked_manifest_malformed", "tracked path has no components")
    try:
        current = os.open(root, _directory_open_flags())
    except OSError as error:
        raise HarnessRefusal(
            "selected_input_unavailable", f"source root unavailable for {relative}"
        ) from error
    try:
        for component in parts[:-1]:
            try:
                metadata = os.stat(component, dir_fd=current, follow_symlinks=False)
            except OSError as error:
                raise HarnessRefusal(
                    "selected_input_unavailable",
                    f"selected input parent unavailable: {relative}",
                ) from error
            if stat.S_ISLNK(metadata.st_mode):
                raise HarnessRefusal(
                    "selected_input_symlink",
                    f"selected input parent is a symlink: {relative}",
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise HarnessRefusal(
                    "selected_input_unavailable",
                    f"selected input parent is not a directory: {relative}",
                )
            try:
                following = os.open(component, _directory_open_flags(), dir_fd=current)
            except OSError as error:
                raise HarnessRefusal(
                    "selected_input_unavailable",
                    f"selected input parent changed: {relative}",
                ) from error
            os.close(current)
            current = following
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _lstat_tracked_path(root: pathlib.Path, relative: str) -> os.stat_result | None:
    try:
        parent, name = _open_parent_directory(root, relative)
    except HarnessRefusal as error:
        if error.code == "selected_input_unavailable":
            return None
        raise
    try:
        try:
            return os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise HarnessRefusal(
                "tracked_input_unavailable", f"tracked input unavailable: {relative}"
            ) from error
    finally:
        os.close(parent)


def _open_tracked_regular(root: pathlib.Path, relative: str) -> int:
    parent, name = _open_parent_directory(root, relative)
    try:
        try:
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise HarnessRefusal(
                "selected_input_unavailable", f"selected input unavailable: {relative}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise HarnessRefusal(
                "selected_input_symlink", f"selected input is a symlink: {relative}"
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessRefusal(
                "selected_input_special", f"selected input is not regular: {relative}"
            )
        flags = (
            os.O_RDONLY
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, dir_fd=parent)
        except OSError as error:
            raise HarnessRefusal(
                "selected_input_unavailable", f"selected input changed: {relative}"
            ) from error
        try:
            opened = os.fstat(descriptor)
        except OSError:
            os.close(descriptor)
            raise
        if not stat.S_ISREG(opened.st_mode) or _stat_fingerprint(opened) != _stat_fingerprint(
            metadata
        ):
            os.close(descriptor)
            raise HarnessRefusal(
                "selected_input_unavailable", f"selected input changed: {relative}"
            )
        return descriptor
    finally:
        os.close(parent)


def _sha256_descriptor(descriptor: int, limit_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.read(descriptor, min(1024 * 1024, limit_bytes + 1 - total))
        if not block:
            break
        total += len(block)
        if total > limit_bytes:
            raise HarnessRefusal("selected_input_oversized", "selected input grew while reading")
        digest.update(block)
    return digest.hexdigest(), total


def _open_absolute_regular_no_follow(path: pathlib.Path, label: str) -> int:
    try:
        relative = path.relative_to("/").as_posix()
    except ValueError as error:
        raise HarnessRefusal("path_not_absolute", f"{label} must be an absolute path") from error
    try:
        return _open_tracked_regular(pathlib.Path("/"), relative)
    except HarnessRefusal as error:
        raise HarnessRefusal(
            "binary_path_unsafe",
            f"{label} must have a no-follow regular-file path: {path}",
        ) from error


def _validate_binary_metadata(metadata: os.stat_result, limits: Limits) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise HarnessRefusal("binary_not_regular", "Again binary is not a regular file")
    if metadata.st_nlink != 1:
        raise HarnessRefusal("binary_hardlinked", "Again binary must have one link")
    if metadata.st_mode & 0o111 == 0:
        raise HarnessRefusal("binary_not_executable", "Again binary is not executable")
    if metadata.st_size == 0 or metadata.st_size > limits.max_binary_bytes:
        raise HarnessRefusal("binary_oversized", "Again binary has an unsupported byte size")
    if is_sparse(metadata):
        raise HarnessRefusal("binary_sparse", "Again binary must not be sparse")


def _write_all(descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        written = os.write(descriptor, value[offset:])
        if written <= 0:
            raise HarnessRefusal("binary_copy_failed", "short write while pinning Again binary")
        offset += written


def pin_again_binary(
    source: pathlib.Path,
    private_directory: pathlib.Path,
    limits: Limits = DEFAULT_LIMITS,
    *,
    after_copy: Callable[[], None] | None = None,
) -> PinnedBinary:
    """Copy one stable no-follow executable into private harness ownership."""

    private_directory.mkdir(mode=0o700)
    destination = private_directory / "again"
    source_descriptor = _open_absolute_regular_no_follow(source, "--binary")
    destination_descriptor: int | None = None
    try:
        before = os.fstat(source_descriptor)
        _validate_binary_metadata(before, limits)
        try:
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o700,
            )
        except OSError as error:
            raise HarnessRefusal("binary_copy_failed", "cannot create pinned Again binary") from error
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(
                source_descriptor,
                min(1024 * 1024, limits.max_binary_bytes + 1 - total),
            )
            if not block:
                break
            total += len(block)
            if total > limits.max_binary_bytes:
                raise HarnessRefusal("binary_oversized", "Again binary grew while pinning")
            _write_all(destination_descriptor, block)
            digest.update(block)
        os.fchmod(destination_descriptor, 0o500)
        os.fsync(destination_descriptor)
        after = os.fstat(source_descriptor)
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)

    if _stat_fingerprint(before) != _stat_fingerprint(after) or total != before.st_size:
        raise HarnessRefusal("binary_changed", "Again binary changed while being pinned")
    if after_copy is not None:
        after_copy()

    observed_descriptor = _open_absolute_regular_no_follow(source, "--binary")
    try:
        observed = os.fstat(observed_descriptor)
        _validate_binary_metadata(observed, limits)
        observed_digest, observed_size = _sha256_descriptor(
            observed_descriptor, limits.max_binary_bytes
        )
    finally:
        os.close(observed_descriptor)
    pinned_digest = sha256_file(destination)
    pinned = destination.stat()
    if (
        _stat_fingerprint(observed) != _stat_fingerprint(before)
        or observed_size != total
        or observed_digest != digest.hexdigest()
        or pinned_digest != digest.hexdigest()
        or pinned.st_size != total
        or pinned.st_nlink != 1
        or not stat.S_ISREG(pinned.st_mode)
        or pinned.st_mode & 0o111 == 0
    ):
        raise HarnessRefusal("binary_changed", "Again binary changed during stable pinning")
    return PinnedBinary(
        source=source,
        executable=destination,
        sha256=digest.hexdigest(),
        size=total,
        source_fingerprint=_stat_fingerprint(before),
    )


def verify_binary_source_unchanged(
    binary: PinnedBinary, limits: Limits = DEFAULT_LIMITS
) -> None:
    descriptor = _open_absolute_regular_no_follow(binary.source, "--binary")
    try:
        metadata = os.fstat(descriptor)
        _validate_binary_metadata(metadata, limits)
        digest, size = _sha256_descriptor(descriptor, limits.max_binary_bytes)
    finally:
        os.close(descriptor)
    if (
        _stat_fingerprint(metadata) != binary.source_fingerprint
        or digest != binary.sha256
        or size != binary.size
    ):
        raise HarnessRefusal("binary_changed", "Again binary changed during the corpus")


def _tracked_worktree_digest(
    root: pathlib.Path, entries: Sequence[TrackedEntry], limits: Limits
) -> tuple[str, int]:
    digest = hashlib.sha256()
    logical_bytes = 0
    for entry in entries:
        digest.update(entry.path_bytes)
        digest.update(b"\0")
        metadata = _lstat_tracked_path(root, entry.path)
        if metadata is None:
            digest.update(b"missing\0")
            continue
        fingerprint = _stat_fingerprint(metadata)
        digest.update(",".join(str(value) for value in fingerprint).encode("ascii"))
        digest.update(b"\0")
        if stat.S_ISREG(metadata.st_mode):
            logical_bytes += metadata.st_size
            if logical_bytes > limits.max_repository_logical_bytes:
                raise HarnessRefusal(
                    "repository_oversized", "tracked worktree bytes exceed their bound"
                )
    return digest.hexdigest(), logical_bytes


def _read_repository_state(
    root: pathlib.Path, limits: Limits
) -> tuple[str, bytes, tuple[TrackedEntry, ...], str, int, str]:
    git_sha = run_git(root, ("rev-parse", "HEAD"), limit_bytes=4096).decode(
        "ascii", errors="strict"
    ).strip()
    if not HEX_OBJECT_RE.fullmatch(git_sha):
        raise HarnessRefusal("git_head_malformed", "repository HEAD is not a canonical Git object")
    status = run_git(
        root,
        ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        limit_bytes=limits.max_status_bytes,
    )
    manifest = run_git(
        root,
        ("ls-files", "-z", "--stage"),
        limit_bytes=limits.max_manifest_bytes,
    )
    entries = parse_tracked_manifest(manifest, limits)
    stat_digest, logical_bytes = _tracked_worktree_digest(root, entries, limits)
    return git_sha, status, entries, stat_digest, logical_bytes, sha256_bytes(manifest)


def _selected_files(
    root: pathlib.Path,
    language: str,
    entries: Sequence[TrackedEntry],
    limits: Limits,
) -> tuple[SelectedFile, ...]:
    suffixes = LANGUAGE_SUFFIXES[language]
    candidates = [entry for entry in entries if entry.path.lower().endswith(suffixes)]
    if len(candidates) < limits.selected_files:
        raise HarnessRefusal(
            "insufficient_tracked_inputs",
            f"{language} repository has fewer than {limits.selected_files} tracked inputs",
        )
    selected: list[SelectedFile] = []
    for entry in candidates[: limits.selected_files]:
        if entry.mode == "120000":
            raise HarnessRefusal("selected_input_symlink", f"tracked symlink selected: {entry.path}")
        if entry.mode not in {"100644", "100755"}:
            raise HarnessRefusal("selected_input_special", f"non-regular input selected: {entry.path}")
        descriptor = _open_tracked_regular(root, entry.path)
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_size == 0:
                raise HarnessRefusal("selected_input_empty", f"empty input selected: {entry.path}")
            if metadata.st_size > limits.max_selected_file_bytes:
                raise HarnessRefusal(
                    "selected_input_oversized", f"selected input is too large: {entry.path}"
                )
            if is_sparse(metadata):
                raise HarnessRefusal(
                    "selected_input_sparse", f"sparse input selected: {entry.path}"
                )
            digest, size = _sha256_descriptor(descriptor, limits.max_selected_file_bytes)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if _stat_fingerprint(after) != _stat_fingerprint(metadata) or size != metadata.st_size:
            raise HarnessRefusal(
                "source_changed_during_inspection",
                f"selected source changed while hashing: {entry.path}",
            )
        selected.append(
            SelectedFile(
                path=entry.path,
                size=size,
                sha256=digest,
                executable=entry.mode == "100755",
                stat_fingerprint=_stat_fingerprint(metadata),
            )
        )
    return tuple(selected)


def inspect_repository(
    root: pathlib.Path, language: str, limits: Limits = DEFAULT_LIMITS
) -> RepositorySnapshot:
    if language not in LANGUAGE_SUFFIXES:
        raise ValueError(f"unsupported language: {language}")
    initial = _read_repository_state(root, limits)
    selected = _selected_files(root, language, initial[2], limits)
    final = _read_repository_state(root, limits)
    if initial != final:
        raise HarnessRefusal(
            "source_changed_during_inspection", f"source changed while inspecting {root}"
        )
    return RepositorySnapshot(
        language=language,
        root=root,
        git_sha=initial[0],
        dirty=bool(initial[1]),
        dirty_status_sha256=sha256_bytes(initial[1]),
        tracked_manifest_sha256=initial[5],
        tracked_worktree_stat_sha256=initial[3],
        tracked_files=len(initial[2]),
        repository_logical_bytes=initial[4],
        selected=selected,
    )


def _snapshot_identity(snapshot: RepositorySnapshot) -> tuple[Any, ...]:
    return (
        snapshot.git_sha,
        snapshot.dirty,
        snapshot.dirty_status_sha256,
        snapshot.tracked_manifest_sha256,
        snapshot.tracked_worktree_stat_sha256,
        snapshot.tracked_files,
        snapshot.repository_logical_bytes,
        snapshot.selected,
    )


def copy_selected_files(
    snapshot: RepositorySnapshot,
    workspace: pathlib.Path,
    *,
    limits: Limits = DEFAULT_LIMITS,
    after_copy: Callable[[str, int], None] | None = None,
) -> tuple[SelectedFile, ...]:
    workspace.mkdir(mode=0o700)
    (workspace / ".git").mkdir(mode=0o700)
    copied: list[SelectedFile] = []
    for index, expected in enumerate(snapshot.selected):
        destination = workspace.joinpath(*pathlib.PurePosixPath(expected.path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = _open_tracked_regular(snapshot.root, expected.path)
        except HarnessRefusal as error:
            raise HarnessRefusal(
                "source_changed_during_copy", f"selected source changed: {expected.path}"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or _stat_fingerprint(before) != expected.stat_fingerprint
                or is_sparse(before)
            ):
                raise HarnessRefusal(
                    "source_changed_during_copy", f"selected source changed: {expected.path}"
                )
            digest = hashlib.sha256()
            total = 0
            with destination.open("xb") as output:
                while True:
                    block = os.read(descriptor, 1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > limits.max_selected_file_bytes:
                        raise HarnessRefusal(
                            "selected_input_oversized", f"selected input grew: {expected.path}"
                        )
                    output.write(block)
                    digest.update(block)
                output.flush()
                os.fsync(output.fileno())
            if after_copy is not None:
                after_copy(expected.path, index)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        try:
            observed_descriptor = _open_tracked_regular(snapshot.root, expected.path)
        except HarnessRefusal as error:
            raise HarnessRefusal(
                "source_changed_during_copy", f"selected source changed: {expected.path}"
            ) from error
        try:
            observed_path = os.fstat(observed_descriptor)
        finally:
            os.close(observed_descriptor)
        if (
            _stat_fingerprint(before) != _stat_fingerprint(after)
            or _stat_fingerprint(after) != _stat_fingerprint(observed_path)
            or total != expected.size
            or digest.hexdigest() != expected.sha256
        ):
            raise HarnessRefusal(
                "source_changed_during_copy", f"selected source changed: {expected.path}"
            )
        copied.append(
            SelectedFile(
                path=expected.path,
                size=total,
                sha256=digest.hexdigest(),
                executable=expected.executable,
                stat_fingerprint=_stat_fingerprint(destination.stat()),
            )
        )
    final = inspect_repository(snapshot.root, snapshot.language, limits)
    if _snapshot_identity(final) != _snapshot_identity(snapshot):
        raise HarnessRefusal(
            "source_changed_during_copy", f"source changed while copying {snapshot.root}"
        )
    return tuple(copied)


def build_command_corpus(selected: Sequence[SelectedFile]) -> tuple[CommandSpec, ...]:
    if len(selected) != 2:
        raise ValueError("the v1 corpus requires exactly two selected inputs")
    first, second = (item.path for item in selected)
    return (
        CommandSpec("file0-cat", ("cat", "--", first)),
        CommandSpec("file0-head-lines", ("head", "-n", "20", "--", first)),
        CommandSpec("file0-tail-lines", ("tail", "-n", "20", "--", first)),
        CommandSpec("file0-wc-bytes", ("wc", "-c", "--", first)),
        CommandSpec("file0-wc-lines", ("wc", "-l", "--", first)),
        CommandSpec("file0-grep-lines", ("grep", "-n", "--", "", first)),
        CommandSpec("file1-cat", ("cat", "--", second)),
        CommandSpec("file1-head-bytes", ("head", "-c", "512", "--", second)),
        CommandSpec("file1-tail-bytes", ("tail", "-c", "512", "--", second)),
        CommandSpec("file1-wc-bytes", ("wc", "-c", "--", second)),
    )


def sanitized_environment(state: pathlib.Path, home: pathlib.Path) -> tuple[dict[str, str], list[str]]:
    removed = sorted(os.environ)
    environment = {
        "AGAIN_HOME": str(state),
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    return environment, removed


def stream_record(completed: Completed) -> dict[str, Any]:
    return {
        "status": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stdout_sha256": sha256_bytes(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stderr_sha256": sha256_bytes(completed.stderr),
    }


def streams_equal(left: Completed, right: Completed) -> bool:
    return (
        left.returncode == right.returncode
        and left.stdout == right.stdout
        and left.stderr == right.stderr
    )


def parse_json(completed: Completed, label: str) -> dict[str, Any]:
    if completed.returncode != 0:
        raise HarnessRefusal(
            "again_support_command_failed",
            f"{label} failed: {completed.stderr[:512].decode(errors='replace')}",
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise HarnessRefusal("again_json_malformed", f"{label} returned malformed JSON") from error
    if not isinstance(value, dict):
        raise HarnessRefusal("again_json_malformed", f"{label} did not return an object")
    return value


def require_event(
    event: dict[str, Any], *, disposition: str, reason: str, label: str
) -> str:
    result_id = event.get("result_id")
    if (
        event.get("disposition") != disposition
        or event.get("reason") != reason
        or not isinstance(result_id, str)
        or not result_id
    ):
        raise HarnessRefusal(
            "again_event_mismatch",
            f"{label} event did not prove {disposition}/{reason}: {event!r}",
        )
    return result_id


def require_mutation_invalidation(prior_result_id: str, event: dict[str, Any]) -> str:
    result_id = require_event(
        event,
        disposition="executed",
        reason="DOUBLE_EXECUTION_VALIDATED",
        label="mutation",
    )
    if result_id == prior_result_id:
        raise HarnessRefusal("stale_result_replayed", "mutation reused the prior result id")
    return result_id


def nearest_rank(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty timing distribution")
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def timing_record(values: Sequence[float]) -> dict[str, Any]:
    return {
        "samples_ms": list(values),
        "minimum_ms": min(values),
        "p50_ms": nearest_rank(values, 0.50),
        "p95_ms": nearest_rank(values, 0.95),
        "maximum_ms": max(values),
        "mean_ms": statistics.fmean(values),
    }


def mutate_copied_input(path: pathlib.Path) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise HarnessRefusal("mutation_input_invalid", "mutation input is not a regular file")
    if metadata.st_size == 0 or is_sparse(metadata):
        raise HarnessRefusal("mutation_input_invalid", "mutation input is empty or sparse")
    before_hash = sha256_file(path)
    with path.open("r+b", buffering=0) as target:
        original = target.read(1)
        if len(original) != 1:
            raise HarnessRefusal("mutation_input_invalid", "mutation byte was unavailable")
        target.seek(0)
        target.write(bytes((original[0] ^ 1,)))
        os.fsync(target.fileno())
    after = path.lstat()
    after_hash = sha256_file(path)
    if after.st_size != metadata.st_size or after_hash == before_hash:
        raise HarnessRefusal("mutation_failed", "controlled same-size mutation failed")
    return {
        "path": path.as_posix(),
        "size_before": metadata.st_size,
        "size_after": after.st_size,
        "sha256_before": before_hash,
        "sha256_after": after_hash,
    }


def _support_command(
    binary: pathlib.Path,
    parts: Sequence[str],
    workspace: pathlib.Path,
    environment: dict[str, str],
    limits: Limits,
) -> dict[str, Any]:
    return parse_json(
        run_bounded(
            (str(binary), *parts),
            cwd=workspace,
            environment=environment,
            timeout_seconds=limits.timeout_seconds,
            stream_limit_bytes=limits.stream_bytes,
        ),
        "again " + " ".join(parts),
    )


def run_repository_corpus(
    binary: pathlib.Path,
    snapshot: RepositorySnapshot,
    workspace: pathlib.Path,
    environment: dict[str, str],
    limits: Limits = DEFAULT_LIMITS,
) -> dict[str, Any]:
    commands = build_command_corpus(snapshot.selected)
    records: list[dict[str, Any]] = []
    native_timings: list[float] = []
    cold_timings: list[float] = []
    warm_timings: list[float] = []
    result_ids: dict[str, str] = {}
    for command in commands:
        native = run_bounded(
            command.argv,
            cwd=workspace,
            environment=environment,
            timeout_seconds=limits.timeout_seconds,
            stream_limit_bytes=limits.stream_bytes,
        )
        if native.returncode != 0:
            raise HarnessRefusal(
                "native_command_failed",
                f"native {command.command_id} returned {native.returncode}",
            )
        again_argv = (str(binary), "run", "--", *command.argv)
        cold = run_bounded(
            again_argv,
            cwd=workspace,
            environment=environment,
            timeout_seconds=limits.timeout_seconds,
            stream_limit_bytes=limits.stream_bytes,
        )
        if not streams_equal(native, cold):
            raise HarnessRefusal("cold_stream_mismatch", f"cold mismatch: {command.command_id}")
        cold_event = _support_command(binary, ("explain", "--json"), workspace, environment, limits)
        cold_id = require_event(
            cold_event,
            disposition="executed",
            reason="DOUBLE_EXECUTION_VALIDATED",
            label=f"{command.command_id} cold",
        )
        warm = run_bounded(
            again_argv,
            cwd=workspace,
            environment=environment,
            timeout_seconds=limits.timeout_seconds,
            stream_limit_bytes=limits.stream_bytes,
        )
        if not streams_equal(native, warm):
            raise HarnessRefusal("warm_stream_mismatch", f"warm mismatch: {command.command_id}")
        warm_event = _support_command(binary, ("explain", "--json"), workspace, environment, limits)
        warm_id = require_event(
            warm_event,
            disposition="replayed_full",
            reason="EXACT_REUSE_NET_V1",
            label=f"{command.command_id} warm",
        )
        if warm_id != cold_id:
            raise HarnessRefusal("wrong_result_replayed", f"wrong result: {command.command_id}")
        result_ids[command.command_id] = cold_id
        native_timings.append(native.elapsed_ms)
        cold_timings.append(cold.elapsed_ms)
        warm_timings.append(warm.elapsed_ms)
        records.append(
            {
                "command_id": command.command_id,
                "argv": list(command.argv),
                "native": {"elapsed_ms": native.elapsed_ms, **stream_record(native)},
                "cold_again": {
                    "elapsed_ms": cold.elapsed_ms,
                    "event": {"disposition": "executed", "reason": "DOUBLE_EXECUTION_VALIDATED"},
                    "result_id": cold_id,
                    **stream_record(cold),
                },
                "warm_again": {
                    "elapsed_ms": warm.elapsed_ms,
                    "event": {"disposition": "replayed_full", "reason": "EXACT_REUSE_NET_V1"},
                    "result_id": warm_id,
                    **stream_record(warm),
                },
            }
        )

    mutation_command = next(item for item in commands if item.command_id == "file0-wc-bytes")
    mutation_path = workspace.joinpath(
        *pathlib.PurePosixPath(snapshot.selected[0].path).parts
    )
    mutation = mutate_copied_input(mutation_path)
    mutation["path"] = snapshot.selected[0].path
    native_mutated = run_bounded(
        mutation_command.argv,
        cwd=workspace,
        environment=environment,
        timeout_seconds=limits.timeout_seconds,
        stream_limit_bytes=limits.stream_bytes,
    )
    original_record = next(
        record for record in records if record["command_id"] == mutation_command.command_id
    )
    if stream_record(native_mutated) != {
        key: original_record["native"][key]
        for key in ("status", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256")
    }:
        raise HarnessRefusal(
            "mutation_changed_oracle", "same-size mutation changed the wc -c oracle"
        )
    mutated_again = run_bounded(
        (str(binary), "run", "--", *mutation_command.argv),
        cwd=workspace,
        environment=environment,
        timeout_seconds=limits.timeout_seconds,
        stream_limit_bytes=limits.stream_bytes,
    )
    if not streams_equal(native_mutated, mutated_again):
        raise HarnessRefusal("mutation_stream_mismatch", "mutation run changed exact streams")
    mutation_event = _support_command(
        binary, ("explain", "--json"), workspace, environment, limits
    )
    mutation_result_id = require_mutation_invalidation(
        result_ids[mutation_command.command_id], mutation_event
    )
    mutation.update(
        {
            "command_id": mutation_command.command_id,
            "argv": list(mutation_command.argv),
            "native_output_unchanged": True,
            "prior_result_id": result_ids[mutation_command.command_id],
            "post_mutation_result_id": mutation_result_id,
            "prior_result_replayed": False,
            "native": {"elapsed_ms": native_mutated.elapsed_ms, **stream_record(native_mutated)},
            "again": {"elapsed_ms": mutated_again.elapsed_ms, **stream_record(mutated_again)},
        }
    )

    stats = _support_command(binary, ("stats", "--json"), workspace, environment, limits)
    expected_stats = {
        "executions": 11,
        "full_replays": 10,
        "compact_replays": 0,
        "bypasses": 0,
        "quarantines": 0,
        "duplicate_bytes_omitted": 0,
    }
    for key, expected in expected_stats.items():
        if stats.get(key) != expected:
            raise HarnessRefusal(
                "again_stats_mismatch", f"stats {key}={stats.get(key)!r}, expected {expected}"
            )
    return {
        "language": snapshot.language,
        "commands": records,
        "timing_ms": {
            "native": timing_record(native_timings),
            "cold_again": timing_record(cold_timings),
            "warm_again": timing_record(warm_timings),
        },
        "mutation": mutation,
        "again_stats": stats,
    }


def snapshot_record(
    snapshot: RepositorySnapshot, *, source_copy_verification: str
) -> dict[str, Any]:
    return {
        "language": snapshot.language,
        "source_root": str(snapshot.root),
        "source_git_sha": snapshot.git_sha,
        "dirty": snapshot.dirty,
        "dirty_status_sha256": snapshot.dirty_status_sha256,
        "tracked_manifest_sha256": snapshot.tracked_manifest_sha256,
        "tracked_worktree_stat_sha256": snapshot.tracked_worktree_stat_sha256,
        "tracked_files": snapshot.tracked_files,
        "repository_logical_bytes": snapshot.repository_logical_bytes,
        "source_copy_verification": source_copy_verification,
        "selected": [
            {
                "path": item.path,
                "size": item.size,
                "sha256": item.sha256,
                "executable": item.executable,
            }
            for item in snapshot.selected
        ],
    }


def host_record() -> dict[str, str]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def subprocess_boundary_record() -> dict[str, Any]:
    return {
        "network_sandbox": False,
        "fresh_socket_creation_blocked": False,
        "ambient_inherited_descriptors_closed": True,
        "descendant_sentinel": "bounded_best_effort",
        "trusted_argv_only": True,
    }


def canonical_json_bytes(report: dict[str, Any]) -> bytes:
    return (
        json.dumps(report, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")


def write_json_exclusive(path: pathlib.Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as output:
            output.write(canonical_json_bytes(report))
    except FileExistsError as error:
        raise HarnessRefusal("output_exists", f"refusing to overwrite {path}") from error


def emit_report(path: pathlib.Path | None, report: dict[str, Any]) -> None:
    if path is None:
        sys.stdout.buffer.write(canonical_json_bytes(report))
    else:
        write_json_exclusive(path, report)
        print(path)


def build_non_pass_report(
    *,
    code: str,
    detail: str,
    binary: PinnedBinary,
    snapshots: Sequence[RepositorySnapshot],
    removed_inputs: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "harness_version": HARNESS_VERSION,
        "command_corpus_version": COMMAND_CORPUS_VERSION,
        "result": "non_pass",
        "non_pass": {
            "code": code,
            "detail_sha256": sha256_bytes(detail.encode("utf-8", errors="replace")),
        },
        "scope": {
            "claim": "non-authoritative local preflight over explicit repository inputs",
            "subprocess_boundary": subprocess_boundary_record(),
        },
        "provenance": {
            "binary": str(binary.source),
            "binary_execution": "private_no_follow_copy",
            "binary_sha256": binary.sha256,
            "binary_bytes": binary.size,
            "harness_sha256": sha256_file(pathlib.Path(__file__).resolve()),
            "platform": host_record(),
            "unmodeled_inputs_removed": list(removed_inputs),
            "repositories": [
                snapshot_record(snapshot, source_copy_verification="not_attempted")
                for snapshot in snapshots
            ],
        },
        "repositories": [],
        "correctness": {"passed": False},
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    for _language, argument in LANGUAGE_ARGUMENTS:
        parser.add_argument(argument, type=pathlib.Path, required=True)
    parser.add_argument("--json-out", type=pathlib.Path)
    return parser.parse_args(argv)


def require_distinct_repository_roots(roots: Sequence[pathlib.Path]) -> None:
    if len(set(roots)) != len(roots):
        raise HarnessRefusal(
            "duplicate_repository_root",
            "each language must use a distinct real repository root",
        )


def require_new_output_path(
    path: pathlib.Path, source_roots: Sequence[pathlib.Path]
) -> pathlib.Path:
    if not path.is_absolute():
        raise HarnessRefusal("path_not_absolute", "--json-out must be an absolute path")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise HarnessRefusal(
            "output_path_unavailable", f"--json-out cannot be resolved: {error}"
        ) from error
    if resolved != path:
        raise HarnessRefusal(
            "path_not_canonical", "--json-out must be canonical and symlink-free"
        )
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise HarnessRefusal(
            "output_path_unavailable", f"--json-out is unavailable: {error}"
        ) from error
    else:
        raise HarnessRefusal("output_exists", f"refusing to overwrite {path}")
    for root in source_roots:
        if resolved == root or root in resolved.parents:
            raise HarnessRefusal(
                "output_inside_source",
                f"--json-out must not write inside source repository {root}",
            )
    return resolved


def _require_absolute_file(path: pathlib.Path, label: str, *, executable: bool) -> pathlib.Path:
    if not path.is_absolute():
        raise HarnessRefusal("path_not_absolute", f"{label} must be an absolute path")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HarnessRefusal("path_unavailable", f"{label} is unavailable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HarnessRefusal("path_not_regular", f"{label} must be a non-symlink regular file")
    if executable and not os.access(path, os.X_OK):
        raise HarnessRefusal("binary_not_executable", f"{label} is not executable")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    binary_source = _require_absolute_file(arguments.binary, "--binary", executable=True)
    output = arguments.json_out

    snapshots: list[RepositorySnapshot] = []
    for language, argument in LANGUAGE_ARGUMENTS:
        raw_root = getattr(arguments, argument.removeprefix("--").replace("-", "_"))
        root = require_absolute_directory(raw_root, argument)
        snapshots.append(inspect_repository(root, language))
    source_roots = [snapshot.root for snapshot in snapshots]
    require_distinct_repository_roots(source_roots)
    if output is not None:
        output = require_new_output_path(output, source_roots)

    harness = pathlib.Path(__file__).resolve()
    harness_before = (sha256_file(harness), _stat_fingerprint(harness.stat()))
    all_removed: set[str] = set()
    reports: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="again-real-repository-corpus-") as temporary:
        temporary_root = pathlib.Path(temporary)
        binary = pin_again_binary(binary_source, temporary_root / "pinned-binary")
        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        control_workspace = temporary_root / "control-workspace"
        control_workspace.mkdir(mode=0o700)
        (control_workspace / ".git").mkdir(mode=0o700)
        control_state = temporary_root / "control-state"
        control_environment, removed = sanitized_environment(control_state, home)
        all_removed.update(removed)
        doctor_completed = run_bounded(
            (str(binary.executable), "doctor", "--json"),
            cwd=control_workspace,
            environment=control_environment,
            timeout_seconds=DEFAULT_LIMITS.timeout_seconds,
            stream_limit_bytes=DEFAULT_LIMITS.stream_bytes,
        )
        verify_binary_source_unchanged(binary)
        if doctor_completed.returncode != 0:
            report = build_non_pass_report(
                code="again_doctor_failed",
                detail=doctor_completed.stderr.decode(errors="replace"),
                binary=binary,
                snapshots=snapshots,
                removed_inputs=sorted(all_removed),
            )
            emit_report(output, report)
            return 2
        try:
            doctor = json.loads(doctor_completed.stdout)
        except json.JSONDecodeError:
            report = build_non_pass_report(
                code="again_doctor_malformed",
                detail=doctor_completed.stdout.decode(errors="replace"),
                binary=binary,
                snapshots=snapshots,
                removed_inputs=sorted(all_removed),
            )
            emit_report(output, report)
            return 2
        profile = doctor.get("audited_apple_tool_profile") if isinstance(doctor, dict) else None
        if not isinstance(profile, str) or profile.startswith("unsupported:"):
            report = build_non_pass_report(
                code="unsupported_host_profile",
                detail=profile if isinstance(profile, str) else "doctor profile missing",
                binary=binary,
                snapshots=snapshots,
                removed_inputs=sorted(all_removed),
            )
            emit_report(output, report)
            return 2

        for snapshot in snapshots:
            workspace = temporary_root / f"workspace-{snapshot.language}"
            copy_selected_files(snapshot, workspace)
            state = temporary_root / f"state-{snapshot.language}"
            environment, removed = sanitized_environment(state, home)
            all_removed.update(removed)
            reports.append(
                run_repository_corpus(binary.executable, snapshot, workspace, environment)
            )

    verify_binary_source_unchanged(binary)
    harness_after = (sha256_file(harness), _stat_fingerprint(harness.stat()))
    if harness_after != harness_before:
        raise HarnessRefusal("harness_changed", "harness changed during the corpus")
    report = {
        "schema": SCHEMA,
        "harness_version": HARNESS_VERSION,
        "command_corpus_version": COMMAND_CORPUS_VERSION,
        "result": "pass",
        "scope": {
            "languages": [language for language, _argument in LANGUAGE_ARGUMENTS],
            "repositories": 4,
            "commands_per_repository": 10,
            "native_invocations": 44,
            "again_run_invocations": 84,
            "again_support_invocations": 89,
            "again_total_process_invocations": 173,
            "mutation_invalidations": 4,
            "claim": "explicit narrow read-only product path over copied tracked real-repository inputs",
            "subprocess_boundary": subprocess_boundary_record(),
        },
        "limits": dataclasses.asdict(DEFAULT_LIMITS),
        "correctness": {
            "passed": True,
            "exact_status_stdout_stderr": True,
            "every_cold_run_executed": True,
            "every_warm_run_replayed_full": True,
            "every_mutation_forced_execution": True,
            "tracked_source_state_unchanged_during_copy": True,
        },
        "repositories": reports,
        "provenance": {
            "binary": str(binary.source),
            "binary_execution": "private_no_follow_copy",
            "binary_sha256": binary.sha256,
            "binary_bytes": binary.size,
            "harness_sha256": harness_before[0],
            "platform": host_record(),
            "unmodeled_inputs_removed": sorted(all_removed),
            "repositories": [
                snapshot_record(
                    snapshot,
                    source_copy_verification="tracked_state_verified_unchanged",
                )
                for snapshot in snapshots
            ],
        },
    }
    emit_report(output, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessRefusal as error:
        raise SystemExit(f"{error.code}: {error}") from error
