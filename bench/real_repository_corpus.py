#!/usr/bin/env python3
"""Validate Again against copied tracked inputs from four real repositories.

The harness never clones, downloads, or executes source-repository code. It
reads explicit local Git worktrees, copies two deterministic tracked regular
files per language into private temporary workspaces, and exercises only the
fixed read-only command corpus declared below.
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
import resource
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
HARNESS_VERSION = "1.0.0"
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


@dataclasses.dataclass(frozen=True)
class Limits:
    max_tracked_files: int = 100_000
    max_manifest_bytes: int = 32 * 1024 * 1024
    max_status_bytes: int = 4 * 1024 * 1024
    max_repository_logical_bytes: int = 8 * 1024 * 1024 * 1024
    max_selected_file_bytes: int = 8 * 1024 * 1024
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


def _file_limit_setter(limit_bytes: int) -> Callable[[], None]:
    def apply() -> None:
        _soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        effective = limit_bytes
        if hard != resource.RLIM_INFINITY:
            effective = min(effective, hard)
        resource.setrlimit(resource.RLIMIT_FSIZE, (effective, hard))

    return apply


def run_bounded(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: dict[str, str],
    timeout_seconds: float,
    stream_limit_bytes: int,
) -> Completed:
    """Run a noninteractive process with bounded captured streams."""

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
            preexec_fn=_file_limit_setter(stream_limit_bytes + 1),
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise HarnessRefusal(
                "command_timeout", f"command exceeded {timeout_seconds:g}s: {argv!r}"
            ) from error
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        stdout_bytes = os.fstat(stdout_file.fileno()).st_size
        stderr_bytes = os.fstat(stderr_file.fileno()).st_size
        if stdout_bytes > stream_limit_bytes or stderr_bytes > stream_limit_bytes:
            raise HarnessRefusal(
                "stream_limit_exceeded",
                f"command exceeded the {stream_limit_bytes}-byte stream limit: {argv!r}",
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        return Completed(
            argv=tuple(argv),
            returncode=returncode,
            stdout=stdout_file.read(),
            stderr=stderr_file.read(),
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
    top_level = run_git(
        resolved,
        ("rev-parse", "--show-toplevel"),
        limit_bytes=4096,
    ).decode("utf-8", errors="strict").strip()
    if pathlib.Path(top_level).resolve(strict=True) != resolved:
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
    seen: set[str] = set()
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode_bytes, object_bytes, stage_bytes = header.split(b" ")
            mode = mode_bytes.decode("ascii")
            object_id = object_bytes.decode("ascii")
            stage = stage_bytes.decode("ascii")
            path = raw_path.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError) as error:
            raise HarnessRefusal("tracked_manifest_malformed", "malformed tracked entry") from error
        path_parts = pathlib.PurePosixPath(path).parts
        if (
            not path
            or pathlib.PurePosixPath(path).is_absolute()
            or ".." in path_parts
            or any(part.lower() == ".git" for part in path_parts)
            or stage != "0"
            or not HEX_OBJECT_RE.fullmatch(object_id)
            or mode not in {"100644", "100755", "120000", "160000"}
            or path in seen
        ):
            raise HarnessRefusal("tracked_manifest_malformed", f"unsafe tracked entry: {path!r}")
        seen.add(path)
        entries.append(TrackedEntry(mode=mode, object_id=object_id, path=path))
    return tuple(sorted(entries, key=lambda entry: entry.path.encode("utf-8")))


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


def _require_no_symlink_components(root: pathlib.Path, relative: str) -> pathlib.Path:
    current = root
    for component in pathlib.PurePosixPath(relative).parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise HarnessRefusal("selected_input_unavailable", f"selected input unavailable: {relative}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise HarnessRefusal("selected_input_symlink", f"selected input uses a symlink: {relative}")
    return current


def _tracked_worktree_digest(
    root: pathlib.Path, entries: Sequence[TrackedEntry], limits: Limits
) -> tuple[str, int]:
    digest = hashlib.sha256()
    logical_bytes = 0
    for entry in entries:
        path = root.joinpath(*pathlib.PurePosixPath(entry.path).parts)
        digest.update(entry.path.encode("utf-8"))
        digest.update(b"\0")
        try:
            metadata = path.lstat()
        except FileNotFoundError:
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
        source = _require_no_symlink_components(root, entry.path)
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise HarnessRefusal("selected_input_special", f"non-regular input selected: {entry.path}")
        if metadata.st_size == 0:
            raise HarnessRefusal("selected_input_empty", f"empty input selected: {entry.path}")
        if metadata.st_size > limits.max_selected_file_bytes:
            raise HarnessRefusal("selected_input_oversized", f"selected input is too large: {entry.path}")
        if is_sparse(metadata):
            raise HarnessRefusal("selected_input_sparse", f"sparse input selected: {entry.path}")
        selected.append(
            SelectedFile(
                path=entry.path,
                size=metadata.st_size,
                sha256=sha256_file(source),
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
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)
    for index, expected in enumerate(snapshot.selected):
        source = _require_no_symlink_components(snapshot.root, expected.path)
        destination = workspace.joinpath(*pathlib.PurePosixPath(expected.path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(source, os.O_RDONLY | nofollow | cloexec)
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
        observed_path = source.lstat()
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


def canonical_json_bytes(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


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
    binary: pathlib.Path,
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
        "provenance": {
            "binary": str(binary),
            "binary_sha256": sha256_file(binary),
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
    binary = _require_absolute_file(arguments.binary, "--binary", executable=True)
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
    binary_before = (sha256_file(binary), _stat_fingerprint(binary.stat()))
    harness_before = (sha256_file(harness), _stat_fingerprint(harness.stat()))
    all_removed: set[str] = set()
    reports: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="again-real-repository-corpus-") as temporary:
        temporary_root = pathlib.Path(temporary)
        home = temporary_root / "home"
        home.mkdir(mode=0o700)
        control_workspace = temporary_root / "control-workspace"
        control_workspace.mkdir(mode=0o700)
        (control_workspace / ".git").mkdir(mode=0o700)
        control_state = temporary_root / "control-state"
        control_environment, removed = sanitized_environment(control_state, home)
        all_removed.update(removed)
        doctor_completed = run_bounded(
            (str(binary), "doctor", "--json"),
            cwd=control_workspace,
            environment=control_environment,
            timeout_seconds=DEFAULT_LIMITS.timeout_seconds,
            stream_limit_bytes=DEFAULT_LIMITS.stream_bytes,
        )
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
                run_repository_corpus(binary, snapshot, workspace, environment)
            )

    binary_after = (sha256_file(binary), _stat_fingerprint(binary.stat()))
    if binary_after != binary_before:
        raise HarnessRefusal("binary_changed", "Again binary changed during the corpus")
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
            "binary": str(binary),
            "binary_sha256": binary_before[0],
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
