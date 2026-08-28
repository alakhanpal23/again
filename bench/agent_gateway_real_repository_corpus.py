#!/usr/bin/env python3
"""Network-avoiding, fail-closed real-repository corpus for the Again MCP binary.

The harness accepts only explicit canonical repository roots.  It inspects them
with read-only Git commands, copies a deterministic pair of tracked language
files through descriptor-bound checks, and performs every mutation in a private
temporary workspace.  Product observations come only from independent
``again mcp serve`` processes; the direct oracle is a small native
implementation of the two closed repository tools.

Evidence contains paths, hashes, sizes, commands, counters, and timings.  It
never contains copied repository file contents or MCP response bodies.
"""

from __future__ import annotations

import argparse
import collections
import dataclasses
import hashlib
import importlib.util
import json
import os
import pathlib
import platform
import secrets
import signal
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA = "again.agent-gateway-real-repository-corpus.v1"
HARNESS_VERSION = "1.1.0"
MCP_PROTOCOL_VERSION = "2025-06-18"
EXPECTED_DATABASE_SCHEMA = 9
LANGUAGES = ("rust", "python", "go", "typescript")
LANGUAGE_SUFFIXES = {
    "rust": (".rs",),
    "python": (".py",),
    "go": (".go",),
    "typescript": (".ts", ".tsx", ".mts", ".cts"),
}
MAX_REPOSITORY_FILE_BYTES = 4 * 1024 * 1024
MAX_REPOSITORY_SCAN_BYTES = 16 * 1024 * 1024
LARGE_FIXTURE_BYTES = 768 * 1024
BULK_FILE_BYTES = 512 * 1024
BULK_FILE_COUNT = 12
NETWORK_BLOCK_ENDPOINT = "http://127.0.0.1:9"
RELEVANT_MARKER_V1 = "AGAIN_REAL_CORPUS_RELEVANT_V1"
RELEVANT_MARKER_V2 = "AGAIN_REAL_CORPUS_RELEVANT_V2"
IRRELEVANT_MARKER = "AGAIN_REAL_CORPUS_IRRELEVANT_V1"
CONCURRENT_MARKER = "AGAIN_REAL_CORPUS_CONCURRENT_V1"
ORDER_MARKER = "AGAIN_REAL_CORPUS_ORDER_V1"
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_REPOSITORIES = len(LANGUAGES)
PROCESS_STOP_SECONDS = 2.0
MAX_SEARCH_ROOTS = 8
MAX_SEARCH_DEPTH = 4
MAX_SEARCH_CANDIDATES = 128


def _load_sibling(name: str) -> Any:
    path = pathlib.Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(f"_{name}_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load required harness support: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


repository_support = _load_sibling("real_repository_corpus")
gateway_support = _load_sibling("agent_gateway_product_e2e")


class HarnessRefusal(RuntimeError):
    """Typed non-pass result; a refusal can never be reported as a pass."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        cleanup_complete: bool = True,
        cleanup_codes: Sequence[str] = (),
    ):
        super().__init__(message)
        self.code = code
        self.cleanup_complete = cleanup_complete
        self.cleanup_codes = tuple(cleanup_codes)


@dataclasses.dataclass(frozen=True)
class RepositoryInput:
    language: str
    root: pathlib.Path


@dataclasses.dataclass(frozen=True)
class NativeObservation:
    status: str
    value: Mapping[str, Any] | None = None
    error_code: int | None = None


@dataclasses.dataclass(frozen=True)
class EventCursor:
    event_id: int
    started_ms: int


@dataclasses.dataclass(frozen=True)
class PinnedExecutableIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    size: int
    sha256: str


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise HarnessRefusal("noncanonical_json", "value is not canonical JSON") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path, maximum: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if maximum is not None and total > maximum:
                raise HarnessRefusal("file_oversized", f"file exceeds bound: {path}")
            digest.update(block)
    return digest.hexdigest()


def pinned_executable_identity(path: pathlib.Path) -> PinnedExecutableIdentity:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise HarnessRefusal("pinned_binary_changed", "cannot open pinned executable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > repository_support.DEFAULT_LIMITS.max_binary_bytes
            or metadata.st_mode & 0o111 == 0
        ):
            raise HarnessRefusal("pinned_binary_changed", "pinned executable metadata changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > repository_support.DEFAULT_LIMITS.max_binary_bytes:
                raise HarnessRefusal("pinned_binary_changed", "pinned executable exceeds bound")
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    fields = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if fields(metadata) != fields(after) or total != metadata.st_size:
        raise HarnessRefusal("pinned_binary_changed", "pinned executable changed while hashing")
    return PinnedExecutableIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        digest.hexdigest(),
    )


def verify_pinned_executable_unchanged(
    path: pathlib.Path, expected: PinnedExecutableIdentity
) -> None:
    if pinned_executable_identity(path) != expected:
        raise HarnessRefusal("pinned_binary_changed", "pinned executable changed during corpus")


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise HarnessRefusal("output_not_canonical", "evidence path must be absolute and canonical")
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise HarnessRefusal("evidence_oversized", "evidence exceeds its fixed bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        directory = os.open(path.parent, directory_flags)
    except OSError as error:
        raise HarnessRefusal("output_directory", "cannot open evidence directory") from error
    staging_name: str | None = None
    staging_identity: tuple[int, int] | None = None
    final_identity: tuple[int, int] | None = None
    published = False
    try:
        for _ in range(16):
            try:
                staging_name = f".again-evidence-{secrets.token_hex(16)}.tmp"
            except BaseException as error:
                raise HarnessRefusal("output_staging_name", "cannot create staging name") from error
            try:
                descriptor = os.open(
                    staging_name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=directory,
                )
                initial = os.fstat(descriptor)
                staging_identity = (initial.st_dev, initial.st_ino)
                break
            except FileExistsError:
                staging_name = None
        else:
            raise HarnessRefusal("output_staging_exhausted", "cannot reserve evidence staging file")
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
                metadata = os.fstat(output.fileno())
                if (
                    (metadata.st_dev, metadata.st_ino) != staging_identity
                    or not stat.S_ISREG(metadata.st_mode)
                    or stat.S_IMODE(metadata.st_mode) != 0o600
                    or metadata.st_nlink != 1
                    or metadata.st_size != len(encoded)
                ):
                    raise HarnessRefusal("output_staging_invalid", "staged evidence identity changed")
        except BaseException:
            raise

        assert staging_name is not None and staging_identity is not None
        try:
            os.link(
                staging_name,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
            published = True
            final_identity = staging_identity
        except FileExistsError as error:
            raise HarnessRefusal("output_exists", f"refusing to overwrite evidence: {path}") from error
        except OSError as error:
            # Reconcile effect-then-error ambiguity without touching an
            # unrelated final inode.
            try:
                observed = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            except OSError:
                observed = None
            if observed is not None and (observed.st_dev, observed.st_ino) == staging_identity:
                published = True
                final_identity = staging_identity
            raise HarnessRefusal("output_publish", "atomic evidence publication failed") from error

        os.unlink(staging_name, dir_fd=directory)
        staging_name = None
        os.fsync(directory)
        final_descriptor = os.open(
            path.name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory,
        )
        try:
            final = os.fstat(final_descriptor)
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(final_descriptor, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_EVIDENCE_BYTES:
                    raise HarnessRefusal("output_revalidation", "published evidence exceeds bound")
                digest.update(block)
            final_after = os.fstat(final_descriptor)
        finally:
            os.close(final_descriptor)
        if (
            (final.st_dev, final.st_ino) != final_identity
            or (final_after.st_dev, final_after.st_ino) != final_identity
            or (
                final.st_mode,
                final.st_nlink,
                final.st_uid,
                final.st_gid,
                final.st_size,
                final.st_mtime_ns,
                final.st_ctime_ns,
            )
            != (
                final_after.st_mode,
                final_after.st_nlink,
                final_after.st_uid,
                final_after.st_gid,
                final_after.st_size,
                final_after.st_mtime_ns,
                final_after.st_ctime_ns,
            )
            or not stat.S_ISREG(final.st_mode)
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_nlink != 1
            or total != len(encoded)
            or digest.hexdigest() != sha256_bytes(encoded)
        ):
            raise HarnessRefusal("output_revalidation", "published evidence failed revalidation")
    except BaseException as primary:
        cleanup_complete = True
        if staging_name is not None and staging_identity is not None:
            try:
                observed = os.stat(staging_name, dir_fd=directory, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) == staging_identity:
                    os.unlink(staging_name, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_complete = False
        if published and final_identity is not None:
            try:
                observed = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                if (observed.st_dev, observed.st_ino) == final_identity:
                    os.unlink(path.name, dir_fd=directory)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_complete = False
        try:
            os.fsync(directory)
        except OSError:
            cleanup_complete = False
        if isinstance(primary, HarnessRefusal):
            combined_cleanup_complete = primary.cleanup_complete and cleanup_complete
            combined_cleanup_codes = tuple(
                dict.fromkeys(
                    (
                        *primary.cleanup_codes,
                        *(() if cleanup_complete else ("output_cleanup",)),
                    )
                )
            )
            raise HarnessRefusal(
                primary.code,
                str(primary),
                cleanup_complete=combined_cleanup_complete,
                cleanup_codes=combined_cleanup_codes,
            ) from primary
        raise HarnessRefusal(
            "output_write",
            "evidence write failed",
            cleanup_complete=cleanup_complete,
            cleanup_codes=(() if cleanup_complete else ("output_cleanup",)),
        ) from primary
    finally:
        os.close(directory)


def validate_output_location(
    output: pathlib.Path, protected_roots: Sequence[pathlib.Path]
) -> pathlib.Path:
    if not output.is_absolute() or output.resolve(strict=False) != output:
        raise HarnessRefusal("output_not_canonical", "evidence path must be absolute and canonical")
    try:
        output.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise HarnessRefusal("output_unavailable", "evidence output cannot be inspected") from error
    else:
        raise HarnessRefusal("output_exists", f"refusing to overwrite evidence: {output}")
    for root in protected_roots:
        if output == root or root in output.parents:
            raise HarnessRefusal(
                "output_inside_source", f"evidence output cannot be inside source: {root}"
            )
    return output


def _translate_support_refusal(error: BaseException) -> HarnessRefusal:
    code = getattr(error, "code", "support_failure")
    return HarnessRefusal(str(code), str(error))


def _git_environment(home: pathlib.Path | None = None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
    }
    if home is not None:
        environment["HOME"] = str(home)
    return environment


def _git_probe(root: pathlib.Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ("git", "-c", "protocol.allow=never", *arguments),
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessRefusal("git_inspection_failed", "bounded local Git probe failed") from error


def parse_repository_argument(raw: str) -> RepositoryInput:
    language, separator, path_text = raw.partition("=")
    if separator != "=" or language not in LANGUAGES or not path_text:
        raise HarnessRefusal(
            "repository_argument",
            "--repository must be one of rust|python|go|typescript=/absolute/path",
        )
    path = pathlib.Path(path_text)
    if not path.is_absolute():
        raise HarnessRefusal("path_not_absolute", "repository paths must be absolute")
    return RepositoryInput(language, path)


def inspect_input_repository(
    repository: RepositoryInput,
    *,
    limits: Any | None = None,
) -> Any:
    limits = limits or repository_support.Limits(
        max_selected_file_bytes=MAX_REPOSITORY_FILE_BYTES - 4096
    )
    try:
        root = repository_support.require_absolute_directory(repository.root, "repository")
        snapshot = repository_support.inspect_repository(root, repository.language, limits)
    except BaseException as error:
        if hasattr(error, "code"):
            raise _translate_support_refusal(error) from error
        raise
    if snapshot.dirty:
        raise HarnessRefusal("unsupported_git_dirty", "source repository must be clean")
    branch = _git_probe(root, ("symbolic-ref", "--quiet", "HEAD"))
    if branch.returncode != 0 or not branch.stdout.startswith(b"refs/heads/"):
        raise HarnessRefusal("unsupported_git_detached", "detached or unborn HEAD is unsupported")
    shallow = _git_probe(root, ("rev-parse", "--is-shallow-repository"))
    if shallow.returncode != 0 or shallow.stdout.strip() not in {b"true", b"false"}:
        raise HarnessRefusal("unsupported_git_state", "cannot determine shallow repository state")
    if shallow.stdout.strip() == b"true":
        raise HarnessRefusal("unsupported_git_shallow", "shallow repositories are unsupported")
    sparse = _git_probe(root, ("config", "--type=bool", "--get", "core.sparseCheckout"))
    if sparse.returncode not in {0, 1}:
        raise HarnessRefusal("unsupported_git_state", "cannot determine sparse checkout state")
    if sparse.returncode == 0 and sparse.stdout.strip() == b"true":
        raise HarnessRefusal("unsupported_git_sparse", "sparse checkouts are unsupported")
    for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "REBASE_HEAD", "BISECT_START"):
        probe = _git_probe(root, ("rev-parse", "--quiet", "--verify", name))
        if probe.returncode == 0:
            raise HarnessRefusal(
                "unsupported_git_operation", f"in-progress Git operation is unsupported: {name}"
            )
        if probe.returncode not in {1, 128}:
            raise HarnessRefusal("unsupported_git_state", f"cannot inspect Git state: {name}")
    for selected in snapshot.selected:
        try:
            (root / selected.path).read_bytes().decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise HarnessRefusal(
                "selected_input_binary", f"selected language input is not UTF-8: {selected.path}"
            ) from error
    return snapshot


def discover_go_repository(
    search_roots: Sequence[pathlib.Path],
    *,
    max_depth: int = MAX_SEARCH_DEPTH,
    max_candidates: int = MAX_SEARCH_CANDIDATES,
) -> dict[str, Any]:
    """Search explicit local roots for one eligible clean Go repository, read-only."""

    if not 1 <= len(search_roots) <= MAX_SEARCH_ROOTS:
        raise HarnessRefusal("search_root_bound", "Go search roots exceed their bound")
    if not 0 <= max_depth <= MAX_SEARCH_DEPTH:
        raise HarnessRefusal("search_depth_bound", "Go search depth exceeds its bound")
    if not 1 <= max_candidates <= MAX_SEARCH_CANDIDATES:
        raise HarnessRefusal("search_candidate_bound", "Go candidate limit exceeds its bound")
    roots: list[pathlib.Path] = []
    for root in search_roots:
        if not root.is_absolute():
            raise HarnessRefusal("path_not_absolute", "Go search roots must be absolute")
        try:
            canonical = root.resolve(strict=True)
            metadata = canonical.lstat()
        except OSError as error:
            raise HarnessRefusal("search_root_unavailable", "Go search root is unavailable") from error
        if canonical != root or not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise HarnessRefusal("search_root_not_canonical", "Go search root is not canonical")
        if canonical not in roots:
            roots.append(canonical)
        else:
            raise HarnessRefusal("duplicate_search_root", "Go search roots must be distinct")
    candidates: set[pathlib.Path] = set()
    search_errors: list[dict[str, str]] = []
    for root in roots:
        queue: list[tuple[pathlib.Path, int]] = [(root, 0)]
        while queue and len(candidates) < max_candidates:
            current, depth = queue.pop(0)
            try:
                git_marker = current / ".git"
                if git_marker.exists() or git_marker.is_symlink():
                    metadata = git_marker.lstat()
                    if not stat.S_ISLNK(metadata.st_mode) and (
                        stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
                    ):
                        candidates.add(current)
                if depth >= max_depth:
                    continue
                entries = sorted(os.scandir(current), key=lambda entry: entry.name)
                for entry in entries:
                    if entry.name == ".git" or entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    queue.append((pathlib.Path(entry.path), depth + 1))
            except OSError as error:
                search_errors.append({"root": str(current), "code": "search_unreadable"})
    records: list[dict[str, Any]] = []
    selected: str | None = None
    for candidate in sorted(candidates):
        tracked = _git_probe(candidate, ("ls-files", "-z", "--", "*.go"))
        paths = [item for item in tracked.stdout.split(b"\0") if item]
        regular = True
        bounded = True
        for relative in paths:
            try:
                relative_text = relative.decode("utf-8")
                relative_path = pathlib.PurePosixPath(relative_text)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    regular = False
                    continue
                metadata = (candidate / relative_path).lstat()
                regular = regular and stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)
                bounded = bounded and metadata.st_size <= MAX_REPOSITORY_FILE_BYTES
            except (OSError, UnicodeDecodeError, ValueError):
                regular = False
        status = _git_probe(candidate, ("status", "--porcelain=v1", "-z", "--untracked-files=all"))
        clean = status.returncode == 0 and status.stdout == b""
        try:
            inspect_input_repository(RepositoryInput("go", candidate))
            inspection_code = None
        except HarnessRefusal as error:
            inspection_code = error.code
        eligible = (
            tracked.returncode == 0
            and len(paths) >= 2
            and regular
            and bounded
            and clean
            and inspection_code is None
        )
        records.append(
            {
                "repository_root": str(candidate),
                "tracked_go_file_count": len(paths) if tracked.returncode == 0 else None,
                "checks": {
                    "git_probe_succeeded": tracked.returncode == 0,
                    "at_least_two_tracked_go_files": len(paths) >= 2,
                    "tracked_files_regular_non_symlink": regular,
                    "tracked_files_bounded": bounded,
                    "clean_worktree": clean,
                    "full_repository_inspection_passed": inspection_code is None,
                },
                "eligible": eligible,
                "refusal_code": None if eligible else inspection_code or "go_eligibility_failed",
            }
        )
        if eligible and selected is None:
            selected = str(candidate)
    return {
        "search_roots": [str(root) for root in roots],
        "max_depth": max_depth,
        "max_candidates": max_candidates,
        "candidate_count": len(records),
        "search_errors": search_errors,
        "selected_repository": selected,
        "go_repository_eligible": selected is not None,
        "eligibility_checks": records,
    }


def snapshot_identity(snapshot: Any) -> tuple[Any, ...]:
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


def _run_git_mutating_copy(root: pathlib.Path, *arguments: str) -> None:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=root,
        env={**_git_environment(), "HOME": str(root)},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if completed.returncode != 0:
        raise HarnessRefusal(
            "copied_git_setup_failed",
            completed.stderr.decode("utf-8", errors="replace")[:1000],
        )


def _write_new(path: pathlib.Path, value: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(value)


def prepare_workspace(snapshot: Any, workspace: pathlib.Path) -> dict[str, Any]:
    try:
        copied = repository_support.copy_selected_files(
            snapshot,
            workspace,
            limits=repository_support.Limits(
                max_selected_file_bytes=MAX_REPOSITORY_FILE_BYTES - 4096
            ),
        )
    except BaseException as error:
        if hasattr(error, "code"):
            raise _translate_support_refusal(error) from error
        raise
    first = workspace / copied[0].path
    second = workspace / copied[1].path
    first_text = first.read_text(encoding="utf-8")
    first.write_text(
        first_text
        + f"\n{RELEVANT_MARKER_V1}\n{IRRELEVANT_MARKER}\n",
        encoding="utf-8",
    )
    edge_files = {
        "edge/empty.txt": b"",
        "edge/binary.dat": b"prefix\x00\xffsuffix\n",
        "edge/large.txt": (b"large-fixture-line\n" * ((LARGE_FIXTURE_BYTES // 19) + 1))[
            :LARGE_FIXTURE_BYTES
        ],
        "edge/order-z.txt": f"{ORDER_MARKER} z\n".encode(),
        "edge/order-a.txt": f"{ORDER_MARKER} a\n".encode(),
        "edge/\u96ea-\u03bb.txt": f"{ORDER_MARKER} unicode\n".encode(),
        "status/tracked.txt": b"tracked-v1\n",
        "status/rename-old.txt": b"rename-v1\n",
        "status/delete.txt": b"delete-v1\n",
        "status/replace.txt": b"replace-v1\n",
        ".gitignore": b"status/ignored.txt\n",
    }
    for relative, value in edge_files.items():
        _write_new(workspace / relative, value)
    for index in range(BULK_FILE_COUNT):
        suffix = f"\n{CONCURRENT_MARKER}\n".encode() if index == BULK_FILE_COUNT - 1 else b"\n"
        prefix = f"bulk-{index:02d}\n".encode()
        filler = b"offline-corpus-filler\n" * ((BULK_FILE_BYTES // 22) + 1)
        _write_new(workspace / "bulk" / f"{index:02d}.txt", (prefix + filler)[: BULK_FILE_BYTES] + suffix)
    _run_git_mutating_copy(workspace, "init", "-q")
    _run_git_mutating_copy(workspace, "config", "user.name", "Again Corpus")
    _run_git_mutating_copy(workspace, "config", "user.email", "again-corpus@example.invalid")
    _run_git_mutating_copy(workspace, "config", "commit.gpgsign", "false")
    _run_git_mutating_copy(workspace, "add", "--all")
    _run_git_mutating_copy(workspace, "commit", "-q", "-m", "private corpus copy")
    _write_new(workspace / "status/untracked.txt", b"untracked-v1\n")
    _write_new(workspace / "status/ignored.txt", b"ignored-v1\n")
    return {
        "selected": [
            {
                "path": item.path,
                "source_size": item.size,
                "source_sha256": item.sha256,
                "copied_sha256": sha256_file(workspace / item.path),
            }
            for item in copied
        ],
        "fixture_manifest_sha256": workspace_manifest_sha256(workspace),
        "first_path": copied[0].path,
        "second_path": copied[1].path,
    }


def workspace_manifest_sha256(workspace: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (item for item in workspace.rglob("*") if ".git" not in item.relative_to(workspace).parts),
        key=lambda item: item.relative_to(workspace).as_posix(),
    ):
        relative = path.relative_to(workspace).as_posix()
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (path.is_dir() or stat.S_ISREG(metadata.st_mode)):
            raise HarnessRefusal("workspace_special_file", f"private workspace has unsafe node: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        if stat.S_ISREG(metadata.st_mode):
            digest.update(str(metadata.st_size).encode("ascii"))
            digest.update(b"\0")
            digest.update(bytes.fromhex(sha256_file(path)))
    return digest.hexdigest()


def _safe_relative(workspace: pathlib.Path, relative: str) -> pathlib.Path:
    pure = pathlib.PurePosixPath(relative)
    if not relative or pure.is_absolute() or ".." in pure.parts or "\x00" in relative:
        raise HarnessRefusal("native_invalid_path", "path is not bounded and relative")
    path = workspace.joinpath(*pure.parts)
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise HarnessRefusal("native_missing", "path is missing") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise HarnessRefusal("native_symlink", "symlink paths are refused")
    return path


def native_read(workspace: pathlib.Path, relative: str) -> NativeObservation:
    try:
        path = _safe_relative(workspace, relative)
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_REPOSITORY_FILE_BYTES:
            raise HarnessRefusal("native_not_regular", "path is not an admitted regular file")
        raw = path.read_bytes()
        text = raw.decode("utf-8", errors="strict")
    except (HarnessRefusal, UnicodeDecodeError):
        return NativeObservation("error", error_code=-32602)
    return NativeObservation(
        "ok",
        {
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"path": relative, "bytes": len(raw)},
        },
    )


def _rust_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def native_search(
    workspace: pathlib.Path,
    pattern: str,
    relative: str = ".",
    maximum: int = 200,
) -> NativeObservation:
    if not pattern or len(pattern.encode("utf-8")) > 4096 or not 1 <= maximum <= 500:
        return NativeObservation("error", error_code=-32602)
    try:
        root = _safe_relative(workspace, relative)
    except HarnessRefusal:
        return NativeObservation("error", error_code=-32602)
    if root.is_file():
        paths = [root]
    elif root.is_dir():
        paths = []
        for candidate in root.rglob("*"):
            if ".git" in candidate.relative_to(workspace).parts:
                continue
            try:
                metadata = candidate.lstat()
            except OSError:
                return NativeObservation("error", error_code=-32603)
            if stat.S_ISLNK(metadata.st_mode):
                return NativeObservation("error", error_code=-32603)
            if stat.S_ISREG(metadata.st_mode):
                paths.append(candidate)
    else:
        return NativeObservation("error", error_code=-32602)
    paths.sort(key=lambda path: path.relative_to(workspace).as_posix())
    scanned = 0
    rendered_bytes = 0
    matches: list[dict[str, Any]] = []
    truncated = False
    for path in paths:
        metadata = path.stat()
        scanned += metadata.st_size
        if metadata.st_size > MAX_REPOSITORY_FILE_BYTES or scanned > MAX_REPOSITORY_SCAN_BYTES:
            return NativeObservation("error", error_code=-32021)
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(_rust_lines(text), 1):
            if pattern not in line:
                continue
            encoded = line.encode("utf-8")
            if len(encoded) > 4096:
                encoded = encoded[:4096]
                while True:
                    try:
                        snippet = encoded.decode("utf-8")
                        break
                    except UnicodeDecodeError:
                        encoded = encoded[:-1]
            else:
                snippet = line
            path_text = path.relative_to(workspace).as_posix()
            estimated = len(path_text.encode()) + len(snippet.encode()) + 32
            if rendered_bytes + estimated > 512 * 1024:
                truncated = True
                break
            rendered_bytes += estimated
            matches.append(
                {
                    "path": path_text,
                    "line": line_number,
                    "text": snippet,
                    "lineTruncated": snippet != line,
                }
            )
            if len(matches) >= maximum:
                truncated = True
                break
        if truncated:
            break
    rendered = "\n".join(
        f"{item['path']}:{item['line']}:{item['text']}" for item in matches
    )
    return NativeObservation(
        "ok",
        {
            "content": [{"type": "text", "text": rendered}],
            "structuredContent": {
                "pattern": pattern,
                "path": relative,
                "matches": matches,
                "truncated": truncated,
            },
        },
    )


def result_without_reference(result: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in result.items() if key != "_meta"}


def result_id(result: Mapping[str, Any]) -> str | None:
    metadata = result.get("_meta")
    again = metadata.get("again") if isinstance(metadata, dict) else None
    candidate = again.get("resultId") if isinstance(again, dict) else None
    if isinstance(candidate, str) and len(candidate) == 64:
        return candidate
    return None


def compare_observation(response: Mapping[str, Any], native: NativeObservation) -> dict[str, Any]:
    if native.status == "ok":
        actual = response.get("result")
        if not isinstance(actual, dict) or "error" in response:
            raise HarnessRefusal("status_mismatch", "native success and Again status differ")
        comparable = result_without_reference(actual)
        if comparable != native.value:
            raise HarnessRefusal("content_or_order_mismatch", "Again result differs from native oracle")
        return {
            "status": "ok",
            "result_id": result_id(actual),
            "payload_sha256": sha256_bytes(canonical_json_bytes(comparable)),
        }
    error = response.get("error")
    if not isinstance(error, dict) or "result" in response:
        raise HarnessRefusal("status_mismatch", "native refusal and Again status differ")
    if error.get("code") != native.error_code:
        raise HarnessRefusal(
            "error_status_mismatch",
            f"Again error {error.get('code')!r}, expected {native.error_code!r}",
        )
    return {
        "status": "error",
        "error_code": error.get("code"),
        "result_id": None,
        "payload_sha256": sha256_bytes(canonical_json_bytes(error)),
    }


class GatewayAudit:
    """Read-only event accounting; rows never act as result authority."""

    def __init__(self, database: pathlib.Path):
        self.database = database

    def _connection(self) -> sqlite3.Connection:
        if not self.database.is_file() or self.database.is_symlink():
            raise HarnessRefusal("database_missing", "gateway database is unavailable")
        connection = sqlite3.connect(
            f"file:{self.database.as_posix()}?mode=ro", uri=True, timeout=2, isolation_level=None
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != EXPECTED_DATABASE_SCHEMA:
            connection.close()
            raise HarnessRefusal(
                "database_schema", f"expected schema {EXPECTED_DATABASE_SCHEMA}, got {version}"
            )
        return connection

    def begin(self) -> EventCursor:
        with self._connection() as connection:
            event_id = int(
                connection.execute("SELECT COALESCE(MAX(id),0) FROM gateway_events").fetchone()[0]
            )
        return EventCursor(event_id, int(time.time() * 1000))

    def end(self, cursor: EventCursor) -> dict[str, Any]:
        ended_ms = int(time.time() * 1000)
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT id,event_type,call_id,lease_id,gateway_result_id,reason,created_ms
                FROM gateway_events
                WHERE id > ?1 AND created_ms BETWEEN ?2 AND ?3
                ORDER BY id
                """,
                (cursor.event_id, cursor.started_ms, ended_ms),
            ).fetchall()
        counts = collections.Counter(str(row["event_type"]) for row in rows)
        return {
            "event_counts": dict(sorted(counts.items())),
            "event_rows": len(rows),
            "event_id_first": int(rows[0]["id"]) if rows else None,
            "event_id_last": int(rows[-1]["id"]) if rows else cursor.event_id,
        }

    def totals(self) -> dict[str, int]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_type,COUNT(*) FROM gateway_events GROUP BY event_type ORDER BY event_type"
            ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}


def _server_environment(
    state: pathlib.Path, home: pathlib.Path, temporary: pathlib.Path
) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "AGAIN_HOME": str(state),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
        "CARGO_NET_OFFLINE": "true",
        "http_proxy": NETWORK_BLOCK_ENDPOINT,
        "https_proxy": NETWORK_BLOCK_ENDPOINT,
        "all_proxy": NETWORK_BLOCK_ENDPOINT,
        "HTTP_PROXY": NETWORK_BLOCK_ENDPOINT,
        "HTTPS_PROXY": NETWORK_BLOCK_ENDPOINT,
        "ALL_PROXY": NETWORK_BLOCK_ENDPOINT,
        "NO_PROXY": "",
        "no_proxy": "",
    }


def network_boundary_record() -> dict[str, Any]:
    return {
        "harness_clone_download_or_network_client_path": False,
        "git_protocol_allowlist": "file",
        "proxy_environment_redirected_to_loopback_refusal": True,
        "network_namespace_sandbox": False,
        "fresh_socket_creation_blocked": False,
        "trusted_product_operations": ["repo.read", "repo.search"],
    }


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_process_group_exit(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _terminate_process_group(process: subprocess.Popen[bytes], process_group: int) -> None:
    if _process_group_exists(process_group):
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=PROCESS_STOP_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    if not _wait_for_process_group_exit(process_group, PROCESS_STOP_SECONDS):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
    try:
        process.wait(timeout=PROCESS_STOP_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise HarnessRefusal("process_leader_remaining", "MCP leader did not terminate") from error
    if not _wait_for_process_group_exit(process_group, PROCESS_STOP_SECONDS):
        raise HarnessRefusal("process_group_remaining", "MCP process group did not terminate")


class CorpusMcpSession(gateway_support.McpSession):
    """Product protocol session with corpus-owned whole-group cleanup."""

    def __init__(
        self,
        *,
        binary: pathlib.Path,
        workspace: pathlib.Path,
        state: pathlib.Path,
        home: pathlib.Path,
        temporary: pathlib.Path,
        label: str,
        timeout_seconds: float,
    ) -> None:
        self.label = label
        self.timeout_seconds = timeout_seconds
        self.argv = (
            str(binary),
            "mcp",
            "serve",
            "--workspace",
            str(workspace),
            "--authorization-scope",
            "again-real-repository-corpus:shared-v1",
        )
        self.environment = _server_environment(state, home, temporary)
        try:
            self.process = subprocess.Popen(
                self.argv,
                cwd=workspace,
                env=self.environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=True,
            )
        except OSError as error:
            raise HarnessRefusal("process_launch", "MCP process did not launch") from error
        self.process_group = self.process.pid
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            cleanup_codes: list[str] = []
            try:
                _terminate_process_group(self.process, self.process_group)
            except HarnessRefusal as cleanup:
                cleanup_codes.append(cleanup.code)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        cleanup_codes.append("pipe_close")
            raise HarnessRefusal(
                "process_pipe_failure",
                "MCP pipes were not created",
                cleanup_complete=not cleanup_codes,
                cleanup_codes=tuple(dict.fromkeys(cleanup_codes)),
            )
        self._stdin = self.process.stdin
        self._stdout = self.process.stdout
        self._stderr = self.process.stderr
        self._stdout_buffer = bytearray()
        self._stderr_capture = bytearray()
        self._stderr_overflow = False
        self._write_lock = threading.Lock()
        self._request_lock = threading.Lock()
        self.request_hashes: list[str] = []
        self.response_hashes: list[str] = []
        self.advertised_tools: set[str] = set()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        try:
            self._stderr_thread.start()
        except BaseException as primary:
            cleanup_codes = []
            try:
                _terminate_process_group(self.process, self.process_group)
            except HarnessRefusal as cleanup:
                cleanup_codes.append(cleanup.code)
            for stream in (self._stdin, self._stdout, self._stderr):
                try:
                    stream.close()
                except OSError:
                    cleanup_codes.append("pipe_close")
            raise HarnessRefusal(
                "stderr_thread_start",
                "MCP stderr drain did not start",
                cleanup_complete=not cleanup_codes,
                cleanup_codes=tuple(dict.fromkeys(cleanup_codes)),
            ) from primary
        self._closed_record: dict[str, Any] | None = None

    def close_and_evidence(self) -> tuple[dict[str, Any], tuple[str, ...]]:
        if self._closed_record is not None:
            return dict(self._closed_record), ()
        failures: list[str] = []
        if not self._stdin.closed:
            try:
                self._stdin.close()
            except (BrokenPipeError, OSError):
                failures.append("stdin_close")
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=PROCESS_STOP_SECONDS)
            except subprocess.TimeoutExpired:
                failures.append("leader_grace_timeout")
        if self.process.poll() is not None:
            # A just-reaped leader can leave a short-lived process-group view
            # while the kernel finishes accounting for the final member. Give
            # a naturally exiting group one bounded grace period before
            # signaling it or classifying it as descendant-bearing evidence.
            descendants_observed = not _wait_for_process_group_exit(
                self.process_group, PROCESS_STOP_SECONDS
            )
        else:
            descendants_observed = _process_group_exists(self.process_group)
        if descendants_observed:
            try:
                _terminate_process_group(self.process, self.process_group)
            except HarnessRefusal as error:
                failures.append(error.code)
            if self.process.poll() is not None and self.process.returncode == 0:
                failures.append("process_group_descendant")
        for name, stream in (
            ("stdin", self._stdin),
            ("stdout", self._stdout),
            ("stderr", self._stderr),
        ):
            if not stream.closed:
                try:
                    stream.close()
                except OSError:
                    failures.append(f"{name}_close")
        self._stderr_thread.join(timeout=PROCESS_STOP_SECONDS)
        if self._stderr_thread.is_alive():
            failures.append("stderr_drain_timeout")
        if self._stderr_overflow:
            failures.append("stderr_oversized")
        return_code = self.process.poll()
        group_reaped = not _process_group_exists(self.process_group)
        streams_closed = all(stream.closed for stream in (self._stdin, self._stdout, self._stderr))
        cleanup_complete = (
            return_code is not None
            and group_reaped
            and streams_closed
            and not self._stderr_thread.is_alive()
        )
        record = {
            "label": self.label,
            "argv": list(self.argv),
            "pid": self.process.pid,
            "return_code": return_code,
            "process_group_reaped": group_reaped,
            "stderr_complete": not self._stderr_thread.is_alive() and not self._stderr_overflow,
            "cleanup_complete": cleanup_complete,
            "stdout": {
                "frame_count": len(self.response_hashes),
                "response_sha256": list(self.response_hashes),
            },
            "stderr": {
                "bytes": len(self._stderr_capture),
                "sha256": sha256_bytes(bytes(self._stderr_capture)),
                "truncated": self._stderr_overflow,
            },
            "request_sha256": list(self.request_hashes),
        }
        if cleanup_complete:
            self._closed_record = dict(record)
        return record, tuple(dict.fromkeys(failures))


def start_session(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    state: pathlib.Path,
    root: pathlib.Path,
    label: str,
    timeout_seconds: float,
    sessions: list[CorpusMcpSession],
) -> Any:
    home = root / f"home-{label}"
    temporary = root / f"tmp-{label}"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    session = CorpusMcpSession(
        binary=binary,
        workspace=workspace,
        state=state,
        home=home,
        temporary=temporary,
        label=label,
        timeout_seconds=timeout_seconds,
    )
    sessions.append(session)
    try:
        expected = _server_environment(state, home, temporary)
        if session.environment != expected:
            raise HarnessRefusal("server_environment", "MCP server environment is not isolated")
        session.handshake(f"again-real-repository-corpus-{label}")
    except BaseException as primary:
        cleanup_record, cleanup_codes = session.close_and_evidence()
        cleanup_complete = bool(cleanup_record.get("cleanup_complete"))
        if isinstance(primary, HarnessRefusal):
            raise HarnessRefusal(
                primary.code,
                str(primary),
                cleanup_complete=cleanup_complete,
                cleanup_codes=cleanup_codes,
            ) from primary
        raise HarnessRefusal(
            "session_handshake",
            "MCP session handshake failed",
            cleanup_complete=cleanup_complete,
            cleanup_codes=cleanup_codes,
        ) from primary
    return session


def _timed_tool_call(
    session: Any, request_id: str, tool: str, arguments: Mapping[str, Any]
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()
    response = session.tool_call(request_id, tool, arguments)
    return response, (time.perf_counter_ns() - started) / 1_000_000


def invocation_record(
    *,
    label: str,
    tool: str,
    arguments: Mapping[str, Any],
    response: Mapping[str, Any],
    native: NativeObservation,
    elapsed_ms: float,
    audit: Mapping[str, Any],
) -> dict[str, Any]:
    comparison = compare_observation(response, native)
    return {
        "label": label,
        "command": {"tool": tool, "arguments": dict(arguments)},
        "elapsed_ms": elapsed_ms,
        "response_sha256": sha256_bytes(canonical_json_bytes(response)),
        "comparison": comparison,
        "audit": dict(audit),
    }


def latency_analysis(value: Any, timeout_seconds: float) -> dict[str, Any]:
    timings: list[tuple[str, float]] = []

    def visit(current: Any) -> None:
        if isinstance(current, dict):
            label = current.get("label")
            elapsed = current.get("elapsed_ms")
            if (
                isinstance(label, str)
                and isinstance(current.get("command"), dict)
                and isinstance(elapsed, (int, float))
                and not isinstance(elapsed, bool)
            ):
                timings.append((label, float(elapsed)))
            for child in current.values():
                visit(child)
        elif isinstance(current, list):
            for child in current:
                visit(child)

    visit(value)
    if not timings:
        raise HarnessRefusal("timing_missing", "no invocation timings were recorded")
    ordered = sorted(elapsed for _, elapsed in timings)

    def nearest_rank(fraction: float) -> float:
        index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
        return ordered[index]

    anomaly_threshold = min(timeout_seconds * 1000, max(2000.0, nearest_rank(0.95) * 4))
    anomalous = [
        {"label": label, "elapsed_ms": elapsed}
        for label, elapsed in sorted(timings, key=lambda item: item[1], reverse=True)
        if elapsed > anomaly_threshold
    ]
    return {
        "count": len(timings),
        "minimum_ms": ordered[0],
        "median_ms": nearest_rank(0.5),
        "p95_ms": nearest_rank(0.95),
        "maximum_ms": ordered[-1],
        "anomaly_threshold_ms": anomaly_threshold,
        "anomalous": anomalous,
        "slowest": [
            {"label": label, "elapsed_ms": elapsed}
            for label, elapsed in sorted(timings, key=lambda item: item[1], reverse=True)[:5]
        ],
    }


def reconcile_gateway_counters(totals: Mapping[str, int]) -> dict[str, int]:
    counters = {
        "requested": int(totals.get("requested", 0)),
        "provider_executions": int(totals.get("executed", 0)),
        "inflight_joins": int(totals.get("inflight_join", 0)),
        "exact_hits": int(totals.get("exact_hit", 0)),
    }
    routes = (
        counters["provider_executions"]
        + counters["inflight_joins"]
        + counters["exact_hits"]
    )
    if counters["requested"] != routes:
        raise HarnessRefusal(
            "gateway_counter_mismatch",
            f"requested={counters['requested']} but terminal routes={routes}",
        )
    if int(totals.get("completed", 0)) + int(totals.get("failed", 0)) != counters[
        "provider_executions"
    ]:
        raise HarnessRefusal(
            "gateway_counter_mismatch", "provider executions do not reconcile to completion/failure"
        )
    return counters


def process_evidence(
    records: Sequence[Mapping[str, Any]],
    expected_labels: Sequence[str],
    expected_binary: pathlib.Path | None = None,
) -> list[dict[str, Any]]:
    records = [dict(record) for record in records]
    labels = [record.get("label") for record in records]
    pids = [record.get("pid") for record in records]
    if (
        labels != list(expected_labels)
        or len(set(labels)) != len(labels)
        or len(set(pids)) != len(pids)
        or any(not isinstance(pid, int) or pid <= 0 for pid in pids)
        or any(
            record.get("return_code") != 0
            or not isinstance(record.get("return_code"), int)
            or isinstance(record.get("return_code"), bool)
            for record in records
        )
        or any(record.get("process_group_reaped") is not True for record in records)
        or any(record.get("stderr_complete") is not True for record in records)
        or any(record.get("cleanup_complete") is not True for record in records)
        or (
            expected_binary is not None
            and any(
                not isinstance(record.get("argv"), list)
                or not record["argv"]
                or record["argv"][0] != str(expected_binary)
                for record in records
            )
        )
    ):
        raise HarnessRefusal("process_ledger", "MCP process ledger is not one-to-one")
    return records


def run_verified_call(
    session: Any,
    audit: GatewayAudit,
    label: str,
    tool: str,
    arguments: Mapping[str, Any],
    native: NativeObservation,
) -> dict[str, Any]:
    cursor = audit.begin()
    response, elapsed = _timed_tool_call(session, label, tool, arguments)
    return invocation_record(
        label=label,
        tool=tool,
        arguments=arguments,
        response=response,
        native=native,
        elapsed_ms=elapsed,
        audit=audit.end(cursor),
    )


def require_event(record: Mapping[str, Any], event_type: str) -> None:
    counts = record.get("audit", {}).get("event_counts", {})
    if not isinstance(counts, dict) or int(counts.get(event_type, 0)) < 1:
        raise HarnessRefusal("event_missing", f"{record.get('label')} lacks {event_type}")


def run_cold_warm(
    first: Any,
    second: Any,
    audit: GatewayAudit,
    label: str,
    tool: str,
    arguments: Mapping[str, Any],
    native: NativeObservation,
) -> dict[str, Any]:
    cold = run_verified_call(first, audit, f"{label}:cold", tool, arguments, native)
    warm = run_verified_call(second, audit, f"{label}:warm", tool, arguments, native)
    if native.status == "ok":
        cold_id = cold["comparison"]["result_id"]
        warm_id = warm["comparison"]["result_id"]
        if cold_id is None or warm_id != cold_id:
            raise HarnessRefusal("reuse_identity", f"{label} did not reuse the exact result")
        require_event(cold, "executed")
        require_event(warm, "exact_hit")
    return {"cold": cold, "warm": warm}


def _replace_file(path: pathlib.Path, value: bytes) -> dict[str, Any]:
    before = sha256_file(path)
    replacement = path.with_name(path.name + ".replacement")
    with replacement.open("xb") as output:
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    os.replace(replacement, path)
    return {"path": path.name, "sha256_before": before, "sha256_after": sha256_file(path)}


def run_repository(
    *,
    binary: pathlib.Path,
    snapshot: Any,
    temporary_root: pathlib.Path,
    timeout_seconds: float,
) -> dict[str, Any]:
    temporary_root.mkdir(mode=0o700)
    workspace = temporary_root / f"workspace-{snapshot.language}"
    state = temporary_root / f"state-{snapshot.language}"
    state.mkdir(mode=0o700)
    prepared = prepare_workspace(snapshot, workspace)
    sessions: list[CorpusMcpSession] = []
    scenarios: dict[str, Any] = {}
    false_hits = 0
    started_ns = time.perf_counter_ns()
    report: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    try:
        first = start_session(
            binary,
            workspace,
            state,
            temporary_root,
            f"{snapshot.language}-a",
            timeout_seconds,
            sessions,
        )
        second = start_session(
            binary,
            workspace,
            state,
            temporary_root,
            f"{snapshot.language}-b",
            timeout_seconds,
            sessions,
        )
        audit = GatewayAudit(state / "again.sqlite")

        first_path = prepared["first_path"]
        second_path = prepared["second_path"]
        scenarios["real_tracked_read"] = run_cold_warm(
            first,
            second,
            audit,
            "real-tracked-read",
            "repo.read",
            {"path": first_path},
            native_read(workspace, first_path),
        )

        concurrent_arguments = {"pattern": CONCURRENT_MARKER, "path": "bulk", "maxResults": 50}
        concurrent_native = native_search(workspace, CONCURRENT_MARKER, "bulk", 50)
        cursor = audit.begin()
        barrier = threading.Barrier(3)
        outcomes: list[dict[str, Any]] = [{}, {}]

        def worker(index: int, session: Any) -> None:
            try:
                barrier.wait(timeout=5)
                response, elapsed = _timed_tool_call(
                    session,
                    f"concurrent-{index}",
                    "repo.search",
                    concurrent_arguments,
                )
                outcomes[index] = {"response": response, "elapsed_ms": elapsed}
            except BaseException as error:  # re-raised by the controller
                outcomes[index] = {"error": error}

        workers = [
            threading.Thread(target=worker, args=(0, first)),
            threading.Thread(target=worker, args=(1, second)),
        ]
        for thread in workers:
            thread.start()
        barrier.wait(timeout=5)
        for thread in workers:
            thread.join(timeout_seconds)
        if any(thread.is_alive() for thread in workers):
            raise HarnessRefusal("concurrent_timeout", "concurrent MCP calls did not finish")
        for outcome in outcomes:
            if "error" in outcome:
                error = outcome["error"]
                if hasattr(error, "code"):
                    raise HarnessRefusal(str(error.code), str(error)) from error
                raise HarnessRefusal("concurrent_failure", str(error)) from error
        concurrent_audit = audit.end(cursor)
        concurrent_records = [
            invocation_record(
                label=f"concurrent-{index}",
                tool="repo.search",
                arguments=concurrent_arguments,
                response=outcome["response"],
                native=concurrent_native,
                elapsed_ms=outcome["elapsed_ms"],
                audit=concurrent_audit,
            )
            for index, outcome in enumerate(outcomes)
        ]
        ids = [record["comparison"]["result_id"] for record in concurrent_records]
        counts = concurrent_audit["event_counts"]
        if ids[0] is None or ids[0] != ids[1] or counts.get("executed") != 1 or counts.get("inflight_join") != 1:
            raise HarnessRefusal("concurrent_join_unproven", "two MCP processes did not execute/join exactly once")
        scenarios["concurrent_process_join"] = {
            "calls": concurrent_records,
            "exactly_one_provider_execution": True,
            "joined_current_inflight": True,
        }

        later = run_verified_call(
            first,
            audit,
            "later-reuse",
            "repo.search",
            concurrent_arguments,
            concurrent_native,
        )
        require_event(later, "exact_hit")
        if later["comparison"]["result_id"] != ids[0]:
            false_hits += 1
            raise HarnessRefusal("later_reuse_identity", "later reuse selected another result")
        scenarios["later_reuse"] = later

        _second_record, second_failures = second.close_and_evidence()
        if second_failures:
            raise HarnessRefusal(
                "process_cleanup",
                "retired MCP session did not close cleanly",
                cleanup_complete=False,
                cleanup_codes=second_failures,
            )
        restarted = start_session(
            binary,
            workspace,
            state,
            temporary_root,
            f"{snapshot.language}-restarted",
            timeout_seconds,
            sessions,
        )
        restart = run_verified_call(
            restarted,
            audit,
            "restart-reuse",
            "repo.search",
            concurrent_arguments,
            concurrent_native,
        )
        require_event(restart, "exact_hit")
        if restart["comparison"]["result_id"] != ids[0]:
            false_hits += 1
            raise HarnessRefusal("restart_reuse_identity", "restart did not preserve exact result")
        scenarios["restart_reuse"] = restart

        irrelevant_arguments = {
            "pattern": IRRELEVANT_MARKER,
            "path": first_path,
            "maxResults": 20,
        }
        irrelevant_native = native_search(workspace, IRRELEVANT_MARKER, first_path, 20)
        irrelevant_pair = run_cold_warm(
            first,
            restarted,
            audit,
            "irrelevant-baseline",
            "repo.search",
            irrelevant_arguments,
            irrelevant_native,
        )
        irrelevant_id = irrelevant_pair["cold"]["comparison"]["result_id"]
        second_file = workspace / second_path
        irrelevant_mutation = _replace_file(
            second_file, second_file.read_bytes() + b"\nDEPENDENCY_IRRELEVANT_MUTATION\n"
        )
        irrelevant_after = run_verified_call(
            restarted,
            audit,
            "irrelevant-after-mutation",
            "repo.search",
            irrelevant_arguments,
            irrelevant_native,
        )
        require_event(irrelevant_after, "exact_hit")
        if irrelevant_after["comparison"]["result_id"] != irrelevant_id:
            false_hits += 1
            raise HarnessRefusal("irrelevant_reuse_missed", "unrelated dependency prevented safe reuse")
        scenarios["dependency_irrelevant_mutation"] = {
            "baseline": irrelevant_pair,
            "mutation": irrelevant_mutation,
            "after": irrelevant_after,
            "safe_exact_reuse": True,
        }

        relevant_arguments = {
            "pattern": RELEVANT_MARKER_V1,
            "path": first_path,
            "maxResults": 20,
        }
        relevant_before_native = native_search(workspace, RELEVANT_MARKER_V1, first_path, 20)
        relevant_pair = run_cold_warm(
            first,
            restarted,
            audit,
            "relevant-baseline",
            "repo.search",
            relevant_arguments,
            relevant_before_native,
        )
        relevant_id = relevant_pair["cold"]["comparison"]["result_id"]
        relevant_file = workspace / first_path
        old = relevant_file.read_text(encoding="utf-8")
        if old.count(RELEVANT_MARKER_V1) != 1:
            raise HarnessRefusal("fixture_marker", "relevant marker is not unique")
        relevant_mutation = _replace_file(
            relevant_file,
            old.replace(RELEVANT_MARKER_V1, RELEVANT_MARKER_V2).encode("utf-8"),
        )
        relevant_after_native = native_search(workspace, RELEVANT_MARKER_V1, first_path, 20)
        relevant_after = run_verified_call(
            first,
            audit,
            "relevant-after-mutation",
            "repo.search",
            relevant_arguments,
            relevant_after_native,
        )
        require_event(relevant_after, "executed")
        if relevant_after["comparison"]["result_id"] in {None, relevant_id}:
            false_hits += 1
            raise HarnessRefusal("relevant_false_hit", "relevant mutation replayed stale output")
        scenarios["dependency_relevant_mutation"] = {
            "baseline": relevant_pair,
            "mutation": relevant_mutation,
            "after": relevant_after,
            "invalidated": True,
        }

        for label, relative in (
            ("tracked", "status/tracked.txt"),
            ("untracked", "status/untracked.txt"),
            ("ignored", "status/ignored.txt"),
            ("unicode", "edge/\u96ea-\u03bb.txt"),
            ("empty", "edge/empty.txt"),
            ("large", "edge/large.txt"),
        ):
            scenarios[f"file_{label}"] = run_cold_warm(
                first,
                restarted,
                audit,
                f"file-{label}",
                "repo.read",
                {"path": relative},
                native_read(workspace, relative),
            )

        order_arguments = {"pattern": ORDER_MARKER, "path": "edge", "maxResults": 50}
        order_native = native_search(workspace, ORDER_MARKER, "edge", 50)
        order_paths = [
            item["path"]
            for item in (order_native.value or {}).get("structuredContent", {}).get("matches", [])
        ]
        if order_paths != sorted(order_paths):
            raise HarnessRefusal("native_order", "native search order is not deterministic")
        scenarios["unicode_search_order"] = run_cold_warm(
            first,
            restarted,
            audit,
            "unicode-search-order",
            "repo.search",
            order_arguments,
            order_native,
        )

        binary_native = native_read(workspace, "edge/binary.dat")
        binary_first = run_verified_call(
            first,
            audit,
            "binary-refusal-1",
            "repo.read",
            {"path": "edge/binary.dat"},
            binary_native,
        )
        binary_second = run_verified_call(
            restarted,
            audit,
            "binary-refusal-2",
            "repo.read",
            {"path": "edge/binary.dat"},
            binary_native,
        )
        if binary_first["comparison"]["result_id"] is not None or binary_second["comparison"]["result_id"] is not None:
            raise HarnessRefusal("binary_result_published", "binary refusal published reusable authority")
        scenarios["binary_refusal"] = {"first": binary_first, "second": binary_second}

        rename_old = "status/rename-old.txt"
        rename_new = "status/rename-new.txt"
        rename_baseline = run_cold_warm(
            first,
            restarted,
            audit,
            "rename-baseline",
            "repo.read",
            {"path": rename_old},
            native_read(workspace, rename_old),
        )
        os.replace(workspace / rename_old, workspace / rename_new)
        rename_missing = run_verified_call(
            first,
            audit,
            "rename-old-missing",
            "repo.read",
            {"path": rename_old},
            native_read(workspace, rename_old),
        )
        rename_new_pair = run_cold_warm(
            first,
            restarted,
            audit,
            "rename-new",
            "repo.read",
            {"path": rename_new},
            native_read(workspace, rename_new),
        )
        scenarios["renamed_file"] = {
            "baseline": rename_baseline,
            "old_path": rename_missing,
            "new_path": rename_new_pair,
        }

        delete_path = "status/delete.txt"
        delete_baseline = run_cold_warm(
            first,
            restarted,
            audit,
            "delete-baseline",
            "repo.read",
            {"path": delete_path},
            native_read(workspace, delete_path),
        )
        (workspace / delete_path).unlink()
        delete_after = run_verified_call(
            restarted,
            audit,
            "delete-after",
            "repo.read",
            {"path": delete_path},
            native_read(workspace, delete_path),
        )
        scenarios["deleted_file"] = {"baseline": delete_baseline, "after": delete_after}

        replace_path = "status/replace.txt"
        replace_baseline = run_cold_warm(
            first,
            restarted,
            audit,
            "replace-baseline",
            "repo.read",
            {"path": replace_path},
            native_read(workspace, replace_path),
        )
        replace_id = replace_baseline["cold"]["comparison"]["result_id"]
        replacement = _replace_file(workspace / replace_path, b"replace-v2\n")
        replace_after = run_verified_call(
            first,
            audit,
            "replace-after",
            "repo.read",
            {"path": replace_path},
            native_read(workspace, replace_path),
        )
        require_event(replace_after, "executed")
        if replace_after["comparison"]["result_id"] in {None, replace_id}:
            false_hits += 1
            raise HarnessRefusal("replacement_false_hit", "replacement replayed stale output")
        scenarios["replaced_file"] = {
            "baseline": replace_baseline,
            "mutation": replacement,
            "after": replace_after,
        }

        totals = audit.totals()
        counters = {**reconcile_gateway_counters(totals), "false_hits": false_hits}
        if counters["false_hits"] != 0:
            raise HarnessRefusal("false_hits", "one or more reuse results were incorrect")
        report = {
            "outcome": "pass",
            "language": snapshot.language,
            "repository": {
                "root": str(snapshot.root),
                "git_sha": snapshot.git_sha,
                "tracked_manifest_sha256": snapshot.tracked_manifest_sha256,
                "tracked_worktree_stat_sha256": snapshot.tracked_worktree_stat_sha256,
                "tracked_files": snapshot.tracked_files,
                "logical_bytes": snapshot.repository_logical_bytes,
                "selected": prepared["selected"],
            },
            "workspace_fixture_manifest_sha256": prepared["fixture_manifest_sha256"],
            "scenarios": scenarios,
            "latency_analysis": latency_analysis(scenarios, timeout_seconds),
            "gateway_event_totals": totals,
            "counters": counters,
            "elapsed_ms": (time.perf_counter_ns() - started_ns) / 1_000_000,
        }
    except BaseException as error:
        primary_error = error

    cleanup_records_by_pid: dict[int, dict[str, Any]] = {}
    cleanup_codes: list[str] = []
    cleanup_complete = True
    for session in reversed(sessions):
        try:
            record, failures = session.close_and_evidence()
        except BaseException:
            cleanup_complete = False
            cleanup_codes.append("cleanup_internal")
            continue
        cleanup_records_by_pid[session.process.pid] = record
        cleanup_codes.extend(failures)
        cleanup_complete = cleanup_complete and bool(record.get("cleanup_complete"))

    if primary_error is not None:
        if isinstance(primary_error, HarnessRefusal):
            combined_codes = (*primary_error.cleanup_codes, *dict.fromkeys(cleanup_codes))
            raise HarnessRefusal(
                primary_error.code,
                str(primary_error),
                cleanup_complete=primary_error.cleanup_complete and cleanup_complete,
                cleanup_codes=combined_codes,
            ) from primary_error
        raise HarnessRefusal(
            "repository_run_internal",
            "repository corpus run failed",
            cleanup_complete=cleanup_complete,
            cleanup_codes=tuple(dict.fromkeys(cleanup_codes)),
        ) from primary_error
    if cleanup_codes or not cleanup_complete:
        raise HarnessRefusal(
            "process_cleanup",
            "one or more MCP sessions did not clean up",
            cleanup_complete=cleanup_complete,
            cleanup_codes=tuple(dict.fromkeys(cleanup_codes)),
        )
    if report is None:
        raise HarnessRefusal("repository_run_internal", "repository report was not constructed")
    ordered_records = [cleanup_records_by_pid[session.process.pid] for session in sessions]
    labels = (
        f"{snapshot.language}-a",
        f"{snapshot.language}-b",
        f"{snapshot.language}-restarted",
    )
    report["processes"] = process_evidence(ordered_records, labels, binary)
    return report


def repository_record(snapshot: Any) -> dict[str, Any]:
    return {
        "language": snapshot.language,
        "root": str(snapshot.root),
        "git_sha": snapshot.git_sha,
        "tracked_manifest_sha256": snapshot.tracked_manifest_sha256,
        "tracked_worktree_stat_sha256": snapshot.tracked_worktree_stat_sha256,
        "tracked_files": snapshot.tracked_files,
        "logical_bytes": snapshot.repository_logical_bytes,
    }


def refusal_record(repository: RepositoryInput, error: HarnessRefusal) -> dict[str, Any]:
    return {
        "outcome": "non_pass",
        "language": repository.language,
        "repository_root": str(repository.root),
        "refusal": {"code": error.code, "detail": str(error)},
        "cleanup": {
            "complete": error.cleanup_complete,
            "codes": list(error.cleanup_codes),
        },
    }


def validate_repository_inputs(repositories: Sequence[RepositoryInput]) -> None:
    if not 1 <= len(repositories) <= MAX_REPOSITORIES:
        raise HarnessRefusal(
            "repository_count_bound",
            f"repository count must be within 1..={MAX_REPOSITORIES}",
        )
    languages: set[str] = set()
    roots: set[pathlib.Path] = set()
    for repository in repositories:
        try:
            canonical = repository.root.resolve(strict=True)
        except OSError as error:
            raise HarnessRefusal("repository_unavailable", "repository root is unavailable") from error
        if canonical != repository.root or not canonical.is_dir():
            raise HarnessRefusal("repository_not_canonical", "repository root is not canonical")
        if repository.language in languages:
            raise HarnessRefusal(
                "duplicate_repository_language", "each language may be supplied only once"
            )
        if canonical in roots:
            raise HarnessRefusal(
                "duplicate_repository_root", "each repository root may be supplied only once"
            )
        languages.add(repository.language)
        roots.add(canonical)


def evaluate(
    *,
    again_binary: pathlib.Path,
    source_root: pathlib.Path,
    source_git_sha: str,
    repositories: Sequence[RepositoryInput],
    timeout_seconds: float,
    go_search_roots: Sequence[pathlib.Path] = (),
    go_search_depth: int = MAX_SEARCH_DEPTH,
    go_search_max_candidates: int = MAX_SEARCH_CANDIDATES,
) -> dict[str, Any]:
    if not again_binary.is_absolute() or not source_root.is_absolute():
        raise HarnessRefusal("path_not_absolute", "binary and source root must be absolute")
    if os.name != "posix" or not hasattr(os, "killpg"):
        raise HarnessRefusal(
            "unsupported_process_group", "whole-process-group cleanup requires POSIX"
        )
    if timeout_seconds < 10 or timeout_seconds > 300:
        raise HarnessRefusal("timeout_bound", "timeout must be within 10..=300 seconds")
    validate_repository_inputs(repositories)
    go_search = (
        discover_go_repository(
            go_search_roots,
            max_depth=go_search_depth,
            max_candidates=go_search_max_candidates,
        )
        if go_search_roots
        else {
            "search_roots": [],
            "max_depth": MAX_SEARCH_DEPTH,
            "max_candidates": MAX_SEARCH_CANDIDATES,
            "candidate_count": 0,
            "search_errors": [],
            "selected_repository": None,
            "go_repository_eligible": False,
            "eligibility_checks": [],
            "refusal_code": "search_not_requested",
        }
    )
    harness = pathlib.Path(__file__).resolve()
    sibling_hashes = {
        path.name: sha256_file(path)
        for path in (
            harness,
            harness.with_name("real_repository_corpus.py"),
            harness.with_name("agent_gateway_product_e2e.py"),
        )
    }
    try:
        source = gateway_support.inspect_clean_source(
            source_root, source_git_sha, pathlib.Path(tempfile.gettempdir())
        )
    except BaseException as error:
        if hasattr(error, "code"):
            raise _translate_support_refusal(error) from error
        raise
    reports: list[dict[str, Any]] = []
    snapshots: list[tuple[RepositoryInput, Any]] = []
    for repository in repositories:
        try:
            snapshot = inspect_input_repository(repository)
            snapshots.append((repository, snapshot))
        except HarnessRefusal as error:
            reports.append(refusal_record(repository, error))
    started_ns = time.perf_counter_ns()
    with tempfile.TemporaryDirectory(prefix="again-real-repo-gateway-corpus-") as temporary:
        root = pathlib.Path(temporary).resolve()
        root.chmod(0o700)
        try:
            pinned = repository_support.pin_again_binary(again_binary, root / "pinned-again")
        except BaseException as error:
            if hasattr(error, "code"):
                raise _translate_support_refusal(error) from error
            raise
        pinned_identity = pinned_executable_identity(pinned.executable)
        for repository, snapshot in snapshots:
            before = snapshot_identity(snapshot)
            try:
                repository_report = run_repository(
                    binary=pinned.executable,
                    snapshot=snapshot,
                    temporary_root=root / f"run-{len(reports)}",
                    timeout_seconds=timeout_seconds,
                )
                after = inspect_input_repository(repository)
                if snapshot_identity(after) != before:
                    raise HarnessRefusal(
                        "source_changed_during_run", "source repository changed during the corpus"
                    )
                reports.append(repository_report)
            except HarnessRefusal as error:
                reports.append(refusal_record(repository, error))
        try:
            repository_support.verify_binary_source_unchanged(pinned)
        except BaseException as error:
            if hasattr(error, "code"):
                raise _translate_support_refusal(error) from error
            raise
        verify_pinned_executable_unchanged(pinned.executable, pinned_identity)
        binary_record = {
            "requested_path": str(pinned.source),
            "sha256": pinned.sha256,
            "bytes": pinned.size,
            "executed_copy_revalidated": True,
        }
    if sibling_hashes != {
        path.name: sha256_file(path)
        for path in (
            harness,
            harness.with_name("real_repository_corpus.py"),
            harness.with_name("agent_gateway_product_e2e.py"),
        )
    }:
        raise HarnessRefusal("harness_changed", "harness or support changed during execution")
    present = collections.Counter(item.language for item in repositories)
    for language in LANGUAGES:
        if present[language] == 0:
            reports.append(
                {
                    "outcome": "non_pass",
                    "language": language,
                    "repository_root": None,
                    "refusal": {
                        "code": "repository_not_supplied",
                        "detail": "no explicit locally available repository was supplied",
                    },
                }
            )
    passed = sum(item.get("outcome") == "pass" for item in reports)
    non_pass = sum(item.get("outcome") != "pass" for item in reports)
    return {
        "schema": SCHEMA,
        "harness_version": HARNESS_VERSION,
        "outcome": "pass" if passed and non_pass == 0 else "non_pass",
        "network_boundary": network_boundary_record(),
        "source_repositories_read_only": True,
        "binary": binary_record,
        "again_source": source,
        "harness_sha256": sibling_hashes[harness.name],
        "support_sha256": {
            key: value for key, value in sibling_hashes.items() if key != harness.name
        },
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "summary": {
            "repositories_requested": len(repositories),
            "repositories_passed": passed,
            "typed_non_pass": non_pass,
            "languages_requested": dict(sorted(present.items())),
            "go_repository_eligible": go_search["go_repository_eligible"],
        },
        "go_repository_search": go_search,
        "repositories": reports,
        "elapsed_ms": (time.perf_counter_ns() - started_ns) / 1_000_000,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--go-search-root", action="append", default=[])
    parser.add_argument("--go-search-depth", type=int, default=MAX_SEARCH_DEPTH)
    parser.add_argument("--go-search-max-candidates", type=int, default=MAX_SEARCH_CANDIDATES)
    parser.add_argument("--json-out", required=True, type=pathlib.Path)
    parser.add_argument("--timeout-seconds", type=float, default=90.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    output = arguments.json_out
    try:
        repositories = [parse_repository_argument(item) for item in arguments.repository]
        validate_output_location(
            output, [arguments.source_root, *(repository.root for repository in repositories)]
        )
        report = evaluate(
            again_binary=arguments.again_binary,
            source_root=arguments.source_root,
            source_git_sha=arguments.source_git_sha,
            repositories=repositories,
            timeout_seconds=arguments.timeout_seconds,
            go_search_roots=[pathlib.Path(item) for item in arguments.go_search_root],
            go_search_depth=arguments.go_search_depth,
            go_search_max_candidates=arguments.go_search_max_candidates,
        )
        write_json_exclusive(output, report)
        print(
            json.dumps(
                {
                    "outcome": report["outcome"],
                    "evidence": str(output),
                    "sha256": sha256_file(output),
                    "summary": report["summary"],
                },
                sort_keys=True,
            )
        )
        return 0 if report["outcome"] == "pass" else 2
    except HarnessRefusal as error:
        refusal = {
            "schema": SCHEMA,
            "outcome": "non_pass",
            "refusal": {"code": error.code, "detail": str(error)},
            "cleanup": {
                "complete": error.cleanup_complete,
                "codes": list(error.cleanup_codes),
            },
        }
        try:
            write_json_exclusive(output, refusal)
        except HarnessRefusal:
            pass
        print(json.dumps(refusal, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
