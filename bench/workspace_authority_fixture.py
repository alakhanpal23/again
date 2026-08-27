#!/usr/bin/env python3
"""Portable mutation fixtures for the Rust workspace-authority tests.

This is a deliberately small reference oracle, not a second production
authority. It performs bounded, read-only snapshots of private test fixtures so
the Python suite can exercise the same mutation categories on macOS and Linux.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import stat
import subprocess
from collections.abc import Callable, Sequence
from typing import Any


@dataclasses.dataclass(frozen=True)
class Limits:
    max_plan_entries: int = 1_024
    max_path_bytes: int = 4_096
    max_file_bytes: int = 256 * 1024 * 1024
    max_total_bytes: int = 1024 * 1024 * 1024
    max_tree_entries: int = 100_000
    max_tree_depth: int = 256
    max_directory_entries: int = 16_384
    max_identity_bytes: int = 16 * 1024


class FixtureRefusal(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class ObservationPlan:
    content_paths: tuple[str, ...] = ()
    recursive_trees: tuple[str, ...] = ()
    directory_listings: tuple[str, ...] = ()
    negative_dependencies: tuple[str, ...] = ()


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def canonical_digest(domain: str, value: Any) -> str:
    digest = hashlib.sha256()
    encoded_domain = domain.encode("ascii")
    digest.update(len(encoded_domain).to_bytes(8, "little"))
    digest.update(encoded_domain)
    encoded_value = canonical_bytes(value)
    digest.update(len(encoded_value).to_bytes(8, "little"))
    digest.update(encoded_value)
    return digest.hexdigest()


def secret_digest(domain: str, value: bytes, *, maximum: int) -> str:
    if not value or len(value) > maximum:
        raise FixtureRefusal("input_limit_exceeded", "secret-bearing input is out of bounds")
    digest = hashlib.sha256()
    digest.update(domain.encode("ascii"))
    digest.update(len(value).to_bytes(8, "little"))
    digest.update(value)
    return digest.hexdigest()


def task_digest(*, task_id: str, task_revision: int, plan_revision: int) -> str:
    if not task_id:
        raise FixtureRefusal("invalid_observation_plan", "task ID is required")
    return canonical_digest(
        "again.fixture.task-state.v1",
        {
            "plan_revision": plan_revision,
            "task_id": task_id,
            "task_revision": task_revision,
        },
    )


def environment_digest(*, tool_path: pathlib.Path, tool_version: str, limits: Limits) -> str:
    if not tool_version or len(tool_version.encode()) > limits.max_identity_bytes:
        raise FixtureRefusal("input_limit_exceeded", "tool version is out of bounds")
    tool = _stable_regular_file(tool_path, limits)
    return canonical_digest(
        "again.fixture.environment.v1",
        {
            "architecture": os.uname().machine,
            "os": os.uname().sysname,
            "tool": tool,
            "tool_version_digest": secret_digest(
                "again.fixture.tool-version.v1",
                tool_version.encode(),
                maximum=limits.max_identity_bytes,
            ),
        },
    )


def _identity(path: pathlib.Path) -> tuple[int, ...]:
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _authority_identity(path: pathlib.Path) -> tuple[int, ...]:
    return _identity(path)[:5]


def _validate_relative(raw: str, limits: Limits, *, allow_empty: bool) -> str:
    encoded = os.fsencode(raw)
    if len(encoded) > limits.max_path_bytes:
        raise FixtureRefusal("input_limit_exceeded", f"path is too long: {raw!r}")
    path = pathlib.PurePath(raw)
    if path.is_absolute() or ".." in path.parts:
        raise FixtureRefusal("invalid_observation_plan", f"unsafe path: {raw!r}")
    normalized = pathlib.PurePath(*[part for part in path.parts if part not in ("", ".")])
    value = str(normalized)
    if value == ".":
        value = ""
    if not allow_empty and not value:
        raise FixtureRefusal("invalid_observation_plan", "empty path is not allowed")
    return value


def _normalize_plan(plan: ObservationPlan, limits: Limits) -> ObservationPlan:
    total = sum(
        len(paths)
        for paths in (
            plan.content_paths,
            plan.recursive_trees,
            plan.directory_listings,
            plan.negative_dependencies,
        )
    )
    if total > limits.max_plan_entries:
        raise FixtureRefusal("input_limit_exceeded", "too many observation-plan entries")

    def normalize(paths: Sequence[str], *, allow_empty: bool) -> tuple[str, ...]:
        values = tuple(sorted(_validate_relative(path, limits, allow_empty=allow_empty) for path in paths))
        if len(values) != len(set(values)):
            raise FixtureRefusal("invalid_observation_plan", "duplicate observation path")
        return values

    return ObservationPlan(
        content_paths=normalize(plan.content_paths, allow_empty=False),
        recursive_trees=normalize(plan.recursive_trees, allow_empty=True),
        directory_listings=normalize(plan.directory_listings, allow_empty=True),
        negative_dependencies=normalize(plan.negative_dependencies, allow_empty=False),
    )


def _reject_symlink_or_special(path: pathlib.Path, *, directory: bool | None = None) -> os.stat_result:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise FixtureRefusal("symlink_refused", f"symlink refused: {path}")
    ordinary = stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
    if not ordinary:
        raise FixtureRefusal("special_file_refused", f"special file refused: {path}")
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise FixtureRefusal("special_file_refused", f"directory required: {path}")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise FixtureRefusal("special_file_refused", f"regular file required: {path}")
    return metadata


def _stable_regular_file(path: pathlib.Path, limits: Limits) -> dict[str, Any]:
    before = _reject_symlink_or_special(path, directory=False)
    if before.st_size > limits.max_file_bytes:
        raise FixtureRefusal("input_limit_exceeded", f"file is too large: {path}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_mode) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
        ):
            raise FixtureRefusal("concurrent_mutation", f"file changed while opening: {path}")
        for block in iter(lambda: source.read(64 * 1024), b""):
            size += len(block)
            if size > limits.max_file_bytes:
                raise FixtureRefusal("input_limit_exceeded", f"file grew beyond bound: {path}")
            digest.update(block)
        after_handle = os.fstat(source.fileno())
    after_path = path.lstat()
    if _stat_tuple(before) != _stat_tuple(after_handle) or _stat_tuple(before) != _stat_tuple(after_path):
        raise FixtureRefusal("concurrent_mutation", f"file changed while reading: {path}")
    return {
        "content_digest": digest.hexdigest(),
        "identity": _stat_tuple(before),
        "size": size,
    }


def _stat_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _list_directory(path: pathlib.Path, limits: Limits) -> tuple[tuple[int, ...], list[str]]:
    before = _reject_symlink_or_special(path, directory=True)
    names = sorted(os.listdir(path), key=os.fsencode)
    if len(names) > limits.max_directory_entries:
        raise FixtureRefusal("input_limit_exceeded", f"directory has too many entries: {path}")
    if any(len(os.fsencode(name)) > limits.max_path_bytes for name in names):
        raise FixtureRefusal("input_limit_exceeded", f"directory name is too long: {path}")
    after = path.lstat()
    if _stat_tuple(before) != _stat_tuple(after):
        raise FixtureRefusal("concurrent_mutation", f"directory changed while listing: {path}")
    return _stat_tuple(before), names


def _walk_tree(path: pathlib.Path, limits: Limits) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    total_bytes = 0

    def walk(current: pathlib.Path, relative: str, depth: int) -> None:
        nonlocal total_bytes
        if depth > limits.max_tree_depth:
            raise FixtureRefusal("input_limit_exceeded", "tree is too deep")
        if len(records) >= limits.max_tree_entries:
            raise FixtureRefusal("input_limit_exceeded", "tree has too many entries")
        identity, names = _list_directory(current, limits)
        records.append({"kind": "directory", "path": relative, "identity": identity})
        for name in names:
            child = current / name
            metadata = _reject_symlink_or_special(child)
            child_relative = str(pathlib.PurePath(relative) / name) if relative else name
            if stat.S_ISDIR(metadata.st_mode):
                walk(child, child_relative, depth + 1)
            else:
                if len(records) >= limits.max_tree_entries:
                    raise FixtureRefusal("input_limit_exceeded", "tree has too many entries")
                observed = _stable_regular_file(child, limits)
                total_bytes += observed["size"]
                if total_bytes > limits.max_total_bytes:
                    raise FixtureRefusal("input_limit_exceeded", "tree bytes exceed total bound")
                records.append({"kind": "file", "path": child_relative, **observed})

    walk(path, "", 0)
    return records, total_bytes


def _git_state(root: pathlib.Path, limits: Limits) -> dict[str, Any]:
    dot_git = root / ".git"
    if not dot_git.exists() and not dot_git.is_symlink():
        return {"kind": "not_git_repository"}
    metadata = _reject_symlink_or_special(dot_git)
    if not stat.S_ISDIR(metadata.st_mode):
        raise FixtureRefusal("special_file_refused", "reference fixture requires a .git directory")
    sparse = dot_git / "info" / "sparse-checkout"
    if sparse.exists() or sparse.is_symlink():
        raise FixtureRefusal("sparse_checkout_ambiguous", "sparse checkout marker is present")
    head = _stable_regular_file(dot_git / "HEAD", limits)
    index_path = dot_git / "index"
    index = _stable_regular_file(index_path, limits) if index_path.exists() else None
    completed = subprocess.run(
        ("git", "rev-parse", "--verify", "HEAD"),
        cwd=root,
        env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    head_object = completed.stdout.decode("ascii").strip() if completed.returncode == 0 else None
    return {
        "head_file": head,
        "head_object": head_object,
        "index": index,
        "kind": "git",
    }


def observe_repository(
    root: pathlib.Path,
    plan: ObservationPlan,
    limits: Limits = Limits(),
    *,
    between_samples: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Return one deterministic reference epoch or a typed refusal."""

    plan = _normalize_plan(plan, limits)
    _reject_symlink_or_special(root, directory=True)
    canonical_root = root.resolve(strict=True)
    root_identity = _identity(canonical_root)
    git_before = _git_state(canonical_root, limits)

    def sample() -> tuple[list[dict[str, Any]], int]:
        observations: list[dict[str, Any]] = []
        total_bytes = 0
        for relative in plan.content_paths:
            observed = _stable_regular_file(canonical_root / relative, limits)
            total_bytes += observed["size"]
            observations.append({"kind": "content", "path": relative, **observed})
        for relative in plan.recursive_trees:
            records, tree_bytes = _walk_tree(canonical_root / relative, limits)
            total_bytes += tree_bytes
            observations.append({"kind": "tree", "path": relative, "records": records})
        for relative in plan.directory_listings:
            identity, names = _list_directory(canonical_root / relative, limits)
            records = []
            for name in names:
                child = canonical_root / relative / name
                child_metadata = _reject_symlink_or_special(child)
                records.append({"identity": _stat_tuple(child_metadata), "name": name})
            observations.append(
                {"identity": identity, "kind": "listing", "path": relative, "records": records}
            )
        for relative in plan.negative_dependencies:
            candidate = canonical_root / relative
            if candidate.exists() or candidate.is_symlink():
                metadata = _reject_symlink_or_special(candidate)
                identity: tuple[int, ...] | None = _stat_tuple(metadata)
                present = True
            else:
                identity = None
                present = False
            observations.append(
                {"identity": identity, "kind": "negative", "path": relative, "present": present}
            )
        if total_bytes > limits.max_total_bytes:
            raise FixtureRefusal("input_limit_exceeded", "observed bytes exceed total bound")
        return observations, total_bytes

    first, total_bytes = sample()
    if between_samples is not None:
        between_samples()
    try:
        current_root_identity = _identity(canonical_root)
    except FileNotFoundError as error:
        raise FixtureRefusal("repository_replaced", "repository disappeared") from error
    if current_root_identity != root_identity:
        raise FixtureRefusal("repository_replaced", "repository identity changed")
    second, second_total = sample()
    if first != second or total_bytes != second_total:
        raise FixtureRefusal("concurrent_mutation", "repository observations changed")
    git_after = _git_state(canonical_root, limits)
    if git_before != git_after:
        raise FixtureRefusal("git_state_changed", "Git state changed")

    payload = {
        "canonical_workspace": os.fsencode(canonical_root).hex(),
        "git": git_before,
        "observations": first,
        "plan": dataclasses.asdict(plan),
        "schema_version": 1,
        "workspace_identity": _authority_identity(canonical_root),
    }
    return {"digest": canonical_digest("again.fixture.repository-epoch.v1", payload), **payload}
