#!/usr/bin/env python3
"""Offline, fail-closed real-repository corpus for the Again MCP binary.

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
EXPECTED_DATABASE_SCHEMA = 7
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

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


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


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    if not path.is_absolute() or path.resolve(strict=False) != path:
        raise HarnessRefusal("output_not_canonical", "evidence path must be absolute and canonical")
    encoded = canonical_json_bytes(value)
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise HarnessRefusal("evidence_oversized", "evidence exceeds its fixed bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise HarnessRefusal("output_exists", f"refusing to overwrite evidence: {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


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


def start_session(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    state: pathlib.Path,
    root: pathlib.Path,
    label: str,
    timeout_seconds: float,
) -> Any:
    home = root / f"home-{label}"
    temporary = root / f"tmp-{label}"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    session = gateway_support.McpSession(
        binary=binary,
        workspace=workspace,
        again_home=state,
        home=home,
        temporary=temporary,
        authorization_scope="again-real-repository-corpus:shared-v1",
        label=label,
        timeout_seconds=timeout_seconds,
    )
    # McpSession constructs the same environment internally.  Verify the
    # complete offline boundary rather than relying on inherited variables.
    expected = _server_environment(state, home, temporary)
    if session.environment != expected:
        session.close()
        raise HarnessRefusal("server_environment", "MCP server environment is not isolated")
    session.handshake(f"again-real-repository-corpus-{label}")
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


def process_evidence(sessions: Sequence[Any]) -> list[dict[str, Any]]:
    records = [session.evidence() for session in sessions]
    labels = [record.get("label") for record in records]
    pids = [record.get("pid") for record in records]
    if len(set(labels)) != len(labels) or len(set(pids)) != len(pids):
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
    sessions: list[Any] = []
    scenarios: dict[str, Any] = {}
    false_hits = 0
    started_ns = time.perf_counter_ns()
    try:
        first = start_session(binary, workspace, state, temporary_root, f"{snapshot.language}-a", timeout_seconds)
        second = start_session(binary, workspace, state, temporary_root, f"{snapshot.language}-b", timeout_seconds)
        sessions.extend((first, second))
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

        second.close()
        restarted = start_session(
            binary, workspace, state, temporary_root, f"{snapshot.language}-restarted", timeout_seconds
        )
        sessions.append(restarted)
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
        return {
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
            "processes": process_evidence(sessions),
        }
    finally:
        failures: list[str] = []
        for session in reversed(sessions):
            try:
                session.close()
            except BaseException as error:
                failures.append(str(error))
        if failures and sys.exc_info()[0] is None:
            raise HarnessRefusal("process_cleanup", "; ".join(failures))


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
    }


def evaluate(
    *,
    again_binary: pathlib.Path,
    source_root: pathlib.Path,
    source_git_sha: str,
    repositories: Sequence[RepositoryInput],
    timeout_seconds: float,
) -> dict[str, Any]:
    if not again_binary.is_absolute() or not source_root.is_absolute():
        raise HarnessRefusal("path_not_absolute", "binary and source root must be absolute")
    if timeout_seconds < 10 or timeout_seconds > 300:
        raise HarnessRefusal("timeout_bound", "timeout must be within 10..=300 seconds")
    if not repositories:
        raise HarnessRefusal("repositories_missing", "at least one explicit repository is required")
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
        for repository, snapshot in snapshots:
            before = snapshot_identity(snapshot)
            try:
                reports.append(
                    run_repository(
                        binary=pinned.executable,
                        snapshot=snapshot,
                        temporary_root=root / f"run-{len(reports)}",
                        timeout_seconds=timeout_seconds,
                    )
                )
                after = inspect_input_repository(repository)
                if snapshot_identity(after) != before:
                    raise HarnessRefusal(
                        "source_changed_during_run", "source repository changed during the corpus"
                    )
            except HarnessRefusal as error:
                reports.append(refusal_record(repository, error))
        try:
            repository_support.verify_binary_source_unchanged(pinned)
        except BaseException as error:
            if hasattr(error, "code"):
                raise _translate_support_refusal(error) from error
            raise
        binary_record = {
            "requested_path": str(pinned.source),
            "sha256": pinned.sha256,
            "bytes": pinned.size,
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
        "offline": True,
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
        },
        "repositories": reports,
        "elapsed_ms": (time.perf_counter_ns() - started_ns) / 1_000_000,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--repository", action="append", default=[])
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
        }
        try:
            write_json_exclusive(output, refusal)
        except HarnessRefusal:
            pass
        print(json.dumps(refusal, sort_keys=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
