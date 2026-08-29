#!/usr/bin/env python3
"""Fail-closed production-binary E2E evidence for the Again MCP gateway.

Product evidence from this program is produced only by the explicit compiled
``again`` binary and independent ``again mcp serve`` processes.  The harness
contains no substitute MCP provider.  Its SQLite access is URI read-only and
is used to reconcile product events with already-observed JSON-RPC output;
database metadata is never accepted as output evidence by itself.
"""

from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import select
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from typing import Any, BinaryIO


REPORT_SCHEMA = "again.agent-gateway-product-e2e.v1"
HARNESS_VERSION = "1.0.0"
EXPECTED_DATABASE_SCHEMA = 13
MCP_PROTOCOL_VERSION = "2025-06-18"
SOURCE_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RESULT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
FIXTURE_FILE_COUNT = 48
FIXTURE_FILE_BYTES = 256 * 1024
LEASE_TTL_SECONDS = 30.0
RECOVERY_GRACE_SECONDS = 6.0
PROCESS_STOP_SECONDS = 2.0
EVENT_OBSERVATION_TIMEOUT_SECONDS = 15.0
NETWORK_BLOCK_ENDPOINT = "http://127.0.0.1:9"
EXPECTED_ADVERTISED_TOOLS = (
    "again.task_start",
    "git.blame",
    "git.diff",
    "git.log",
    "git.show",
    "git.status",
    "repo.glob",
    "repo.list",
    "repo.manifest",
    "repo.read",
    "repo.references",
    "repo.search",
    "repo.stat",
    "repo.tree",
    "task.claim",
    "task.inspect",
    "task.list",
    "task.start",
    "task.transition",
)
E2E_EXERCISED_TOOLS = frozenset(("again.task_start", "repo.read", "repo.search"))


class HarnessRefusal(RuntimeError):
    """A typed non-pass result, never an implicit or partial pass."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class EventWindow:
    start_ms: int
    end_ms: int
    first_event_id: int
    last_event_id: int


@dataclasses.dataclass(frozen=True)
class EventWindowStart:
    started_ms: int
    prior_event_id: int


@dataclasses.dataclass(frozen=True)
class PinnedBinary:
    requested_path: pathlib.Path
    executable_path: pathlib.Path
    sha256: str
    size: int


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path, maximum: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if maximum is not None and total > maximum:
                raise HarnessRefusal("file_oversized", f"file exceeds byte bound: {path}")
            digest.update(block)
    return digest.hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise HarnessRefusal("noncanonical_json", "value is not canonical JSON") from error
    return rendered.encode("utf-8") + b"\n"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessRefusal("duplicate_json_key", f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise HarnessRefusal("nonfinite_json_number", f"invalid JSON number: {value}")


def _validate_json_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise HarnessRefusal("json_node_limit", "JSON node limit exceeded")
        if depth > MAX_JSON_DEPTH:
            raise HarnessRefusal("json_depth_limit", "JSON depth limit exceeded")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise HarnessRefusal("nonfinite_json_number", "non-finite JSON number")


def parse_json_rpc_line(raw: bytes, maximum: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    """Parse exactly one bounded, newline-terminated JSON-RPC response."""

    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise HarnessRefusal("truncated_output", "JSON-RPC frame is not one complete line")
    if len(raw) > maximum:
        raise HarnessRefusal("response_oversized", "JSON-RPC response exceeds byte bound")
    payload = raw[:-1]
    if payload.endswith(b"\r"):
        raise HarnessRefusal("invalid_json_framing", "CRLF JSON-RPC framing is refused")
    try:
        text = payload.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except HarnessRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessRefusal("malformed_json", "malformed JSON-RPC response") from error
    _validate_json_bounds(value)
    if not isinstance(value, dict):
        raise HarnessRefusal("invalid_json_rpc", "JSON-RPC response is not an object")
    if value.get("jsonrpc") != "2.0" or "id" not in value:
        raise HarnessRefusal("invalid_json_rpc", "invalid JSON-RPC response envelope")
    allowed = {"jsonrpc", "id", "result", "error"}
    if set(value) - allowed or (("result" in value) + ("error" in value) != 1):
        raise HarnessRefusal("invalid_json_rpc", "ambiguous JSON-RPC response envelope")
    return value


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    if not path.is_absolute():
        raise HarnessRefusal("output_not_absolute", "evidence output must be absolute")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    rendered = canonical_json_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise HarnessRefusal("output_exists", f"refusing to overwrite evidence: {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _clean_git_environment(home: pathlib.Path) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
    }


def _run_local_git(
    root: pathlib.Path,
    arguments: Sequence[str],
    *,
    home: pathlib.Path,
    timeout: float = 10.0,
) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-c", "protocol.allow=never", *arguments],
            cwd=root,
            env=_clean_git_environment(home),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HarnessRefusal("git_inspection_failed", "bounded local Git command failed") from error
    if completed.returncode != 0:
        raise HarnessRefusal(
            "git_inspection_failed",
            completed.stderr.decode("utf-8", errors="replace")[:1000],
        )
    return completed.stdout


def inspect_clean_source(
    source_root: pathlib.Path, expected_sha: str, isolated_home: pathlib.Path
) -> dict[str, Any]:
    if not source_root.is_absolute() or source_root.resolve() != source_root:
        raise HarnessRefusal("source_root_not_canonical", "source root must be absolute and canonical")
    if not SOURCE_SHA_RE.fullmatch(expected_sha):
        raise HarnessRefusal("source_sha_malformed", "source Git SHA must be 40 lowercase hex bytes")
    head = _run_local_git(source_root, ["rev-parse", "--verify", "HEAD"], home=isolated_home)
    actual = head.decode("ascii", errors="strict").strip()
    if actual != expected_sha:
        raise HarnessRefusal("source_sha_mismatch", f"source HEAD is {actual}, expected {expected_sha}")
    status = _run_local_git(
        source_root,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        home=isolated_home,
    )
    if status:
        raise HarnessRefusal("source_dirty", "source worktree must be clean")
    return {
        "git_sha": actual,
        "git_sha256": sha256_bytes(actual.encode("ascii")),
        "root": str(source_root),
        "clean": True,
    }


def pin_binary(requested: pathlib.Path, destination: pathlib.Path) -> PinnedBinary:
    if not requested.is_absolute() or requested.resolve() != requested:
        raise HarnessRefusal("binary_not_canonical", "--again-binary must be absolute and canonical")
    before = os.stat(requested, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise HarnessRefusal("binary_not_regular", "Again binary must be a non-empty regular file")
    if before.st_size > MAX_BINARY_BYTES or not os.access(requested, os.X_OK):
        raise HarnessRefusal("binary_invalid", "Again binary is oversized or not executable")
    source_hash = sha256_file(requested, MAX_BINARY_BYTES)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    with requested.open("rb") as source, destination.open("xb") as target:
        shutil.copyfileobj(source, target, 1024 * 1024)
        target.flush()
        os.fsync(target.fileno())
    destination.chmod(0o500)
    after = os.stat(requested, follow_symlinks=False)
    fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if fingerprint(before) != fingerprint(after) or sha256_file(destination) != source_hash:
        raise HarnessRefusal("binary_changed", "Again binary changed while being pinned")
    return PinnedBinary(requested, destination, source_hash, before.st_size)


def _write_fixture_file(path: pathlib.Path, header: bytes, size: int) -> None:
    if len(header) > size:
        raise HarnessRefusal("fixture_definition_invalid", "fixture header exceeds file size")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fill = b"abcdefghijklmnopqrstuvwxyz0123456789"
    with path.open("xb") as output:
        output.write(header)
        remaining = size - len(header)
        while remaining:
            block = fill[: min(remaining, len(fill))]
            output.write(block)
            remaining -= len(block)


def create_fixture(root: pathlib.Path, isolated_home: pathlib.Path) -> dict[str, Any]:
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main"],
        cwd=root,
        env=_clean_git_environment(isolated_home),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=10,
    )
    markers = (
        b"TOKEN_CONCURRENT\n"
        b"TOKEN_RELEVANT_V1\n"
        b"TOKEN_FOLLOWER_CANCEL\n"
        b"TOKEN_LEADER_CANCEL\n"
        b"TOKEN_CRASH_RECOVERY\n"
    )
    files: list[pathlib.Path] = []
    for index in range(FIXTURE_FILE_COUNT):
        path = root / "scope" / f"payload-{index:03d}.txt"
        _write_fixture_file(path, markers if index == 0 else b"bounded fixture\n", FIXTURE_FILE_BYTES)
        files.append(path)
    for name in ("follower", "leader", "restart", "corruption"):
        path = root / "health" / f"{name}.txt"
        _write_fixture_file(path, f"health:{name}\n".encode(), 64)
        files.append(path)
    outside = root / "outside" / "irrelevant.txt"
    _write_fixture_file(outside, b"outside dependency scope\n", 128)
    files.append(outside)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Again E2E",
            "-c",
            "user.email=again-e2e.invalid",
            "add",
            "--all",
        ],
        cwd=root,
        env=_clean_git_environment(isolated_home),
        check=True,
        timeout=20,
    )
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Again E2E",
            "-c",
            "user.email=again-e2e.invalid",
            "commit",
            "--quiet",
            "-m",
            "bounded gateway fixture",
        ],
        cwd=root,
        env=_clean_git_environment(isolated_home),
        check=True,
        timeout=20,
    )
    entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in sorted(files)
    ]
    total = sum(int(entry["bytes"]) for entry in entries)
    if total > 13 * 1024 * 1024:
        raise HarnessRefusal("fixture_oversized", "fixture exceeds declared logical byte bound")
    fixture_sha = _run_local_git(root, ["rev-parse", "HEAD"], home=isolated_home).decode().strip()
    if _run_local_git(root, ["status", "--porcelain=v1"], home=isolated_home):
        raise HarnessRefusal("fixture_dirty", "new fixture repository is unexpectedly dirty")
    manifest = {
        "schema": "again.agent-gateway-product-e2e-fixture.v1",
        "git_sha": fixture_sha,
        "logical_bytes": total,
        "file_count": len(entries),
        "files": entries,
    }
    manifest["manifest_sha256"] = sha256_bytes(canonical_json_bytes(manifest))
    return manifest


def _server_environment(
    *, again_home: pathlib.Path, home: pathlib.Path, temporary: pathlib.Path
) -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "AGAIN_HOME": str(again_home),
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


def terminate_process_group(process: subprocess.Popen[bytes], timeout: float = PROCESS_STOP_SECONDS) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=timeout)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=timeout)


class McpSession:
    """One real stdio MCP server with separate, bounded stream capture."""

    def __init__(
        self,
        *,
        binary: pathlib.Path,
        workspace: pathlib.Path,
        again_home: pathlib.Path,
        home: pathlib.Path,
        temporary: pathlib.Path,
        authorization_scope: str,
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
            authorization_scope,
        )
        self.environment = _server_environment(
            again_home=again_home, home=home, temporary=temporary
        )
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
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise HarnessRefusal("process_pipe_failure", "failed to create MCP stdio pipes")
        self._stdin: BinaryIO = self.process.stdin
        self._stdout: BinaryIO = self.process.stdout
        self._stderr: BinaryIO = self.process.stderr
        self._stdout_buffer = bytearray()
        self._stderr_capture = bytearray()
        self._stderr_overflow = False
        self._write_lock = threading.Lock()
        self._request_lock = threading.Lock()
        self.request_hashes: list[str] = []
        self.response_hashes: list[str] = []
        self.advertised_tools: set[str] = set()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()

    def _drain_stderr(self) -> None:
        while True:
            try:
                block = os.read(self._stderr.fileno(), 65536)
            except OSError:
                return
            if not block:
                return
            remaining = MAX_STDERR_BYTES - len(self._stderr_capture)
            if remaining > 0:
                self._stderr_capture.extend(block[:remaining])
            if len(block) > remaining:
                self._stderr_overflow = True

    def _send(self, value: Mapping[str, Any]) -> str:
        encoded = canonical_json_bytes(value)
        digest = sha256_bytes(encoded)
        with self._write_lock:
            try:
                self._stdin.write(encoded)
                self._stdin.flush()
            except (BrokenPipeError, OSError) as error:
                raise HarnessRefusal("server_pipe_closed", f"{self.label} stdin closed") from error
        self.request_hashes.append(digest)
        return digest

    def _read_line(self, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        descriptor = self._stdout.fileno()
        while True:
            newline = self._stdout_buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self._stdout_buffer[: newline + 1])
                del self._stdout_buffer[: newline + 1]
                return frame
            if len(self._stdout_buffer) > MAX_FRAME_BYTES:
                raise HarnessRefusal("response_oversized", f"{self.label} response exceeded bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessRefusal("response_timeout", f"{self.label} response timed out")
            readable, _, _ = select.select([descriptor], [], [], remaining)
            if not readable:
                raise HarnessRefusal("response_timeout", f"{self.label} response timed out")
            block = os.read(descriptor, min(65536, MAX_FRAME_BYTES + 1 - len(self._stdout_buffer)))
            if not block:
                if self._stdout_buffer:
                    raise HarnessRefusal("truncated_output", f"{self.label} ended mid-frame")
                raise HarnessRefusal("server_eof", f"{self.label} closed stdout")
            self._stdout_buffer.extend(block)

    def request(self, value: Mapping[str, Any], timeout: float | None = None) -> dict[str, Any]:
        expected_id = value.get("id")
        if expected_id is None:
            raise HarnessRefusal("request_id_missing", "MCP request needs an id")
        with self._request_lock:
            self._send(value)
            response = parse_json_rpc_line(
                self._read_line(self.timeout_seconds if timeout is None else timeout)
            )
        if response.get("id") != expected_id:
            raise HarnessRefusal("response_id_mismatch", f"{self.label} response id mismatch")
        self.response_hashes.append(sha256_bytes(canonical_json_bytes(response)))
        return response

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> str:
        frame: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            frame["params"] = dict(params)
        return self._send(frame)

    def handshake(self, client_name: str) -> dict[str, Any]:
        initialized = self.request(
            {
                "jsonrpc": "2.0",
                "id": f"{self.label}:initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": client_name, "version": HARNESS_VERSION},
                },
            }
        )
        if initialized.get("result", {}).get("protocolVersion") != MCP_PROTOCOL_VERSION:
            raise HarnessRefusal("handshake_failed", f"{self.label} protocol mismatch")
        self.notify("notifications/initialized")
        listing = self.request(
            {
                "jsonrpc": "2.0",
                "id": f"{self.label}:tools-list",
                "method": "tools/list",
                "params": {},
            }
        )
        tools = listing.get("result", {}).get("tools")
        if not isinstance(tools, list):
            raise HarnessRefusal("tools_list_invalid", f"{self.label} returned invalid tools list")
        names = [item.get("name") for item in tools if isinstance(item, dict)]
        if names != list(EXPECTED_ADVERTISED_TOOLS):
            raise HarnessRefusal("tools_list_unexpected", f"unexpected advertised tools: {names!r}")
        self.advertised_tools = set(names)
        return {"initialize": initialized, "tools_list": listing}

    def tool_call(
        self,
        request_id: str,
        tool: str,
        arguments: Mapping[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if tool not in self.advertised_tools or tool not in E2E_EXERCISED_TOOLS:
            raise HarnessRefusal("tool_not_advertised", f"refusing unadvertised tool: {tool}")
        return self.request(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": tool, "arguments": dict(arguments)},
            },
            timeout,
        )

    def cancel(self, request_id: str) -> str:
        return self.notify("notifications/cancelled", {"requestId": request_id})

    def kill(self) -> None:
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=PROCESS_STOP_SECONDS)

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self._stdin.close()
                self.process.wait(timeout=PROCESS_STOP_SECONDS)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                terminate_process_group(self.process)
        self._stderr_thread.join(timeout=PROCESS_STOP_SECONDS)
        if self._stderr_overflow:
            raise HarnessRefusal("stderr_oversized", f"{self.label} stderr exceeded bound")
        for stream in (self._stdin, self._stdout, self._stderr):
            if not stream.closed:
                stream.close()

    def evidence(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "argv": list(self.argv),
            "pid": self.process.pid,
            "return_code": self.process.poll(),
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


class GatewayEvents:
    """Read-only, schema-pinned event snapshots."""

    REQUIRED_TABLES = {
        "gateway_events",
        "gateway_requests",
        "gateway_results",
        "inflight_leases",
        "results",
    }

    def __init__(self, database: pathlib.Path):
        self.database = database

    def _snapshot(self) -> sqlite3.Connection:
        if not self.database.is_file():
            raise HarnessRefusal("database_missing", f"gateway database is missing: {self.database}")
        uri = f"file:{self.database.as_posix()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != EXPECTED_DATABASE_SCHEMA:
            connection.close()
            raise HarnessRefusal(
                "unknown_database_schema",
                f"expected gateway schema {EXPECTED_DATABASE_SCHEMA}, got {version}",
            )
        tables = {
            str(row[0])
            for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
        }
        if not self.REQUIRED_TABLES.issubset(tables):
            connection.close()
            raise HarnessRefusal("unknown_database_schema", "required gateway tables are missing")
        return connection

    def max_event_id(self) -> int:
        with self._snapshot() as connection:
            return int(connection.execute("SELECT COALESCE(MAX(id), 0) FROM gateway_events").fetchone()[0])

    def begin(self) -> EventWindowStart:
        return EventWindowStart(int(time.time() * 1000), self.max_event_id())

    def end(self, start: EventWindowStart) -> EventWindow:
        return EventWindow(
            start_ms=start.started_ms,
            end_ms=int(time.time() * 1000),
            first_event_id=start.prior_event_id + 1,
            last_event_id=self.max_event_id(),
        )

    def bindings(self, window: EventWindow) -> list[dict[str, str]]:
        with self._snapshot() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT r.request_digest, r.state_digest, r.policy_digest,
                                r.binding_digest
                FROM gateway_events AS e
                JOIN gateway_requests AS r ON r.call_id = e.call_id
                WHERE e.id BETWEEN ?1 AND ?2
                  AND e.created_ms BETWEEN ?3 AND ?4
                ORDER BY r.binding_digest
                """,
                (window.first_event_id, window.last_event_id, window.start_ms, window.end_ms),
            ).fetchall()
        return [dict(row) for row in rows]

    def events(self, binding: str, window: EventWindow) -> list[dict[str, Any]]:
        with self._snapshot() as connection:
            rows = connection.execute(
                """
                SELECT e.id, e.event_type, e.call_id, e.lease_id,
                       e.gateway_result_id, e.reason, e.created_ms,
                       r.request_digest, r.state_digest, r.policy_digest,
                       r.binding_digest, r.role, r.status
                FROM gateway_events AS e
                JOIN gateway_requests AS r ON r.call_id = e.call_id
                WHERE r.binding_digest = ?1
                  AND e.id BETWEEN ?2 AND ?3
                  AND e.created_ms BETWEEN ?4 AND ?5
                ORDER BY e.id
                """,
                (
                    binding,
                    window.first_event_id,
                    window.last_event_id,
                    window.start_ms,
                    window.end_ms,
                ),
            ).fetchall()
        return [dict(row) for row in rows]

    def result_events(
        self, gateway_result_id: str, window: EventWindow
    ) -> list[dict[str, Any]]:
        """Return events bound directly to one result, including pre-request quarantine."""

        if not RESULT_ID_RE.fullmatch(gateway_result_id):
            raise HarnessRefusal("result_id_malformed", "gateway result ID is malformed")
        with self._snapshot() as connection:
            rows = connection.execute(
                """
                SELECT e.id, e.event_type, e.call_id, e.lease_id,
                       e.gateway_result_id, e.reason, e.created_ms,
                       r.call_id AS request_row_call_id
                FROM gateway_events AS e
                LEFT JOIN gateway_requests AS r ON r.call_id = e.call_id
                WHERE e.gateway_result_id = ?1
                  AND e.id BETWEEN ?2 AND ?3
                  AND e.created_ms BETWEEN ?4 AND ?5
                ORDER BY e.id
                """,
                (
                    gateway_result_id,
                    window.first_event_id,
                    window.last_event_id,
                    window.start_ms,
                    window.end_ms,
                ),
            ).fetchall()
        return [dict(row) for row in rows]

    def wait_for_binding(self, start: EventWindowStart, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            window = EventWindow(
                start.started_ms,
                int(time.time() * 1000),
                start.prior_event_id + 1,
                self.max_event_id(),
            )
            bindings = self.bindings(window)
            if len(bindings) == 1:
                return bindings[0]["binding_digest"]
            if len(bindings) > 1:
                raise HarnessRefusal("ambiguous_request_binding", "scenario produced multiple bindings")
            time.sleep(0.002)
        raise HarnessRefusal(
            "event_binding_timeout", "timed out waiting for request binding"
        )

    def wait_for_event(
        self, binding: str, start: EventWindowStart, event_type: str, timeout: float
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            window = EventWindow(
                start.started_ms,
                int(time.time() * 1000),
                start.prior_event_id + 1,
                self.max_event_id(),
            )
            if any(item["event_type"] == event_type for item in self.events(binding, window)):
                return
            time.sleep(0.002)
        safe_event_type = (
            event_type
            if event_type
            in {
                "completed",
                "executed",
                "follower_cancelled",
                "inflight_candidate",
            }
            else "unknown"
        )
        raise HarnessRefusal(
            f"event_{safe_event_type}_timeout",
            f"timed out waiting for {safe_event_type}",
        )

    def lease(self, binding: str, status: str | None = None) -> dict[str, Any]:
        query = """
            SELECT lease_id, call_id, binding_digest, owner, status, reason,
                   acquired_ms, heartbeat_ms, expires_ms, execution_started_ms,
                   completed_ms, lifecycle_generation, gateway_result_id
            FROM inflight_leases WHERE binding_digest = ?1
        """
        parameters: list[Any] = [binding]
        if status is not None:
            query += " AND status = ?2"
            parameters.append(status)
        query += " ORDER BY lifecycle_generation DESC LIMIT 1"
        with self._snapshot() as connection:
            row = connection.execute(query, parameters).fetchone()
        if row is None:
            raise HarnessRefusal("lease_missing", f"gateway lease missing for {binding}")
        return dict(row)

    def result_count(self, binding: str, window: EventWindow) -> int:
        with self._snapshot() as connection:
            return int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM gateway_results
                    WHERE binding_digest=?1 AND status='ready'
                      AND created_ms BETWEEN ?2 AND ?3
                    """,
                    (binding, window.start_ms, window.end_ms),
                ).fetchone()[0]
            )

    def stdout_digest_for_result(self, gateway_result_id: str) -> str:
        if not RESULT_ID_RE.fullmatch(gateway_result_id):
            raise HarnessRefusal("result_id_malformed", "gateway result ID is malformed")
        with self._snapshot() as connection:
            row = connection.execute(
                "SELECT stdout_digest FROM gateway_results WHERE gateway_result_id=?1 AND status='ready'",
                (gateway_result_id,),
            ).fetchone()
        if row is None:
            raise HarnessRefusal("gateway_result_missing", "gateway result row is unavailable")
        return str(row[0])


def reconcile_events(
    events: Sequence[Mapping[str, Any]], expected: Mapping[str, int]
) -> dict[str, int]:
    actual = Counter(str(item.get("event_type")) for item in events)
    expected_counter = Counter(expected)
    if actual != expected_counter:
        missing = expected_counter - actual
        extra = actual - expected_counter
        raise HarnessRefusal(
            "event_reconciliation_failed",
            f"missing events={dict(missing)!r}, extra events={dict(extra)!r}",
        )
    return dict(sorted(actual.items()))


def require_success(response: Mapping[str, Any], label: str) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict) or "error" in response:
        raise HarnessRefusal("tool_call_failed", f"{label} did not return a tool result")
    return result


def result_id(result: Mapping[str, Any]) -> str | None:
    metadata = result.get("_meta")
    if not isinstance(metadata, dict):
        return None
    again = metadata.get("again")
    if not isinstance(again, dict):
        return None
    candidate = again.get("resultId")
    return candidate if isinstance(candidate, str) and RESULT_ID_RE.fullmatch(candidate) else None


def result_without_reference(result: Mapping[str, Any]) -> dict[str, Any]:
    value = copy.deepcopy(dict(result))
    value.pop("_meta", None)
    return value


def detect_false_hits(cases: Sequence[Mapping[str, Any]]) -> int:
    false_hits = 0
    for case in cases:
        classification = case.get("classification")
        same = case.get("same_result")
        if classification == "reuse" and same is not True:
            false_hits += 1
        elif classification == "invalidation" and same is not False:
            false_hits += 1
        elif classification in {"cancelled", "crashed"} and case.get("published") is True:
            false_hits += 1
        elif classification == "corrupt_refusal" and case.get("served_result_id") is not None:
            false_hits += 1
    return false_hits


def corrupt_copied_blob(state_root: pathlib.Path, digest: str) -> dict[str, Any]:
    if not RESULT_ID_RE.fullmatch(digest):
        raise HarnessRefusal("blob_digest_malformed", "blob digest is malformed")
    path = state_root / "blobs" / digest[:2] / digest[2:]
    if not path.is_file() or path.is_symlink():
        raise HarnessRefusal("blob_missing", "copied evidence blob is unavailable")
    before = path.read_bytes()
    if not before:
        raise HarnessRefusal("blob_empty", "cannot corrupt an empty evidence blob")
    changed = bytes([before[0] ^ 0x01]) + before[1:]
    path.write_bytes(changed)
    after_hash = sha256_file(path)
    if after_hash == sha256_bytes(before):
        raise HarnessRefusal("corruption_failed", "copied blob did not change")
    return {
        "relative_path": path.relative_to(state_root).as_posix(),
        "bytes": len(before),
        "sha256_before": sha256_bytes(before),
        "sha256_after": after_hash,
    }


def _binding_and_events(
    reader: GatewayEvents,
    window: EventWindow,
    expected: Mapping[str, int],
) -> tuple[str, list[dict[str, Any]], dict[str, int]]:
    bindings = reader.bindings(window)
    if len(bindings) != 1:
        raise HarnessRefusal(
            "ambiguous_request_binding", f"expected one request binding, got {len(bindings)}"
        )
    binding = bindings[0]["binding_digest"]
    events = reader.events(binding, window)
    counts = reconcile_events(events, expected)
    return binding, events, counts


def _window_record(window: EventWindow, binding: str, counts: Mapping[str, int]) -> dict[str, Any]:
    return {
        "request_binding": binding,
        "time_window": dataclasses.asdict(window),
        "event_counts": dict(counts),
    }


def _search_arguments(pattern: str) -> dict[str, Any]:
    return {"pattern": pattern, "path": "scope", "maxResults": 50}


def _timed_call(call: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], float]:
    started = time.perf_counter_ns()
    response = call()
    return response, (time.perf_counter_ns() - started) / 1_000_000


def _thread_call(call: Callable[[], dict[str, Any]]) -> tuple[threading.Thread, dict[str, Any]]:
    outcome: dict[str, Any] = {}

    def worker() -> None:
        try:
            outcome["response"] = call()
        except BaseException as error:  # collected and re-raised by the controlling thread
            outcome["error"] = error

    thread = threading.Thread(target=worker)
    thread.start()
    return thread, outcome


def _join_call(thread: threading.Thread, outcome: dict[str, Any], timeout: float) -> dict[str, Any]:
    thread.join(timeout)
    if thread.is_alive():
        raise HarnessRefusal("call_thread_timeout", "MCP call thread did not terminate")
    if "error" in outcome:
        error = outcome["error"]
        if isinstance(error, HarnessRefusal):
            raise error
        raise HarnessRefusal("call_thread_failed", str(error)) from error
    response = outcome.get("response")
    if not isinstance(response, dict):
        raise HarnessRefusal("call_thread_failed", "MCP call did not return a response")
    return response


def _session(
    pinned: PinnedBinary,
    workspace: pathlib.Path,
    state: pathlib.Path,
    root: pathlib.Path,
    label: str,
    timeout: float,
) -> McpSession:
    home = root / f"home-{label}"
    temporary = root / f"tmp-{label}"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    session = McpSession(
        binary=pinned.executable_path,
        workspace=workspace,
        again_home=state,
        home=home,
        temporary=temporary,
        authorization_scope="again-product-e2e:shared-v1",
        label=label,
        timeout_seconds=timeout,
    )
    session.handshake(f"again-product-e2e-{label}")
    return session


def run_product_e2e(
    *,
    again_binary: pathlib.Path,
    source_root: pathlib.Path,
    source_git_sha: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    if timeout_seconds <= LEASE_TTL_SECONDS + RECOVERY_GRACE_SECONDS:
        raise HarnessRefusal("timeout_too_short", "timeout must exceed the real lease recovery bound")
    harness_path = pathlib.Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="again-gateway-product-e2e-") as temporary_name:
        root = pathlib.Path(temporary_name).resolve()
        root.chmod(0o700)
        isolated_home = root / "source-home"
        isolated_home.mkdir(mode=0o700)
        source = inspect_clean_source(source_root, source_git_sha, isolated_home)
        pinned = pin_binary(again_binary, root / "pinned" / "again")
        workspace = root / "fixture-repository"
        fixture = create_fixture(workspace, isolated_home)
        state = root / "external-again-home"
        state.mkdir(mode=0o700)
        sessions: list[McpSession] = []
        scenarios: dict[str, Any] = {}
        false_hit_cases: list[dict[str, Any]] = []
        provider_execution_count = 0
        started_ns = time.perf_counter_ns()
        try:
            first = _session(pinned, workspace, state, root, "server-a", timeout_seconds)
            second = _session(pinned, workspace, state, root, "server-b", timeout_seconds)
            sessions.extend([first, second])
            reader = GatewayEvents(state / "again.sqlite")

            # 1-2: independent real processes contend for one exact request.
            concurrent_args = _search_arguments("TOKEN_CONCURRENT")
            start = reader.begin()
            barrier = threading.Barrier(3)
            outcomes: list[dict[str, Any]] = [{}, {}]

            def concurrent_worker(index: int, session: McpSession) -> None:
                try:
                    barrier.wait(timeout=5)
                    outcomes[index]["response"], outcomes[index]["elapsed_ms"] = _timed_call(
                        lambda: session.tool_call(
                            f"concurrent-{index}", "repo.search", concurrent_args
                        )
                    )
                except BaseException as error:
                    outcomes[index]["error"] = error

            workers = [
                threading.Thread(target=concurrent_worker, args=(0, first)),
                threading.Thread(target=concurrent_worker, args=(1, second)),
            ]
            for worker in workers:
                worker.start()
            barrier.wait(timeout=5)
            for worker in workers:
                worker.join(timeout_seconds)
            if any(worker.is_alive() for worker in workers):
                raise HarnessRefusal("concurrent_timeout", "concurrent MCP calls did not finish")
            for outcome in outcomes:
                if "error" in outcome:
                    error = outcome["error"]
                    if isinstance(error, HarnessRefusal):
                        raise error
                    raise HarnessRefusal("concurrent_call_failed", str(error)) from error
            concurrent_responses = [outcome["response"] for outcome in outcomes]
            concurrent_results = [
                require_success(response, "concurrent search") for response in concurrent_responses
            ]
            concurrent_ids = [result_id(result) for result in concurrent_results]
            if result_without_reference(concurrent_results[0]) != result_without_reference(
                concurrent_results[1]
            ):
                raise HarnessRefusal(
                    "joined_observation_mismatch",
                    "leader and follower observations differ",
                )
            concurrent_id = concurrent_ids[0]
            if concurrent_id is None or concurrent_ids[1] != concurrent_id:
                raise HarnessRefusal("result_reference_missing", "joined result has no exact ID")
            window = reader.end(start)
            concurrent_binding, events, counts = _binding_and_events(
                reader,
                window,
                {
                    "requested": 2,
                    "executed": 1,
                    "inflight_candidate": 1,
                    "inflight_join": 1,
                    "completed": 1,
                },
            )
            roles = Counter(item["role"] for item in events if item["event_type"] == "requested")
            if roles != Counter({"leader": 1, "follower": 1}):
                raise HarnessRefusal("leader_follower_unproven", f"unexpected roles: {dict(roles)}")
            provider_execution_count += 1
            scenarios["concurrent_join"] = {
                "classification": {"leader": 1, "joined_follower": 1},
                "identical_responses": False,
                "identical_observations": True,
                "recipient_bound_presentations": True,
                "result_id": concurrent_id,
                "response_sha256": [
                    sha256_bytes(canonical_json_bytes(response)) for response in concurrent_responses
                ],
                "timings_ms": [outcome["elapsed_ms"] for outcome in outcomes],
                **_window_record(window, concurrent_binding, counts),
            }

            # 3: the exact request is served again without provider execution.
            start = reader.begin()
            exact_response, exact_ms = _timed_call(
                lambda: first.tool_call("exact-repeat", "repo.search", concurrent_args)
            )
            exact_result = require_success(exact_response, "exact repeat")
            window = reader.end(start)
            exact_binding, _, counts = _binding_and_events(
                reader,
                window,
                {"requested": 1, "exact_candidate": 1, "exact_hit": 1},
            )
            if (
                exact_binding != concurrent_binding
                or result_id(exact_result) != concurrent_id
                or result_without_reference(exact_result)
                != result_without_reference(concurrent_results[0])
            ):
                raise HarnessRefusal("exact_reuse_unproven", "exact repeat did not preserve binding/output")
            scenarios["exact_repeat"] = {
                "classification": "exact_reuse",
                "identical_response": False,
                "identical_observation": True,
                "result_id": result_id(exact_result),
                "timing_ms": exact_ms,
                **_window_record(window, exact_binding, counts),
            }
            false_hit_cases.append({"classification": "reuse", "same_result": True})

            # 4: cache one search, then prove a searched-file mutation changes
            # the binding and output for that exact same request.
            relevant_args = _search_arguments("TOKEN_RELEVANT_V1")
            baseline_start = reader.begin()
            relevant_baseline_response, baseline_ms = _timed_call(
                lambda: first.tool_call(
                    "relevant-baseline", "repo.search", relevant_args
                )
            )
            relevant_baseline = require_success(
                relevant_baseline_response, "relevant mutation baseline"
            )
            baseline_window = reader.end(baseline_start)
            baseline_binding, _, baseline_counts = _binding_and_events(
                reader,
                baseline_window,
                {"requested": 1, "executed": 1, "completed": 1},
            )
            provider_execution_count += 1
            if result_id(relevant_baseline) is None:
                raise HarnessRefusal(
                    "result_reference_missing", "relevant baseline has no result ID"
                )
            relevant_path = workspace / "scope" / "payload-000.txt"
            relevant_before = sha256_file(relevant_path)
            relevant_bytes = relevant_path.read_bytes()
            if b"TOKEN_RELEVANT_V1" not in relevant_bytes:
                raise HarnessRefusal("fixture_marker_missing", "relevant marker is absent")
            relevant_path.write_bytes(relevant_bytes.replace(b"TOKEN_RELEVANT_V1", b"TOKEN_RELEVANT_V2", 1))
            relevant_after = sha256_file(relevant_path)
            start = reader.begin()
            relevant_response, relevant_ms = _timed_call(
                lambda: second.tool_call("relevant-mutation", "repo.search", relevant_args)
            )
            relevant_result = require_success(relevant_response, "relevant mutation")
            window = reader.end(start)
            relevant_binding, _, counts = _binding_and_events(
                reader, window, {"requested": 1, "executed": 1, "completed": 1}
            )
            provider_execution_count += 1
            if relevant_binding == baseline_binding or relevant_before == relevant_after:
                raise HarnessRefusal("relevant_mutation_ignored", "relevant mutation did not partition state")
            matches = relevant_result.get("structuredContent", {}).get("matches")
            if (
                matches != []
                or result_id(relevant_result) is None
                or result_id(relevant_result) == result_id(relevant_baseline)
                or result_without_reference(relevant_result)
                == result_without_reference(relevant_baseline)
            ):
                raise HarnessRefusal("stale_search_output", "removed marker remained in search output")
            scenarios["relevant_mutation"] = {
                "classification": "executed_new_state",
                "old_result_served": False,
                "file_sha256_before": relevant_before,
                "file_sha256_after": relevant_after,
                "baseline_result_id": result_id(relevant_baseline),
                "new_result_id": result_id(relevant_result),
                "baseline_timing_ms": baseline_ms,
                "baseline_window": _window_record(
                    baseline_window, baseline_binding, baseline_counts
                ),
                "timing_ms": relevant_ms,
                **_window_record(window, relevant_binding, counts),
            }
            false_hit_cases.append({"classification": "invalidation", "same_result": False})

            # 5: a file outside the proven search subtree preserves the binding.
            irrelevant_path = workspace / "outside" / "irrelevant.txt"
            irrelevant_before = sha256_file(irrelevant_path)
            irrelevant_path.write_bytes(b"outside dependency changed\n".ljust(128, b"x"))
            irrelevant_after = sha256_file(irrelevant_path)
            start = reader.begin()
            irrelevant_response, irrelevant_ms = _timed_call(
                lambda: first.tool_call("irrelevant-mutation", "repo.search", relevant_args)
            )
            irrelevant_result = require_success(irrelevant_response, "irrelevant mutation")
            window = reader.end(start)
            irrelevant_binding, _, counts = _binding_and_events(
                reader,
                window,
                {"requested": 1, "exact_candidate": 1, "exact_hit": 1},
            )
            if (
                irrelevant_binding != relevant_binding
                or result_id(irrelevant_result) != result_id(relevant_result)
                or result_without_reference(irrelevant_result)
                != result_without_reference(relevant_result)
            ):
                raise HarnessRefusal(
                    "dependency_proof_failed", "out-of-scope mutation did not produce proven exact reuse"
                )
            scenarios["irrelevant_mutation"] = {
                "classification": "reuse_supported_by_dependency_proof",
                "file_sha256_before": irrelevant_before,
                "file_sha256_after": irrelevant_after,
                "timing_ms": irrelevant_ms,
                **_window_record(window, irrelevant_binding, counts),
            }
            false_hit_cases.append({"classification": "reuse", "same_result": True})

            # 6: cancel only a joined follower; the leader remains publishable.
            follower_args = _search_arguments("TOKEN_FOLLOWER_CANCEL")
            start = reader.begin()
            leader_thread, leader_outcome = _thread_call(
                lambda: first.tool_call("follower-case-leader", "repo.search", follower_args)
            )
            follower_binding = reader.wait_for_binding(
                start, EVENT_OBSERVATION_TIMEOUT_SECONDS
            )
            reader.wait_for_event(
                follower_binding,
                start,
                "executed",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            follower_thread, follower_outcome = _thread_call(
                lambda: second.tool_call("follower-case-cancel", "repo.search", follower_args)
            )
            reader.wait_for_event(
                follower_binding,
                start,
                "inflight_candidate",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            second.cancel("follower-case-cancel")
            follower_response = _join_call(follower_thread, follower_outcome, timeout_seconds)
            leader_response = _join_call(leader_thread, leader_outcome, timeout_seconds)
            if follower_response.get("error", {}).get("code") != -32800:
                raise HarnessRefusal("follower_cancel_failed", "follower did not return cancellation")
            leader_result = require_success(leader_response, "leader after follower cancellation")
            # Response delivery and durable event observation are independent
            # threads. Wait for both terminal facts before closing the evidence
            # window so scheduler timing cannot turn a correct cancellation
            # into a missing-event false failure.
            reader.wait_for_event(
                follower_binding,
                start,
                "follower_cancelled",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            reader.wait_for_event(
                follower_binding,
                start,
                "completed",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            window = reader.end(start)
            binding, _, counts = _binding_and_events(
                reader,
                window,
                {
                    "requested": 2,
                    "executed": 1,
                    "inflight_candidate": 1,
                    "follower_cancelled": 1,
                    "completed": 1,
                },
            )
            if binding != follower_binding or result_id(leader_result) is None:
                raise HarnessRefusal("leader_invalid_after_follower_cancel", "leader was not reusable")
            provider_execution_count += 1
            health_start = reader.begin()
            health = require_success(
                second.tool_call(
                    "health-after-follower", "repo.read", {"path": "health/follower.txt"}
                ),
                "health after follower cancellation",
            )
            health_window = reader.end(health_start)
            health_binding, _, health_counts = _binding_and_events(
                reader, health_window, {"requested": 1, "executed": 1, "completed": 1}
            )
            provider_execution_count += 1
            scenarios["follower_cancellation"] = {
                "classification": "follower_cancelled_leader_valid",
                "leader_result_id": result_id(leader_result),
                "follower_error_code": -32800,
                "health_result_sha256": sha256_bytes(canonical_json_bytes(health)),
                "health_window": _window_record(health_window, health_binding, health_counts),
                **_window_record(window, binding, counts),
            }
            false_hit_cases.append({"classification": "cancelled", "published": False})

            # 7: cancel a leader and prove no result exists before a fresh retry.
            leader_cancel_args = _search_arguments("TOKEN_LEADER_CANCEL")
            start = reader.begin()
            cancelled_thread, cancelled_outcome = _thread_call(
                lambda: first.tool_call(
                    "leader-case-cancel", "repo.search", leader_cancel_args
                )
            )
            cancelled_binding = reader.wait_for_binding(
                start, EVENT_OBSERVATION_TIMEOUT_SECONDS
            )
            reader.wait_for_event(
                cancelled_binding,
                start,
                "executed",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            first.cancel("leader-case-cancel")
            cancelled_response = _join_call(cancelled_thread, cancelled_outcome, timeout_seconds)
            if cancelled_response.get("error", {}).get("code") != -32800:
                raise HarnessRefusal("leader_cancel_failed", "leader did not return cancellation")
            cancellation_live_window = reader.end(start)
            if reader.result_count(cancelled_binding, cancellation_live_window) != 0:
                raise HarnessRefusal("cancelled_result_published", "cancelled leader published a result")
            window = cancellation_live_window
            binding, _, counts = _binding_and_events(
                reader, window, {"requested": 1, "executed": 1, "failed": 1}
            )
            provider_execution_count += 1
            retry_start = reader.begin()
            retry_result = require_success(
                second.tool_call("leader-case-retry", "repo.search", leader_cancel_args),
                "retry after leader cancellation",
            )
            retry_window = reader.end(retry_start)
            retry_binding, _, retry_counts = _binding_and_events(
                reader, retry_window, {"requested": 1, "executed": 1, "completed": 1}
            )
            provider_execution_count += 1
            if retry_binding != cancelled_binding or result_id(retry_result) is None:
                raise HarnessRefusal("leader_cancel_recovery_failed", "fresh retry was not reusable")
            scenarios["leader_cancellation"] = {
                "classification": "cancelled_without_publication",
                "cancel_error_code": -32800,
                "ready_results_before_retry": 0,
                "retry_result_id": result_id(retry_result),
                "retry_window": _window_record(retry_window, retry_binding, retry_counts),
                **_window_record(window, binding, counts),
            }
            false_hit_cases.append({"classification": "cancelled", "published": False})

            # 8: kill an executing lease owner and recover after the real TTL.
            crash_args = _search_arguments("TOKEN_CRASH_RECOVERY")
            crash_start = reader.begin()
            crash_thread, crash_outcome = _thread_call(
                lambda: first.tool_call("crash-owner", "repo.search", crash_args)
            )
            crash_binding = reader.wait_for_binding(
                crash_start, EVENT_OBSERVATION_TIMEOUT_SECONDS
            )
            reader.wait_for_event(
                crash_binding,
                crash_start,
                "executed",
                EVENT_OBSERVATION_TIMEOUT_SECONDS,
            )
            old_lease = reader.lease(crash_binding, "active")
            first.kill()
            crash_thread.join(5.0)
            if crash_thread.is_alive():
                raise HarnessRefusal("killed_call_survived", "killed server call did not terminate")
            crash_live_window = reader.end(crash_start)
            if reader.result_count(crash_binding, crash_live_window) != 0:
                raise HarnessRefusal("killed_result_published", "killed leader published a result")
            second.close()
            deadline_ms = int(old_lease["expires_ms"]) + 25
            remaining = max(0.0, (deadline_ms - int(time.time() * 1000)) / 1000)
            if remaining > LEASE_TTL_SECONDS + 1.0:
                raise HarnessRefusal("lease_recovery_unbounded", "lease expiry exceeded declared TTL")
            if remaining:
                time.sleep(remaining)
            restarted = _session(pinned, workspace, state, root, "server-restarted", timeout_seconds)
            sessions.append(restarted)
            recovery_start = reader.begin()
            recovery_response, recovery_ms = _timed_call(
                lambda: restarted.tool_call("crash-recovery", "repo.search", crash_args)
            )
            recovery_result = require_success(recovery_response, "crash recovery")
            recovery_window = reader.end(recovery_start)
            recovery_binding, recovery_events, recovery_counts = _binding_and_events(
                reader,
                recovery_window,
                {"lease_expired": 1, "requested": 1, "executed": 1, "completed": 1},
            )
            provider_execution_count += 2  # killed provider attempt plus recovered attempt
            new_lease = reader.lease(crash_binding)
            if (
                recovery_binding != crash_binding
                or int(new_lease["lifecycle_generation"])
                != int(old_lease["lifecycle_generation"]) + 1
                or new_lease["status"] != "completed"
                or any(item["event_type"] == "stale_completion" for item in recovery_events)
                or result_id(recovery_result) is None
            ):
                raise HarnessRefusal("lease_recovery_failed", "lease recovery invariants failed")
            health_start = reader.begin()
            restart_health = require_success(
                restarted.tool_call(
                    "health-after-restart", "repo.read", {"path": "health/restart.txt"}
                ),
                "health after restart",
            )
            health_window = reader.end(health_start)
            health_binding, _, health_counts = _binding_and_events(
                reader, health_window, {"requested": 1, "executed": 1, "completed": 1}
            )
            provider_execution_count += 1
            scenarios["lease_owner_crash"] = {
                "classification": "bounded_recovery_without_stale_completion",
                "killed_pid": first.process.pid,
                "old_lease": old_lease,
                "new_lease": new_lease,
                "recovery_timing_ms": recovery_ms,
                "health_result_sha256": sha256_bytes(canonical_json_bytes(restart_health)),
                "health_window": _window_record(health_window, health_binding, health_counts),
                **_window_record(recovery_window, recovery_binding, recovery_counts),
            }
            false_hit_cases.append({"classification": "crashed", "published": False})

            # Resolve the CAS digest while the recovered gateway still owns a
            # live SQLite connection. After an intentionally killed writer,
            # reopening a WAL database read-only may require recovery and can
            # fail even though the database bytes are intact. The digest is
            # metadata only; the subsequent copy still happens after every
            # gateway process is stopped.
            current_result_id = result_id(recovery_result)
            if current_result_id is None:
                raise HarnessRefusal(
                    "result_reference_missing", "recovery result has no current result ID"
                )
            stdout_digest = reader.stdout_digest_for_result(current_result_id)

            # Stop all primary processes before making a consistent byte-for-byte copy.
            restarted.close()
            for session in sessions:
                session.close()

            # 9: corrupt only the copied evidence state; output must be recomputed.
            copied_state = root / "corrupted-state-copy"
            shutil.copytree(state, copied_state, copy_function=shutil.copy2)
            corruption = corrupt_copied_blob(copied_state, stdout_digest)
            corrupt_reader = GatewayEvents(copied_state / "again.sqlite")
            corrupt_session = _session(
                pinned, workspace, copied_state, root, "server-corrupted-copy", timeout_seconds
            )
            sessions.append(corrupt_session)
            start = corrupt_reader.begin()
            corrupt_response, corrupt_ms = _timed_call(
                lambda: corrupt_session.tool_call(
                    "corrupt-evidence-retry", "repo.search", crash_args
                )
            )
            corrupt_result = require_success(corrupt_response, "corrupted evidence retry")
            window = corrupt_reader.end(start)
            corrupt_events = corrupt_reader.result_events(current_result_id, window)
            corrupt_counts = reconcile_events(corrupt_events, {"binding_quarantined": 1})
            if (
                corrupt_events[0].get("request_row_call_id") is not None
                or corrupt_events[0].get("reason") != "result_corrupt"
            ):
                raise HarnessRefusal(
                    "corrupt_quarantine_unproven",
                    "corrupt result was not quarantined before request authority",
                )
            # The hardened store quarantines before issuing a ready acquisition.
            # Absence of a result reference plus exact recomputed bytes proves the
            # corrupt blob was not delivered by the direct no-reuse fallback.
            if (
                result_id(corrupt_result) is not None
                or result_without_reference(corrupt_result)
                != result_without_reference(recovery_result)
            ):
                raise HarnessRefusal("corrupt_evidence_served", "corrupted evidence was not refused")
            provider_execution_count += 1
            health_start = corrupt_reader.begin()
            corruption_health = require_success(
                corrupt_session.tool_call(
                    "health-after-corruption",
                    "repo.read",
                    {"path": "health/corruption.txt"},
                ),
                "health after corruption",
            )
            health_window = corrupt_reader.end(health_start)
            health_binding, _, health_counts = _binding_and_events(
                corrupt_reader,
                health_window,
                {"requested": 1, "executed": 1, "completed": 1},
            )
            provider_execution_count += 1
            scenarios["corrupted_evidence"] = {
                "classification": "blob_validation_refused_reuse",
                "corruption": corruption,
                "served_result_id": None,
                "recomputed_output_matches": True,
                "timing_ms": corrupt_ms,
                "prior_request_binding": crash_binding,
                "health_result_sha256": sha256_bytes(canonical_json_bytes(corruption_health)),
                "health_window": _window_record(health_window, health_binding, health_counts),
                "quarantine_window": {
                    "gateway_result_id": current_result_id,
                    "time_window": dataclasses.asdict(window),
                    "event_counts": corrupt_counts,
                    "reason": "result_corrupt",
                    "request_authority_issued": False,
                },
            }
            false_hit_cases.append(
                {"classification": "corrupt_refusal", "served_result_id": result_id(corrupt_result)}
            )
            corrupt_session.close()
            false_hits = detect_false_hits(false_hit_cases)
            if false_hits != 0:
                raise HarnessRefusal("false_hit_detected", f"detected {false_hits} false hits")

            elapsed_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
            process_evidence = [session.evidence() for session in sessions]
            report = {
                "schema": REPORT_SCHEMA,
                "harness_version": HARNESS_VERSION,
                "classification": {"type": "pass", "code": "all_scenarios_passed"},
                "binary": {
                    "requested_path": str(pinned.requested_path),
                    "sha256": pinned.sha256,
                    "bytes": pinned.size,
                },
                "source": source,
                "harness": {
                    "path": str(harness_path),
                    "sha256": sha256_file(harness_path),
                },
                "fixture_manifest": fixture,
                "commands": [item["argv"] for item in process_evidence],
                "environment": {
                    "allowlisted_keys": sorted(_server_environment(
                        again_home=state,
                        home=root / "environment-placeholder-home",
                        temporary=root / "environment-placeholder-tmp",
                    )),
                    "again_home_external_to_fixture": True,
                    "private_mode": "0700",
                    "network_policy": {
                        "product_operations": sorted(E2E_EXERCISED_TOOLS),
                        "git_protocol_allowlist": "file",
                        "proxy_endpoint": NETWORK_BLOCK_ENDPOINT,
                        "network_client_code_in_harness": False,
                    },
                    "user_codex_or_claude_configuration_touched": False,
                },
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                },
                "mcp": {
                    "protocol_version": MCP_PROTOCOL_VERSION,
                    "advertised_tools": list(EXPECTED_ADVERTISED_TOOLS),
                    "processes": process_evidence,
                },
                "scenarios": scenarios,
                "provider_execution_count": provider_execution_count,
                "false_hit_count": false_hits,
                "timings": {
                    "total_ms": elapsed_ms,
                    "lease_ttl_seconds": LEASE_TTL_SECONDS,
                    "timeout_seconds": timeout_seconds,
                },
            }
            report["report_sha256"] = sha256_bytes(canonical_json_bytes(report))
            return report
        finally:
            close_error: BaseException | None = None
            for session in sessions:
                try:
                    session.close()
                except BaseException as error:
                    close_error = close_error or error
            if close_error is not None and sys.exc_info()[0] is None:
                raise close_error


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", type=pathlib.Path, required=True)
    parser.add_argument(
        "--source-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
        help="clean source worktree whose HEAD must equal --source-git-sha",
    )
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=45.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    output = arguments.output
    if not output.is_absolute():
        raise SystemExit("--output must be absolute")
    if output.exists() or output.is_symlink():
        raise SystemExit(f"refusing to overwrite existing evidence: {output}")
    try:
        report = run_product_e2e(
            again_binary=arguments.again_binary,
            source_root=arguments.source_root.resolve(),
            source_git_sha=arguments.source_git_sha,
            timeout_seconds=arguments.timeout_seconds,
        )
        exit_code = 0
    except HarnessRefusal as error:
        report = {
            "schema": REPORT_SCHEMA,
            "harness_version": HARNESS_VERSION,
            "classification": {"type": "non_pass", "code": error.code},
            "message": str(error),
            "requested": {
                "again_binary": str(arguments.again_binary),
                "source_root": str(arguments.source_root),
                "source_git_sha": arguments.source_git_sha,
            },
            "harness": {
                "path": str(pathlib.Path(__file__).resolve()),
                "sha256": sha256_file(pathlib.Path(__file__).resolve()),
            },
        }
        report["report_sha256"] = sha256_bytes(canonical_json_bytes(report))
        exit_code = 2
    except Exception as error:
        report = {
            "schema": REPORT_SCHEMA,
            "harness_version": HARNESS_VERSION,
            "classification": {"type": "non_pass", "code": "internal_harness_error"},
            "message": f"{type(error).__name__}: {error}",
            "requested": {
                "again_binary": str(arguments.again_binary),
                "source_root": str(arguments.source_root),
                "source_git_sha": arguments.source_git_sha,
            },
            "harness": {
                "path": str(pathlib.Path(__file__).resolve()),
                "sha256": sha256_file(pathlib.Path(__file__).resolve()),
            },
        }
        report["report_sha256"] = sha256_bytes(canonical_json_bytes(report))
        exit_code = 2
    write_json_exclusive(output, report)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
