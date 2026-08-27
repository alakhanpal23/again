#!/usr/bin/env python3
"""Bounded offline evaluation of ``again mcp serve`` over stdio.

The harness never downloads, clones, opens a socket, or invokes a network
client. It mutates only a uniquely named fixture directory in an explicit
repository, removes that directory on exit, and runs the supplied Again binary
with an isolated temporary state directory.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Any


SCHEMA = "again.agent-gateway-eval.v1"
HARNESS_VERSION = "1.0.0"
MCP_PROTOCOL_VERSION = "2025-06-18"
FIXTURE_DIRECTORY = "agent_gateway_eval_fixture_v1"
RELEVANT_FILE = "relevant.txt"
IRRELEVANT_FILE = "irrelevant.txt"
SEARCH_NEEDLE = "AGAIN_GATEWAY_EVAL_NEEDLE"
CANCELLATION_QUERY = "AGAIN_GATEWAY_EVAL_CANCEL"


@dataclasses.dataclass(frozen=True)
class EvalLimits:
    timeout_seconds: float = 10.0
    shutdown_timeout_seconds: float = 2.0
    max_request_bytes: int = 2 * 1024 * 1024
    max_response_bytes: int = 8 * 1024 * 1024
    max_stderr_bytes: int = 1024 * 1024
    max_command_output_bytes: int = 1024 * 1024
    gateway_message_limit_bytes: int = 1024 * 1024
    adversarial_json_depth: int = 64
    fixture_payload_bytes: int = 64 * 1024

    def validate(self) -> None:
        integers = (
            self.max_request_bytes,
            self.max_response_bytes,
            self.max_stderr_bytes,
            self.max_command_output_bytes,
            self.gateway_message_limit_bytes,
            self.adversarial_json_depth,
            self.fixture_payload_bytes,
        )
        if self.timeout_seconds <= 0 or self.shutdown_timeout_seconds <= 0:
            raise HarnessRefusal("invalid_limits", "timeouts must be positive")
        if self.timeout_seconds > 300 or self.shutdown_timeout_seconds > 30:
            raise HarnessRefusal("invalid_limits", "timeouts exceed the harness maximum")
        if any(value <= 0 for value in integers):
            raise HarnessRefusal("invalid_limits", "byte, depth, and fixture limits must be positive")
        if self.gateway_message_limit_bytes >= self.max_request_bytes:
            raise HarnessRefusal(
                "invalid_limits",
                "request bound must admit one deliberately oversized gateway frame",
            )
        if self.adversarial_json_depth <= 48:
            raise HarnessRefusal(
                "invalid_limits", "adversarial JSON depth must exceed the gateway default"
            )
        if (
            self.max_request_bytes > 16 * 1024 * 1024
            or self.max_response_bytes > 64 * 1024 * 1024
            or self.max_stderr_bytes > 16 * 1024 * 1024
            or self.max_command_output_bytes > 16 * 1024 * 1024
            or self.gateway_message_limit_bytes > 8 * 1024 * 1024
            or self.adversarial_json_depth > 128
            or self.fixture_payload_bytes > 8 * 1024 * 1024
        ):
            raise HarnessRefusal("invalid_limits", "a configured harness maximum is too large")
        if self.fixture_payload_bytes > self.max_response_bytes // 2:
            raise HarnessRefusal(
                "invalid_limits", "fixture payload must leave bounded response headroom"
            )


@dataclasses.dataclass(frozen=True)
class EvalConfig:
    binary: pathlib.Path
    repository: pathlib.Path
    read_tool: str | None = None
    search_tool: str | None = None
    read_path_argument: str = "path"
    search_query_argument: str = "query"
    search_path_argument: str = "path"


class HarnessRefusal(RuntimeError):
    """A typed fail-closed harness outcome."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float


@dataclasses.dataclass(frozen=True)
class RpcFrame:
    raw: bytes
    value: dict[str, Any]
    elapsed_ms: float

    def result_bytes(self) -> bytes:
        if "result" not in self.value or "error" in self.value:
            raise HarnessRefusal("rpc_error", "JSON-RPC response did not contain a result")
        return raw_json_object_member(self.raw, "result")

    def result_sha256(self) -> str:
        return sha256_bytes(self.result_bytes())


@dataclasses.dataclass(frozen=True)
class ProcessSummary:
    returncode: int
    stderr_bytes: int
    stderr_sha256: str
    forced_shutdown: bool


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: pathlib.Path, *, maximum: int = 512 * 1024 * 1024) -> str:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise HarnessRefusal("binary_invalid", "binary is not a bounded regular file")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if _stat_identity(before) != _stat_identity(opened):
            raise HarnessRefusal("binary_changed", "binary changed while opening")
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if total > maximum:
                raise HarnessRefusal("binary_invalid", "binary grew beyond its bound")
            digest.update(block)
        after_handle = os.fstat(source.fileno())
    after_path = path.stat()
    if (
        _stat_identity(before) != _stat_identity(after_handle)
        or _stat_identity(before) != _stat_identity(after_path)
        or total != before.st_size
    ):
        raise HarnessRefusal("binary_changed", "binary changed while hashing")
    return digest.hexdigest()


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def strict_json_loads(value: bytes) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise HarnessRefusal("duplicate_response_key", "server response has a duplicate key")
            result[key] = item
        return result

    def reject_non_finite(constant: str) -> Any:
        raise HarnessRefusal(
            "malformed_response", f"server response used non-finite number {constant}"
        )

    try:
        text = value.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_constant=reject_non_finite,
        )
    except HarnessRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise HarnessRefusal("malformed_response", "server emitted malformed JSON") from error


def raw_json_object_member(value: bytes, member: str) -> bytes:
    """Return one top-level member's exact UTF-8 JSON spelling."""

    try:
        text = value.decode("utf-8")
        decoder = json.JSONDecoder()
        cursor = 0

        def skip_space(position: int) -> int:
            while position < len(text) and text[position] in " \t\r\n":
                position += 1
            return position

        cursor = skip_space(cursor)
        if cursor >= len(text) or text[cursor] != "{":
            raise ValueError("response is not an object")
        cursor += 1
        while True:
            cursor = skip_space(cursor)
            if cursor >= len(text) or text[cursor] == "}":
                break
            key, cursor = decoder.raw_decode(text, cursor)
            if not isinstance(key, str):
                raise ValueError("object key is not a string")
            cursor = skip_space(cursor)
            if cursor >= len(text) or text[cursor] != ":":
                raise ValueError("object member has no colon")
            value_start = skip_space(cursor + 1)
            _parsed, value_end = decoder.raw_decode(text, value_start)
            if key == member:
                return text[value_start:value_end].encode("utf-8")
            cursor = skip_space(value_end)
            if cursor < len(text) and text[cursor] == ",":
                cursor += 1
                continue
            if cursor < len(text) and text[cursor] == "}":
                break
            raise ValueError("object member has no delimiter")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HarnessRefusal(
            "invalid_response", "could not isolate raw JSON-RPC result bytes"
        ) from error
    raise HarnessRefusal("invalid_response", f"JSON-RPC response has no {member} member")


def _terminate_process(process: subprocess.Popen[bytes], timeout: float) -> bool:
    """Terminate an exact child process group; return whether force was needed."""

    if process.poll() is not None:
        return False
    forced = True
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return forced
    try:
        process.wait(timeout=timeout)
        return forced
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return forced
    process.wait(timeout=timeout)
    return forced


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    stream_limit_bytes: int,
) -> CommandResult:
    if not argv or timeout_seconds <= 0 or stream_limit_bytes <= 0:
        raise HarnessRefusal("invalid_command", "bounded command inputs are invalid")
    started = time.monotonic_ns()
    process = subprocess.Popen(
        tuple(argv),
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    if process.stdout is None or process.stderr is None:
        _terminate_process(process, min(1.0, timeout_seconds))
        raise HarnessRefusal("command_pipe", "bounded command pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessRefusal("command_timeout", "bounded command timed out")
            events = selector.select(remaining)
            if not events:
                raise HarnessRefusal("command_timeout", "bounded command timed out")
            for key, _mask in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = captured[key.data]
                target.extend(chunk)
                if len(target) > stream_limit_bytes:
                    raise HarnessRefusal(
                        "command_output_limit", f"bounded command {key.data} exceeded its limit"
                    )
        remaining = max(0.001, deadline - time.monotonic())
        returncode = process.wait(timeout=remaining)
    except BaseException:
        _terminate_process(process, min(1.0, timeout_seconds))
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        returncode=returncode,
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
        elapsed_ms=(time.monotonic_ns() - started) / 1_000_000,
    )


class McpStdioClient:
    """Bounded newline-delimited JSON-RPC client for one server process."""

    def __init__(
        self,
        argv: Sequence[str],
        *,
        cwd: pathlib.Path,
        environment: Mapping[str, str],
        limits: EvalLimits,
    ) -> None:
        if not argv:
            raise HarnessRefusal("invalid_server", "server argv cannot be empty")
        self.limits = limits
        self.process = subprocess.Popen(
            tuple(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name == "posix",
            bufsize=0,
        )
        if (
            self.process.stdin is None
            or self.process.stdout is None
            or self.process.stderr is None
        ):
            _terminate_process(self.process, min(1.0, limits.shutdown_timeout_seconds))
            raise HarnessRefusal("server_pipe", "MCP server pipes were not created")
        self._stdin = self.process.stdin
        os.set_blocking(self._stdin.fileno(), False)
        self._stdout = self.process.stdout
        self._stdout_buffer = bytearray()
        self._selector = selectors.DefaultSelector()
        self._selector.register(self._stdout, selectors.EVENT_READ)
        self._sent_ns: dict[Any, int] = {}
        self._pending: dict[Any, RpcFrame] = {}
        self._stderr_digest = hashlib.sha256()
        self._stderr_bytes = 0
        self._stderr_prefix = bytearray()
        self._stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self._stderr_thread.start()
        self._closed = False

    def _drain_stderr(self) -> None:
        if self.process.stderr is None:
            return
        while True:
            chunk = os.read(self.process.stderr.fileno(), 64 * 1024)
            if not chunk:
                return
            self._stderr_digest.update(chunk)
            self._stderr_bytes += len(chunk)
            room = self.limits.max_stderr_bytes - len(self._stderr_prefix)
            if room > 0:
                self._stderr_prefix.extend(chunk[:room])
            if self._stderr_bytes > self.limits.max_stderr_bytes:
                return

    def send_raw(self, payload: bytes, *, request_id: Any | None = None) -> None:
        if self._closed:
            raise HarnessRefusal("server_closed", "cannot write to a closed MCP server")
        if b"\n" in payload or b"\r" in payload:
            raise HarnessRefusal("invalid_frame", "outbound MCP frames must be newline-free")
        if len(payload) > self.limits.max_request_bytes:
            raise HarnessRefusal("request_limit", "outbound MCP frame exceeds harness bound")
        if request_id is not None:
            if request_id in self._sent_ns or request_id in self._pending:
                raise HarnessRefusal("duplicate_request_id", "request ID is already pending")
            self._sent_ns[request_id] = time.monotonic_ns()
        try:
            frame = memoryview(payload + b"\n")
            selector = selectors.DefaultSelector()
            selector.register(self._stdin, selectors.EVENT_WRITE)
            deadline = time.monotonic() + self.limits.timeout_seconds
            try:
                while frame:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise HarnessRefusal("request_timeout", "MCP request write timed out")
                    try:
                        written = os.write(self._stdin.fileno(), frame)
                    except BlockingIOError:
                        continue
                    if written <= 0:
                        raise HarnessRefusal("server_closed", "MCP request write made no progress")
                    frame = frame[written:]
            finally:
                selector.close()
        except BrokenPipeError as error:
            raise HarnessRefusal("server_closed", "MCP server closed stdin") from error

    def send_json(self, value: Mapping[str, Any]) -> None:
        request_id = value.get("id")
        self.send_raw(canonical_json_bytes(dict(value)), request_id=request_id)

    def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = dict(params)
        self.send_json(message)

    def request(
        self,
        request_id: Any,
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> RpcFrame:
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            message["params"] = dict(params)
        self.send_json(message)
        return self.receive(request_id)

    def call_tool(self, request_id: Any, name: str, arguments: Mapping[str, Any]) -> RpcFrame:
        return self.request(
            request_id,
            "tools/call",
            {"name": name, "arguments": dict(arguments)},
        )

    def receive(self, request_id: Any) -> RpcFrame:
        if request_id in self._pending:
            return self._pending.pop(request_id)
        deadline = time.monotonic() + self.limits.timeout_seconds
        while True:
            frame = self._read_frame(deadline)
            response_id = frame.value.get("id")
            if response_id == request_id:
                return frame
            if response_id is None:
                raise HarnessRefusal("unexpected_response", "expected an identified JSON-RPC response")
            if response_id in self._pending:
                raise HarnessRefusal("duplicate_response", "server emitted a duplicate response ID")
            self._pending[response_id] = frame

    def receive_any(self) -> RpcFrame:
        return self._read_frame(time.monotonic() + self.limits.timeout_seconds)

    def _read_frame(self, deadline: float) -> RpcFrame:
        while b"\n" not in self._stdout_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessRefusal("response_timeout", "MCP response timed out")
            events = self._selector.select(remaining)
            if not events:
                raise HarnessRefusal("response_timeout", "MCP response timed out")
            chunk = os.read(self._stdout.fileno(), 64 * 1024)
            if not chunk:
                raise HarnessRefusal(
                    "server_closed",
                    f"MCP server exited before responding (status={self.process.poll()!r})",
                )
            self._stdout_buffer.extend(chunk)
            newline = self._stdout_buffer.find(b"\n")
            if newline < 0 and len(self._stdout_buffer) > self.limits.max_response_bytes + 1:
                raise HarnessRefusal("response_limit", "MCP response exceeded harness bound")
            if newline > self.limits.max_response_bytes:
                raise HarnessRefusal("response_limit", "MCP response exceeded harness bound")
        raw, _, remainder = self._stdout_buffer.partition(b"\n")
        self._stdout_buffer = bytearray(remainder)
        if raw.endswith(b"\r"):
            raw = raw[:-1]
        if len(raw) > self.limits.max_response_bytes:
            raise HarnessRefusal("response_limit", "MCP response exceeded harness bound")
        value = strict_json_loads(bytes(raw))
        if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
            raise HarnessRefusal("invalid_response", "server emitted an invalid JSON-RPC response")
        response_id = value.get("id")
        sent = self._sent_ns.pop(response_id, None)
        elapsed_ms = 0.0 if sent is None else (time.monotonic_ns() - sent) / 1_000_000
        return RpcFrame(raw=bytes(raw), value=value, elapsed_ms=elapsed_ms)

    def close(self, *, require_clean: bool) -> ProcessSummary:
        if self._closed:
            raise HarnessRefusal("server_closed", "MCP server was closed more than once")
        self._closed = True
        self._selector.close()
        try:
            self._stdin.close()
        except BrokenPipeError:
            pass
        forced = False
        try:
            returncode = self.process.wait(timeout=self.limits.shutdown_timeout_seconds)
        except subprocess.TimeoutExpired:
            forced = _terminate_process(self.process, self.limits.shutdown_timeout_seconds)
            returncode = self.process.returncode
        self._stderr_thread.join(timeout=self.limits.shutdown_timeout_seconds)
        if self._stderr_thread.is_alive():
            raise HarnessRefusal("stderr_cleanup", "MCP stderr drain did not terminate")
        self._stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()
        summary = ProcessSummary(
            returncode=int(returncode),
            stderr_bytes=self._stderr_bytes,
            stderr_sha256=self._stderr_digest.hexdigest(),
            forced_shutdown=forced,
        )
        if require_clean and (summary.returncode != 0 or summary.forced_shutdown):
            raise HarnessRefusal(
                "server_cleanup",
                f"MCP server did not exit cleanly (status={summary.returncode})",
            )
        if self._stderr_bytes > self.limits.max_stderr_bytes:
            raise HarnessRefusal("stderr_limit", "MCP server stderr exceeded its bound")
        return summary


class EvaluationFixture:
    """Own exactly two new files beneath one new repository directory."""

    def __init__(self, repository: pathlib.Path, payload_bytes: int) -> None:
        self.repository = repository
        self.root = repository / FIXTURE_DIRECTORY
        self.relevant = self.root / RELEVANT_FILE
        self.irrelevant = self.root / IRRELEVANT_FILE
        self.payload_bytes = payload_bytes
        self._root_identity: tuple[int, int] | None = None

    def create(self) -> None:
        try:
            self.root.mkdir(mode=0o700)
        except FileExistsError as error:
            raise HarnessRefusal(
                "fixture_exists", f"refusing to overwrite existing fixture: {self.root}"
            ) from error
        try:
            metadata = self.root.stat()
            self._root_identity = (metadata.st_dev, metadata.st_ino)
            header = f"VERSION_ONE\n{SEARCH_NEEDLE}\n".encode("ascii")
            if len(header) > self.payload_bytes:
                raise HarnessRefusal(
                    "invalid_limits", "fixture payload is smaller than its header"
                )
            relevant = header + b"r" * (self.payload_bytes - len(header))
            self._write_new(self.relevant, relevant)
            self._write_new(self.irrelevant, b"IRRELEVANT_ONE\n")
        except BaseException:
            for path in (self.relevant, self.irrelevant):
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    path.unlink()
            try:
                self.root.rmdir()
            except OSError:
                pass
            raise

    @staticmethod
    def _write_new(path: pathlib.Path, value: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(value)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise HarnessRefusal("fixture_write", "fixture write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _replace_owned(path: pathlib.Path, value: bytes) -> None:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise HarnessRefusal("fixture_replaced", "owned fixture file is no longer private")
        with path.open("r+b", buffering=0) as destination:
            opened = os.fstat(destination.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise HarnessRefusal("fixture_replaced", "owned fixture changed while opening")
            destination.truncate(0)
            destination.write(value)
            os.fsync(destination.fileno())

    def mutate_irrelevant(self) -> None:
        self._replace_owned(self.irrelevant, b"IRRELEVANT_TWO\n")

    def mutate_relevant(self) -> None:
        current = self.relevant.read_bytes()
        changed = current.replace(b"VERSION_ONE", b"VERSION_TWO", 1)
        if changed == current or len(changed) != len(current):
            raise HarnessRefusal("fixture_invalid", "relevant fixture mutation was not exact")
        self._replace_owned(self.relevant, changed)

    def initial_hashes(self) -> dict[str, str]:
        return {
            "relevant_sha256": sha256_bytes(self.relevant.read_bytes()),
            "irrelevant_sha256": sha256_bytes(self.irrelevant.read_bytes()),
        }

    def cleanup(self) -> None:
        try:
            metadata = self.root.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISDIR(metadata.st_mode):
            raise HarnessRefusal("fixture_replaced", "fixture directory type changed")
        if self._root_identity != (metadata.st_dev, metadata.st_ino):
            raise HarnessRefusal("fixture_replaced", "fixture directory identity changed")
        actual = {entry.name for entry in self.root.iterdir()}
        expected = {RELEVANT_FILE, IRRELEVANT_FILE}
        if actual != expected:
            raise HarnessRefusal("fixture_cleanup", "fixture directory contains an unknown entry")
        for path in (self.relevant, self.irrelevant):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise HarnessRefusal("fixture_cleanup", "fixture file is unsafe to remove")
            path.unlink()
        self.root.rmdir()


def sanitized_environment(state: pathlib.Path, home: pathlib.Path) -> dict[str, str]:
    state.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    environment = {
        "AGAIN_HOME": str(state),
        "AGAIN_MCP_OFFLINE": "1",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    temporary = os.environ.get("TMPDIR")
    if temporary:
        environment["TMPDIR"] = temporary
    return environment


def _git_output(
    root: pathlib.Path,
    environment: Mapping[str, str],
    limits: EvalLimits,
    *arguments: str,
) -> str:
    git_environment = dict(environment)
    git_environment["GIT_OPTIONAL_LOCKS"] = "0"
    completed = run_bounded_command(
        ("/usr/bin/git", "-C", str(root), *arguments),
        cwd=root,
        environment=git_environment,
        timeout_seconds=limits.timeout_seconds,
        stream_limit_bytes=limits.max_command_output_bytes,
    )
    if completed.returncode != 0 or completed.stderr:
        raise HarnessRefusal("git_inspection", "bounded Git inspection failed")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise HarnessRefusal("git_inspection", "Git identity was not ASCII") from error


def validate_configuration(
    config: EvalConfig,
    environment: Mapping[str, str],
    limits: EvalLimits,
) -> EvalConfig:
    limits.validate()
    try:
        binary_input = config.binary.lstat()
    except OSError as error:
        raise HarnessRefusal("binary_invalid", "Again binary is unreadable") from error
    if stat.S_ISLNK(binary_input.st_mode) or not stat.S_ISREG(binary_input.st_mode):
        raise HarnessRefusal("binary_invalid", "Again binary must be a non-symlink regular file")
    binary = config.binary.resolve(strict=True)
    if not os.access(binary, os.X_OK):
        raise HarnessRefusal("binary_invalid", "Again binary is not executable")
    try:
        repository_input = config.repository.lstat()
    except OSError as error:
        raise HarnessRefusal("repository_invalid", "repository is unreadable") from error
    if stat.S_ISLNK(repository_input.st_mode) or not stat.S_ISDIR(repository_input.st_mode):
        raise HarnessRefusal("repository_invalid", "repository must be a non-symlink directory")
    repository = config.repository.resolve(strict=True)
    top_level = pathlib.Path(_git_output(repository, environment, limits, "rev-parse", "--show-toplevel"))
    if top_level.resolve(strict=True) != repository:
        raise HarnessRefusal("repository_invalid", "repository must name the Git worktree root")
    for name, value in (
        ("read tool", config.read_tool),
        ("search tool", config.search_tool),
        ("read path argument", config.read_path_argument),
        ("search query argument", config.search_query_argument),
        ("search path argument", config.search_path_argument),
    ):
        if value is not None and (
            not value
            or len(value) > 128
            or not value.isascii()
            or not all(character.isalnum() or character in "._-/" for character in value)
        ):
            raise HarnessRefusal("configuration_invalid", f"{name} is invalid")
    return dataclasses.replace(config, binary=binary, repository=repository)


def normalize_stats(value: Mapping[str, Any]) -> dict[str, int]:
    names = {
        "provider_executions": "executed",
        "exact_hits": "exact_hits",
        "inflight_joins": "inflight_joins",
        "bytes_omitted": "duplicate_bytes_omitted",
        "estimated_tokens_avoided": "estimated_tokens_avoided",
        "wall_time_saved_ms": "estimated_execution_ms_saved",
    }
    normalized: dict[str, int] = {}
    for output, source in names.items():
        item = value.get(source)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise HarnessRefusal("stats_invalid", f"stats field {source} is missing or invalid")
        normalized[output] = item
    return normalized


def stats_delta(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    result: dict[str, int] = {}
    if before.keys() != after.keys():
        raise HarnessRefusal("stats_invalid", "stats snapshots have different fields")
    for key in before:
        difference = after[key] - before[key]
        if difference < 0:
            raise HarnessRefusal("stats_rollback", f"stats field {key} moved backwards")
        result[key] = difference
    return result


def production_stats_reader(
    binary: pathlib.Path,
    repository: pathlib.Path,
    environment: Mapping[str, str],
    limits: EvalLimits,
) -> Callable[[McpStdioClient], Mapping[str, Any]]:
    def read(_client: McpStdioClient) -> Mapping[str, Any]:
        completed = run_bounded_command(
            (str(binary), "stats", "--json"),
            cwd=repository,
            environment=environment,
            timeout_seconds=limits.timeout_seconds,
            stream_limit_bytes=limits.max_command_output_bytes,
        )
        if completed.returncode != 0 or completed.stderr:
            raise HarnessRefusal("stats_failed", "Again stats command failed")
        value = strict_json_loads(completed.stdout)
        if not isinstance(value, dict):
            raise HarnessRefusal("stats_invalid", "Again stats output is not an object")
        return value

    return read


def _require_success(frame: RpcFrame, label: str) -> None:
    if "error" in frame.value or "result" not in frame.value:
        raise HarnessRefusal("scenario_failed", f"{label} did not return a successful result")


def _require_error(frame: RpcFrame, label: str, allowed_codes: set[int]) -> int:
    error = frame.value.get("error")
    if not isinstance(error, dict) or error.get("code") not in allowed_codes:
        raise HarnessRefusal("scenario_failed", f"{label} did not return the required error")
    return int(error["code"])


def _tool_names(
    tools_result: Any,
    *,
    read_tool: str | None,
    search_tool: str | None,
) -> tuple[str, str, list[str]]:
    if not isinstance(tools_result, dict) or not isinstance(tools_result.get("tools"), list):
        raise HarnessRefusal("catalog_invalid", "tools/list result is malformed")
    names: list[str] = []
    for tool in tools_result["tools"]:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise HarnessRefusal("catalog_invalid", "tools/list contains a malformed tool")
        names.append(tool["name"])
    if len(names) != len(set(names)) or names != sorted(names):
        raise HarnessRefusal("catalog_invalid", "tool names are duplicate or nondeterministic")

    def choose(explicit: str | None, suffixes: tuple[str, ...], label: str) -> str:
        if explicit is not None:
            if explicit not in names:
                raise HarnessRefusal("catalog_invalid", f"configured {label} tool is absent")
            return explicit
        candidates = [name for name in names if any(name.endswith(suffix) for suffix in suffixes)]
        if len(candidates) != 1:
            raise HarnessRefusal(
                "catalog_ambiguous", f"could not uniquely discover repository {label} tool"
            )
        return candidates[0]

    read = choose(
        read_tool,
        (".read", ".read_file", ".repository_read", "/read"),
        "read",
    )
    search = choose(
        search_tool,
        (".search", ".repository_search", "/search"),
        "search",
    )
    if read == search:
        raise HarnessRefusal("catalog_invalid", "read and search tools must be distinct")
    return read, search, names


def _require_tool_arguments(
    tools_result: Mapping[str, Any], tool_name: str, argument_names: Sequence[str]
) -> None:
    tools = tools_result.get("tools")
    if not isinstance(tools, list):
        raise HarnessRefusal("catalog_invalid", "tools/list result is malformed")
    selected = next(
        (tool for tool in tools if isinstance(tool, dict) and tool.get("name") == tool_name),
        None,
    )
    schema = selected.get("inputSchema") if isinstance(selected, dict) else None
    properties = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(properties, dict) or any(name not in properties for name in argument_names):
        raise HarnessRefusal(
            "catalog_invalid", f"tool {tool_name} does not declare configured arguments"
        )


def _tool_call_message(request_id: Any, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": dict(arguments)},
    }


def _timing(frame: RpcFrame) -> float:
    return round(frame.elapsed_ms, 3)


def _error_record(frame: RpcFrame, code: int) -> dict[str, Any]:
    return {
        "code": code,
        "elapsed_ms": _timing(frame),
        "response_sha256": sha256_bytes(canonical_json_bytes(frame.value)),
    }


def evaluate(
    config: EvalConfig,
    *,
    state_root: pathlib.Path,
    home: pathlib.Path,
    limits: EvalLimits = EvalLimits(),
    server_argv: Sequence[str] | None = None,
    stats_reader: Callable[[McpStdioClient], Mapping[str, Any]] | None = None,
    source_root: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Run the complete scenario matrix and return a stable evidence object."""

    environment = sanitized_environment(state_root, home)
    config = validate_configuration(config, environment, limits)
    source_root = (
        pathlib.Path(__file__).resolve().parents[1]
        if source_root is None
        else source_root.resolve(strict=True)
    )
    source_sha = _git_output(source_root, environment, limits, "rev-parse", "HEAD")
    fixture_git_sha = _git_output(config.repository, environment, limits, "rev-parse", "HEAD")
    binary_digest = file_sha256(config.binary)
    harness_path = pathlib.Path(__file__).resolve()
    harness_digest = file_sha256(harness_path)
    argv = (
        (str(config.binary), "mcp", "serve") if server_argv is None else tuple(server_argv)
    )
    if stats_reader is None:
        stats_reader = production_stats_reader(
            config.binary, config.repository, environment, limits
        )

    fixture = EvaluationFixture(config.repository, limits.fixture_payload_bytes)
    fixture.create()
    fixture_hashes = fixture.initial_hashes()
    client: McpStdioClient | None = None
    process_summary: ProcessSummary | None = None
    try:
        client = McpStdioClient(
            argv,
            cwd=config.repository,
            environment=environment,
            limits=limits,
        )
        initialize = client.request(
            "initialize",
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "again-agent-gateway-eval",
                    "version": HARNESS_VERSION,
                },
            },
        )
        _require_success(initialize, "initialize")
        if initialize.value["result"].get("protocolVersion") != MCP_PROTOCOL_VERSION:
            raise HarnessRefusal("protocol_mismatch", "server negotiated an unexpected MCP version")
        client.notify("notifications/initialized")

        tools_first = client.request("tools-list-1", "tools/list")
        tools_second = client.request("tools-list-2", "tools/list")
        _require_success(tools_first, "first tools/list")
        _require_success(tools_second, "second tools/list")
        if tools_first.result_bytes() != tools_second.result_bytes():
            raise HarnessRefusal("nondeterministic_response", "tools/list bytes changed")
        read_tool, search_tool, catalog_names = _tool_names(
            tools_first.value["result"],
            read_tool=config.read_tool,
            search_tool=config.search_tool,
        )
        _require_tool_arguments(
            tools_first.value["result"], read_tool, (config.read_path_argument,)
        )
        _require_tool_arguments(
            tools_first.value["result"],
            search_tool,
            (config.search_query_argument, config.search_path_argument),
        )

        read_arguments = {
            config.read_path_argument: f"{FIXTURE_DIRECTORY}/{RELEVANT_FILE}"
        }
        search_arguments = {
            config.search_query_argument: SEARCH_NEEDLE,
            config.search_path_argument: FIXTURE_DIRECTORY,
        }
        baseline_stats = normalize_stats(stats_reader(client))

        search = client.call_tool("search", search_tool, search_arguments)
        _require_success(search, "repository search")
        after_search_stats = normalize_stats(stats_reader(client))
        search_delta = stats_delta(baseline_stats, after_search_stats)
        if search_delta["provider_executions"] != 1:
            raise HarnessRefusal("stats_mismatch", "repository search did not execute once")

        concurrent_started = time.monotonic_ns()
        client.send_json(_tool_call_message("concurrent-a", read_tool, read_arguments))
        client.send_json(_tool_call_message("concurrent-b", read_tool, read_arguments))
        concurrent_a = client.receive("concurrent-a")
        concurrent_b = client.receive("concurrent-b")
        concurrent_elapsed = (time.monotonic_ns() - concurrent_started) / 1_000_000
        _require_success(concurrent_a, "first concurrent read")
        _require_success(concurrent_b, "second concurrent read")
        concurrent_bytes = concurrent_a.result_bytes()
        if concurrent_bytes != concurrent_b.result_bytes():
            raise HarnessRefusal(
                "nondeterministic_response", "concurrent identical calls returned different bytes"
            )
        after_concurrent_stats = normalize_stats(stats_reader(client))
        concurrent_delta = stats_delta(after_search_stats, after_concurrent_stats)
        if (
            concurrent_delta["provider_executions"] != 1
            or concurrent_delta["inflight_joins"] != 1
        ):
            raise HarnessRefusal(
                "stats_mismatch", "concurrent identical calls did not elect one execution and one join"
            )

        later = client.call_tool("later-reuse", read_tool, read_arguments)
        _require_success(later, "later exact reuse")
        if later.result_bytes() != concurrent_bytes:
            raise HarnessRefusal("nondeterministic_response", "later exact reuse changed result bytes")
        after_later_stats = normalize_stats(stats_reader(client))
        later_delta = stats_delta(after_concurrent_stats, after_later_stats)
        if later_delta["provider_executions"] != 0 or later_delta["exact_hits"] != 1:
            raise HarnessRefusal("stats_mismatch", "later identical call was not an exact hit")

        fixture.mutate_irrelevant()
        irrelevant = client.call_tool("irrelevant-mutation", read_tool, read_arguments)
        _require_success(irrelevant, "irrelevant mutation preservation")
        if irrelevant.result_bytes() != concurrent_bytes:
            raise HarnessRefusal(
                "nondeterministic_response", "irrelevant mutation changed scoped read bytes"
            )
        after_irrelevant_stats = normalize_stats(stats_reader(client))
        irrelevant_delta = stats_delta(after_later_stats, after_irrelevant_stats)
        if (
            irrelevant_delta["provider_executions"] != 0
            or irrelevant_delta["exact_hits"] != 1
        ):
            raise HarnessRefusal("stats_mismatch", "irrelevant mutation invalidated exact reuse")

        fixture.mutate_relevant()
        relevant = client.call_tool("relevant-mutation", read_tool, read_arguments)
        _require_success(relevant, "relevant mutation invalidation")
        relevant_bytes = relevant.result_bytes()
        if relevant_bytes == concurrent_bytes:
            raise HarnessRefusal(
                "nondeterministic_response", "relevant mutation did not change repository read bytes"
            )
        after_relevant_stats = normalize_stats(stats_reader(client))
        relevant_delta = stats_delta(after_irrelevant_stats, after_relevant_stats)
        if relevant_delta["provider_executions"] != 1:
            raise HarnessRefusal("stats_mismatch", "relevant mutation did not execute provider")

        malformed_started = time.monotonic_ns()
        client.send_raw(b'{"jsonrpc":"2.0","id":')
        malformed = client.receive_any()
        malformed = dataclasses.replace(
            malformed,
            elapsed_ms=(time.monotonic_ns() - malformed_started) / 1_000_000,
        )
        malformed_code = _require_error(malformed, "malformed input", {-32_700})

        oversized_started = time.monotonic_ns()
        oversized_payload = b"x" * (limits.gateway_message_limit_bytes + 1)
        client.send_raw(oversized_payload)
        oversized = client.receive_any()
        oversized = dataclasses.replace(
            oversized,
            elapsed_ms=(time.monotonic_ns() - oversized_started) / 1_000_000,
        )
        oversized_code = _require_error(oversized, "oversized input", {-32_021})

        nested: Any = "leaf"
        for _ in range(limits.adversarial_json_depth):
            nested = {"nested": nested}
        deep_started = time.monotonic_ns()
        deep_payload = canonical_json_bytes(
            _tool_call_message(
                "deep-input",
                read_tool,
                {config.read_path_argument: nested},
            )
        )
        client.send_raw(deep_payload)
        deep = client.receive_any()
        deep = dataclasses.replace(
            deep, elapsed_ms=(time.monotonic_ns() - deep_started) / 1_000_000
        )
        deep_code = _require_error(deep, "deep input", {-32_021})

        duplicate_started = time.monotonic_ns()
        duplicate_payload = (
            b'{"jsonrpc":"2.0","id":"duplicate-input","method":"tools/call",'
            b'"params":{"name":"'
            + read_tool.encode("ascii")
            + b'","arguments":{"path":"one","path":"two"}}}'
        )
        client.send_raw(duplicate_payload)
        duplicate = client.receive_any()
        duplicate = dataclasses.replace(
            duplicate,
            elapsed_ms=(time.monotonic_ns() - duplicate_started) / 1_000_000,
        )
        duplicate_code = _require_error(duplicate, "duplicate-key input", {-32_700})

        recovery = client.request("recovery-ping", "ping")
        _require_success(recovery, "post-adversarial ping")
        if recovery.value["result"] != {}:
            raise HarnessRefusal("scenario_failed", "post-adversarial ping result changed")
        after_adversarial_stats = normalize_stats(stats_reader(client))
        if after_adversarial_stats != after_relevant_stats:
            raise HarnessRefusal("stats_mismatch", "invalid inputs reached provider accounting")

        cancellation_arguments = {
            config.search_query_argument: CANCELLATION_QUERY,
            config.search_path_argument: FIXTURE_DIRECTORY,
        }
        cancellation_started = time.monotonic_ns()
        client.send_json(
            _tool_call_message("cancellation-target", search_tool, cancellation_arguments)
        )
        client.notify(
            "notifications/cancelled",
            {"requestId": "cancellation-target", "reason": "evaluation cleanup"},
        )
        cancellation = client.receive("cancellation-target")
        cancellation = dataclasses.replace(
            cancellation,
            elapsed_ms=(time.monotonic_ns() - cancellation_started) / 1_000_000,
        )
        cancellation_won = "error" in cancellation.value
        cancellation_code = _require_error(cancellation, "cancellation", {-32_800})
        after_cancellation_stats = normalize_stats(stats_reader(client))
        cancellation_delta = stats_delta(after_adversarial_stats, after_cancellation_stats)

        cleanup = client.call_tool("cancellation-target", read_tool, read_arguments)
        _require_success(cleanup, "post-cancellation request-ID reuse")
        if cleanup.result_bytes() != relevant_bytes:
            raise HarnessRefusal(
                "nondeterministic_response", "post-cancellation cleanup changed exact read bytes"
            )
        final_stats = normalize_stats(stats_reader(client))
        cleanup_delta = stats_delta(after_cancellation_stats, final_stats)
        if cleanup_delta["provider_executions"] != 0 or cleanup_delta["exact_hits"] != 1:
            raise HarnessRefusal(
                "stats_mismatch", "post-cancellation cleanup was not an exact hit"
            )
        final_delta = stats_delta(baseline_stats, final_stats)
        process_summary = client.close(require_clean=True)
        client = None

        baseline_provider_ms = min(concurrent_a.elapsed_ms, concurrent_b.elapsed_ms)
        observed_wall_saved = sum(
            max(0.0, baseline_provider_ms - frame.elapsed_ms)
            for frame in (later, irrelevant, cleanup)
        )
        evidence = {
            "schema": SCHEMA,
            "harness_version": HARNESS_VERSION,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "offline_contract": {
                "downloads": False,
                "clones": False,
                "network_access": False,
                "transport": "newline-delimited MCP JSON-RPC over stdio",
            },
            "provenance": {
                "binary": {
                    "path": str(config.binary),
                    "sha256": binary_digest,
                },
                "source_git_sha": source_sha,
                "fixture_repository_git_sha": fixture_git_sha,
                "harness_sha256": harness_digest,
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                },
            },
            "configuration": {
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                "response_equality_basis": "raw UTF-8 JSON-RPC result bytes excluding envelope",
                "server_argv_shape": ["<explicit-binary>", "mcp", "serve"],
                "read_tool": read_tool,
                "search_tool": search_tool,
                "catalog_names": catalog_names,
                "limits": dataclasses.asdict(limits),
                "isolated_again_home": True,
            },
            "fixture": {
                "directory": FIXTURE_DIRECTORY,
                "payload_bytes": limits.fixture_payload_bytes,
                **fixture_hashes,
            },
            "scenarios": {
                "initialize": {
                    "elapsed_ms": _timing(initialize),
                    "response_sha256": initialize.result_sha256(),
                },
                "tools_list": {
                    "first_elapsed_ms": _timing(tools_first),
                    "second_elapsed_ms": _timing(tools_second),
                    "response_sha256": tools_first.result_sha256(),
                    "deterministic": True,
                },
                "repository_search": {
                    "elapsed_ms": _timing(search),
                    "response_sha256": search.result_sha256(),
                    "stats_delta": search_delta,
                },
                "concurrent_identical_calls": {
                    "batch_elapsed_ms": round(concurrent_elapsed, 3),
                    "first_elapsed_ms": _timing(concurrent_a),
                    "second_elapsed_ms": _timing(concurrent_b),
                    "response_sha256": sha256_bytes(concurrent_bytes),
                    "deterministic": True,
                    "stats_delta": concurrent_delta,
                },
                "later_exact_reuse": {
                    "elapsed_ms": _timing(later),
                    "response_sha256": later.result_sha256(),
                    "stats_delta": later_delta,
                },
                "irrelevant_mutation_preservation": {
                    "elapsed_ms": _timing(irrelevant),
                    "response_sha256": irrelevant.result_sha256(),
                    "stats_delta": irrelevant_delta,
                },
                "relevant_mutation_invalidation": {
                    "elapsed_ms": _timing(relevant),
                    "response_sha256": relevant.result_sha256(),
                    "stats_delta": relevant_delta,
                },
                "malformed_input": _error_record(malformed, malformed_code),
                "oversized_input": _error_record(oversized, oversized_code),
                "deep_input": _error_record(deep, deep_code),
                "duplicate_key_input": _error_record(duplicate, duplicate_code),
                "cancellation_cleanup": {
                    "elapsed_ms": _timing(cancellation),
                    "cancellation_won_race": cancellation_won,
                    "error_code": cancellation_code,
                    "response_sha256": sha256_bytes(canonical_json_bytes(cancellation.value)),
                    "stats_delta": cancellation_delta,
                    "request_id_reusable_after_terminal_state": True,
                    "cleanup_elapsed_ms": _timing(cleanup),
                    "cleanup_response_sha256": cleanup.result_sha256(),
                    "cleanup_stats_delta": cleanup_delta,
                },
                "post_adversarial_recovery": {
                    "elapsed_ms": _timing(recovery),
                    "response_sha256": recovery.result_sha256(),
                },
            },
            "measurements": {
                **final_delta,
                "observed_wall_time_saved_ms": round(observed_wall_saved, 3),
                "stats_baseline": baseline_stats,
                "stats_final": final_stats,
            },
            "server_process": dataclasses.asdict(process_summary),
            "gates": {
                "protocol_handshake": "pass",
                "deterministic_required_responses": "pass",
                "concurrent_join": "pass",
                "later_exact_reuse": "pass",
                "relevant_mutation_invalidation": "pass",
                "irrelevant_mutation_preservation": "pass",
                "adversarial_input_rejection_and_recovery": "pass",
                "cancellation_cleanup": "pass",
                "stats_reconciled": "pass",
            },
        }
        return evidence
    finally:
        if client is not None:
            try:
                client.close(require_clean=False)
            except HarnessRefusal:
                pass
        fixture.cleanup()


def write_json_exclusive(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        dict(value),
        ensure_ascii=True,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    ).encode("ascii") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise HarnessRefusal(
            "evidence_exists", f"refusing to overwrite existing evidence: {path}"
        ) from error
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HarnessRefusal("evidence_write", "evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        path.unlink(missing_ok=True)
        raise
    os.close(descriptor)


def _path_is_within(path: pathlib.Path, parent: pathlib.Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--repository", type=pathlib.Path, required=True)
    parser.add_argument("--json-out", type=pathlib.Path, required=True)
    parser.add_argument("--read-tool")
    parser.add_argument("--search-tool")
    parser.add_argument("--read-path-argument", default="path")
    parser.add_argument("--search-query-argument", default="query")
    parser.add_argument("--search-path-argument", default="path")
    parser.add_argument("--timeout-seconds", type=float, default=10.0)
    arguments = parser.parse_args(argv)
    if arguments.json_out.exists() or arguments.json_out.is_symlink():
        raise HarnessRefusal(
            "evidence_exists",
            f"refusing to overwrite existing evidence: {arguments.json_out}",
        )
    json_out = arguments.json_out.resolve(strict=False)
    if not json_out.parent.is_dir():
        raise HarnessRefusal("evidence_parent", "evidence parent directory does not exist")
    try:
        repository = arguments.repository.resolve(strict=True)
    except OSError as error:
        raise HarnessRefusal("repository_invalid", "repository is unreadable") from error
    if _path_is_within(json_out, repository):
        raise HarnessRefusal("evidence_location", "evidence output must be outside the repository")

    config = EvalConfig(
        binary=arguments.binary,
        repository=arguments.repository,
        read_tool=arguments.read_tool,
        search_tool=arguments.search_tool,
        read_path_argument=arguments.read_path_argument,
        search_query_argument=arguments.search_query_argument,
        search_path_argument=arguments.search_path_argument,
    )
    limits = EvalLimits(timeout_seconds=arguments.timeout_seconds)
    with tempfile.TemporaryDirectory(prefix="again-agent-gateway-eval-") as temporary:
        private = pathlib.Path(temporary)
        evidence = evaluate(
            config,
            state_root=private / "state",
            home=private / "home",
            limits=limits,
        )
    write_json_exclusive(json_out, evidence)
    print(f"wrote agent gateway evaluation evidence to {json_out}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessRefusal as error:
        print(f"agent gateway eval refused [{error.code}]: {error}", file=sys.stderr)
        raise SystemExit(2) from error
