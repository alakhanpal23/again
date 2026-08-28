#!/usr/bin/env python3
"""Bounded, fail-closed chaos evidence over the real Again MCP binary.

The scenario engine is the production-binary product E2E harness. This wrapper
adds independent false-hit reconciliation, descriptor-pinned executable
handoff, complete process-group cleanup, resource-leak observations, strict
stdio framing, and transactional evidence publication. Proxy variables reduce
accidental network use; they are not a kernel socket sandbox.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import random
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, BinaryIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bench import agent_gateway_product_e2e as product


SCHEMA = "again.agent-gateway-chaos-soak.v2"
MAX_PROCESSES = 32
MAX_OPERATIONS = 2_000
MAX_EVIDENCE_BYTES = 1_000_000
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
PROCESS_STOP_SECONDS = 2.0
LEASE_SECONDS = int(product.LEASE_TTL_SECONDS)
RESULT_ID_LENGTH = 64


class HarnessRefusal(RuntimeError):
    """A typed non-pass condition."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> bytes:
    try:
        rendered = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as error:
        raise HarnessRefusal("noncanonical_json", "value is not canonical JSON") from error
    return rendered.encode("utf-8") + b"\n"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HarnessRefusal("duplicate_json_key", "JSON contains a duplicate key")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
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
            raise HarnessRefusal("nonfinite_json_number", "JSON number is non-finite")


def parse_json_rpc_line(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_FRAME_BYTES:
        raise HarnessRefusal("response_oversized", "JSON-RPC frame exceeded its bound")
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or raw.endswith(b"\r\n"):
        raise HarnessRefusal("invalid_json_framing", "JSON-RPC frame is not one LF line")
    try:
        value = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except HarnessRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise HarnessRefusal("malformed_json", "JSON-RPC frame is malformed") from error
    _validate_json_bounds(value)
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0" or "id" not in value:
        raise HarnessRefusal("invalid_json_rpc", "JSON-RPC response envelope is invalid")
    if set(value) - {"jsonrpc", "id", "result", "error"}:
        raise HarnessRefusal("invalid_json_rpc", "JSON-RPC response has unknown fields")
    if ("result" in value) + ("error" in value) != 1:
        raise HarnessRefusal("invalid_json_rpc", "JSON-RPC response is ambiguous")
    return value


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclasses.dataclass(frozen=True)
class PinnedBinary:
    requested_path: pathlib.Path
    executable_path: pathlib.Path
    sha256: str
    size: int
    identity: tuple[int, ...]


def pin_binary_exact(requested: pathlib.Path, destination: pathlib.Path) -> PinnedBinary:
    if not requested.is_absolute() or requested.resolve(strict=True) != requested:
        raise HarnessRefusal("binary_not_canonical", "Again binary must be absolute and canonical")
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(requested, source_flags)
    except OSError as error:
        raise HarnessRefusal("binary_open", "Again binary could not be opened safely") from error
    destination_fd: int | None = None
    try:
        before = os.fstat(source_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_BINARY_BYTES
            or before.st_mode & 0o111 == 0
        ):
            raise HarnessRefusal("binary_invalid", "Again binary is not a bounded executable")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o500,
        )
        os.fchmod(destination_fd, 0o500)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_BINARY_BYTES:
                raise HarnessRefusal("binary_oversized", "Again binary exceeded its bound")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise HarnessRefusal("binary_copy", "Again binary copy made no progress")
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        path_after = os.stat(requested, follow_symlinks=False)
        if (
            total != before.st_size
            or _stat_identity(before) != _stat_identity(after)
            or _stat_identity(after) != _stat_identity(path_after)
        ):
            raise HarnessRefusal("binary_changed", "Again binary changed while being pinned")
        return PinnedBinary(
            requested,
            destination,
            digest.hexdigest(),
            total,
            _stat_identity(os.fstat(destination_fd)),
        )
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def revalidate_pinned_binary(pinned: PinnedBinary) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(pinned.executable_path, flags)
    except OSError as error:
        raise HarnessRefusal("binary_reopen", "pinned Again executable could not be reopened") from error
    try:
        before = os.fstat(descriptor)
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_BINARY_BYTES:
                raise HarnessRefusal("binary_oversized", "pinned Again executable exceeded its bound")
            digest.update(block)
        after = os.fstat(descriptor)
        path_after = os.stat(pinned.executable_path, follow_symlinks=False)
    finally:
        os.close(descriptor)
    if (
        _stat_identity(before) != pinned.identity
        or _stat_identity(after) != pinned.identity
        or _stat_identity(path_after) != pinned.identity
        or total != pinned.size
        or digest.hexdigest() != pinned.sha256
        or before.st_mode & 0o111 == 0
    ):
        raise HarnessRefusal("binary_revalidation", "pinned Again executable changed")
    return {"sha256": pinned.sha256, "bytes": pinned.size, "stable": True}


def _process_group_exists(process_group: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_group_absent(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def terminate_owned_process_group(process_group: int) -> dict[str, Any]:
    """Terminate a private group even if its original leader already exited."""

    existed = _process_group_exists(process_group)
    if existed:
        try:
            os.killpg(process_group, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    if not _wait_group_absent(process_group, PROCESS_STOP_SECONDS):
        try:
            os.killpg(process_group, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    absent = _wait_group_absent(process_group, PROCESS_STOP_SECONDS)
    if not absent:
        raise HarnessRefusal("process_group_leak", "owned process group remained after SIGKILL")
    return {"existed_at_cleanup": existed, "absent_after_cleanup": absent}


class Session:
    """A strict, bounded stdio session over one real Again process."""

    def __init__(
        self,
        binary: pathlib.Path,
        repo: pathlib.Path,
        state: pathlib.Path,
        label: str,
        timeout: float = 5.0,
    ) -> None:
        self.argv = (
            str(binary),
            "mcp",
            "serve",
            "--workspace",
            str(repo),
            "--authorization-scope",
            "again-chaos-soak:exact-v2",
        )
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(state.parent / f"home-{label}"),
            "TMPDIR": str(state.parent / f"tmp-{label}"),
            "AGAIN_HOME": str(state),
            "LC_ALL": "C",
            "LANG": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "CARGO_NET_OFFLINE": "true",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
        pathlib.Path(environment["HOME"]).mkdir(mode=0o700)
        pathlib.Path(environment["TMPDIR"]).mkdir(mode=0o700)
        state.mkdir(mode=0o700, exist_ok=True)
        self.process = subprocess.Popen(
            self.argv,
            cwd=repo,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=os.name == "posix",
        )
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            terminate_owned_process_group(self.process.pid)
            raise HarnessRefusal("process_pipe", "MCP stdio pipes were not created")
        self.stdin: BinaryIO = self.process.stdin
        self.stdout: BinaryIO = self.process.stdout
        self.stderr: BinaryIO = self.process.stderr
        self.process_group = self.process.pid
        self.timeout = timeout
        self.buffer = bytearray()
        self.stderr_capture = bytearray()
        self.stderr_overflow = False
        self.lock = threading.Lock()
        self.stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self.stderr_thread.start()

    def _drain_stderr(self) -> None:
        while True:
            try:
                block = os.read(self.stderr.fileno(), 65536)
            except OSError:
                return
            if not block:
                return
            room = MAX_STDERR_BYTES - len(self.stderr_capture)
            if room > 0:
                self.stderr_capture.extend(block[:room])
            if len(block) > room:
                self.stderr_overflow = True

    def _read_line(self, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        selector = selectors.DefaultSelector()
        selector.register(self.stdout, selectors.EVENT_READ)
        try:
            while True:
                newline = self.buffer.find(b"\n")
                if newline >= 0:
                    frame = bytes(self.buffer[: newline + 1])
                    del self.buffer[: newline + 1]
                    return frame
                if len(self.buffer) > MAX_FRAME_BYTES:
                    raise HarnessRefusal("response_oversized", "MCP response exceeded its bound")
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise HarnessRefusal("response_timeout", "MCP response timed out")
                block = os.read(
                    self.stdout.fileno(),
                    min(65536, MAX_FRAME_BYTES + 1 - len(self.buffer)),
                )
                if not block:
                    code = "truncated_output" if self.buffer else "server_eof"
                    raise HarnessRefusal(code, "MCP response stream ended unexpectedly")
                self.buffer.extend(block)
        finally:
            selector.close()

    def request(
        self,
        request_id: str,
        method: str,
        params: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        frame: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            frame["params"] = dict(params)
        with self.lock:
            try:
                self.stdin.write(canonical_json(frame))
                self.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                raise HarnessRefusal("server_pipe", "MCP request pipe closed") from error
            response = parse_json_rpc_line(self._read_line(self.timeout))
        if response.get("id") != request_id:
            raise HarnessRefusal("response_id", "MCP response ID changed")
        return response

    def notify(self, method: str) -> None:
        with self.lock:
            self.stdin.write(canonical_json({"jsonrpc": "2.0", "method": method}))
            self.stdin.flush()

    def handshake(self) -> None:
        response = self.request(
            "initialize",
            "initialize",
            {
                "protocolVersion": product.MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "chaos-soak", "version": "2"},
            },
        )
        if response.get("result", {}).get("protocolVersion") != product.MCP_PROTOCOL_VERSION:
            raise HarnessRefusal("handshake", "MCP protocol version changed")
        self.notify("notifications/initialized")
        listing = self.request("tools", "tools/list", {})
        tools = listing.get("result", {}).get("tools")
        names = [item.get("name") for item in tools] if isinstance(tools, list) else []
        if names != ["repo.read", "repo.search"]:
            raise HarnessRefusal("tools", "MCP tool list changed")

    def close(self) -> dict[str, Any]:
        first_error: BaseException | None = None
        if not self.stdin.closed:
            try:
                self.stdin.close()
            except OSError as error:
                first_error = first_error or error
        try:
            self.process.wait(timeout=PROCESS_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            pass
        try:
            group = terminate_owned_process_group(self.process_group)
        except BaseException as error:
            first_error = first_error or error
            group = {"existed_at_cleanup": True, "absent_after_cleanup": False}
        try:
            self.process.wait(timeout=PROCESS_STOP_SECONDS)
        except subprocess.TimeoutExpired as error:
            first_error = first_error or error
        for stream in (self.stdin, self.stdout, self.stderr):
            if not stream.closed:
                try:
                    stream.close()
                except OSError as error:
                    first_error = first_error or error
        self.stderr_thread.join(PROCESS_STOP_SECONDS)
        if self.stderr_thread.is_alive() or self.stderr_overflow:
            first_error = first_error or HarnessRefusal(
                "stderr_bound", "MCP stderr did not drain exactly within its bound"
            )
        if first_error is not None:
            if isinstance(first_error, HarnessRefusal):
                raise first_error
            raise HarnessRefusal("session_cleanup", type(first_error).__name__) from first_error
        return {
            "argv": list(self.argv),
            "return_code": self.process.returncode,
            "process_group": group,
            "stderr_bytes": len(self.stderr_capture),
            "stderr_sha256": sha256_bytes(bytes(self.stderr_capture)),
        }


def _valid_result_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == RESULT_ID_LENGTH
        and all(character in "0123456789abcdef" for character in value)
    )


def _clean_exit_code(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 0


def _event_counts(scenario: Mapping[str, Any]) -> Mapping[str, Any]:
    value = scenario.get("event_counts")
    return value if isinstance(value, dict) else {}


def derive_false_hits(report: Mapping[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """Reconcile response IDs, mutation output, and exact event windows."""

    scenarios = report.get("scenarios")
    if not isinstance(scenarios, dict):
        raise HarnessRefusal("scenario_shape", "product scenario report is missing")
    required = {
        "concurrent_join",
        "exact_repeat",
        "relevant_mutation",
        "irrelevant_mutation",
        "follower_cancellation",
        "leader_cancellation",
        "lease_owner_crash",
        "corrupted_evidence",
    }
    if set(scenarios) != required:
        raise HarnessRefusal("scenario_shape", "product scenario set changed")
    concurrent = scenarios["concurrent_join"]
    exact = scenarios["exact_repeat"]
    mutation = scenarios["relevant_mutation"]
    irrelevant = scenarios["irrelevant_mutation"]
    follower = scenarios["follower_cancellation"]
    leader = scenarios["leader_cancellation"]
    lease = scenarios["lease_owner_crash"]
    corrupt = scenarios["corrupted_evidence"]
    cases = [
        {
            "name": "concurrent_join",
            "false_hit": not (
                _valid_result_id(concurrent.get("result_id"))
                and concurrent.get("identical_responses") is True
                and _event_counts(concurrent)
                == {
                    "completed": 1,
                    "executed": 1,
                    "inflight_candidate": 1,
                    "inflight_join": 1,
                    "requested": 2,
                }
            ),
        },
        {
            "name": "exact_hit",
            "false_hit": not (
                exact.get("result_id") == concurrent.get("result_id")
                and exact.get("identical_response") is True
                and _event_counts(exact)
                == {"exact_candidate": 1, "exact_hit": 1, "requested": 1}
            ),
        },
        {
            "name": "mutation_invalidation",
            "false_hit": not (
                _valid_result_id(mutation.get("baseline_result_id"))
                and _valid_result_id(mutation.get("new_result_id"))
                and mutation.get("baseline_result_id") != mutation.get("new_result_id")
                and mutation.get("old_result_served") is False
                and mutation.get("request_binding")
                != mutation.get("baseline_window", {}).get("request_binding")
                and _event_counts(mutation)
                == {"completed": 1, "executed": 1, "requested": 1}
            ),
        },
        {
            "name": "irrelevant_exact_hit",
            "false_hit": not (
                irrelevant.get("request_binding") == mutation.get("request_binding")
                and _event_counts(irrelevant)
                == {"exact_candidate": 1, "exact_hit": 1, "requested": 1}
            ),
        },
        {
            "name": "follower_cancellation",
            "false_hit": not (
                follower.get("follower_error_code") == -32800
                and _valid_result_id(follower.get("leader_result_id"))
                and _event_counts(follower)
                == {
                    "completed": 1,
                    "executed": 1,
                    "follower_cancelled": 1,
                    "inflight_candidate": 1,
                    "requested": 2,
                }
            ),
        },
        {
            "name": "leader_cancellation",
            "false_hit": not (
                leader.get("cancel_error_code") == -32800
                and leader.get("ready_results_before_retry") == 0
                and _valid_result_id(leader.get("retry_result_id"))
                and _event_counts(leader) == {"executed": 1, "failed": 1, "requested": 1}
            ),
        },
        {
            "name": "lease_expiry_restart",
            "false_hit": not (
                lease.get("classification") == "bounded_recovery_without_stale_completion"
                and lease.get("new_lease", {}).get("status") == "completed"
                and int(lease.get("new_lease", {}).get("lifecycle_generation", -1))
                == int(lease.get("old_lease", {}).get("lifecycle_generation", -3)) + 1
                and _event_counts(lease)
                == {
                    "completed": 1,
                    "executed": 1,
                    "lease_expired": 1,
                    "requested": 1,
                }
            ),
        },
        {
            "name": "cas_corruption_quarantine",
            "false_hit": not (
                corrupt.get("served_result_id") is None
                and corrupt.get("recomputed_output_matches") is True
                and corrupt.get("quarantine_window", {}).get("reason") == "result_corrupt"
                and corrupt.get("quarantine_window", {}).get("request_authority_issued") is False
                and corrupt.get("quarantine_window", {}).get("event_counts")
                == {"binding_quarantined": 1}
            ),
        },
    ]
    return sum(bool(case["false_hit"]) for case in cases), cases


def _open_fd_snapshot(maximum: int = 4096) -> dict[int, tuple[int, int, int]]:
    result: dict[int, tuple[int, int, int]] = {}
    for descriptor in range(maximum):
        try:
            metadata = os.fstat(descriptor)
        except OSError:
            continue
        result[descriptor] = (metadata.st_dev, metadata.st_ino, metadata.st_mode)
    return result


def _source_identity(root: pathlib.Path) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/empty",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    head = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=root,
        env=environment,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    status = subprocess.run(
        ["/usr/bin/git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=root,
        env=environment,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if head.returncode != 0 or status.returncode != 0 or status.stdout:
        raise HarnessRefusal("source_dirty", "source worktree must be clean and inspectable")
    revision = head.stdout.decode("ascii", errors="strict").strip()
    if len(revision) != 40 or any(character not in "0123456789abcdef" for character in revision):
        raise HarnessRefusal("source_sha", "source Git SHA is malformed")
    return revision


@contextlib.contextmanager
def _harden_product_harness() -> Iterator[dict[str, Any]]:
    original_session = product.McpSession
    original_pin = product.pin_binary
    registry: dict[pathlib.Path, PinnedBinary] = {}
    process_groups: set[int] = set()
    revalidations = 0

    class HardenedSession(original_session):  # type: ignore[misc, valid-type]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            process_groups.add(self.process.pid)

        def kill(self) -> None:
            if _process_group_exists(self.process.pid):
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                self.process.wait(timeout=PROCESS_STOP_SECONDS)
            except subprocess.TimeoutExpired as error:
                raise HarnessRefusal("process_reap", "killed MCP leader was not reaped") from error
            terminate_owned_process_group(self.process.pid)

        def close(self) -> None:
            nonlocal revalidations
            first_error: BaseException | None = None
            try:
                super().close()
            except BaseException as error:
                first_error = error
            try:
                terminate_owned_process_group(self.process.pid)
            except BaseException as error:
                first_error = first_error or error
            binary_path = pathlib.Path(self.argv[0])
            pinned = registry.get(binary_path)
            if pinned is None:
                first_error = first_error or HarnessRefusal(
                    "binary_registry", "executed Again path was not a registered pin"
                )
            else:
                try:
                    revalidate_pinned_binary(pinned)
                    revalidations += 1
                except BaseException as error:
                    first_error = first_error or error
            if first_error is not None:
                raise first_error

    def exact_product_pin(
        requested: pathlib.Path, destination: pathlib.Path
    ) -> product.PinnedBinary:
        pinned = pin_binary_exact(requested, destination)
        registry[pinned.executable_path] = pinned
        return product.PinnedBinary(
            pinned.requested_path,
            pinned.executable_path,
            pinned.sha256,
            pinned.size,
        )

    product.McpSession = HardenedSession
    product.pin_binary = exact_product_pin
    state = {
        "process_groups": process_groups,
        "revalidations": lambda: revalidations,
    }
    try:
        yield state
    finally:
        product.McpSession = original_session
        product.pin_binary = original_pin
        cleanup_error: BaseException | None = None
        for process_group in sorted(process_groups):
            try:
                terminate_owned_process_group(process_group)
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            raise cleanup_error


def _fixture(root: pathlib.Path) -> pathlib.Path:
    repo = root / "exact-probe-repository"
    repo.mkdir(mode=0o700)
    (repo / "README.md").write_text("chaos fixture\n", encoding="utf-8")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root / "git-home"),
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    pathlib.Path(environment["HOME"]).mkdir(mode=0o700)
    commands = (
        ["/usr/bin/git", "init", "-q", "--initial-branch=main"],
        ["/usr/bin/git", "add", "README.md"],
        [
            "/usr/bin/git",
            "-c",
            "user.name=Chaos Soak",
            "-c",
            "user.email=chaos-soak.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "exact probe fixture",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=repo,
            env=environment,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
        if completed.returncode != 0:
            raise HarnessRefusal("fixture_git", "exact probe fixture Git command failed")
    return repo


def _exact_probe(
    binary: pathlib.Path,
    root: pathlib.Path,
    concurrency: int,
    operations: int,
) -> dict[str, Any]:
    repo = _fixture(root)
    state = root / "exact-probe-state"
    sessions: list[Session] = []
    cleanup: list[dict[str, Any]] = []
    result_ids: list[str] = []
    active_error: BaseException | None = None
    try:
        for index in range(concurrency):
            session = Session(binary, repo, state, f"probe-{index}")
            sessions.append(session)
            session.handshake()

        def call(index: int) -> str:
            session = sessions[index % len(sessions)]
            response = session.request(
                f"probe-{index}",
                "tools/call",
                {"name": "repo.read", "arguments": {"path": "README.md"}},
            )
            result = response.get("result")
            if not isinstance(result, dict):
                raise HarnessRefusal("exact_result", "repo.read did not return a result")
            expected = {
                "content": [{"type": "text", "text": "chaos fixture\n"}],
                "structuredContent": {"path": "README.md", "bytes": 14},
            }
            if product.result_without_reference(result) != expected:
                raise HarnessRefusal("exact_result", "repo.read result bytes changed")
            identifier = product.result_id(result)
            if not _valid_result_id(identifier):
                raise HarnessRefusal("exact_result_id", "repo.read result ID is missing")
            return str(identifier)

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            result_ids = list(executor.map(call, range(operations)))
    except BaseException as error:
        active_error = error
        raise
    finally:
        cleanup_error: BaseException | None = None
        for session in reversed(sessions):
            try:
                cleanup.append(session.close())
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if cleanup_error is not None and active_error is None:
            raise cleanup_error
    if len(set(result_ids)) != 1:
        raise HarnessRefusal("probe_result_divergence", "exact probe returned divergent result IDs")
    expected_argv = [
        str(binary),
        "mcp",
        "serve",
        "--workspace",
        str(repo),
        "--authorization-scope",
        "again-chaos-soak:exact-v2",
    ]
    if any(item["argv"] != expected_argv for item in cleanup):
        raise HarnessRefusal("probe_argv", "exact probe launched an unexpected argv")
    if any(not _clean_exit_code(item.get("return_code")) for item in cleanup):
        raise HarnessRefusal("probe_shutdown", "exact probe server did not exit cleanly")
    return {
        "operations": operations,
        "sessions": concurrency,
        "unique_result_ids": len(set(result_ids)),
        "result_id": result_ids[0],
        "result_sha256": sha256_bytes(canonical_json({"text": "chaos fixture\n"})),
        "cleanup": cleanup,
    }


def write_exclusive(path: pathlib.Path, payload: bytes) -> None:
    """Publish complete bytes atomically without replacing an existing name."""

    if len(payload) > MAX_EVIDENCE_BYTES:
        raise HarnessRefusal("evidence_oversized", "evidence exceeded its byte bound")
    if not path.is_absolute():
        raise HarnessRefusal("evidence_path", "evidence path must be absolute")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd = os.open(path.parent, parent_flags)
    pending_name = (
        f".{path.name}.{os.getpid()}."
        f"{random.SystemRandom().randrange(1 << 63):016x}.pending"
    )
    descriptor: int | None = None
    published = False
    try:
        descriptor = os.open(
            pending_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=parent_fd,
        )
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HarnessRefusal("evidence_write", "evidence write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        try:
            os.link(
                pending_name,
                path.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise HarnessRefusal("evidence_exists", "refusing to replace existing evidence") from error
        published = True
        os.fsync(parent_fd)
        os.unlink(pending_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if not published:
            try:
                os.unlink(pending_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def run(
    binary: pathlib.Path,
    *,
    mode: str = "quick",
    concurrency: int | None = None,
    duration: float = 45.0,
    seed: int = 1,
    output: pathlib.Path | None = None,
) -> dict[str, Any]:
    if mode not in {"quick", "soak"}:
        raise HarnessRefusal("mode", "mode must be quick or soak")
    if concurrency is None:
        concurrency = 2 if mode == "quick" else 4
    if concurrency not in {1, 2, 4, 8, 16, 32} or concurrency > MAX_PROCESSES:
        raise HarnessRefusal("concurrency", "concurrency must be one of 1,2,4,8,16,32")
    if not product.LEASE_TTL_SECONDS + product.RECOVERY_GRACE_SECONDS < duration <= 3600:
        raise HarnessRefusal("duration", "duration must exceed lease recovery and be at most one hour")
    operations = min(
        MAX_OPERATIONS,
        16 if mode == "quick" else max(32, int(duration * concurrency)),
    )
    source_root = pathlib.Path(__file__).resolve().parents[1]
    source_sha = _source_identity(source_root)
    baseline_fds = _open_fd_snapshot()
    started = time.monotonic_ns()
    root = pathlib.Path(tempfile.mkdtemp(prefix="again-chaos-soak-v2-")).resolve()
    root.chmod(0o700)
    process_cleanup: list[dict[str, Any]] = []
    product_temp_paths: set[pathlib.Path] = set()
    try:
        outer_pin = pin_binary_exact(binary.resolve(strict=True), root / "pinned" / "again")
        with _harden_product_harness() as hardening:
            try:
                product_report = product.run_product_e2e(
                    again_binary=outer_pin.executable_path,
                    source_root=source_root,
                    source_git_sha=source_sha,
                    timeout_seconds=duration,
                )
            except product.HarnessRefusal as error:
                raise HarnessRefusal(error.code, str(error)) from error
            for process_group in sorted(hardening["process_groups"]):
                process_cleanup.append(terminate_owned_process_group(process_group))
            revalidations = int(hardening["revalidations"]())
        post_product_pin = revalidate_pinned_binary(outer_pin)
        for argv in product_report.get("commands", []):
            if not isinstance(argv, list) or len(argv) != 7:
                raise HarnessRefusal("product_argv", "product E2E retained malformed argv")
            executable = pathlib.Path(str(argv[0]))
            workspace = pathlib.Path(str(argv[4]))
            expected = [
                str(executable),
                "mcp",
                "serve",
                "--workspace",
                str(workspace),
                "--authorization-scope",
                "again-product-e2e:shared-v1",
            ]
            if argv != expected or not executable.is_absolute() or not workspace.is_absolute():
                raise HarnessRefusal("product_argv", "product E2E launched unexpected argv")
            product_temp_paths.add(executable.parents[1])
        false_hits, false_hit_cases = derive_false_hits(product_report)
        if false_hits != int(product_report.get("false_hit_count", -1)):
            raise HarnessRefusal("false_hit_reconciliation", "independent false-hit count diverged")
        if false_hits:
            raise HarnessRefusal("false_hit", f"observed {false_hits} false-hit scenarios")
        exact_probe = _exact_probe(outer_pin.executable_path, root, concurrency, operations)
        post_probe_pin = revalidate_pinned_binary(outer_pin)
        binary_evidence = {
            "requested_path": str(outer_pin.requested_path),
            "sha256": outer_pin.sha256,
            "bytes": outer_pin.size,
            "descriptor_pinned": True,
            "post_product": post_product_pin,
            "post_probe": post_probe_pin,
            "execution_copy_revalidations": revalidations,
        }
        scenario_digest = sha256_bytes(canonical_json(product_report["scenarios"]))
    finally:
        shutil.rmtree(root)
    root_absent = not root.exists()
    product_temp_absent = all(not path.exists() for path in product_temp_paths)
    final_fds = _open_fd_snapshot()
    leaked_fds = sorted(
        descriptor
        for descriptor, identity in final_fds.items()
        if descriptor not in baseline_fds or baseline_fds[descriptor] != identity
    )
    resource_leaks: list[dict[str, Any]] = []
    if leaked_fds:
        resource_leaks.append({"kind": "file_descriptors", "count": len(leaked_fds)})
    if any(not item["absent_after_cleanup"] for item in process_cleanup):
        resource_leaks.append({"kind": "process_groups"})
    if not root_absent or not product_temp_absent:
        resource_leaks.append({"kind": "temporary_state"})
    if resource_leaks:
        raise HarnessRefusal("resource_leak", json.dumps(resource_leaks, sort_keys=True))
    elapsed = (time.monotonic_ns() - started) / 1_000_000_000
    evidence: dict[str, Any] = {
        "schema": SCHEMA,
        "classification": {"type": "pass", "code": "all_exact_scenarios_reconciled"},
        "mode": mode,
        "source_git_sha": source_sha,
        "harness_sha256": sha256_bytes(pathlib.Path(__file__).read_bytes()),
        "binary": binary_evidence,
        "seed": seed,
        "concurrency": concurrency,
        "operations": operations,
        "lease_seconds": LEASE_SECONDS,
        "elapsed_seconds": round(elapsed, 6),
        "scenario_digest_sha256": scenario_digest,
        "scenario_names": sorted(product_report["scenarios"]),
        "scenario_reconciliation": false_hit_cases,
        "false_hit_count": false_hits,
        "exact_probe": exact_probe,
        "resource_observation": {
            "baseline_open_fds": len(baseline_fds),
            "final_open_fds": len(final_fds),
            "new_or_changed_open_fds": len(leaked_fds),
            "owned_process_groups": len(process_cleanup) + int(exact_probe["sessions"]),
            "all_owned_process_groups_absent": True,
            "temporary_state_absent": root_absent and product_temp_absent,
            "resource_leaks": resource_leaks,
        },
        "network_boundary": {
            "proxy_environment_redirected": True,
            "git_protocol_allowlist": "file",
            "kernel_socket_sandbox": False,
            "network_namespace": False,
            "network_impossibility_proven": False,
        },
        "limitations": [
            "Proxy variables are not a kernel-enforced network sandbox.",
            "The hash authenticates observed executable bytes, not publisher identity or build provenance.",
            "Resource observations cover this harness process, its owned process groups, and its temporary roots.",
        ],
    }
    evidence["report_sha256"] = sha256_bytes(canonical_json(evidence))
    if output is not None:
        write_exclusive(output.resolve(strict=False), canonical_json(evidence))
    return evidence


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", type=pathlib.Path, required=True)
    parser.add_argument("--mode", choices=("quick", "soak"), default="quick")
    parser.add_argument("--concurrency", type=int)
    parser.add_argument("--duration", type=float, default=45.0)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--json-out", type=pathlib.Path)
    arguments = parser.parse_args(argv)
    try:
        evidence = run(
            arguments.again_binary,
            mode=arguments.mode,
            concurrency=arguments.concurrency,
            duration=arguments.duration,
            seed=arguments.seed,
            output=arguments.json_out,
        )
    except HarnessRefusal as error:
        parser.error(f"{error.code}: {error}")
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
