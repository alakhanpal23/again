#!/usr/bin/env python3
"""Isolated production-binary onboarding smoke test for the Again MCP gateway.

The harness runs the real ``again`` binary with a closed environment whose
standard Codex, Claude, Again, Git, and temporary locations are redirected into
a private temporary root. MCP configuration removal is deliberately a harness
cleanup operation: the released CLI does not currently expose an MCP-config
remover, and this program removes only an exact unchanged Again-owned pair that
it created in that non-concurrent private root.
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
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any, BinaryIO

if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bench import agent_gateway_product_e2e as product


REPORT_SCHEMA = "again.agent-gateway-onboarding-smoke.v1"
HARNESS_VERSION = "1.0.0"
MCP_PROTOCOL_VERSION = "2025-06-18"
MAX_COMMAND_BYTES = 2 * 1024 * 1024
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 64 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
PROCESS_STOP_SECONDS = 2.0
NETWORK_BLOCK_ENDPOINT = "http://127.0.0.1:9"
OWNER_SUFFIX = ".again-owner-v2"
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_BLAKE3_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)
_BLAKE3_PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
_BLAKE3_CHUNK_START = 1
_BLAKE3_CHUNK_END = 2
_BLAKE3_ROOT = 8
_BLAKE3_SINGLE_CHUNK_BYTES = 1_024


class HarnessRefusal(RuntimeError):
    """A stable non-pass classification."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessRefusal("duplicate_json_key", f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise HarnessRefusal("nonfinite_json_number", f"invalid JSON number: {value}")


def _validate_json_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise HarnessRefusal("json_node_limit", "JSON node bound exceeded")
        if depth > MAX_JSON_DEPTH:
            raise HarnessRefusal("json_depth_limit", "JSON depth bound exceeded")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise HarnessRefusal("nonfinite_json_number", "non-finite JSON number")


def strict_json_loads(raw: bytes) -> Any:
    if len(raw) > MAX_COMMAND_BYTES:
        raise HarnessRefusal("json_oversized", "JSON document exceeded its byte bound")
    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except HarnessRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessRefusal("malformed_json", "JSON document is malformed") from error
    _validate_json_bounds(value)
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return product.canonical_json_bytes(value)


def sha256_bytes(value: bytes) -> str:
    return product.sha256_bytes(value)


def sha256_file(path: pathlib.Path, maximum: int | None = None) -> str:
    return product.sha256_file(path, maximum)


def _rotate_right_32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & 0xFFFF_FFFF


def _blake3_mix(
    state: list[int], a: int, b: int, c: int, d: int, first: int, second: int
) -> None:
    state[a] = (state[a] + state[b] + first) & 0xFFFF_FFFF
    state[d] = _rotate_right_32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFF_FFFF
    state[b] = _rotate_right_32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b] + second) & 0xFFFF_FFFF
    state[d] = _rotate_right_32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFF_FFFF
    state[b] = _rotate_right_32(state[b] ^ state[c], 7)


def _blake3_compress(
    chaining_value: Sequence[int], block_words: Sequence[int], block_length: int, flags: int
) -> list[int]:
    state = [*chaining_value, *_BLAKE3_IV[:4], 0, 0, block_length, flags]
    message = list(block_words)
    for _round in range(7):
        _blake3_mix(state, 0, 4, 8, 12, message[0], message[1])
        _blake3_mix(state, 1, 5, 9, 13, message[2], message[3])
        _blake3_mix(state, 2, 6, 10, 14, message[4], message[5])
        _blake3_mix(state, 3, 7, 11, 15, message[6], message[7])
        _blake3_mix(state, 0, 5, 10, 15, message[8], message[9])
        _blake3_mix(state, 1, 6, 11, 12, message[10], message[11])
        _blake3_mix(state, 2, 7, 8, 13, message[12], message[13])
        _blake3_mix(state, 3, 4, 9, 14, message[14], message[15])
        message = [message[index] for index in _BLAKE3_PERMUTATION]
    return [
        *(state[index] ^ state[index + 8] for index in range(8)),
        *(state[index + 8] ^ chaining_value[index] for index in range(8)),
    ]


def blake3_single_chunk(value: bytes) -> str:
    """Compute unkeyed BLAKE3 for the small setup commitments used here."""

    if len(value) > _BLAKE3_SINGLE_CHUNK_BYTES:
        raise HarnessRefusal("commitment_oversized", "setup commitment exceeds one BLAKE3 chunk")
    blocks = [value[offset : offset + 64] for offset in range(0, len(value), 64)] or [b""]
    chaining_value = list(_BLAKE3_IV)
    for index, block in enumerate(blocks):
        padded = block + b"\0" * (64 - len(block))
        words = [
            int.from_bytes(padded[offset : offset + 4], "little")
            for offset in range(0, 64, 4)
        ]
        flags = _BLAKE3_CHUNK_START if index == 0 else 0
        if index == len(blocks) - 1:
            flags |= _BLAKE3_CHUNK_END | _BLAKE3_ROOT
            output = _blake3_compress(chaining_value, words, len(block), flags)
            return b"".join(word.to_bytes(4, "little") for word in output)[:32].hex()
        chaining_value = _blake3_compress(
            chaining_value, words, len(block), flags
        )[:8]
    raise AssertionError("BLAKE3 input always has a final block")


def _hash_field(value: bytes) -> bytes:
    return len(value).to_bytes(8, "little") + value


def expected_workspace_digest(workspace: pathlib.Path) -> str:
    return blake3_single_chunk(os.fsencode(workspace))


def expected_ownership_digest(
    *,
    client: str,
    config_path: pathlib.Path,
    workspace: pathlib.Path,
    config_document: str,
) -> str:
    commitment = bytearray(b"again.agent-gateway-setup.owner.v2\0")
    for field in (
        client.encode("utf-8"),
        os.fsencode(config_path),
        os.fsencode(workspace),
        config_document.encode("utf-8"),
    ):
        commitment.extend(_hash_field(field))
    return blake3_single_chunk(bytes(commitment))


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    product.write_json_exclusive(path, value)


def closed_environment(
    *,
    binary_directory: pathlib.Path,
    home: pathlib.Path,
    state: pathlib.Path,
    temporary: pathlib.Path,
) -> dict[str, str]:
    """Build the entire child environment without inheriting ambient secrets."""

    return {
        "PATH": f"{binary_directory}:/usr/bin:/bin",
        "HOME": str(home),
        "AGAIN_HOME": str(state),
        "TMPDIR": str(temporary),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
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


def _wait_for_process_group_exit(process_group: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(process_group):
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)
    return True


def _terminate_process_group(
    process: subprocess.Popen[bytes], process_group: int | None = None
) -> None:
    """Terminate the complete private process group, even if its leader exited."""

    process_group = process.pid if process_group is None else process_group
    if os.name == "posix":
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
                # Darwin can transiently retain an adopted zombie group for
                # which signal 0 succeeds while SIGKILL returns EPERM. It is
                # safe only if the group then disappears within the deadline.
                pass
        try:
            process.wait(timeout=PROCESS_STOP_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise HarnessRefusal("process_cleanup", "process leader did not terminate") from error
        if not _wait_for_process_group_exit(process_group, PROCESS_STOP_SECONDS):
            raise HarnessRefusal("process_cleanup", "process descendants remained after SIGKILL")
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=PROCESS_STOP_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=PROCESS_STOP_SECONDS)


def pin_binary_exact(requested: pathlib.Path, destination: pathlib.Path) -> product.PinnedBinary:
    """Copy and hash the executable through one no-follow source descriptor."""

    if not requested.is_absolute() or requested.resolve() != requested:
        raise HarnessRefusal("binary_not_canonical", "--again-binary must be absolute and canonical")
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
            or before.st_size > product.MAX_BINARY_BYTES
            or before.st_mode & 0o111 == 0
        ):
            raise HarnessRefusal("binary_invalid", "Again binary is not a bounded executable file")
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
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(source_fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > product.MAX_BINARY_BYTES:
                raise HarnessRefusal("binary_invalid", "Again binary exceeded its byte bound")
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_fd, view)
                view = view[written:]
        os.fsync(destination_fd)
        after = os.fstat(source_fd)
        path_after = os.stat(requested, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if before.st_size != total or identity(before) != identity(after) or identity(after) != identity(path_after):
            raise HarnessRefusal("binary_changed", "Again binary identity changed while being pinned")
        return product.PinnedBinary(requested, destination, digest.hexdigest(), total)
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        os.close(source_fd)


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> CommandResult:
    if not argv or timeout_seconds <= 0 or any(not item or "\0" in item for item in argv):
        raise HarnessRefusal("invalid_command", "bounded command arguments are invalid")
    started = time.monotonic_ns()
    try:
        process = subprocess.Popen(
            tuple(argv),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
        )
    except OSError as error:
        raise HarnessRefusal("command_launch", "could not launch Again") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process_group(process)
        raise HarnessRefusal("command_pipe", "Again CLI output pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process_group(process)
                raise HarnessRefusal("command_timeout", "Again CLI command timed out")
            events = selector.select(remaining)
            if not events:
                _terminate_process_group(process)
                raise HarnessRefusal("command_timeout", "Again CLI command timed out")
            for key, _mask in events:
                block = os.read(key.fd, 65_536)
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                target = captured[key.data]
                if len(target) + len(block) > MAX_COMMAND_BYTES:
                    _terminate_process_group(process)
                    raise HarnessRefusal(
                        "command_output_limit", "Again CLI output exceeded its bound"
                    )
                target.extend(block)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_group(process)
            raise HarnessRefusal("command_timeout", "Again CLI command timed out")
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            _terminate_process_group(process)
            raise HarnessRefusal("command_timeout", "Again CLI command timed out") from error
        if os.name == "posix" and _process_group_exists(process.pid):
            _terminate_process_group(process)
            raise HarnessRefusal(
                "command_descendant", "Again CLI left a descendant in its process group"
            )
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        returncode=int(process.returncode),
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
        elapsed_ms=(time.monotonic_ns() - started) / 1_000_000,
    )


def require_success(result: CommandResult, label: str) -> bytes:
    if result.returncode != 0:
        raise HarnessRefusal(
            "command_failed",
            f"{label} exited {result.returncode}: "
            f"{result.stderr[:500].decode('utf-8', errors='replace')}",
        )
    return result.stdout


def setup_command(
    binary: pathlib.Path,
    client: str,
    workspace: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    config_path: pathlib.Path | None = None,
) -> CommandResult:
    argv = [
        str(binary),
        "mcp",
        "setup",
        "--client",
        client,
        "--workspace",
        str(workspace),
        "--json",
    ]
    if config_path is not None:
        argv.extend(["--install-owned-config", str(config_path)])
    return run_bounded_command(
        argv,
        cwd=workspace,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )


def _shell_quote(value: str) -> str:
    safe = b"_./,:=@%+-"
    encoded = value.encode("utf-8")
    if encoded and all(byte < 128 and (chr(byte).isalnum() or byte in safe) for byte in encoded):
        return value
    return "'" + value.replace("'", "'\\''") + "'"


def _expected_local_cli(client: str, arguments: Sequence[str]) -> str:
    prefix = (
        "codex mcp add again -- again"
        if client == "codex"
        else "claude mcp add -s user again -- again"
    )
    return prefix + "".join(f" {_shell_quote(argument)}" for argument in arguments)


def _expected_config_document(client: str, arguments: Sequence[str]) -> str:
    if client == "codex":
        encoded = ", ".join(
            json.dumps(argument, ensure_ascii=False, separators=(",", ":"))
            for argument in arguments
        )
        return (
            "# Created and wholly owned by Again gateway setup v2.\n"
            "[mcp_servers.again]\n"
            "command = \"again\"\n"
            f"args = [{encoded}]\n"
        )
    return (
        json.dumps(
            {
                "mcpServers": {
                    "again": {
                        "args": list(arguments),
                        "command": "again",
                        "type": "stdio",
                    }
                }
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def validate_setup_plan(
    value: Any,
    *,
    client: str,
    workspace: pathlib.Path,
    config_path: pathlib.Path,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessRefusal("setup_plan_invalid", "setup plan is not an object")
    stdio = value.get("stdio")
    expected_args = ["mcp", "serve", "--workspace", str(workspace)]
    expected_owner = config_path.with_name(config_path.name + OWNER_SUFFIX)
    expected_document = _expected_config_document(client, expected_args)
    expected_owner_digest = expected_ownership_digest(
        client=client,
        config_path=config_path,
        workspace=workspace,
        config_document=expected_document,
    )
    if (
        set(value)
        != {
            "version",
            "client",
            "server_name",
            "stdio",
            "local_cli_command",
            "workspace",
            "config_path",
            "ownership_path",
            "ownership_digest",
            "writes_by_default",
            "install_policy",
            "config_document",
        }
        or value.get("version") != 2
        or value.get("client") != client
        or value.get("server_name") != "again"
        or not isinstance(stdio, dict)
        or set(stdio) != {"transport", "command", "args"}
        or stdio.get("transport") != "stdio"
        or stdio.get("command") != "again"
        or stdio.get("args") != expected_args
        or value.get("local_cli_command") != _expected_local_cli(client, expected_args)
        or value.get("workspace") != str(workspace)
        or value.get("config_path") != str(config_path)
        or value.get("ownership_path") != str(expected_owner)
        or value.get("ownership_digest") != expected_owner_digest
        or value.get("writes_by_default") is not False
        or value.get("install_policy") != "create_absent_or_verify_exact_owned_v1"
        or value.get("config_document") != expected_document
        or len(expected_document.encode("utf-8")) > MAX_CONFIG_BYTES
    ):
        raise HarnessRefusal("setup_plan_invalid", "setup plan violated its closed schema")
    if client == "claude":
        document = strict_json_loads(value["config_document"].encode("utf-8"))
        expected = {
            "mcpServers": {
                "again": {"args": expected_args, "command": "again", "type": "stdio"}
            }
        }
        if document != expected:
            raise HarnessRefusal("setup_config_invalid", "Claude config does not bind the plan")
    return value


def read_private_regular(path: pathlib.Path, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HarnessRefusal("owned_file_unsafe", f"owned path could not be opened safely: {path.name}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            raise HarnessRefusal("owned_file_unsafe", f"owned path is not bounded regular data: {path.name}")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(65_536, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > maximum:
                raise HarnessRefusal("owned_file_oversized", f"owned path exceeded its bound: {path.name}")
        after = os.fstat(descriptor)
        path_after = os.stat(path, follow_symlinks=False)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if identity(before) != identity(after) or identity(after) != identity(path_after):
            raise HarnessRefusal("owned_file_changed", f"owned path changed while inspected: {path.name}")
        return b"".join(chunks), after
    finally:
        os.close(descriptor)


def inspect_private_regular(path: pathlib.Path, expected: bytes) -> dict[str, Any]:
    observed, metadata = read_private_regular(path, max(len(expected), MAX_CONFIG_BYTES))
    if observed != expected:
        raise HarnessRefusal("owned_file_changed", f"owned bytes changed: {path.name}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise HarnessRefusal("owned_file_permissions", f"owned path is not mode 0600: {path.name}")
    return {
        "bytes": len(observed),
        "sha256": sha256_bytes(observed),
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
    }


def parse_owner_record(raw: bytes, plan: Mapping[str, Any]) -> dict[str, str]:
    if len(raw) > 1_024:
        raise HarnessRefusal("owner_record_oversized", "ownership record exceeded its bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise HarnessRefusal("owner_record_invalid", "ownership record is not UTF-8") from error
    lines = text.splitlines()
    if len(lines) != 5 or lines[0] != "again-agent-gateway-owner-v2":
        raise HarnessRefusal("owner_record_invalid", "ownership record framing is invalid")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if line.count("=") != 1:
            raise HarnessRefusal("owner_record_invalid", "ownership record field is malformed")
        key, value = line.split("=", 1)
        if key in fields:
            raise HarnessRefusal("owner_record_invalid", "ownership record field is duplicated")
        fields[key] = value
    if (
        fields.get("client") != plan["client"]
        or fields.get("server") != "again"
        or fields.get("workspace_digest")
        != expected_workspace_digest(pathlib.Path(str(plan["workspace"])))
        or fields.get("digest")
        != expected_ownership_digest(
            client=str(plan["client"]),
            config_path=pathlib.Path(str(plan["config_path"])),
            workspace=pathlib.Path(str(plan["workspace"])),
            config_document=str(plan["config_document"]),
        )
        or fields.get("digest") != plan["ownership_digest"]
    ):
        raise HarnessRefusal("owner_record_invalid", "ownership record does not match the plan")
    return fields


def installed_stdio_command(
    *,
    client: str,
    config_path: pathlib.Path,
    workspace: pathlib.Path,
    expected_document: str,
) -> tuple[str, list[str]]:
    """Parse the exact installed file and derive the command actually launched."""

    raw, _metadata = read_private_regular(config_path, MAX_CONFIG_BYTES)
    if raw != expected_document.encode("utf-8"):
        raise HarnessRefusal("installed_config_changed", "installed configuration bytes changed")
    expected_args = ["mcp", "serve", "--workspace", str(workspace)]
    if client == "claude":
        value = strict_json_loads(raw)
        expected = {
            "mcpServers": {
                "again": {"args": expected_args, "command": "again", "type": "stdio"}
            }
        }
        if value != expected:
            raise HarnessRefusal("installed_config_invalid", "installed Claude topology changed")
        return "again", list(value["mcpServers"]["again"]["args"])
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise HarnessRefusal("installed_config_invalid", "installed Codex config is not UTF-8") from error
    lines = text.splitlines()
    if len(lines) != 4 or lines[:3] != [
        "# Created and wholly owned by Again gateway setup v2.",
        "[mcp_servers.again]",
        'command = "again"',
    ] or not lines[3].startswith("args = "):
        raise HarnessRefusal("installed_config_invalid", "installed Codex topology changed")
    arguments = strict_json_loads(lines[3][len("args = ") :].encode("utf-8"))
    if arguments != expected_args:
        raise HarnessRefusal("installed_config_invalid", "installed Codex arguments changed")
    return "again", list(arguments)


def remove_exact_owned_pair(config_path: pathlib.Path, plan: Mapping[str, Any]) -> dict[str, Any]:
    """Remove an exact pair in the harness's private, non-concurrent root."""

    owner_path = pathlib.Path(plan["ownership_path"])
    if owner_path != config_path.with_name(config_path.name + OWNER_SUFFIX):
        raise HarnessRefusal("removal_path_mismatch", "ownership path is not the expected sibling")
    config_expected = plan["config_document"].encode("utf-8")
    config_record = inspect_private_regular(config_path, config_expected)
    owner_raw, _metadata = read_private_regular(owner_path, 1_024)
    owner_record = inspect_private_regular(owner_path, owner_raw)
    parse_owner_record(owner_raw, plan)
    config_path.unlink()
    owner_path.unlink()
    if config_path.exists() or config_path.is_symlink() or owner_path.exists() or owner_path.is_symlink():
        raise HarnessRefusal("removal_incomplete", "exact owned pair remained after cleanup")
    return {"config": config_record, "ownership": owner_record, "removed": True}


class ConfiguredMcpSession:
    """A bounded session launched from an exact installed configuration file."""

    def __init__(
        self,
        *,
        binary: pathlib.Path,
        client: str,
        config_path: pathlib.Path,
        plan: Mapping[str, Any],
        workspace: pathlib.Path,
        environment: Mapping[str, str],
        label: str,
        timeout_seconds: float,
    ) -> None:
        command, arguments = installed_stdio_command(
            client=client,
            config_path=config_path,
            workspace=workspace,
            expected_document=str(plan["config_document"]),
        )
        stdio = plan["stdio"]
        if command != "again" or arguments != [
            "mcp",
            "serve",
            "--workspace",
            str(workspace),
        ] or stdio != {"transport": "stdio", "command": command, "args": arguments}:
            raise HarnessRefusal("configured_command_invalid", "installed command changed")
        resolved = pathlib.Path(environment["PATH"].split(os.pathsep, 1)[0]) / "again"
        if resolved.resolve() != binary.resolve():
            raise HarnessRefusal("configured_binary_mismatch", "installed command does not resolve to pinned binary")
        self.argv = (command, *arguments)
        self.label = label
        self.timeout_seconds = timeout_seconds
        try:
            self.process = subprocess.Popen(
                self.argv,
                cwd=workspace,
                env=dict(environment),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                shell=False,
                start_new_session=os.name == "posix",
            )
        except OSError as error:
            raise HarnessRefusal("mcp_launch_failed", "installed MCP command did not launch") from error
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            _terminate_process_group(self.process)
            raise HarnessRefusal("mcp_pipe_failed", "MCP pipes were not created")
        self.process_group = self.process.pid
        self.stdin: BinaryIO = self.process.stdin
        self.stdout: BinaryIO = self.process.stdout
        self.stderr: BinaryIO = self.process.stderr
        self.stdout_buffer = bytearray()
        self.stderr_bytes = bytearray()
        self.stderr_overflow = False
        self.request_hashes: list[str] = []
        self.response_hashes: list[str] = []
        self.stderr_thread = threading.Thread(target=self._drain_stderr, daemon=True)
        self.stderr_thread.start()

    def _drain_stderr(self) -> None:
        while True:
            try:
                block = os.read(self.stderr.fileno(), 65_536)
            except OSError:
                return
            if not block:
                return
            room = MAX_STDERR_BYTES - len(self.stderr_bytes)
            if room > 0:
                self.stderr_bytes.extend(block[:room])
            if len(block) > room:
                self.stderr_overflow = True

    def _read_line(self) -> bytes:
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            newline = self.stdout_buffer.find(b"\n")
            if newline >= 0:
                frame = bytes(self.stdout_buffer[: newline + 1])
                del self.stdout_buffer[: newline + 1]
                return frame
            if len(self.stdout_buffer) > MAX_FRAME_BYTES:
                raise HarnessRefusal("mcp_response_oversized", "MCP response exceeded its bound")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessRefusal("mcp_response_timeout", "MCP response timed out")
            readable, _, _ = select.select([self.stdout.fileno()], [], [], remaining)
            if not readable:
                raise HarnessRefusal("mcp_response_timeout", "MCP response timed out")
            block = os.read(
                self.stdout.fileno(),
                min(65_536, MAX_FRAME_BYTES + 1 - len(self.stdout_buffer)),
            )
            if not block:
                raise HarnessRefusal("mcp_server_eof", "MCP server closed its response stream")
            self.stdout_buffer.extend(block)

    def _send(self, value: Mapping[str, Any]) -> None:
        encoded = canonical_json_bytes(value)
        self.request_hashes.append(sha256_bytes(encoded))
        try:
            self.stdin.write(encoded)
            self.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise HarnessRefusal("mcp_server_pipe", "MCP server closed its request stream") from error

    def request(self, request_id: str, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": dict(params),
            }
        )
        response = product.parse_json_rpc_line(self._read_line())
        if response.get("id") != request_id:
            raise HarnessRefusal("mcp_response_id", "MCP response ID changed")
        self.response_hashes.append(sha256_bytes(canonical_json_bytes(response)))
        return response

    def handshake(self) -> None:
        initialized = self.request(
            f"{self.label}:initialize",
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": self.label, "version": HARNESS_VERSION},
            },
        )
        if initialized.get("result", {}).get("protocolVersion") != MCP_PROTOCOL_VERSION:
            raise HarnessRefusal("mcp_handshake", "MCP protocol version changed")
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        listing = self.request(f"{self.label}:tools", "tools/list", {})
        tools = listing.get("result", {}).get("tools")
        names = [item.get("name") for item in tools] if isinstance(tools, list) else []
        if names != list(product.EXPECTED_ADVERTISED_TOOLS):
            raise HarnessRefusal("mcp_tools", f"unexpected installed tools: {names!r}")

    def tool_call(self, request_id: str, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name not in product.E2E_EXERCISED_TOOLS:
            raise HarnessRefusal("mcp_tool", "smoke harness permits only built-in read tools")
        return self.request(
            request_id,
            "tools/call",
            {"name": name, "arguments": dict(arguments)},
        )

    def close(self) -> dict[str, Any]:
        cleanup_failure: HarnessRefusal | None = None
        if self.process.poll() is None:
            try:
                self.stdin.close()
                self.process.wait(timeout=PROCESS_STOP_SECONDS)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired) as error:
                cleanup_failure = HarnessRefusal(
                    "mcp_cleanup", "MCP leader did not stop after request-stream closure"
                )
                try:
                    _terminate_process_group(self.process, self.process_group)
                except HarnessRefusal as terminate_error:
                    cleanup_failure = cleanup_failure or terminate_error
        descendants_observed = os.name == "posix" and _process_group_exists(self.process_group)
        if descendants_observed:
            try:
                _terminate_process_group(self.process, self.process_group)
            except HarnessRefusal as error:
                cleanup_failure = cleanup_failure or error
            cleanup_failure = cleanup_failure or HarnessRefusal(
                "mcp_cleanup", "MCP leader left a live process-group descendant"
            )
        for stream in (self.stdin, self.stdout, self.stderr):
            if not stream.closed:
                try:
                    stream.close()
                except OSError as error:
                    cleanup_failure = cleanup_failure or HarnessRefusal(
                        "mcp_cleanup", f"MCP stream close failed: {type(error).__name__}"
                    )
        self.stderr_thread.join(timeout=PROCESS_STOP_SECONDS)
        if self.stderr_thread.is_alive() or self.stderr_overflow:
            cleanup_failure = cleanup_failure or HarnessRefusal(
                "mcp_stderr", "MCP stderr did not drain within bounds"
            )
        returncode = self.process.poll()
        group_reaped = not _process_group_exists(self.process_group)
        if returncode != 0 or not group_reaped:
            cleanup_failure = cleanup_failure or HarnessRefusal(
                "mcp_cleanup", "MCP process did not exit and reap cleanly"
            )
        if cleanup_failure is not None:
            raise cleanup_failure
        return {
            "argv": list(self.argv),
            "return_code": returncode,
            "process_group_reaped": group_reaped,
            "request_sha256": list(self.request_hashes),
            "response_sha256": list(self.response_hashes),
            "stderr": {
                "bytes": len(self.stderr_bytes),
                "sha256": sha256_bytes(bytes(self.stderr_bytes)),
                "truncated": False,
            },
        }


def create_fixture(workspace: pathlib.Path, git_home: pathlib.Path) -> dict[str, Any]:
    workspace.mkdir(mode=0o700, parents=True, exist_ok=False)
    scope = workspace / "scope"
    scope.mkdir(mode=0o700)
    files = {
        "README.md": b"# Again onboarding smoke fixture\n",
        "scope/read.txt": b"ONBOARDING_READ_V1\nexact installed config\n",
        "scope/search.txt": b"ONBOARDING_SEARCH_V1\nmutation target\n",
    }
    for relative, content in files.items():
        path = workspace / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(content)
    environment = product._clean_git_environment(git_home)
    commands = (
        ["git", "init", "--quiet", "--initial-branch=main"],
        ["git", "add", "--all"],
        [
            "git",
            "-c",
            "user.name=Again Onboarding Smoke",
            "-c",
            "user.email=again-onboarding.invalid",
            "commit",
            "--quiet",
            "-m",
            "bounded onboarding fixture",
        ],
    )
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0:
            raise HarnessRefusal("fixture_git", "could not create local fixture repository")
    revision = product._run_local_git(
        workspace, ["rev-parse", "HEAD"], home=git_home
    ).decode("ascii").strip()
    entries = [
        {
            "path": relative,
            "bytes": len(content),
            "sha256": sha256_bytes(content),
        }
        for relative, content in sorted(files.items())
    ]
    manifest = {"git_sha": revision, "files": entries, "file_count": len(entries)}
    manifest["manifest_sha256"] = sha256_bytes(canonical_json_bytes(manifest))
    return manifest


def _expected_default_config(home: pathlib.Path, client: str) -> pathlib.Path:
    return home / (".codex/config.toml" if client == "codex" else ".claude.json")


def _install_and_verify(
    *,
    binary: pathlib.Path,
    client: str,
    workspace: pathlib.Path,
    home: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    config_path = _expected_default_config(home, client)
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    install = setup_command(
        binary,
        client,
        workspace,
        environment,
        timeout_seconds,
        config_path,
    )
    plan = validate_setup_plan(
        strict_json_loads(require_success(install, f"{client} install")),
        client=client,
        workspace=workspace,
        config_path=config_path,
    )
    config = inspect_private_regular(config_path, plan["config_document"].encode("utf-8"))
    owner_path = pathlib.Path(plan["ownership_path"])
    owner_raw, _metadata = read_private_regular(owner_path, 1_024)
    owner = inspect_private_regular(owner_path, owner_raw)
    parse_owner_record(owner_raw, plan)
    before = (
        read_private_regular(config_path, MAX_CONFIG_BYTES)[0],
        owner_raw,
    )
    reinstall = setup_command(
        binary,
        client,
        workspace,
        environment,
        timeout_seconds,
        config_path,
    )
    repeated_plan = validate_setup_plan(
        strict_json_loads(require_success(reinstall, f"{client} reinstall")),
        client=client,
        workspace=workspace,
        config_path=config_path,
    )
    if repeated_plan != plan or before != (
        read_private_regular(config_path, MAX_CONFIG_BYTES)[0],
        read_private_regular(owner_path, 1_024)[0],
    ):
        raise HarnessRefusal("setup_not_idempotent", f"{client} reinstall changed owned state")
    if b"already_installed_owned" not in reinstall.stderr:
        raise HarnessRefusal("setup_outcome", f"{client} reinstall outcome was not explicit")
    return plan, {
        "install_elapsed_ms": install.elapsed_ms,
        "reinstall_elapsed_ms": reinstall.elapsed_ms,
        "config": config,
        "ownership": owner,
        "idempotent": True,
    }


def _test_unowned_refusal(
    *,
    binary: pathlib.Path,
    workspace: pathlib.Path,
    root: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    parent = root / "unowned"
    parent.mkdir(mode=0o700)
    path = parent / "config.toml"
    sentinel = b"[mcp_servers.user]\ncommand = \"user-owned\"\n"
    path.write_bytes(sentinel)
    result = setup_command(
        binary, "codex", workspace, environment, timeout_seconds, path
    )
    if result.returncode == 0 or path.read_bytes() != sentinel:
        raise HarnessRefusal("unowned_overwritten", "unowned config was not preserved")
    owner = path.with_name(path.name + OWNER_SUFFIX)
    if owner.exists() or owner.is_symlink():
        raise HarnessRefusal("unowned_owner_created", "unowned refusal created ownership state")
    return {
        "classification": "unowned_configuration_refused",
        "return_code": result.returncode,
        "preserved_sha256": sha256_bytes(sentinel),
    }


def _test_symlink_refusal(
    *,
    binary: pathlib.Path,
    workspace: pathlib.Path,
    root: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    if os.name != "posix":
        return {"classification": "unsupported_host", "reason": "symlink_requires_posix"}
    scenarios: dict[str, Any] = {}

    config_parent = root / "symlink-config"
    config_parent.mkdir(mode=0o700)
    config_target = config_parent / "user-target.toml"
    config_sentinel = b"user config target must not change\n"
    config_target.write_bytes(config_sentinel)
    config_path = config_parent / "config.toml"
    config_path.symlink_to(config_target)
    config_result = setup_command(
        binary, "codex", workspace, environment, timeout_seconds, config_path
    )
    config_owner = config_path.with_name(config_path.name + OWNER_SUFFIX)
    if (
        config_result.returncode == 0
        or config_target.read_bytes() != config_sentinel
        or not config_path.is_symlink()
        or config_owner.exists()
        or config_owner.is_symlink()
    ):
        raise HarnessRefusal("symlink_followed", "symlinked config was not safely refused")
    scenarios["config_file"] = {
        "return_code": config_result.returncode,
        "target_preserved_sha256": sha256_bytes(config_sentinel),
        "counterpart_absent": True,
    }

    owner_parent = root / "symlink-owner"
    owner_parent.mkdir(mode=0o700)
    owner_path_config = owner_parent / "config.toml"
    owner_path = owner_path_config.with_name(owner_path_config.name + OWNER_SUFFIX)
    owner_target = owner_parent / "user-owner-target"
    owner_sentinel = b"user owner target must not change\n"
    owner_target.write_bytes(owner_sentinel)
    owner_path.symlink_to(owner_target)
    owner_result = setup_command(
        binary, "codex", workspace, environment, timeout_seconds, owner_path_config
    )
    if (
        owner_result.returncode == 0
        or owner_target.read_bytes() != owner_sentinel
        or not owner_path.is_symlink()
        or owner_path_config.exists()
        or owner_path_config.is_symlink()
    ):
        raise HarnessRefusal("symlink_followed", "symlinked ownership was not safely refused")
    scenarios["ownership_file"] = {
        "return_code": owner_result.returncode,
        "target_preserved_sha256": sha256_bytes(owner_sentinel),
        "counterpart_absent": True,
    }

    parent_target = root / "symlink-parent-target"
    parent_target.mkdir(mode=0o700)
    parent_link = root / "symlink-parent-link"
    parent_link.symlink_to(parent_target, target_is_directory=True)
    parent_config = parent_link / "config.toml"
    parent_result = setup_command(
        binary, "codex", workspace, environment, timeout_seconds, parent_config
    )
    parent_owner = parent_target / (parent_config.name + OWNER_SUFFIX)
    if (
        parent_result.returncode == 0
        or not parent_link.is_symlink()
        or (parent_target / "config.toml").exists()
        or parent_owner.exists()
        or parent_owner.is_symlink()
    ):
        raise HarnessRefusal("symlink_followed", "symlinked config parent was not safely refused")
    scenarios["config_parent"] = {
        "return_code": parent_result.returncode,
        "target_directory_unchanged": True,
    }
    return {
        "classification": "all_symlink_surfaces_refused",
        "scenarios": scenarios,
    }


def require_exact_search_result(
    result: Mapping[str, Any], *, expected_matches: Sequence[Mapping[str, Any]], expected_text: str
) -> str:
    expected_structured = {
        "schemaVersion": 1,
        "pattern": "ONBOARDING_SEARCH_V1",
        "path": "scope",
        "matches": [dict(item) for item in expected_matches],
        "truncated": False,
    }
    if result.get("structuredContent") != expected_structured or result.get("content") != [
        {"type": "text", "text": expected_text}
    ]:
        raise HarnessRefusal("search_output_mismatch", "repo.search returned unexpected exact bytes")
    result_identifier = product.result_id(result)
    if result_identifier is None or not HEX_64.fullmatch(result_identifier):
        raise HarnessRefusal("search_result_identity", "repo.search omitted its exact result identity")
    return result_identifier


def revalidate_pinned_binary(pinned: product.PinnedBinary) -> dict[str, Any]:
    metadata = os.stat(pinned.executable_path, follow_symlinks=False)
    digest = sha256_file(pinned.executable_path, product.MAX_BINARY_BYTES)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != pinned.size
        or digest != pinned.sha256
        or metadata.st_mode & 0o111 == 0
    ):
        raise HarnessRefusal("pinned_binary_changed", "pinned executable changed during smoke run")
    return {
        "sha256": digest,
        "bytes": metadata.st_size,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "stable_after_run": True,
    }


def run_onboarding_smoke(
    *,
    again_binary: pathlib.Path,
    source_root: pathlib.Path,
    source_git_sha: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    if timeout_seconds <= 0 or timeout_seconds > 120:
        raise HarnessRefusal("timeout_invalid", "timeout must be in (0, 120] seconds")
    harness_path = pathlib.Path(__file__).resolve()
    with tempfile.TemporaryDirectory(prefix="again-gateway-onboarding-") as temporary_name:
        root = pathlib.Path(temporary_name).resolve()
        root.chmod(0o700)
        source_home = root / "source-home"
        source_home.mkdir(mode=0o700)
        source = product.inspect_clean_source(source_root, source_git_sha, source_home)
        pinned = pin_binary_exact(again_binary, root / "pinned" / "again")
        workspace = root / "fixture-repository"
        fixture = create_fixture(workspace, source_home)
        home = root / "isolated-home"
        state = root / "isolated-again-home"
        temporary = root / "isolated-tmp"
        for directory in (home, state, temporary):
            directory.mkdir(mode=0o700)
        environment = closed_environment(
            binary_directory=pinned.executable_path.parent,
            home=home,
            state=state,
            temporary=temporary,
        )

        setup_evidence: dict[str, Any] = {}
        plans: dict[str, dict[str, Any]] = {}
        for client in ("codex", "claude"):
            default_path = _expected_default_config(home, client)
            first = setup_command(
                pinned.executable_path,
                client,
                workspace,
                environment,
                timeout_seconds,
            )
            second = setup_command(
                pinned.executable_path,
                client,
                workspace,
                environment,
                timeout_seconds,
            )
            if first.returncode != 0 or second.returncode != 0 or first.stdout != second.stdout:
                raise HarnessRefusal("dry_run_nondeterministic", f"{client} dry run changed")
            dry_plan = validate_setup_plan(
                strict_json_loads(first.stdout),
                client=client,
                workspace=workspace,
                config_path=default_path,
            )
            owner_path = default_path.with_name(default_path.name + OWNER_SUFFIX)
            if default_path.exists() or default_path.is_symlink() or owner_path.exists() or owner_path.is_symlink():
                raise HarnessRefusal("dry_run_wrote", f"{client} dry run changed configuration")
            plan, install_evidence = _install_and_verify(
                binary=pinned.executable_path,
                client=client,
                workspace=workspace,
                home=home,
                environment=environment,
                timeout_seconds=timeout_seconds,
            )
            if plan != dry_plan:
                raise HarnessRefusal("dry_install_plan_mismatch", f"{client} plan changed on install")
            plans[client] = plan
            setup_evidence[client] = {
                "dry_run_deterministic": True,
                "workspace": str(workspace),
                "workspace_bound_args": plan["stdio"]["args"],
                "config_path": str(default_path),
                **install_evidence,
            }

        unowned = _test_unowned_refusal(
            binary=pinned.executable_path,
            workspace=workspace,
            root=root,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )
        symlink = _test_symlink_refusal(
            binary=pinned.executable_path,
            workspace=workspace,
            root=root,
            environment=environment,
            timeout_seconds=timeout_seconds,
        )

        sessions: list[ConfiguredMcpSession] = []
        session_evidence: list[dict[str, Any]] = []
        try:
            codex = ConfiguredMcpSession(
                binary=pinned.executable_path,
                client="codex",
                config_path=pathlib.Path(plans["codex"]["config_path"]),
                plan=plans["codex"],
                workspace=workspace,
                environment=environment,
                label="onboarding-codex",
                timeout_seconds=timeout_seconds,
            )
            sessions.append(codex)
            codex.handshake()
            read_response = codex.tool_call(
                "codex-read", "repo.read", {"path": "scope/read.txt"}
            )
            read_result = product.require_success(read_response, "installed Codex repo.read")
            if b"ONBOARDING_READ_V1" not in canonical_json_bytes(read_result):
                raise HarnessRefusal("read_output_mismatch", "installed repo.read lost fixture bytes")
            baseline_response = codex.tool_call(
                "codex-search",
                "repo.search",
                {"pattern": "ONBOARDING_SEARCH_V1", "path": "scope", "maxResults": 50},
            )
            baseline_result = product.require_success(
                baseline_response, "installed Codex repo.search"
            )
            baseline_result_id = require_exact_search_result(
                baseline_result,
                expected_matches=[
                    {
                        "path": "scope/search.txt",
                        "line": 1,
                        "text": "ONBOARDING_SEARCH_V1",
                        "lineTruncated": False,
                    }
                ],
                expected_text="scope/search.txt:1:ONBOARDING_SEARCH_V1",
            )

            claude = ConfiguredMcpSession(
                binary=pinned.executable_path,
                client="claude",
                config_path=pathlib.Path(plans["claude"]["config_path"]),
                plan=plans["claude"],
                workspace=workspace,
                environment=environment,
                label="onboarding-claude",
                timeout_seconds=timeout_seconds,
            )
            sessions.append(claude)
            claude.handshake()
            claude_read_response = claude.tool_call(
                "claude-read", "repo.read", {"path": "scope/read.txt"}
            )
            claude_read = product.require_success(
                claude_read_response, "installed Claude repo.read"
            )
            if claude_read != read_result:
                raise HarnessRefusal("client_output_mismatch", "Codex and Claude config paths differ")

            mutation_path = workspace / "scope/search.txt"
            before = mutation_path.read_bytes()
            mutation_path.write_bytes(before.replace(b"ONBOARDING_SEARCH_V1", b"ONBOARDING_SEARCH_V2"))
            after = mutation_path.read_bytes()
            if before == after:
                raise HarnessRefusal("mutation_failed", "fixture mutation did not change bytes")
            changed_response = claude.tool_call(
                "claude-search-after-mutation",
                "repo.search",
                {"pattern": "ONBOARDING_SEARCH_V1", "path": "scope", "maxResults": 50},
            )
            changed_result = product.require_success(
                changed_response, "installed Claude mutated repo.search"
            )
            changed_result_id = require_exact_search_result(
                changed_result, expected_matches=[], expected_text=""
            )
            if changed_result_id == baseline_result_id or changed_result == baseline_result:
                raise HarnessRefusal("mutation_replayed", "relevant mutation returned stale search")
            mutation = {
                "classification": "relevant_mutation_invalidated",
                "sha256_before": sha256_bytes(before),
                "sha256_after": sha256_bytes(after),
                "baseline_result_id": baseline_result_id,
                "changed_result_id": changed_result_id,
                "old_result_served": False,
            }
        finally:
            active_error = sys.exc_info()[1]
            cleanup_errors: list[BaseException] = []
            for session in reversed(sessions):
                try:
                    session_evidence.append(session.close())
                except BaseException as error:
                    cleanup_errors.append(error)
            session_evidence.reverse()
            if cleanup_errors and active_error is None:
                raise cleanup_errors[0]

        removal: dict[str, Any] = {
            "product_mcp_remove_command": False,
            "classification": "harness_private_nonconcurrent_exact_owned_pair_cleanup",
            "concurrent_path_adversary_proven": False,
            "clients": {},
        }
        for client, plan in plans.items():
            config_path = pathlib.Path(plan["config_path"])
            original = config_path.read_bytes()
            config_path.write_bytes(original + b"# user modification\n")
            refused = False
            try:
                remove_exact_owned_pair(config_path, plan)
            except HarnessRefusal as error:
                refused = error.code == "owned_file_changed"
            if not refused or not config_path.exists():
                raise HarnessRefusal("changed_removal_allowed", "modified config cleanup did not refuse")
            config_path.write_bytes(original)
            if os.name == "posix":
                config_path.chmod(0o600)
            removal["clients"][client] = {
                "modified_pair_refused": True,
                **remove_exact_owned_pair(config_path, plan),
            }

        report: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "harness_version": HARNESS_VERSION,
            "classification": {"type": "pass", "code": "all_scenarios_passed"},
            "source": source,
            "binary": {
                "requested_path": str(pinned.requested_path),
                "sha256": pinned.sha256,
                "bytes": pinned.size,
                "descriptor_pinned": True,
                "post_run": revalidate_pinned_binary(pinned),
            },
            "harness": {
                "path": str(harness_path),
                "sha256": sha256_file(harness_path),
            },
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "environment": {
                "inherited_parent_names": [],
                "child_names": sorted(environment),
                "credential_names_present": sorted(
                    name
                    for name in environment
                    if any(token in name.casefold() for token in ("token", "secret", "password", "credential", "api_key"))
                ),
                "network_proxies": NETWORK_BLOCK_ENDPOINT,
                "standard_user_config_roots_redirected": True,
                "ambient_parent_environment_inherited": False,
                "filesystem_access_denial_proven": False,
                "repository_local_git_configuration_may_be_read": True,
            },
            "fixture": fixture,
            "setup": setup_evidence,
            "refusals": {"unowned": unowned, "symlink": symlink},
            "mcp": {
                "installed_clients": ["codex", "claude"],
                "tools": list(product.EXPECTED_ADVERTISED_TOOLS),
                "sessions": session_evidence,
                "mutation": mutation,
            },
            "removal": removal,
        }
        if report["environment"]["credential_names_present"]:
            raise HarnessRefusal("credential_environment", "closed environment retained credential names")
        report["report_sha256"] = sha256_bytes(canonical_json_bytes(report))
        return report


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", type=pathlib.Path, required=True)
    parser.add_argument(
        "--source-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parent.parent,
    )
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=15.0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    output = arguments.output
    if not output.is_absolute():
        raise SystemExit("--output must be absolute")
    if output.exists() or output.is_symlink():
        raise SystemExit(f"refusing to overwrite existing evidence: {output}")
    try:
        report = run_onboarding_smoke(
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
