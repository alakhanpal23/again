#!/usr/bin/env python3
"""Isolated production-binary onboarding smoke test for the Again MCP gateway.

The harness runs the real ``again`` binary with a closed environment.  It
never reads or writes the user's actual Codex, Claude, Again, Git, or temporary
configuration.  MCP configuration removal is deliberately a harness cleanup
operation: the released CLI does not currently expose an MCP-config remover,
and this program removes only an exact unchanged Again-owned pair that it
created inside its private temporary directory.
"""

from __future__ import annotations

import argparse
import dataclasses
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


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=PROCESS_STOP_SECONDS)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return
    process.wait(timeout=PROCESS_STOP_SECONDS)


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
        or value.get("workspace") != str(workspace)
        or value.get("config_path") != str(config_path)
        or value.get("ownership_path") != str(expected_owner)
        or not isinstance(value.get("ownership_digest"), str)
        or not HEX_64.fullmatch(value["ownership_digest"])
        or value.get("writes_by_default") is not False
        or value.get("install_policy") != "create_absent_or_verify_exact_owned_v1"
        or not isinstance(value.get("config_document"), str)
        or len(value["config_document"].encode("utf-8")) > MAX_CONFIG_BYTES
    ):
        raise HarnessRefusal("setup_plan_invalid", "setup plan violated its closed schema")
    if client == "claude":
        document = strict_json_loads(value["config_document"].encode("utf-8"))
        server = document.get("mcpServers", {}).get("again") if isinstance(document, dict) else None
        if not isinstance(server, dict) or server.get("command") != "again" or server.get("args") != expected_args:
            raise HarnessRefusal("setup_config_invalid", "Claude config does not bind the plan")
    else:
        expected = (
            "# Created and wholly owned by Again gateway setup v2.\n"
            "[mcp_servers.again]\n"
            "command = \"again\"\n"
            f"args = [\"mcp\", \"serve\", \"--workspace\", {json.dumps(str(workspace))}]\n"
        )
        if value["config_document"] != expected:
            raise HarnessRefusal("setup_config_invalid", "Codex config does not bind the plan")
    return value


def inspect_private_regular(path: pathlib.Path, expected: bytes) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        observed = path.read_bytes()
    except OSError as error:
        raise HarnessRefusal("owned_file_missing", f"missing owned file: {path.name}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HarnessRefusal("owned_file_unsafe", f"owned path is not regular: {path.name}")
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
        or not HEX_64.fullmatch(fields.get("workspace_digest", ""))
        or fields.get("digest") != plan["ownership_digest"]
    ):
        raise HarnessRefusal("owner_record_invalid", "ownership record does not match the plan")
    return fields


def remove_exact_owned_pair(config_path: pathlib.Path, plan: Mapping[str, Any]) -> dict[str, Any]:
    """Remove only the exact temporary pair described by this setup plan."""

    owner_path = pathlib.Path(plan["ownership_path"])
    if owner_path != config_path.with_name(config_path.name + OWNER_SUFFIX):
        raise HarnessRefusal("removal_path_mismatch", "ownership path is not the expected sibling")
    config_expected = plan["config_document"].encode("utf-8")
    config_record = inspect_private_regular(config_path, config_expected)
    owner_raw = owner_path.read_bytes()
    owner_record = inspect_private_regular(owner_path, owner_raw)
    parse_owner_record(owner_raw, plan)
    config_path.unlink()
    owner_path.unlink()
    if config_path.exists() or config_path.is_symlink() or owner_path.exists() or owner_path.is_symlink():
        raise HarnessRefusal("removal_incomplete", "exact owned pair remained after cleanup")
    return {"config": config_record, "ownership": owner_record, "removed": True}


class ConfiguredMcpSession:
    """A bounded session launched from an exact installed setup plan."""

    def __init__(
        self,
        *,
        binary: pathlib.Path,
        plan: Mapping[str, Any],
        workspace: pathlib.Path,
        environment: Mapping[str, str],
        label: str,
        timeout_seconds: float,
    ) -> None:
        stdio = plan["stdio"]
        if stdio["command"] != "again" or stdio["args"] != [
            "mcp",
            "serve",
            "--workspace",
            str(workspace),
        ]:
            raise HarnessRefusal("configured_command_invalid", "installed command changed")
        resolved = pathlib.Path(environment["PATH"].split(os.pathsep, 1)[0]) / "again"
        if resolved.resolve() != binary.resolve():
            raise HarnessRefusal("configured_binary_mismatch", "installed command does not resolve to pinned binary")
        self.argv = (stdio["command"], *stdio["args"])
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
        if names != ["repo.read", "repo.search"]:
            raise HarnessRefusal("mcp_tools", f"unexpected installed tools: {names!r}")

    def tool_call(self, request_id: str, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name not in {"repo.read", "repo.search"}:
            raise HarnessRefusal("mcp_tool", "smoke harness permits only built-in read tools")
        return self.request(
            request_id,
            "tools/call",
            {"name": name, "arguments": dict(arguments)},
        )

    def close(self) -> dict[str, Any]:
        if self.process.poll() is None:
            try:
                self.stdin.close()
                self.process.wait(timeout=PROCESS_STOP_SECONDS)
            except (BrokenPipeError, OSError, subprocess.TimeoutExpired):
                _terminate_process_group(self.process)
        self.stderr_thread.join(timeout=PROCESS_STOP_SECONDS)
        if self.stderr_thread.is_alive() or self.stderr_overflow:
            raise HarnessRefusal("mcp_stderr", "MCP stderr did not drain within bounds")
        returncode = self.process.poll()
        group_reaped = True
        if os.name == "posix":
            try:
                os.killpg(self.process.pid, 0)
            except ProcessLookupError:
                group_reaped = True
            except PermissionError:
                group_reaped = False
            else:
                group_reaped = False
        for stream in (self.stdin, self.stdout, self.stderr):
            if not stream.closed:
                stream.close()
        if returncode != 0 or not group_reaped:
            raise HarnessRefusal("mcp_cleanup", "MCP process did not exit and reap cleanly")
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
    owner_raw = owner_path.read_bytes()
    owner = inspect_private_regular(owner_path, owner_raw)
    parse_owner_record(owner_raw, plan)
    before = (config_path.read_bytes(), owner_raw)
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
    if repeated_plan != plan or before != (config_path.read_bytes(), owner_path.read_bytes()):
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
    parent = root / "symlink"
    parent.mkdir(mode=0o700)
    target = parent / "user-target.toml"
    sentinel = b"user target must not change\n"
    target.write_bytes(sentinel)
    path = parent / "config.toml"
    path.symlink_to(target)
    result = setup_command(
        binary, "codex", workspace, environment, timeout_seconds, path
    )
    if result.returncode == 0 or target.read_bytes() != sentinel or not path.is_symlink():
        raise HarnessRefusal("symlink_followed", "symlinked config was not safely refused")
    return {
        "classification": "unsafe_existing_path_refused",
        "return_code": result.returncode,
        "target_preserved_sha256": sha256_bytes(sentinel),
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
        pinned = product.pin_binary(again_binary, root / "pinned" / "again")
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
            if b"ONBOARDING_SEARCH_V1" not in canonical_json_bytes(baseline_result):
                raise HarnessRefusal("search_output_mismatch", "installed search lost fixture match")

            claude = ConfiguredMcpSession(
                binary=pinned.executable_path,
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
            structured = changed_result.get("structuredContent")
            matches = structured.get("matches") if isinstance(structured, dict) else None
            if matches != [] or changed_result == baseline_result:
                raise HarnessRefusal("mutation_replayed", "relevant mutation returned stale search")
            mutation = {
                "classification": "relevant_mutation_invalidated",
                "sha256_before": sha256_bytes(before),
                "sha256_after": sha256_bytes(after),
                "baseline_result_id": product.result_id(baseline_result),
                "changed_result_id": product.result_id(changed_result),
                "old_result_served": False,
            }
        finally:
            cleanup_errors: list[HarnessRefusal] = []
            for session in reversed(sessions):
                try:
                    session_evidence.append(session.close())
                except HarnessRefusal as error:
                    cleanup_errors.append(error)
            session_evidence.reverse()
            if cleanup_errors:
                raise cleanup_errors[0]

        removal: dict[str, Any] = {
            "product_mcp_remove_command": False,
            "classification": "harness_exact_owned_pair_cleanup",
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
                "real_user_configuration_accessed": False,
            },
            "fixture": fixture,
            "setup": setup_evidence,
            "refusals": {"unowned": unowned, "symlink": symlink},
            "mcp": {
                "installed_clients": ["codex", "claude"],
                "tools": ["repo.read", "repo.search"],
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
