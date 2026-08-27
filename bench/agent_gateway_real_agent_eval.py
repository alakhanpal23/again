#!/usr/bin/env python3
"""Retained paired evaluation for real Codex/Claude sessions and Again MCP.

Dry-run mode inspects local binaries, validates command templates, creates an
isolated fixture repository, and verifies ``again mcp setup --json`` plans. It
does not start an agent. Live mode is additionally gated by ``--allow-network``
and explicit run/time ceilings because it can make paid model calls.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA = "again.agent-gateway-real-agent-eval.v1"
HARNESS_VERSION = "1.0.0"
MAX_AGENT_RUNS = 64
MAX_TIMEOUT_SECONDS = 900.0
MAX_TEMPLATE_ARGUMENTS = 96
MAX_TEMPLATE_TOKEN_BYTES = 8 * 1024
MAX_COMMAND_STDOUT_BYTES = 32 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 4 * 1024 * 1024
MAX_HELP_BYTES = 2 * 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
SUPPORTED_PLACEHOLDERS = {
    "{prompt}",
    "{workspace}",
    "{model}",
    "{config_root}",
    "{mcp_config}",
}
SENSITIVE_ENVIRONMENT_NAMES = {
    "HOME",
    "PATH",
    "CODEX_HOME",
    "CLAUDE_CONFIG_DIR",
    "AGAIN_HOME",
    "TMPDIR",
}
STATS_FIELDS = (
    "requested",
    "executed",
    "exact_hits",
    "inflight_joins",
    "duplicate_bytes_omitted",
    "estimated_tokens_avoided",
    "estimated_execution_ms_saved",
)
CLAUDE_ALLOWED_TOOLS = "Read,Glob,Grep,mcp__again__repo.read,mcp__again__repo.search"
CLAUDE_DISALLOWED_TOOLS = "Edit,Write,Bash,NotebookEdit,WebFetch,WebSearch"


@dataclasses.dataclass(frozen=True)
class TaskSpec:
    task_id: str
    prompt: str
    expected: Mapping[str, Any]
    response_marker: str
    concurrency: int


TASKS = (
    TaskSpec(
        task_id="concurrent_checksum_v1",
        concurrency=2,
        response_marker="CONCURRENT-CHECKSUM-91E2",
        expected={"task_id": "concurrent_checksum_v1", "answer": "91E2-A77C"},
        prompt=(
            "Perform a read-only repository analysis. Never create, edit, rename, or delete "
            "files. Prefer the MCP server named Again when it is available; otherwise use only "
            "the client's built-in read-only repository tools. Read facts/concurrent.txt twice "
            "with identical arguments, then search for CONCURRENT-CHECKSUM-91E2 twice with "
            "identical arguments. What checksum follows that marker? Return only this JSON shape "
            "with the discovered value and no markdown: "
            '{"task_id":"concurrent_checksum_v1","answer":"<value>"}'
        ),
    ),
    TaskSpec(
        task_id="later_checksum_v1",
        concurrency=1,
        response_marker="CONCURRENT-CHECKSUM-91E2",
        expected={"task_id": "later_checksum_v1", "answer": "91E2-A77C"},
        prompt=(
            "Perform a read-only repository analysis. Never create, edit, rename, or delete "
            "files. Prefer the MCP server named Again when it is available; otherwise use only "
            "the client's built-in read-only repository tools. Read facts/concurrent.txt twice "
            "with identical arguments, then search for CONCURRENT-CHECKSUM-91E2 twice with "
            "identical arguments. What checksum follows that marker? Return only this JSON shape "
            "with the discovered value and no markdown: "
            '{"task_id":"later_checksum_v1","answer":"<value>"}'
        ),
    ),
    TaskSpec(
        task_id="marker_locations_v1",
        concurrency=1,
        response_marker="REPEAT_MARKER_7D91",
        expected={
            "task_id": "marker_locations_v1",
            "answer": ["facts/primary.txt", "facts/secondary.txt"],
        },
        prompt=(
            "Perform a read-only repository analysis. Never create, edit, rename, or delete "
            "files. Prefer the MCP server named Again when it is available; otherwise use only "
            "the client's built-in read-only repository tools. Read facts/primary.txt twice with "
            "identical arguments, then search the repository for REPEAT_MARKER_7D91 twice with "
            "identical arguments. Return the sorted paths containing that marker. Return only "
            "this JSON shape with no markdown: "
            '{"task_id":"marker_locations_v1","answer":["<path>","<path>"]}'
        ),
    ),
)

FIXTURE_FILES = {
    "README.md": (
        "# Retained real-agent gateway fixture\n\n"
        "This repository contains deterministic read-only evaluation inputs.\n"
    ),
    "facts/concurrent.txt": (
        "Retained concurrent evaluation record.\n"
        "CONCURRENT-CHECKSUM-91E2: 91E2-A77C\n"
        "The checksum is immutable evaluation data.\n"
    ),
    "facts/primary.txt": (
        "Primary retained evaluation record.\n"
        "REPEAT_MARKER_7D91 appears in this file.\n"
        "Project codename: CERULEAN-ORBIT\n"
    ),
    "facts/secondary.txt": (
        "Secondary retained evaluation record.\n"
        "REPEAT_MARKER_7D91 appears in this file.\n"
        "Deployment region: moon-base-east\n"
    ),
}


class HarnessRefusal(RuntimeError):
    """Typed fail-closed harness outcome."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class CommandTemplate:
    client: str
    arguments: tuple[str, ...]

    @property
    def executable(self) -> pathlib.Path:
        return pathlib.Path(self.arguments[0])

    def render(self, replacements: Mapping[str, str]) -> tuple[str, ...]:
        rendered: list[str] = []
        for token in self.arguments:
            if token in SUPPORTED_PLACEHOLDERS:
                value = replacements.get(token)
                if value is None:
                    raise HarnessRefusal(
                        "template_placeholder", f"no value was supplied for {token}"
                    )
                rendered.append(value)
            else:
                rendered.append(token)
        return tuple(rendered)

    def identity(self) -> str:
        return hashlib.sha256(canonical_json_bytes(list(self.arguments))).hexdigest()


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float
    timed_out: bool
    output_limited: bool


@dataclasses.dataclass(frozen=True)
class ClientInspection:
    client: str
    version: str
    version_tuple: tuple[int, int, int]
    executable_sha256: str


@dataclasses.dataclass(frozen=True)
class RuntimePin:
    version: str
    sha256: str


@dataclasses.dataclass(frozen=True)
class AgentOutputAnalysis:
    malformed: bool
    malformed_reason: str | None
    final_text: str | None
    oracle_passed: bool
    tool_call_count: int
    again_tool_calls_requested: int
    again_discovered: bool
    again_tool_response_bytes: int
    again_tool_results_observed: int
    again_tool_result_mismatches: int
    client_reported_tokens: Mapping[str, int]
    client_reported_model: str | None
    client_reported_error: bool


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def strict_json_loads(value: bytes | str) -> Any:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise HarnessRefusal("duplicate_json_key", "JSON contains a duplicate key")
            result[key] = item
        return result

    def reject_non_finite(constant: str) -> Any:
        raise HarnessRefusal("malformed_json", f"JSON used non-finite value {constant}")

    try:
        text = value.decode("utf-8") if isinstance(value, bytes) else value
        return json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_constant=reject_non_finite,
        )
    except HarnessRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise HarnessRefusal("malformed_json", "input is not bounded UTF-8 JSON") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def file_sha256(path: pathlib.Path, maximum: int = MAX_BINARY_BYTES) -> str:
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise HarnessRefusal("file_bound", f"{path} is not a bounded regular file")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        if _stat_identity(before) != _stat_identity(opened):
            raise HarnessRefusal("file_race", f"{path} changed while opening")
        while True:
            block = source.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise HarnessRefusal("file_bound", f"{path} exceeded its read bound")
            digest.update(block)
        after_handle = os.fstat(source.fileno())
    after_path = path.stat()
    if (
        _stat_identity(before) != _stat_identity(after_handle)
        or _stat_identity(before) != _stat_identity(after_path)
        or total != before.st_size
    ):
        raise HarnessRefusal("file_race", f"{path} changed while hashing")
    return digest.hexdigest()


def validate_again_binary(path: pathlib.Path) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise HarnessRefusal("again_binary", "Again binary is unreadable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HarnessRefusal("again_binary", "Again binary must be a non-symlink regular file")
    resolved = path.resolve(strict=True)
    if not os.access(resolved, os.X_OK):
        raise HarnessRefusal("again_binary", "Again binary is not executable")
    return resolved


def _terminate_process(process: subprocess.Popen[bytes], timeout: float = 1.0) -> None:
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
        process.wait(timeout=timeout)
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
    process.wait(timeout=timeout)


def run_bounded_command(
    argv: Sequence[str],
    *,
    cwd: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    stdout_limit: int = MAX_COMMAND_STDOUT_BYTES,
    stderr_limit: int = MAX_COMMAND_STDERR_BYTES,
) -> CommandResult:
    if (
        not argv
        or timeout_seconds <= 0
        or stdout_limit <= 0
        or stderr_limit <= 0
        or any("\0" in item for item in argv)
    ):
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
        raise HarnessRefusal("command_launch", "could not launch the explicit command") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise HarnessRefusal("command_pipe", "bounded command pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_limited = False
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(remaining)
            if not events:
                timed_out = True
                break
            for key, _mask in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = captured[key.data]
                room = limits[key.data] - len(target)
                if room < len(chunk):
                    target.extend(chunk[: max(0, room)])
                    output_limited = True
                    break
                target.extend(chunk)
            if output_limited:
                break
        if timed_out or output_limited:
            _terminate_process(process)
        else:
            remaining = max(0.001, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process(process)
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return CommandResult(
        returncode=int(process.returncode),
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
        elapsed_ms=(time.monotonic_ns() - started) / 1_000_000,
        timed_out=timed_out,
        output_limited=output_limited,
    )


def require_checked_command(result: CommandResult, label: str) -> bytes:
    if result.timed_out:
        raise HarnessRefusal("command_timeout", f"{label} timed out")
    if result.output_limited:
        raise HarnessRefusal("command_output_limit", f"{label} exceeded its output bound")
    if result.returncode != 0:
        raise HarnessRefusal("command_failed", f"{label} exited nonzero")
    return result.stdout


def _has_pair(arguments: Sequence[str], flag: str, value: str) -> bool:
    return any(
        arguments[index] == flag and arguments[index + 1] == value
        for index in range(len(arguments) - 1)
    )


def _require_template_pair(arguments: Sequence[str], flag: str, value: str) -> None:
    if not _has_pair(arguments, flag, value):
        raise HarnessRefusal(
            "template_safety", f"command template must contain exact pair {flag} {value}"
        )


def parse_command_template(client: str, encoded: str) -> CommandTemplate:
    if client not in {"codex", "claude"}:
        raise HarnessRefusal("client", "unsupported client name")
    value = strict_json_loads(encoded)
    if (
        not isinstance(value, list)
        or not value
        or len(value) > MAX_TEMPLATE_ARGUMENTS
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise HarnessRefusal(
            "template_shape", "command template must be a bounded non-empty JSON string array"
        )
    arguments = tuple(value)
    for token in arguments:
        if len(token.encode("utf-8")) > MAX_TEMPLATE_TOKEN_BYTES or "\0" in token:
            raise HarnessRefusal("template_bound", "command template token exceeds its bound")
        if "$" in token or "`" in token or "\n" in token or "\r" in token:
            raise HarnessRefusal(
                "template_interpolation", "shell interpolation is forbidden in command templates"
            )
        if ("{" in token or "}" in token) and token not in SUPPORTED_PLACEHOLDERS:
            raise HarnessRefusal(
                "template_placeholder", "placeholders must occupy a complete argument"
            )
        lowered = token.casefold()
        if any(word in lowered for word in ("api-key", "apikey", "authorization:", "bearer ")):
            raise HarnessRefusal(
                "template_credential", "credentials may be supplied only through an environment variable"
            )
    executable = pathlib.Path(arguments[0])
    if not executable.is_absolute():
        raise HarnessRefusal("template_executable", "client executable must be an absolute path")
    try:
        resolved = executable.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise HarnessRefusal("template_executable", "client executable is unreadable") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise HarnessRefusal("template_executable", "client executable is not executable")
    if resolved.name in {"sh", "bash", "zsh", "env", "python", "python3"}:
        raise HarnessRefusal("template_shell", "shells and generic interpreters are forbidden")
    required_placeholders = {"{prompt}", "{workspace}", "{model}"}
    if client == "claude":
        required_placeholders.add("{mcp_config}")
    for placeholder in required_placeholders:
        if arguments.count(placeholder) != 1:
            raise HarnessRefusal(
                "template_placeholder", f"template requires exactly one {placeholder}"
            )
    if arguments.count("{prompt}") != 1 or arguments[-1] != "{prompt}":
        raise HarnessRefusal("template_prompt", "prompt placeholder must be the final argument")
    _require_template_pair(arguments, "--model", "{model}")
    if client == "codex":
        for token in (
            "exec",
            "--json",
            "--ephemeral",
        ):
            if token not in arguments:
                raise HarnessRefusal("template_safety", f"Codex template requires {token}")
        _require_template_pair(arguments, "--color", "never")
        _require_template_pair(arguments, "--sandbox", "read-only")
        _require_template_pair(arguments, "--ask-for-approval", "never")
        if not (
            _has_pair(arguments, "-C", "{workspace}")
            or _has_pair(arguments, "--cd", "{workspace}")
        ):
            raise HarnessRefusal("template_safety", "Codex template must bind -C to workspace")
        if any("mcp_servers" in token.casefold() or token.casefold() == "again" for token in arguments[1:]):
            raise HarnessRefusal(
                "template_contamination", "Codex template must not embed an MCP server"
            )
        allowed_tokens = {
            "exec",
            "--json",
            "--ephemeral",
            "--color",
            "never",
            "--sandbox",
            "read-only",
            "--ask-for-approval",
            "-C",
            "--cd",
            "--model",
            "--ignore-rules",
            "--strict-config",
            "--skip-git-repo-check",
            "{workspace}",
            "{model}",
            "{config_root}",
            "{prompt}",
        }
    else:
        for token in (
            "--print",
            "--bare",
            "--strict-mcp-config",
            "--no-session-persistence",
            "--no-chrome",
            "--verbose",
        ):
            if token not in arguments:
                raise HarnessRefusal("template_safety", f"Claude template requires {token}")
        _require_template_pair(arguments, "--output-format", "stream-json")
        _require_template_pair(arguments, "--permission-mode", "plan")
        _require_template_pair(arguments, "--mcp-config", "{mcp_config}")
        _require_template_pair(arguments, "--add-dir", "{workspace}")
        _require_template_pair(arguments, "--allowedTools", CLAUDE_ALLOWED_TOOLS)
        _require_template_pair(arguments, "--disallowedTools", CLAUDE_DISALLOWED_TOOLS)
        allowed_tokens = {
            "--print",
            "--output-format",
            "stream-json",
            "--bare",
            "--strict-mcp-config",
            "--mcp-config",
            "--no-session-persistence",
            "--no-chrome",
            "--permission-mode",
            "plan",
            "--add-dir",
            "--allowedTools",
            CLAUDE_ALLOWED_TOOLS,
            "--disallowedTools",
            CLAUDE_DISALLOWED_TOOLS,
            "--model",
            "--verbose",
            "--disable-slash-commands",
            "--exclude-dynamic-system-prompt-sections",
            "{workspace}",
            "{model}",
            "{config_root}",
            "{mcp_config}",
            "{prompt}",
        }
    forbidden = {
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-skip-permissions",
        "--allow-dangerously-skip-permissions",
        "--search",
        "--chrome",
        "--file",
        "--plugin-url",
        "--worktree",
        "--remote-control",
        "--resume",
        "--continue",
        "--settings",
        "--setting-sources",
    }
    if any(token in forbidden for token in arguments):
        raise HarnessRefusal("template_safety", "command template contains a forbidden option")
    if any(token not in allowed_tokens for token in arguments[1:]):
        raise HarnessRefusal(
            "template_token",
            "command template contains a literal outside the audited token set",
        )
    return CommandTemplate(client=client, arguments=arguments)


def validate_identifier(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}", value):
        raise HarnessRefusal("identifier", f"{label} must be a bounded non-secret identifier")
    lowered = value.casefold()
    if any(word in lowered for word in ("token", "secret", "password", "bearer", "sk-")):
        raise HarnessRefusal("identifier", f"{label} resembles secret material")
    return value


def validate_credential_environment_name(value: str) -> str:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", value):
        raise HarnessRefusal("credential_env", "credential environment name is invalid")
    if value in SENSITIVE_ENVIRONMENT_NAMES:
        raise HarnessRefusal("credential_env", "credential environment name is reserved")
    return value


def validate_client_capabilities(
    client: str,
    version_output: str,
    help_output: str,
    exec_help_output: str = "",
) -> tuple[str, tuple[int, int, int]]:
    if client == "codex":
        match = re.search(r"codex-cli\s+(\d+)\.(\d+)\.(\d+)", version_output)
        required = (
            "Codex CLI",
            "--version",
            "Run Codex non-interactively",
            "--ephemeral",
            "--json",
            "--sandbox",
        )
        combined = f"{help_output}\n{exec_help_output}"
        minimum = (0, 150, 0)
        maximum = (1, 0, 0)
    elif client == "claude":
        match = re.search(r"(\d+)\.(\d+)\.(\d+)\s+\(Claude Code\)", version_output)
        required = (
            "Claude Code",
            "--bare",
            "--strict-mcp-config",
            "--no-session-persistence",
            "stream-json",
            "--permission-mode",
            "--allowedTools",
            "--disallowedTools",
        )
        combined = help_output
        minimum = (2, 1, 0)
        maximum = (3, 0, 0)
    else:
        raise HarnessRefusal("client", "unsupported client name")
    if match is None or any(marker not in combined for marker in required):
        raise HarnessRefusal("client_capability", f"{client} help/version is unsupported")
    version = tuple(int(item) for item in match.groups())
    if version < minimum or version >= maximum:
        raise HarnessRefusal("client_version", f"{client} version is outside the audited range")
    return match.group(0), version


def inspect_client(
    template: CommandTemplate,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> ClientInspection:
    executable = template.executable
    version = run_bounded_command(
        (str(executable), "--version"),
        cwd=executable.parent,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=MAX_HELP_BYTES,
        stderr_limit=MAX_HELP_BYTES,
    )
    help_result = run_bounded_command(
        (str(executable), "--help"),
        cwd=executable.parent,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=MAX_HELP_BYTES,
        stderr_limit=MAX_HELP_BYTES,
    )
    version_text = require_checked_command(version, f"{template.client} --version").decode(
        "utf-8", errors="strict"
    )
    help_text = require_checked_command(help_result, f"{template.client} --help").decode(
        "utf-8", errors="strict"
    )
    exec_help_text = ""
    if template.client == "codex":
        exec_help = run_bounded_command(
            (str(executable), "exec", "--help"),
            cwd=executable.parent,
            environment=environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=MAX_HELP_BYTES,
            stderr_limit=MAX_HELP_BYTES,
        )
        exec_help_text = require_checked_command(exec_help, "codex exec --help").decode(
            "utf-8", errors="strict"
        )
    version_label, version_tuple = validate_client_capabilities(
        template.client, version_text, help_text, exec_help_text
    )
    return ClientInspection(
        client=template.client,
        version=version_label,
        version_tuple=version_tuple,
        executable_sha256=file_sha256(executable.resolve(strict=True)),
    )


def inspect_again(
    binary: pathlib.Path, environment: Mapping[str, str], cwd: pathlib.Path, timeout: float
) -> dict[str, Any]:
    commands = {
        "version": (str(binary), "--version"),
        "setup_help": (str(binary), "mcp", "setup", "--help"),
        "serve_help": (str(binary), "mcp", "serve", "--help"),
        "stats_help": (str(binary), "stats", "--help"),
    }
    outputs: dict[str, str] = {}
    for name, command in commands.items():
        result = run_bounded_command(
            command,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout,
            stdout_limit=MAX_HELP_BYTES,
            stderr_limit=MAX_HELP_BYTES,
        )
        outputs[name] = require_checked_command(result, f"Again {name}").decode("utf-8")
    match = re.search(r"again\s+(\d+)\.(\d+)\.(\d+)", outputs["version"])
    required = {
        "setup_help": ("--client", "--workspace", "--json", "--install-owned-config"),
        "serve_help": ("mcp serve", "--workspace"),
        "stats_help": ("--json",),
    }
    if match is None or any(
        marker not in outputs[name] for name, markers in required.items() for marker in markers
    ):
        raise HarnessRefusal("again_capability", "Again help/version is unsupported")
    version = tuple(int(item) for item in match.groups())
    if version < (0, 1, 0) or version >= (1, 0, 0):
        raise HarnessRefusal("again_version", "Again version is outside the audited range")
    return {
        "path": str(binary),
        "version": match.group(0),
        "version_tuple": list(version),
        "binary_sha256": file_sha256(binary),
    }


def base_environment(home: pathlib.Path, path_directories: Sequence[pathlib.Path]) -> dict[str, str]:
    home.mkdir(mode=0o700, parents=True, exist_ok=False)
    unique_paths: list[str] = []
    for directory in path_directories:
        rendered = str(directory)
        if rendered not in unique_paths:
            unique_paths.append(rendered)
    return {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": os.pathsep.join(unique_paths),
        "TMPDIR": str(home.parent),
        "XDG_CACHE_HOME": str(home / "cache"),
        "XDG_CONFIG_HOME": str(home / "config"),
    }


def _write_new(path: pathlib.Path, value: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise HarnessRefusal("fixture_write", "private file write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_fixture_repository(
    root: pathlib.Path, environment: Mapping[str, str], timeout_seconds: float
) -> dict[str, Any]:
    root.mkdir(mode=0o700)
    manifest: dict[str, str] = {}
    for relative, contents in sorted(FIXTURE_FILES.items()):
        path = root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        encoded = contents.encode("utf-8")
        _write_new(path, encoded)
        manifest[relative] = sha256_bytes(encoded)
    git_environment = dict(environment)
    git_environment.update(
        {
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "TZ": "UTC",
        }
    )
    git_commands = (
        ("/usr/bin/git", "init", "-q"),
        ("/usr/bin/git", "add", "--all"),
        (
            "/usr/bin/git",
            "-c",
            "user.name=Again Real Agent Eval",
            "-c",
            "user.email=real-agent-eval@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-q",
            "-m",
            "retained evaluation fixture",
        ),
    )
    for command in git_commands:
        result = run_bounded_command(
            command,
            cwd=root,
            environment=git_environment,
            timeout_seconds=timeout_seconds,
            stdout_limit=MAX_HELP_BYTES,
            stderr_limit=MAX_HELP_BYTES,
        )
        require_checked_command(result, "fixture Git initialization")
    revision_result = run_bounded_command(
        ("/usr/bin/git", "rev-parse", "HEAD"),
        cwd=root,
        environment=git_environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=1024,
        stderr_limit=1024,
    )
    revision = require_checked_command(revision_result, "fixture Git revision").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise HarnessRefusal("fixture_git", "fixture Git revision is malformed")
    fixture_digest = hashlib.sha256(
        b"again.real-agent-fixture.v1\0" + canonical_json_bytes(manifest)
    ).hexdigest()
    return {
        "git_sha": revision,
        "file_sha256": manifest,
        "fixture_digest_sha256": fixture_digest,
    }


def snapshot_repository_contents(root: pathlib.Path) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    entries = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            continue
        entries += 1
        if entries > 128:
            raise HarnessRefusal("repository_bound", "fixture repository has too many files")
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise HarnessRefusal("repository_unsafe", "fixture contains a symlink or special file")
        if metadata.st_size > 1024 * 1024:
            raise HarnessRefusal("repository_bound", "fixture file exceeds its verification bound")
        rendered = relative.as_posix()
        snapshot[rendered] = {
            "bytes": metadata.st_size,
            "mode": stat.S_IMODE(metadata.st_mode),
            "sha256": file_sha256(path, 1024 * 1024),
        }
    return snapshot


def repository_diff(
    expected_hashes: Mapping[str, str], current: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    expected_names = set(expected_hashes)
    current_names = set(current)
    added = sorted(current_names - expected_names)
    removed = sorted(expected_names - current_names)
    changed = sorted(
        name
        for name in expected_names & current_names
        if current[name].get("sha256") != expected_hashes[name]
    )
    mode_changed = sorted(
        name
        for name in expected_names & current_names
        if current[name].get("mode") != 0o600
    )
    return {
        "clean": not (added or removed or changed or mode_changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "mode_changed": mode_changed,
        "snapshot_sha256": sha256_bytes(canonical_json_bytes(dict(current))),
    }


def validate_setup_plan(
    value: Any, client: str, config_path: pathlib.Path, workspace: pathlib.Path
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HarnessRefusal("setup_plan", "Again setup output is not an object")
    stdio = value.get("stdio")
    expected_args = ["mcp", "serve", "--workspace", str(workspace)]
    if (
        value.get("version") != 2
        or value.get("client") != client
        or value.get("server_name") != "again"
        or not isinstance(stdio, dict)
        or stdio.get("transport") != "stdio"
        or stdio.get("command") != "again"
        or stdio.get("args") != expected_args
        or value.get("workspace") != str(workspace)
        or value.get("config_path") != str(config_path)
        or value.get("writes_by_default") is not False
        or value.get("install_policy") != "create_absent_or_verify_exact_owned_v1"
    ):
        raise HarnessRefusal("setup_plan", "Again setup plan is not the expected workspace binding")
    try:
        metadata = config_path.lstat()
    except OSError as error:
        raise HarnessRefusal("setup_config", "Again setup did not create isolated config") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HarnessRefusal("setup_config", "Again setup config is not a regular file")
    if metadata.st_size > 64 * 1024:
        raise HarnessRefusal("setup_config", "Again setup config exceeds its bound")
    return {
        "version": 2,
        "client": client,
        "server_name": "again",
        "transport": "stdio",
        "workspace_bound_args": expected_args,
        "writes_by_default": False,
        "install_policy": value["install_policy"],
    }


def install_isolated_setup(
    binary: pathlib.Path,
    client: str,
    config_path: pathlib.Path,
    workspace: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    config_path.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    result = run_bounded_command(
        (
            str(binary),
            "mcp",
            "setup",
            "--client",
            client,
            "--workspace",
            str(workspace),
            "--json",
            "--install-owned-config",
            str(config_path),
        ),
        cwd=workspace,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=MAX_HELP_BYTES,
        stderr_limit=MAX_HELP_BYTES,
    )
    output = require_checked_command(result, f"Again {client} MCP setup")
    return validate_setup_plan(strict_json_loads(output), client, config_path, workspace)


def normalize_stats(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        raise HarnessRefusal("stats", "Again stats output is not an object")
    result: dict[str, int] = {}
    for name in STATS_FIELDS:
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise HarnessRefusal("stats", f"Again stats field {name} is invalid")
        result[name] = item
    return result


def stats_delta(before: Mapping[str, int], after: Mapping[str, int]) -> dict[str, int]:
    if before.keys() != after.keys():
        raise HarnessRefusal("stats", "Again stats snapshots have different fields")
    result: dict[str, int] = {}
    for name in before:
        difference = after[name] - before[name]
        if difference < 0:
            raise HarnessRefusal("stats_rollback", f"Again stats field {name} moved backwards")
        result[name] = difference
    return result


def read_again_stats(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> dict[str, int]:
    result = run_bounded_command(
        (str(binary), "stats", "--json"),
        cwd=workspace,
        environment=environment,
        timeout_seconds=timeout_seconds,
        stdout_limit=MAX_HELP_BYTES,
        stderr_limit=MAX_HELP_BYTES,
    )
    return normalize_stats(strict_json_loads(require_checked_command(result, "Again stats")))


def redact_sensitive_bytes(value: bytes, credentials: Sequence[bytes]) -> bytes:
    redacted = value
    for credential in credentials:
        if credential:
            redacted = redacted.replace(credential, b"<redacted-credential>")
    patterns = (
        rb"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s\"',}]+",
        rb"(?i)((?:api[_-]?key|access[_-]?token|secret|password)\s*[\"']?\s*[:=]\s*[\"']?)[^\s\"',}]+",
        rb"(?i)\bsk-[A-Za-z0-9_-]{10,}\b",
    )
    for pattern in patterns:
        redacted = re.sub(pattern, lambda match: match.group(1) + b"<redacted>" if match.lastindex else b"<redacted>", redacted)
    return redacted


def _walk_json(value: Any) -> Sequence[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            result.append(item)
            stack.extend(reversed(list(item.values())))
        elif isinstance(item, list):
            stack.extend(reversed(item))
    return result


def _node_identifier(node: Mapping[str, Any]) -> str | None:
    for key in ("id", "call_id", "tool_use_id"):
        value = node.get(key)
        if isinstance(value, (str, int)) and not isinstance(value, bool):
            return str(value)
    return None


def _tool_label(node: Mapping[str, Any]) -> str:
    parts = []
    for key in ("server", "server_name", "name", "tool", "tool_name"):
        value = node.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts)


def _usage_from_events(events: Sequence[Any]) -> dict[str, int]:
    selected: Mapping[str, Any] | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type", ""))
        usage = event.get("usage")
        if isinstance(usage, dict) and event_type in {"result", "turn.completed", "turn_completed"}:
            selected = usage
    if selected is None:
        return {}
    result: dict[str, int] = {}
    for name, value in selected.items():
        if (
            isinstance(name, str)
            and "token" in name.casefold()
            and isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        ):
            result[name] = value
    return dict(sorted(result.items()))


def analyze_agent_output(client: str, stdout: bytes, task: TaskSpec) -> AgentOutputAnalysis:
    events: list[Any] = []
    malformed_reason: str | None = None
    for line in stdout.splitlines():
        if not line.strip():
            continue
        if len(line) > 4 * 1024 * 1024:
            malformed_reason = "agent JSONL line exceeded its bound"
            break
        try:
            event = strict_json_loads(line)
        except HarnessRefusal:
            malformed_reason = "agent emitted malformed JSONL"
            break
        if not isinstance(event, dict):
            malformed_reason = "agent JSONL event was not an object"
            break
        events.append(event)
    if not events and malformed_reason is None:
        malformed_reason = "agent emitted no JSONL events"

    calls: dict[str, dict[str, Any]] = {}
    anonymous_calls: set[str] = set()
    tool_results: dict[str, Any] = {}
    final_text: str | None = None
    discovered = False
    reported_model: str | None = None
    reported_error = False
    call_types = {"mcp_tool_call", "tool_use", "tool_call", "function_call", "command_execution"}
    for event in events:
        event_type = str(event.get("type", "")).casefold()
        if event_type == "result":
            if isinstance(event.get("result"), str):
                final_text = event["result"]
            if event.get("is_error") is True or event.get("subtype") in {"error", "failure"}:
                reported_error = True
        for node in _walk_json(event):
            node_type = str(node.get("type", "")).casefold()
            if node_type in {"agent_message", "final", "final_message"}:
                for key in ("text", "content", "message"):
                    if isinstance(node.get(key), str):
                        final_text = node[key]
            if node_type == "tool_result":
                identifier = _node_identifier(node)
                if identifier is not None:
                    tool_results[identifier] = node.get("content", node.get("result"))
            if node_type in call_types:
                label = _tool_label(node)
                identifier = _node_identifier(node)
                signature = sha256_bytes(
                    canonical_json_bytes(
                        {
                            "type": node_type,
                            "label": label,
                            "arguments": node.get("arguments", node.get("input")),
                        }
                    )
                )
                key = identifier or signature
                if identifier is None:
                    anonymous_calls.add(signature)
                entry = calls.setdefault(
                    key,
                    {"again": "again" in label.casefold(), "label": label, "result": None},
                )
                entry["again"] = bool(entry["again"] or "again" in label.casefold())
                for result_key in ("result", "output"):
                    if result_key in node and node[result_key] is not None:
                        entry["result"] = node[result_key]
            for key in ("mcp_servers", "mcpServers"):
                servers = node.get(key)
                if isinstance(servers, dict) and any(str(name).casefold() == "again" for name in servers):
                    discovered = True
                if isinstance(servers, list) and any(
                    isinstance(server, dict)
                    and str(server.get("name", server.get("server", ""))).casefold() == "again"
                    for server in servers
                ):
                    discovered = True
            model = node.get("model")
            if isinstance(model, str) and len(model) <= 256:
                reported_model = model
    del anonymous_calls
    for identifier, result in tool_results.items():
        if identifier in calls:
            calls[identifier]["result"] = result
    again_calls = [entry for entry in calls.values() if entry["again"]]
    if again_calls:
        discovered = True
    response_bytes = 0
    results_observed = 0
    result_mismatches = 0
    for entry in again_calls:
        result = entry.get("result")
        if result is None:
            continue
        results_observed += 1
        encoded = canonical_json_bytes(result)
        response_bytes += len(encoded)
        if task.response_marker.encode("ascii") not in encoded:
            result_mismatches += 1

    oracle_passed = False
    if final_text is not None:
        try:
            final_value = strict_json_loads(final_text.strip())
            oracle_passed = final_value == dict(task.expected)
        except HarnessRefusal:
            malformed_reason = malformed_reason or "final response was not exact JSON"
    else:
        malformed_reason = malformed_reason or "agent output contained no final response"
    return AgentOutputAnalysis(
        malformed=malformed_reason is not None,
        malformed_reason=malformed_reason,
        final_text=final_text,
        oracle_passed=oracle_passed,
        tool_call_count=len(calls),
        again_tool_calls_requested=len(again_calls),
        again_discovered=discovered,
        again_tool_response_bytes=response_bytes,
        again_tool_results_observed=results_observed,
        again_tool_result_mismatches=result_mismatches,
        client_reported_tokens=_usage_from_events(events),
        client_reported_model=reported_model,
        client_reported_error=reported_error,
    )


def _looks_like_environment_refusal(text: bytes) -> bool:
    lowered = text.decode("utf-8", errors="replace").casefold()
    markers = (
        "authentication",
        "unauthorized",
        "invalid api key",
        "network",
        "connection refused",
        "connection reset",
        "rate limit",
        "quota",
        "model not found",
        "permission denied",
        "refused",
    )
    return any(marker in lowered for marker in markers)


def build_agent_run_record(
    client: str,
    condition: str,
    replica: int,
    result: CommandResult,
    redacted_stdout: bytes,
    redacted_stderr: bytes,
    analysis: AgentOutputAnalysis,
) -> dict[str, Any]:
    environment_refusal = bool(
        analysis.client_reported_error
        or ((result.returncode != 0 or result.timed_out) and _looks_like_environment_refusal(redacted_stdout + redacted_stderr))
    )
    if result.timed_out:
        classification = "timeout"
    elif result.output_limited:
        classification = "malformed_agent_output"
    elif environment_refusal:
        classification = "environment_network_or_model_refusal"
    elif result.returncode != 0:
        classification = "client_nonzero_exit"
    elif analysis.malformed:
        classification = "malformed_agent_output"
    elif not analysis.oracle_passed:
        classification = "task_failed"
    elif condition == "again_enabled" and analysis.again_tool_calls_requested == 0:
        classification = "agent_did_not_use_again"
    else:
        classification = "task_succeeded"
    final_bytes = len(analysis.final_text.encode("utf-8")) if analysis.final_text is not None else 0
    return {
        "client": client,
        "condition": condition,
        "replica": replica,
        "classification": classification,
        "task_outcome": "pass" if analysis.oracle_passed else "fail",
        "wall_time_ms": round(result.elapsed_ms, 3),
        "process": {
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "output_limited": result.output_limited,
            "stdout_bytes": len(result.stdout),
            "stderr_bytes": len(result.stderr),
            "redacted_stdout_sha256": sha256_bytes(redacted_stdout),
            "redacted_stderr_sha256": sha256_bytes(redacted_stderr),
        },
        "metrics": {
            "tool_call_count": analysis.tool_call_count,
            "again_tool_calls_requested": analysis.again_tool_calls_requested,
            "again_tool_response_bytes": analysis.again_tool_response_bytes,
            "final_response_bytes": final_bytes,
        },
        "observations": {
            "again_discovered": analysis.again_discovered,
            "again_called": analysis.again_tool_calls_requested > 0,
            "again_tool_results_observed": analysis.again_tool_results_observed,
            "again_tool_result_mismatches": analysis.again_tool_result_mismatches,
            "environment_network_or_model_refusal": environment_refusal,
            "malformed_agent_output": analysis.malformed or result.output_limited,
        },
        "client_reported_tokens": {
            "source": "direct_client_output",
            "counts": dict(analysis.client_reported_tokens),
        },
        "client_reported_model": analysis.client_reported_model,
    }


def classify_paired_run(
    baseline_runs: Sequence[Mapping[str, Any]],
    enabled_runs: Sequence[Mapping[str, Any]],
    gateway_delta: Mapping[str, int],
) -> dict[str, Any]:
    baseline_again_calls = sum(
        int(run["metrics"]["again_tool_calls_requested"]) for run in baseline_runs
    )
    if baseline_again_calls != 0:
        raise HarnessRefusal("baseline_contaminated", "baseline agent observed an Again tool call")
    enabled_again_calls = sum(
        int(run["metrics"]["again_tool_calls_requested"]) for run in enabled_runs
    )
    task_failed = any(run["task_outcome"] != "pass" for run in enabled_runs)
    environment_refusal = any(
        bool(run["observations"]["environment_network_or_model_refusal"])
        for run in (*baseline_runs, *enabled_runs)
    )
    mismatches = sum(
        int(run["observations"]["again_tool_result_mismatches"]) for run in enabled_runs
    )
    observed_results = sum(
        int(run["observations"]["again_tool_results_observed"]) for run in enabled_runs
    )
    reuse_events = gateway_delta["exact_hits"] + gateway_delta["inflight_joins"]
    reuse_only_cohort = bool(
        gateway_delta["requested"] > 0
        and gateway_delta["executed"] == 0
        and gateway_delta["requested"] == reuse_events
    )
    false_hits = min(reuse_events, mismatches) if reuse_only_cohort else 0
    if enabled_again_calls == gateway_delta["requested"]:
        reconciliation = "exact"
    elif enabled_again_calls == 0 and gateway_delta["requested"] > 0:
        reconciliation = "gateway_only_client_events_unobservable"
    else:
        reconciliation = "mismatch"
    if environment_refusal:
        classification = "environment_network_or_model_refusal"
    elif task_failed:
        classification = "task_failed"
    elif enabled_again_calls == 0 and gateway_delta["requested"] == 0:
        classification = "agent_did_not_use_again"
    elif enabled_again_calls > 0 and gateway_delta["requested"] == 0:
        classification = "again_call_not_observed_by_gateway"
    elif enabled_again_calls > 0 and gateway_delta["requested"] > 0:
        classification = "end_to_end_again_observed"
    else:
        classification = "gateway_use_observed_only_in_stats"
    return {
        "classification": classification,
        "same_task_model_settings": True,
        "agent_did_not_use_tool": enabled_again_calls == 0 and gateway_delta["requested"] == 0,
        "gateway_provider_executed": gateway_delta["executed"] > 0,
        "gateway_joined_inflight": gateway_delta["inflight_joins"] > 0,
        "gateway_reused_exact": gateway_delta["exact_hits"] > 0,
        "task_failed": task_failed,
        "environment_network_or_model_refusal": environment_refusal,
        "again_tool_calls_requested": enabled_again_calls,
        "gateway_requested": gateway_delta["requested"],
        "provider_calls_executed": gateway_delta["executed"],
        "joined_calls": gateway_delta["inflight_joins"],
        "exact_reuse_hits": gateway_delta["exact_hits"],
        "false_hit_count": false_hits,
        "false_hit_definition": (
            "confirmed only in reuse-only cohorts when an observed response misses the task's "
            "exact fixture marker"
        ),
        "false_hit_observability": (
            "partial_response_capture"
            if observed_results < enabled_again_calls
            else "complete_reuse_only_cohort"
            if reuse_only_cohort
            else "ambiguous_mixed_dispositions"
        ),
        "tool_call_reconciliation": reconciliation,
    }


def _ensure_again_unavailable(path_directories: Sequence[pathlib.Path]) -> None:
    for directory in path_directories:
        candidate = directory / "again"
        if candidate.exists() or candidate.is_symlink():
            raise HarnessRefusal(
                "baseline_contaminated", f"baseline PATH unexpectedly contains {candidate}"
            )


def make_agent_environment(
    *,
    client: str,
    home: pathlib.Path,
    config_root: pathlib.Path,
    again_home: pathlib.Path,
    path_directories: Sequence[pathlib.Path],
    credential_name: str,
    credential_value: str,
) -> dict[str, str]:
    environment = base_environment(home, path_directories)
    config_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    again_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    environment.update(
        {
            "AGAIN_HOME": str(again_home),
            "CODEX_HOME": str(config_root),
            "CLAUDE_CONFIG_DIR": str(config_root),
            credential_name: credential_value,
        }
    )
    return environment


def execute_agent_run(
    *,
    client: str,
    condition: str,
    replica: int,
    template: CommandTemplate,
    model: str,
    task: TaskSpec,
    workspace: pathlib.Path,
    config_root: pathlib.Path,
    mcp_config: pathlib.Path,
    again_home: pathlib.Path,
    path_directories: Sequence[pathlib.Path],
    credential_name: str,
    credential_value: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    environment = make_agent_environment(
        client=client,
        home=config_root.parent / "home",
        config_root=config_root,
        again_home=again_home,
        path_directories=path_directories,
        credential_name=credential_name,
        credential_value=credential_value,
    )
    command = template.render(
        {
            "{prompt}": task.prompt,
            "{workspace}": str(workspace),
            "{model}": model,
            "{config_root}": str(config_root),
            "{mcp_config}": str(mcp_config),
        }
    )
    if any(credential_value and credential_value in token for token in command):
        raise HarnessRefusal("credential_argv", "credential material reached command arguments")
    result = run_bounded_command(
        command,
        cwd=workspace,
        environment=environment,
        timeout_seconds=timeout_seconds,
    )
    secret = credential_value.encode("utf-8")
    redacted_stdout = redact_sensitive_bytes(result.stdout, (secret,))
    redacted_stderr = redact_sensitive_bytes(result.stderr, (secret,))
    analysis = analyze_agent_output(client, redacted_stdout, task)
    return build_agent_run_record(
        client,
        condition,
        replica,
        result,
        redacted_stdout,
        redacted_stderr,
        analysis,
    )


def _empty_mcp_config(path: pathlib.Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    _write_new(path, b'{"mcpServers":{}}\n')


def run_cohort(
    *,
    client: str,
    condition: str,
    task: TaskSpec,
    template: CommandTemplate,
    model: str,
    workspace: pathlib.Path,
    run_root: pathlib.Path,
    again_home: pathlib.Path,
    baseline_paths: Sequence[pathlib.Path],
    enabled_paths: Sequence[pathlib.Path],
    setup_binary: pathlib.Path,
    setup_environment: Mapping[str, str],
    credential_name: str,
    credential_value: str,
    timeout_seconds: float,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    prepared: list[tuple[int, pathlib.Path, pathlib.Path]] = []
    setup_summary: dict[str, Any] | None = None
    for replica in range(task.concurrency):
        replica_root = run_root / f"{condition}-{replica}"
        config_root = replica_root / "client-config"
        mcp_config = config_root / ("config.toml" if client == "codex" else "mcp.json")
        if condition == "again_enabled":
            summary = install_isolated_setup(
                setup_binary,
                client,
                mcp_config,
                workspace,
                setup_environment,
                timeout_seconds,
            )
            setup_summary = summary if setup_summary is None else setup_summary
        elif client == "claude":
            _empty_mcp_config(mcp_config)
        else:
            config_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        prepared.append((replica, config_root, mcp_config))
    paths = enabled_paths if condition == "again_enabled" else baseline_paths
    if condition == "baseline":
        _ensure_again_unavailable(paths)

    def invoke(item: tuple[int, pathlib.Path, pathlib.Path]) -> dict[str, Any]:
        replica, config_root, mcp_config = item
        return execute_agent_run(
            client=client,
            condition=condition,
            replica=replica,
            template=template,
            model=model,
            task=task,
            workspace=workspace,
            config_root=config_root,
            mcp_config=mcp_config,
            again_home=again_home,
            path_directories=paths,
            credential_name=credential_name,
            credential_value=credential_value,
            timeout_seconds=timeout_seconds,
        )

    if task.concurrency == 1:
        return [invoke(prepared[0])], setup_summary
    with concurrent.futures.ThreadPoolExecutor(max_workers=task.concurrency) as executor:
        futures = [executor.submit(invoke, item) for item in prepared]
        results = [future.result() for future in futures]
    results.sort(key=lambda run: int(run["replica"]))
    return results, setup_summary


def source_git_sha(source_root: pathlib.Path, environment: Mapping[str, str], timeout: float) -> str:
    result = run_bounded_command(
        ("/usr/bin/git", "rev-parse", "HEAD"),
        cwd=source_root,
        environment=environment,
        timeout_seconds=timeout,
        stdout_limit=1024,
        stderr_limit=1024,
    )
    revision = require_checked_command(result, "source Git revision").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise HarnessRefusal("source_git", "source Git revision is malformed")
    return revision


def _sum_direct_tokens(runs: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for run in runs:
        counts = run["client_reported_tokens"]["counts"]
        for name, value in counts.items():
            totals[name] = totals.get(name, 0) + int(value)
    return dict(sorted(totals.items()))


def planned_agent_runs(client_count: int) -> int:
    return client_count * 2 * sum(task.concurrency for task in TASKS)


def treatment_order(client_index: int, task_index: int) -> tuple[str, str]:
    if (client_index + task_index) % 2 == 0:
        return ("baseline", "again_enabled")
    return ("again_enabled", "baseline")


def validate_runtime_pin(pin: RuntimePin, observed_version: str, observed_sha256: str) -> None:
    if not pin.version or len(pin.version) > 256 or "\n" in pin.version or "\r" in pin.version:
        raise HarnessRefusal("runtime_pin", "runtime version pin is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", pin.sha256):
        raise HarnessRefusal("runtime_pin", "runtime SHA-256 pin is invalid")
    if pin.version != observed_version or pin.sha256 != observed_sha256:
        raise HarnessRefusal("runtime_pin_mismatch", "runtime identity differs from its exact pin")


def evaluate(
    *,
    mode: str,
    allow_network: bool,
    again_binary: pathlib.Path,
    templates: Mapping[str, CommandTemplate],
    models: Mapping[str, str],
    settings_ids: Mapping[str, str],
    credential_names: Mapping[str, str],
    runtime_pins: Mapping[str, RuntimePin],
    maximum_runs: int,
    timeout_seconds: float,
) -> tuple[dict[str, Any], tuple[bytes, ...]]:
    if mode not in {"dry-run", "live"}:
        raise HarnessRefusal("mode", "evaluation mode is invalid")
    if mode == "live" and not allow_network:
        raise HarnessRefusal("network_authorization", "live mode requires --allow-network")
    if mode == "dry-run" and allow_network:
        raise HarnessRefusal("network_authorization", "dry-run mode refuses --allow-network")
    if not 1 <= maximum_runs <= MAX_AGENT_RUNS:
        raise HarnessRefusal("maximum_runs", "--max-runs is outside the bounded range")
    if not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise HarnessRefusal("timeout", "--timeout-seconds is outside the bounded range")
    clients = tuple(sorted(templates))
    if clients != ("claude", "codex"):
        raise HarnessRefusal("clients", "both explicit Codex and Claude templates are required")
    if set(runtime_pins) != {"again", "claude", "codex"}:
        raise HarnessRefusal("runtime_pin", "exact Again, Claude, and Codex pins are required")
    planned = planned_agent_runs(len(clients))
    if maximum_runs < planned:
        raise HarnessRefusal(
            "maximum_runs", f"--max-runs must admit the fixed {planned}-run paired design"
        )
    again_binary = validate_again_binary(again_binary)
    for client in clients:
        validate_identifier(models[client], f"{client} model")
        validate_identifier(settings_ids[client], f"{client} settings ID")
        validate_credential_environment_name(credential_names[client])
    credentials: dict[str, str] = {}
    if mode == "live":
        for client in clients:
            value = os.environ.get(credential_names[client], "")
            if not value:
                raise HarnessRefusal(
                    "credential_missing", f"live {client} credential environment variable is absent"
                )
            credentials[client] = value

    with tempfile.TemporaryDirectory(prefix="again-real-agent-eval-") as temporary:
        private = pathlib.Path(temporary).resolve()
        bootstrap_home = private / "bootstrap-home"
        bootstrap_environment = base_environment(
            bootstrap_home,
            (
                templates["codex"].executable.parent,
                templates["claude"].executable.parent,
                pathlib.Path("/usr/bin"),
                pathlib.Path("/bin"),
            ),
        )
        source_root = pathlib.Path(__file__).resolve().parents[1]
        fixture_root = private / "repository"
        fixture = create_fixture_repository(fixture_root, bootstrap_environment, timeout_seconds)
        again = inspect_again(again_binary, bootstrap_environment, fixture_root, timeout_seconds)
        inspections = {
            client: inspect_client(templates[client], bootstrap_environment, timeout_seconds)
            for client in clients
        }
        validate_runtime_pin(
            runtime_pins["again"], str(again["version"]), str(again["binary_sha256"])
        )
        again["runtime_pin_verified"] = True
        for client in clients:
            validate_runtime_pin(
                runtime_pins[client],
                inspections[client].version,
                inspections[client].executable_sha256,
            )
        shim_directory = private / "enabled-bin"
        shim_directory.mkdir(mode=0o700)
        (shim_directory / "again").symlink_to(again_binary)
        setup_plans: dict[str, Any] = {}
        for client in clients:
            plan_root = private / "dry-setup" / client
            config = plan_root / ("config.toml" if client == "codex" else "mcp.json")
            setup_plans[client] = install_isolated_setup(
                again_binary,
                client,
                config,
                fixture_root,
                bootstrap_environment,
                timeout_seconds,
            )

        pairs: list[dict[str, Any]] = []
        all_runs: list[dict[str, Any]] = []
        if mode == "live":
            for client_index, client in enumerate(clients):
                client_root = private / "live" / client
                baseline_paths = (
                    templates[client].executable.parent,
                    pathlib.Path("/usr/bin"),
                    pathlib.Path("/bin"),
                )
                enabled_paths = (shim_directory, *baseline_paths)
                for task_index, task in enumerate(TASKS):
                    task_root = client_root / task.task_id
                    task_root.mkdir(mode=0o700, parents=True)
                    pair_repository = task_root / "repository"
                    pair_fixture = create_fixture_repository(
                        pair_repository, bootstrap_environment, timeout_seconds
                    )
                    if pair_fixture["fixture_digest_sha256"] != fixture["fixture_digest_sha256"]:
                        raise HarnessRefusal(
                            "fixture_mismatch", "fresh pair fixture differs from the pinned fixture"
                        )
                    initial_repository_diff = repository_diff(
                        pair_fixture["file_sha256"],
                        snapshot_repository_contents(pair_repository),
                    )
                    if not initial_repository_diff["clean"]:
                        raise HarnessRefusal("fixture_dirty", "fresh pair fixture is not exact")
                    again_home = task_root / "again-state"
                    again_home.mkdir(mode=0o700)
                    baseline_again_home = task_root / "baseline-state"
                    stats_environment = dict(bootstrap_environment)
                    stats_environment["AGAIN_HOME"] = str(again_home)
                    order = treatment_order(client_index, task_index)
                    condition_records: dict[str, dict[str, Any]] = {}
                    setup_summary: dict[str, Any] | None = None
                    for condition in order:
                        before = read_again_stats(
                            again_binary,
                            pair_repository,
                            stats_environment,
                            timeout_seconds,
                        )
                        runs, condition_setup = run_cohort(
                            client=client,
                            condition=condition,
                            task=task,
                            template=templates[client],
                            model=models[client],
                            workspace=pair_repository,
                            run_root=task_root / "runs",
                            again_home=(
                                again_home
                                if condition == "again_enabled"
                                else baseline_again_home
                            ),
                            baseline_paths=baseline_paths,
                            enabled_paths=enabled_paths,
                            setup_binary=again_binary,
                            setup_environment=bootstrap_environment,
                            credential_name=credential_names[client],
                            credential_value=credentials[client],
                            timeout_seconds=timeout_seconds,
                        )
                        after = read_again_stats(
                            again_binary,
                            pair_repository,
                            stats_environment,
                            timeout_seconds,
                        )
                        delta = stats_delta(before, after)
                        final_repository_diff = repository_diff(
                            pair_fixture["file_sha256"],
                            snapshot_repository_contents(pair_repository),
                        )
                        if not final_repository_diff["clean"]:
                            raise HarnessRefusal(
                                "unexpected_repository_mutation",
                                "agent condition changed the retained fixture repository",
                            )
                        if condition == "baseline" and any(delta.values()):
                            raise HarnessRefusal(
                                "baseline_contaminated",
                                "Again stats changed during baseline condition",
                            )
                        condition_records[condition] = {
                            "runs": runs,
                            "gateway_stats_delta": delta,
                            "repository_diff": final_repository_diff,
                        }
                        if condition_setup is not None:
                            setup_summary = condition_setup
                    if setup_summary is None:
                        raise HarnessRefusal(
                            "setup_plan", "enabled condition did not retain an Again setup plan"
                        )
                    baseline_runs = condition_records["baseline"]["runs"]
                    enabled_runs = condition_records["again_enabled"]["runs"]
                    gateway_delta = condition_records["again_enabled"][
                        "gateway_stats_delta"
                    ]
                    reconciliation = classify_paired_run(
                        baseline_runs, enabled_runs, gateway_delta
                    )
                    pair = {
                        "client": client,
                        "task_id": task.task_id,
                        "concurrency": task.concurrency,
                        "treatment_order": list(order),
                        "fresh_isolated_state": True,
                        "fixture_git_sha": pair_fixture["git_sha"],
                        "initial_repository_diff": initial_repository_diff,
                        "baseline": condition_records["baseline"],
                        "again_enabled": {
                            **condition_records["again_enabled"],
                            "setup": setup_summary,
                        },
                        "reconciliation": reconciliation,
                    }
                    pairs.append(pair)
                    all_runs.extend(baseline_runs)
                    all_runs.extend(enabled_runs)

        aggregate_gateway = {name: 0 for name in STATS_FIELDS}
        false_hits = 0
        end_to_end_pairs = 0
        if mode == "live":
            for pair in pairs:
                delta = pair["again_enabled"]["gateway_stats_delta"]
                for name in STATS_FIELDS:
                    aggregate_gateway[name] += int(delta[name])
                false_hits += int(pair["reconciliation"]["false_hit_count"])
                if pair["reconciliation"]["classification"] == "end_to_end_again_observed":
                    end_to_end_pairs += 1

        evidence = {
            "schema": SCHEMA,
            "harness_version": HARNESS_VERSION,
            "evidence_kind": (
                "offline_dry_run_plan" if mode == "dry-run" else "live_paired_agent_observation"
            ),
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "authorization": {
                "network_allowed": allow_network,
                "live_mode_explicit": mode == "live",
                "automatic_paid_calls": False,
                "maximum_agent_runs": maximum_runs,
                "per_run_timeout_seconds": timeout_seconds,
            },
            "provenance": {
                "source_git_sha": source_git_sha(
                    source_root, bootstrap_environment, timeout_seconds
                ),
                "harness_sha256": file_sha256(pathlib.Path(__file__).resolve()),
                "again": again,
                "fixture_repository_git_sha": fixture["git_sha"],
                "fixture_file_sha256": fixture["file_sha256"],
                "fixture_digest_sha256": fixture["fixture_digest_sha256"],
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                },
            },
            "clients": {
                client: {
                    "version": inspections[client].version,
                    "version_tuple": list(inspections[client].version_tuple),
                    "executable_sha256": inspections[client].executable_sha256,
                    "runtime_pin_verified": True,
                    "model": models[client],
                    "settings_id": settings_ids[client],
                    "command_template": list(templates[client].arguments),
                    "command_template_sha256": templates[client].identity(),
                    "credential_injected_only_via_environment": mode == "live",
                    "setup_plan": setup_plans[client],
                }
                for client in clients
            },
            "design": {
                "conditions": ["baseline", "again_enabled"],
                "treatment_assignment": (
                    "deterministic alternation by sorted client index plus task index"
                ),
                "planned_agent_runs": planned,
                "executed_agent_runs": len(all_runs),
                "tasks": [
                    {
                        "task_id": task.task_id,
                        "concurrency": task.concurrency,
                        "oracle_sha256": sha256_bytes(canonical_json_bytes(dict(task.expected))),
                    }
                    for task in TASKS
                ],
                "agent_edits_permitted": False,
                "fixture_repository_is_temporary": True,
                "fresh_configuration_state_and_repository_per_pair": True,
                "repository_contents_verified_after_each_condition": True,
                "measurement_definitions": {
                    "response_bytes": (
                        "canonical bytes of redacted Again tool results observable in client events"
                    ),
                    "false_hit_count": (
                        "confirmed only for response mismatches in reuse-only gateway cohorts"
                    ),
                    "estimated_tokens_avoided": "explicit Again stats estimate",
                },
            },
            "paired_runs": pairs,
            "aggregate": {
                "gateway": aggregate_gateway,
                "again_tool_calls_requested": sum(
                    int(run["metrics"]["again_tool_calls_requested"]) for run in all_runs
                ),
                "tool_call_count": sum(int(run["metrics"]["tool_call_count"]) for run in all_runs),
                "response_bytes": sum(
                    int(run["metrics"]["again_tool_response_bytes"]) for run in all_runs
                ),
                "wall_time_ms": round(sum(float(run["wall_time_ms"]) for run in all_runs), 3),
                "false_hit_count": false_hits,
                "end_to_end_again_pairs": end_to_end_pairs,
                "direct_client_token_counts": {
                    "source": "sum_of_direct_client_output_counts",
                    "counts": _sum_direct_tokens(all_runs),
                },
                "estimated_tokens_avoided": {
                    "source": "again_stats_estimate",
                    "value": aggregate_gateway["estimated_tokens_avoided"],
                },
            },
            "limitations": [
                "No model-quality improvement is inferred from these samples.",
                "Token savings are not claimed; only direct client counts and explicitly labeled Again estimates are recorded.",
                "End-to-end Again success requires both a client-observed Again call and a gateway requested-call counter.",
                "The report does not establish general MCP acceleration, semantic reuse, or production readiness.",
                "In-flight joins depend on naturally overlapping real-agent calls and may be zero.",
            ],
            "manual_live_runs_remaining": planned if mode == "dry-run" else 0,
        }
        secret_bytes = tuple(value.encode("utf-8") for value in credentials.values())
        return evidence, secret_bytes


def write_json_exclusive(
    path: pathlib.Path, value: Mapping[str, Any], credentials: Sequence[bytes] = ()
) -> None:
    encoded = canonical_json_bytes(dict(value)) + b"\n"
    for credential in credentials:
        if credential and (credential in encoded or sha256_bytes(credential).encode("ascii") in encoded):
            raise HarnessRefusal(
                "credential_persistence", "refusing evidence containing credential material"
            )
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("dry-run", "live"), default="dry-run")
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--again-binary", type=pathlib.Path, required=True)
    parser.add_argument("--again-version", required=True)
    parser.add_argument("--again-sha256", required=True)
    parser.add_argument("--codex-command-template", required=True)
    parser.add_argument("--claude-command-template", required=True)
    parser.add_argument("--codex-version", required=True)
    parser.add_argument("--codex-sha256", required=True)
    parser.add_argument("--claude-version", required=True)
    parser.add_argument("--claude-sha256", required=True)
    parser.add_argument("--codex-model", required=True)
    parser.add_argument("--claude-model", required=True)
    parser.add_argument("--codex-settings-id", required=True)
    parser.add_argument("--claude-settings-id", required=True)
    parser.add_argument("--codex-credential-env", default="OPENAI_API_KEY")
    parser.add_argument("--claude-credential-env", default="ANTHROPIC_API_KEY")
    parser.add_argument("--max-runs", type=int, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--json-out", type=pathlib.Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.json_out.exists() or arguments.json_out.is_symlink():
        raise HarnessRefusal(
            "evidence_exists", f"refusing to overwrite existing evidence: {arguments.json_out}"
        )
    output = arguments.json_out.resolve(strict=False)
    if not output.parent.is_dir():
        raise HarnessRefusal("evidence_parent", "evidence parent directory does not exist")
    templates = {
        "codex": parse_command_template("codex", arguments.codex_command_template),
        "claude": parse_command_template("claude", arguments.claude_command_template),
    }
    evidence, credentials = evaluate(
        mode=arguments.mode,
        allow_network=arguments.allow_network,
        again_binary=arguments.again_binary,
        templates=templates,
        models={"codex": arguments.codex_model, "claude": arguments.claude_model},
        settings_ids={
            "codex": arguments.codex_settings_id,
            "claude": arguments.claude_settings_id,
        },
        credential_names={
            "codex": arguments.codex_credential_env,
            "claude": arguments.claude_credential_env,
        },
        runtime_pins={
            "again": RuntimePin(arguments.again_version, arguments.again_sha256),
            "codex": RuntimePin(arguments.codex_version, arguments.codex_sha256),
            "claude": RuntimePin(arguments.claude_version, arguments.claude_sha256),
        },
        maximum_runs=arguments.max_runs,
        timeout_seconds=arguments.timeout_seconds,
    )
    write_json_exclusive(output, evidence, credentials)
    print(f"wrote {evidence['evidence_kind']} to {output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except HarnessRefusal as error:
        print(f"real agent evaluation refused [{error.code}]: {error}", file=sys.stderr)
        raise SystemExit(2) from error
