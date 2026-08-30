#!/usr/bin/env python3
"""Install and exercise one native Again release archive.

This is a product smoke, not a platform-qualification shortcut. It proves that
the archive built on a native runner exposes the daemon-backed local product
while the linux-pytest and team-alpha feature surfaces remain absent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, BinaryIO


SEMVER_TAG = re.compile(
    r"^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$"
)
SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
MCP_PROTOCOL_VERSION = "2025-06-18"
COMMAND_TIMEOUT_SECONDS = 15.0
DAEMON_READY_TIMEOUT_SECONDS = 10.0
MAX_DIAGNOSTIC_BYTES = 16 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024

EXPECTED_TOOLS = {
    "context.cancel",
    "context.delta",
    "context.publish",
    "context.retrieve",
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
}


class SmokeFailure(RuntimeError):
    """A release-package contract did not hold."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-git-sha")
    parser.add_argument("--evidence-output", type=Path)
    return parser.parse_args()


def host_target() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Darwin" and machine in {"arm64", "aarch64"}:
        return "aarch64-apple-darwin"
    if system == "Darwin" and machine in {"x86_64", "amd64"}:
        return "x86_64-apple-darwin"
    if system == "Linux" and machine in {"arm64", "aarch64"}:
        return "aarch64-unknown-linux-gnu"
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "x86_64-unknown-linux-gnu"
    raise SmokeFailure(f"unsupported native smoke host: {system}/{machine}")


def bounded_text(payload: bytes) -> str:
    return payload[:MAX_DIAGNOSTIC_BYTES].decode("utf-8", "replace")


def sha256_file(path: Path, maximum_bytes: int) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
        raise SmokeFailure("file identity is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SmokeFailure("file could not be opened without following links") from error
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if file_identity(opened) != file_identity(before):
            raise SmokeFailure("file changed while opening")
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > maximum_bytes:
                raise SmokeFailure("file exceeded its digest bound")
            digest.update(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    final = path.lstat()
    if (
        total != before.st_size
        or file_identity(before) != file_identity(after)
        or file_identity(before) != file_identity(final)
    ):
        raise SmokeFailure("file changed while hashing")
    return digest.hexdigest()


def file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def write_private_evidence(path: Path, report: dict[str, Any]) -> None:
    if not path.is_absolute():
        raise SmokeFailure("evidence output must be an absolute path")
    payload = (
        json.dumps(report, allow_nan=False, separators=(",", ":"), sort_keys=True).encode()
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise SmokeFailure("evidence output could not be created exclusively") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SmokeFailure("evidence output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        if os.fstat(descriptor).st_mode & 0o777 != 0o600:
            raise SmokeFailure("evidence output permissions are not private")
    finally:
        os.close(descriptor)


def run(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    check: bool = True,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SmokeFailure(f"command did not complete: {argv[0]}") from error
    if check and completed.returncode != 0:
        raise SmokeFailure(
            f"command failed ({completed.returncode}): {' '.join(argv)}\n"
            f"stdout: {bounded_text(completed.stdout)}\n"
            f"stderr: {bounded_text(completed.stderr)}"
        )
    return completed


def strict_json(payload: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SmokeFailure(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicates
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmokeFailure("command returned malformed JSON") from error
    if not isinstance(value, dict):
        raise SmokeFailure("command JSON root is not an object")
    return value


def read_response(stream: BinaryIO, expected_id: str) -> dict[str, Any]:
    ready, _, _ = select.select([stream], [], [], COMMAND_TIMEOUT_SECONDS)
    if not ready:
        raise SmokeFailure(f"MCP response timed out for {expected_id}")
    line = stream.readline()
    if not line:
        raise SmokeFailure(f"MCP connection closed before {expected_id}")
    response = strict_json(line)
    if response.get("id") != expected_id:
        raise SmokeFailure(f"MCP response ID mismatch for {expected_id}")
    if "error" in response:
        raise SmokeFailure(f"MCP request {expected_id} returned an error")
    return response


def send_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    payload = json.dumps(message, separators=(",", ":"), sort_keys=True).encode()
    stream.write(payload + b"\n")
    stream.flush()


def assert_unavailable(binary: Path, command: str, cwd: Path, env: dict[str, str]) -> None:
    completed = run([str(binary), command, "--help"], cwd=cwd, env=env, check=False)
    if completed.returncode == 0 or b"unrecognized subcommand" not in completed.stderr:
        raise SmokeFailure(f"non-shipping command did not refuse explicitly: {command}")


def wait_for_daemon(binary: Path, workspace: Path, env: dict[str, str]) -> dict[str, Any]:
    deadline = time.monotonic() + DAEMON_READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = run(
            [str(binary), "mcp", "daemon", "status", "--workspace", str(workspace)],
            cwd=workspace,
            env=env,
            check=False,
            timeout=2.0,
        )
        if status.returncode == 0:
            report = strict_json(status.stdout)
            if report.get("status") == "ready":
                return report
        time.sleep(0.05)
    raise SmokeFailure("installed daemon did not become ready")


def wait_for_daemon_stopped(binary: Path, workspace: Path, env: dict[str, str]) -> None:
    deadline = time.monotonic() + DAEMON_READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        status = run(
            [str(binary), "mcp", "daemon", "status", "--workspace", str(workspace)],
            cwd=workspace,
            env=env,
            check=False,
            timeout=2.0,
        )
        if status.returncode != 0:
            return
        time.sleep(0.05)
    raise SmokeFailure("installed daemon did not retire after stop")


def exercise_setup_plans(binary: Path, workspace: Path, env: dict[str, str]) -> None:
    expected_binary = str(binary.resolve())
    expected_workspace = str(workspace.resolve())
    for client in ("codex", "claude"):
        plan = strict_json(
            run(
                [
                    str(binary),
                    "mcp",
                    "setup",
                    "--client",
                    client,
                    "--workspace",
                    str(workspace),
                    "--json",
                ],
                cwd=workspace,
                env=env,
            ).stdout
        )
        if (
            plan.get("version") != 3
            or plan.get("client") != client
            or plan.get("server_name") != "again"
            or plan.get("workspace") != expected_workspace
            or plan.get("writes_by_default") is not False
            or plan.get("install_policy") != "official_client_cli_only_v1"
            or plan.get("stdio")
            != {
                "transport": "stdio",
                "command": expected_binary,
                "args": ["mcp", "connect", "--workspace", expected_workspace],
            }
        ):
            raise SmokeFailure(f"installed {client} setup plan is not exact")
        local_command = plan.get("local_cli_command")
        if not isinstance(local_command, str):
            raise SmokeFailure(f"installed {client} setup command is malformed")
        expected_prefix = (
            "codex mcp add again -- "
            if client == "codex"
            else "claude mcp add --transport stdio --scope user again -- "
        )
        if not local_command.startswith(expected_prefix):
            raise SmokeFailure(f"installed {client} setup command is unsupported")


def exercise_mcp(binary: Path, workspace: Path, env: dict[str, str]) -> None:
    proxy = subprocess.Popen(
        [str(binary), "mcp", "connect", "--workspace", str(workspace)],
        cwd=workspace,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        if proxy.stdin is None or proxy.stdout is None:
            raise SmokeFailure("MCP proxy streams were not created")
        send_message(
            proxy.stdin,
            {
                "jsonrpc": "2.0",
                "id": "initialize",
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "release-package-smoke", "version": "1"},
                },
            },
        )
        initialized = read_response(proxy.stdout, "initialize")
        if initialized.get("result", {}).get("protocolVersion") != MCP_PROTOCOL_VERSION:
            raise SmokeFailure("MCP protocol negotiation returned an unexpected version")
        send_message(
            proxy.stdin,
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            },
        )
        send_message(
            proxy.stdin,
            {"jsonrpc": "2.0", "id": "tools", "method": "tools/list", "params": {}},
        )
        listing = read_response(proxy.stdout, "tools")
        entries = listing.get("result", {}).get("tools")
        if not isinstance(entries, list):
            raise SmokeFailure("MCP tools/list result is malformed")
        names = {
            entry.get("name")
            for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("name"), str)
        }
        if names != EXPECTED_TOOLS or len(entries) != len(EXPECTED_TOOLS):
            raise SmokeFailure(f"unexpected installed MCP tool catalog: {sorted(names)}")
    finally:
        if proxy.stdin is not None:
            proxy.stdin.close()
        try:
            proxy.wait(timeout=COMMAND_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            proxy.terminate()
            try:
                proxy.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=2.0)
    if proxy.returncode != 0:
        raise SmokeFailure("installed MCP proxy did not exit cleanly")


def main() -> int:
    args = parse_args()
    repository = Path(__file__).resolve().parent.parent
    archive = args.archive.resolve()
    if (args.evidence_output is None) != (args.source_git_sha is None):
        raise SmokeFailure("evidence output and source Git SHA must be provided together")
    if args.source_git_sha is not None and SOURCE_SHA.fullmatch(args.source_git_sha) is None:
        raise SmokeFailure("source Git SHA is not a lowercase 40-character digest")
    if SEMVER_TAG.fullmatch(args.version) is None:
        raise SmokeFailure("version is not a supported SemVer release tag")
    target = host_target()
    expected_name = f"again-{args.version}-{target}.tar.gz"
    if (
        archive.name != expected_name
        or not archive.is_file()
        or archive.is_symlink()
        or not 0 < archive.stat().st_size <= MAX_ARCHIVE_BYTES
    ):
        raise SmokeFailure(f"archive must be a regular non-symlink file named {expected_name}")

    with tempfile.TemporaryDirectory(prefix="again-release-package-smoke.") as raw_fixture:
        fixture = Path(raw_fixture).resolve()
        artifacts = fixture / "artifacts"
        install_root = fixture / "install"
        workspace = fixture / "workspace"
        home = fixture / "home"
        state = fixture / "state"
        for directory in (artifacts, install_root, workspace, home, state):
            directory.mkdir(mode=0o700)
        installed_archive = artifacts / expected_name
        shutil.copyfile(archive, installed_archive)
        digest = sha256_file(installed_archive, MAX_ARCHIVE_BYTES)
        (artifacts / "SHA256SUMS").write_text(
            f"{digest}  {expected_name}\n", encoding="ascii"
        )
        (workspace / "README.md").write_text("release package smoke\n", encoding="utf-8")

        env = os.environ.copy()
        env["HOME"] = str(home)
        env["AGAIN_HOME"] = str(state)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        run(["git", "init", "--quiet"], cwd=workspace, env=env)

        binary = install_root / "again"
        installed_binary_digest: str | None = None
        daemon_started = False
        uninstall_complete = False
        try:
            run(
                [
                    "sh",
                    str(repository / "scripts" / "install.sh"),
                    "--version",
                    args.version,
                    "--artifact-dir",
                    str(artifacts),
                    "--dest",
                    str(binary),
                ],
                cwd=workspace,
                env=env,
            )
            version = run([str(binary), "--version"], cwd=workspace, env=env)
            installed_binary_digest = sha256_file(binary, MAX_BINARY_BYTES)
            crate_version = args.version[1:].split("-", 1)[0]
            if version.stdout.decode("utf-8", "strict").strip() != f"again {crate_version}":
                raise SmokeFailure("installed binary reported an unexpected version")

            doctor = strict_json(
                run([str(binary), "doctor", "--json"], cwd=workspace, env=env).stdout
            )
            coordinator = doctor.get("coordinator", {})
            pytest_profile = doctor.get("pytest_profile", {})
            if (
                coordinator.get("status") != "ready"
                or coordinator.get("feature_enabled") is not True
                or coordinator.get("same_user_authenticated") is not True
            ):
                raise SmokeFailure("shipping daemon capability is not ready")
            if set(coordinator.get("public_tools", [])) != {
                "task.start",
                "task.inspect",
                "task.list",
                "task.claim",
                "task.transition",
                "context.delta",
                "context.publish",
                "context.retrieve",
                "context.cancel",
            }:
                raise SmokeFailure("doctor reported an unexpected task/context surface")
            if (
                pytest_profile.get("portable_control_plane_enabled") is not False
                or pytest_profile.get("execution_qualified") is not False
                or pytest_profile.get("reuse_enabled") is not False
                or "linux_pytest_feature_disabled" not in pytest_profile.get("blockers", [])
            ):
                raise SmokeFailure("shipping package gained Linux pytest authority")
            assert_unavailable(binary, "team", workspace, env)
            assert_unavailable(binary, "__linux-pytest-namespace-probe-v1", workspace, env)
            exercise_setup_plans(binary, workspace, env)

            before_connect = run(
                [str(binary), "mcp", "daemon", "status", "--workspace", str(workspace)],
                cwd=workspace,
                env=env,
                check=False,
            )
            if before_connect.returncode == 0:
                raise SmokeFailure("daemon was already running before the first connector")

            # The installed connector itself must elect and start the daemon.
            daemon_started = True
            exercise_mcp(binary, workspace, env)
            status = wait_for_daemon(binary, workspace, env)
            if status.get("peerAuthentication") not in {"getpeereid_euid", "so_peercred_euid"}:
                raise SmokeFailure("daemon did not report same-user peer authentication")
            run(
                [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                cwd=workspace,
                env=env,
            )
            wait_for_daemon_stopped(binary, workspace, env)
            daemon_started = False

            run(
                ["sh", str(repository / "scripts" / "uninstall.sh"), "--dest", str(binary)],
                cwd=workspace,
                env=env,
            )
            uninstall_complete = True
            adjacent_state = [
                binary,
                Path(f"{binary}.again-install"),
                Path(f"{binary}.again-lock"),
                Path(f"{binary}.previous"),
            ]
            if any(path.exists() or path.is_symlink() for path in adjacent_state):
                raise SmokeFailure("uninstall left managed package state behind")
        finally:
            if daemon_started and binary.exists():
                run(
                    [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                    cwd=workspace,
                    env=env,
                    check=False,
                    timeout=2.0,
                )
            if not uninstall_complete and binary.exists():
                run(
                    ["sh", str(repository / "scripts" / "uninstall.sh"), "--dest", str(binary)],
                    cwd=workspace,
                    env=env,
                    check=False,
                    timeout=2.0,
                )

    if args.evidence_output is not None:
        if installed_binary_digest is None:
            raise SmokeFailure("installed binary identity was not retained")
        write_private_evidence(
            args.evidence_output,
            {
                "schema": "again.local-beta-native-smoke.v1",
                "classification": {
                    "type": "pass",
                    "code": "native_package_smoke_passed",
                },
                "target": target,
                "source_git_sha": args.source_git_sha,
                "archive_sha256": digest,
                "installed_binary_sha256": installed_binary_digest,
                "checks": {
                    "authenticated_mcp": True,
                    "automatic_daemon_start": True,
                    "client_setup_plans": True,
                    "daemon_started": True,
                    "doctor_passed": True,
                    "exact_tool_catalog": True,
                    "installed": True,
                    "uninstalled": True,
                },
            },
        )

    print(f"native daemon-only package smoke passed: {expected_name}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SmokeFailure as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
