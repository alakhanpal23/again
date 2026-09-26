#!/usr/bin/env python3
"""Probe Again setup against an installed agent CLI without running a model.

The client configuration and Codex skill live under a disposable private home.
This probe never reads or changes the user's normal client configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
from typing import Any


MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024


def pinned_binary(path: pathlib.Path) -> tuple[pathlib.Path, str]:
    resolved = path.resolve(strict=True)
    details = resolved.stat()
    if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= MAX_BINARY_BYTES:
        raise ValueError("binary is not a bounded regular file")
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return resolved, digest.hexdigest()


def command(arguments: list[str], environment: dict[str, str]) -> str:
    result = subprocess.run(
        arguments,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        raise ValueError("client command exceeded output bound")
    if result.returncode:
        raise ValueError(f"client command failed with status {result.returncode}")
    return result.stdout.decode("utf-8")


def source_state(root: pathlib.Path) -> dict[str, Any]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout != ""
    return {"head": head, "dirty": dirty}


def probe(
    again: pathlib.Path, client: pathlib.Path, client_name: str, workspace: pathlib.Path
) -> dict[str, Any]:
    again, again_sha = pinned_binary(again)
    client, client_sha = pinned_binary(client)
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        raise ValueError("workspace is not a directory")
    with tempfile.TemporaryDirectory(prefix="again-client-setup-") as temporary:
        root = pathlib.Path(temporary)
        home = root / "home"
        state = root / "client"
        for directory in (home, state):
            directory.mkdir(mode=0o700)
        environment = {
            "HOME": str(home),
            "PATH": f"{client.parent}:/usr/bin:/bin",
            "TMPDIR": str(root),
        }
        if client_name == "codex":
            environment["CODEX_HOME"] = str(state)
        else:
            environment["CLAUDE_CONFIG_DIR"] = str(state)

        client_version = command([str(client), "--version"], environment).strip()
        prefix = [
            str(again),
            "mcp",
            "setup",
            "--client",
            client_name,
            "--workspace",
            str(workspace),
        ]

        def action(flag: str) -> dict[str, Any]:
            arguments = [*prefix, flag, "--json"]
            if client_name == "codex" and flag != "--remove":
                arguments.append("--with-skill")
            return json.loads(command(arguments, environment))

        applied = action("--apply")
        mcp = applied["mcp"] if client_name == "codex" else applied
        if mcp["after"] != "exact" or not mcp["verified"]:
            raise ValueError("applied MCP entry was not verified")
        if client_name == "codex":
            skill = home / ".agents/skills/again/SKILL.md"
            if not skill.is_file() or "`task.start`" not in skill.read_text():
                raise ValueError("Codex skill was not installed with task guidance")
            if not applied["codexSkill"]["current"]:
                raise ValueError("installed Codex skill was not current")
        inspected = action("--inspect")
        inspected_mcp = inspected["mcp"] if client_name == "codex" else inspected
        if inspected_mcp["after"] != "exact" or not inspected_mcp["verified"]:
            raise ValueError("MCP entry could not be inspected exactly")
        if client_name == "codex" and not inspected["codexSkill"]["current"]:
            raise ValueError("Codex skill could not be inspected exactly")
        repeated = action("--apply")
        repeated_mcp = repeated["mcp"] if client_name == "codex" else repeated
        if repeated_mcp["changed"]:
            raise ValueError("repeated MCP apply was not idempotent")
        removed = action("--remove")
        if removed["after"] != "absent" or not removed["verified"]:
            raise ValueError("MCP entry removal was not verified")
        return {
            "schema": "again.client-setup-probe.v1",
            "client": client_name,
            "client_version": client_version,
            "client_sha256": client_sha,
            "again_sha256": again_sha,
            "workspace_git": source_state(workspace),
            "source_to_binary_binding": "unverified",
            "applied": True,
            "inspected": True,
            "repeated_apply_idempotent": True,
            "removed": True,
            "skill_verified": client_name == "codex",
            "model_calls": 0,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-bin", type=pathlib.Path, required=True)
    parser.add_argument("--client", choices=("codex", "claude"), required=True)
    parser.add_argument("--client-bin", type=pathlib.Path)
    parser.add_argument("--workspace", type=pathlib.Path, required=True)
    parser.add_argument("--json-out", type=pathlib.Path, required=True)
    args = parser.parse_args()
    client = args.client_bin or shutil.which(args.client)
    if client is None:
        parser.error(f"{args.client} executable is unavailable")
    report = probe(args.again_bin, pathlib.Path(client), args.client, args.workspace)
    with args.json_out.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(f"{args.client} setup probe passed; model calls: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
