#!/usr/bin/env python3
"""Exercise a real Codex Bash search through the project Again Brain hook.

This is a bounded live integration gate, not a task-speed benchmark.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time

from agent_gateway_codex_live_probe_v1 import source_state


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = "def balance():\n    return 42\n"
PROMPT = (
    "Run exactly this one shell command in the repository: rg -n -F balance src. "
    "Report the matching line, then stop. Do not edit files or run other commands."
)


def run_json(command: list[str], *, env: dict[str, str], cwd: pathlib.Path) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                            text=True, timeout=45, check=True)
    return json.loads(result.stdout)


def brain_paths(binary: pathlib.Path, workspace: pathlib.Path, env: dict[str, str]) -> list[str]:
    result = run_json([str(binary), "brain", "show", "--workspace", str(workspace)],
                      env=env, cwd=workspace)
    return [row["path"] for row in result["fileObservations"]]


def brief_paths(binary: pathlib.Path, workspace: pathlib.Path, env: dict[str, str],
                task_id: str) -> list[str]:
    brief = run_json([str(binary), "mcp", "brief", "--workspace", str(workspace),
                      "--task-id", task_id, "--task", "Fix ledger balance output"],
                     env=env, cwd=workspace)
    return [row["path"] for row in (brief.get("againBrain") or {}).get("recentCurrentFiles", [])]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = source_state(ROOT, binary)
    if source["binarySourceBindingVerified"] is not True:
        raise RuntimeError(f"live gate requires a clean source-bound binary: {source}")
    codex_version = subprocess.run(["codex", "--version"], capture_output=True,
                                   text=True, check=True, timeout=5).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="again-live-search-hook-") as scratch:
        temporary = pathlib.Path(scratch)
        workspace = temporary / "workspace"
        (workspace / "src").mkdir(parents=True)
        (workspace / "src/ledger.py").write_text(SOURCE)
        (workspace / "src/unrelated.py").write_text("value = 0\n")
        subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
        env = dict(os.environ, AGAIN_HOME=str(temporary / "again-state"))
        setup = run_json([str(binary), "brain", "hook-setup", "--workspace",
                          str(workspace), "--apply"], env=env, cwd=workspace)
        if not setup["installed"]:
            raise RuntimeError("project Brain observer was not installed")
        command = ["codex", "exec", "--ephemeral", "--ignore-user-config", "--json",
                   "--approve-for-me", "-C", str(workspace), PROMPT]
        try:
            codex = subprocess.run(command, cwd=workspace, env=env, capture_output=True,
                                   text=True, timeout=120)
            timed_out = False
        except subprocess.TimeoutExpired as error:
            codex = error
            timed_out = True
        raw = codex.stdout or ""
        if isinstance(raw, bytes):
            raw = raw.decode(errors="replace")
        events = []
        for line in raw.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = value.get("item") or {}
            if value.get("type") == "item.completed" and item.get("type") == "command_execution":
                events.append({"command": item.get("command"), "exitCode": item.get("exit_code"),
                               "outputMarker": "src/ledger.py:1:def balance():" in (item.get("aggregated_output") or "")})
        observed = []
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            observed = brain_paths(binary, workspace, env)
            if "src/ledger.py" in observed:
                break
            time.sleep(0.5)
        before = brief_paths(binary, workspace, env, "live-search-before")
        (workspace / "src/ledger.py").write_text("def balance():\n    return 0\n")
        after = brief_paths(binary, workspace, env, "live-search-after")
        removed = run_json([str(binary), "brain", "hook-setup", "--workspace",
                            str(workspace), "--remove"], env=env, cwd=workspace)
        accepted = (
            not timed_out and codex.returncode == 0
            and any(event["exitCode"] == 0 and event["outputMarker"]
                    and "rg -n -F balance src" in (event["command"] or "") for event in events)
            and "src/ledger.py" in observed
            and "src/ledger.py" in before and "src/ledger.py" not in after
            and removed["changed"] and not (workspace / ".codex/hooks.json").exists()
        )
        report = {
            "schema": "again.codex-brain-live-search-hook.v1",
            "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": source,
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "codexVersion": codex_version,
            "fixtureSha256": hashlib.sha256(SOURCE.encode()).hexdigest(),
            "codexExitCode": None if timed_out else codex.returncode,
            "timedOut": timed_out,
            "completedCommands": events,
            "brainPaths": observed,
            "briefPathsBeforeEdit": before,
            "briefPathsAfterEdit": after,
            "hookRemoved": removed["changed"],
            "accepted": accepted,
            "evidenceScope": "one live Codex search in an isolated repository; no speed claim",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.output.with_suffix(".jsonl").write_text(raw)
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
