#!/usr/bin/env python3
"""Retain one real Codex baseline/Again editable pair and its raw events.

This diagnostic uses the fixed public calculator fixture. It is not a balanced
cohort or an acceleration qualification.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

import agent_gateway_editable_pair as pair
from agent_gateway_codex_live_probe_v1 import sha256, source_state


MAX_EVENT_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 180
AGAIN_INSTRUCTION = (
    "Use Again MCP for repository reads and shared task context. Call task.start "
    "with taskId calculator-fix, includeSourcePreviews=true, and task " + json.dumps(pair.PROMPT) + ". "
    "Use complete digest-checked sourcePreviews in the task.start response. "
    "Call repo.read only for relevant files without a complete preview, or when current bytes "
    "are needed after an ambiguous edit. Then "
)


def run_condition(
    condition: str, workspace: pathlib.Path, binary: pathlib.Path, model: str,
    source_files: int = 0,
    task_start_only_surface: bool = False,
) -> tuple[dict[str, object], bytes]:
    pair.MAX_FIXTURE_FILES = max(pair.MAX_FIXTURE_FILES, source_files + len(pair.FIXTURE) + 8)
    pair.create_fixture(workspace)
    if source_files:
        background = workspace / "src" / "background"
        background.mkdir()
        for index in range(source_files):
            (background / f"module_{index:04}.py").write_text(
                f"value = {index}\n", encoding="utf-8"
            )
    before = pair.snapshot(workspace)
    stats_before = pair.again_stats(binary, workspace)
    codex = pathlib.Path(subprocess.run(
        ["which", "codex"], capture_output=True, text=True, check=True
    ).stdout.strip()).resolve(strict=True)
    command = [
        str(codex), "exec", "--ephemeral", "--ignore-user-config", "--json",
        "--approve-for-me", "-m", model, "-C", str(workspace),
    ]
    if condition == "again":
        if task_start_only_surface:
            bridge = pathlib.Path(__file__).with_name("agent_gateway_codex_task_start_surface_v1.py").resolve()
            server_command = sys.executable
            server_args = [str(bridge), "--binary", str(binary), "--workspace", str(workspace)]
        else:
            server_command = str(binary)
            server_args = ["mcp", "connect", "--workspace", str(workspace)]
        command += [
            "-c", f"mcp_servers.again.command={json.dumps(server_command)}",
            "-c", f"mcp_servers.again.args={json.dumps(server_args)}",
        ]
    command.append((AGAIN_INSTRUCTION if condition == "again" else "") + pair.PROMPT)
    original = hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        started = time.monotonic()
        process = subprocess.Popen(
            command, cwd=workspace, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            start_new_session=True
        )
        first_edit_ms = None
        timed_out = False
        while process.poll() is None:
            elapsed = time.monotonic() - started
            if elapsed >= TIMEOUT_SECONDS:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            target = workspace / pair.TARGET
            if first_edit_ms is None and target.is_file() and hashlib.sha256(target.read_bytes()).digest() != original:
                first_edit_ms = round(elapsed * 1000, 3)
            time.sleep(0.02)
        returncode = process.wait(timeout=10)
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        if first_edit_ms is None and (workspace / pair.TARGET).is_file() and hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest() != original:
            first_edit_ms = elapsed_ms
        stdout.seek(0)
        stderr.seek(0)
        raw = stdout.read(MAX_EVENT_BYTES + 1)
        stderr_bytes = stderr.read(MAX_EVENT_BYTES + 1)
    captured = len(raw) <= MAX_EVENT_BYTES and len(stderr_bytes) <= MAX_EVENT_BYTES
    events = []
    completed = []
    usage = None
    if captured:
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(event)
            item = event.get("item") or {}
            if event.get("type") == "item.completed" and item.get("type") in (
                "mcp_tool_call", "command_execution", "file_change"
            ):
                completed.append({
                    "type": item.get("type"),
                    "tool": item.get("tool"),
                    "status": item.get("status"),
                    "resultBytes": len(json.dumps(item.get("result"), separators=(",", ":")).encode())
                    if item.get("result") is not None else None,
                    "command": str(item.get("command", ""))[:300],
                })
            if event.get("type") == "turn.completed":
                usage = event.get("usage")
    oracle = (
        pair.validate_edit(workspace, before, 30)
        if (workspace / pair.TARGET).is_file()
        else {"passed": False, "reason": "target_missing"}
    )
    stats_after = pair.again_stats(binary, workspace)
    stats = {key: stats_after[key] - stats_before[key] for key in stats_before}
    if condition == "again":
        subprocess.run(
            [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
            capture_output=True, text=True, timeout=10
        )
    result = {
        "condition": condition,
        "exitCode": returncode,
        "timedOut": timed_out,
        "eventsCaptured": captured,
        "elapsedMs": elapsed_ms,
        "firstEditMs": first_edit_ms,
        "rawEventBytes": len(raw),
        "rawEventSha256": hashlib.sha256(raw).hexdigest(),
        "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "eventCount": len(events),
        "completedActions": completed,
        "usage": usage,
        "oracle": oracle,
        "againStatsDelta": stats,
    }
    return result, raw


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default="target/debug/again")
    parser.add_argument("--model", default="gpt-6-sol")
    parser.add_argument("--source-files", type=int, default=0)
    parser.add_argument("--order", choices=("baseline-first", "again-first"), default="baseline-first")
    parser.add_argument("--task-start-only-surface", action="store_true",
                        help="diagnostic: advertise only task.start while forwarding through the authenticated daemon")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not 0 <= args.source_files <= 1000:
        parser.error("--source-files must be between 0 and 1000")
    binary = args.binary.resolve(strict=True)
    connector = subprocess.run(
        [str(binary), "mcp", "connect", "--help"],
        capture_output=True, text=True, timeout=5,
    )
    if connector.returncode != 0:
        parser.error("--binary must be built with the daemon feature (cargo build --features daemon)")
    root = pathlib.Path(__file__).resolve().parents[1]
    codex = pathlib.Path(subprocess.run(
        ["which", "codex"], capture_output=True, text=True, check=True
    ).stdout.strip()).resolve(strict=True)
    version = subprocess.run([str(codex), "--version"], capture_output=True, text=True, check=True).stdout.strip()
    observations = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    order = ("baseline", "again") if args.order == "baseline-first" else ("again", "baseline")
    for condition in order:
        with tempfile.TemporaryDirectory(prefix=f"again-codex-pair-{condition}-") as temporary:
            result, raw = run_condition(
                condition, pathlib.Path(temporary), binary, args.model,
                args.source_files, args.task_start_only_surface,
            )
        raw_path = args.output.with_name(args.output.stem + f"-{condition}.jsonl")
        raw_path.write_bytes(raw)
        result["rawEventFile"] = raw_path.name
        observations.append(result)
    accepted = all(
        result["exitCode"] == 0 and not result["timedOut"]
        and result["eventsCaptured"] and result["oracle"]["passed"]
        for result in observations
    ) and next(result for result in observations if result["condition"] == "baseline")["againStatsDelta"]["requested"] == 0
    report = {
        "schema": "again.codex-editable-pair-diagnostic.v1",
        "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidenceScope": "one unbalanced local pair, not acceleration qualification",
        "codexVersion": version,
        "codexBinarySha256": sha256(codex),
        "againBinarySha256": sha256(binary),
        "harnessSha256": sha256(pathlib.Path(__file__)),
        "source": source_state(root),
        "model": args.model,
        "sourceFiles": args.source_files,
        "approvalMode": "approve-for-me",
        "fixtureSha256": hashlib.sha256(pair.canonical_bytes(pair.FIXTURE)).hexdigest(),
        "promptSha256": hashlib.sha256(pair.PROMPT.encode()).hexdigest(),
        "order": list(order),
        "surface": "task-start-only-diagnostic" if args.task_start_only_surface else "full",
        "observations": observations,
        "accepted": accepted,
    }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
