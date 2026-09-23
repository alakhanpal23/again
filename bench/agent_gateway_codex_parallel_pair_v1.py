#!/usr/bin/env python3
"""Retain balanced live two-Codex editable diagnostics on identical repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time

import agent_gateway_editable_pair as pair


TIMEOUT_SECONDS = 180
MAX_EVENT_BYTES = 8 * 1024 * 1024


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_events(path: pathlib.Path) -> tuple[list[dict], bool]:
    data = path.read_bytes()
    if len(data) > MAX_EVENT_BYTES:
        return [], False
    events = []
    for line in data.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            events.append(value)
    return events, True


def summarize(events: list[dict]) -> dict[str, object]:
    commands = []
    tools = []
    changes = 0
    usage = None
    for event in events:
        if event.get("type") == "item.completed":
            item = event.get("item") or {}
            if item.get("type") == "command_execution":
                commands.append(str(item.get("command", ""))[:300])
            elif item.get("type") == "mcp_tool_call":
                tools.append(str(item.get("tool", "")))
            elif item.get("type") == "file_change":
                changes += 1
        elif event.get("type") == "turn.completed":
            usage = event.get("usage")
    return {"commands": commands, "mcpTools": tools, "fileChanges": changes, "usage": usage}


def run_condition(condition: str, workspace: pathlib.Path, binary: pathlib.Path,
                  codex: pathlib.Path, model: str, source_files: int,
                  output_stem: pathlib.Path, delay_follower: bool) -> dict[str, object]:
    pair.MAX_FIXTURE_FILES = max(pair.MAX_FIXTURE_FILES, source_files + len(pair.FIXTURE) + 8)
    pair.create_fixture(workspace)
    background = workspace / "src" / "background"
    background.mkdir()
    for index in range(source_files):
        (background / f"module_{index:04}.py").write_text(f"value = {index}\n")
    subprocess.run(["/usr/bin/git", "-C", str(workspace), "add", "--all"],
                   check=True, timeout=20, stdout=subprocess.DEVNULL)
    subprocess.run(["/usr/bin/git", "-C", str(workspace),
                    "-c", "user.name=Again Benchmark",
                    "-c", "user.email=again-benchmark@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "-m", "fixture"],
                   check=True, timeout=20, stdout=subprocess.DEVNULL)
    before = pair.snapshot(workspace)
    original = hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest()
    state = workspace.parent / "state"
    state.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment["AGAIN_HOME"] = str(state)
    base = [str(codex), "exec", "--ephemeral", "--ignore-user-config", "--json",
            "--approve-for-me", "-m", model, "-C", str(workspace), pair.PROMPT]
    treatment = [str(binary), "codex", "--workspace", str(workspace),
                 "--task-id", "calculator-fix", "--task", pair.PROMPT, "--",
                 "--ephemeral", "--ignore-user-config", "--json", "--approve-for-me",
                 "-m", model]
    command = treatment if condition == "again" else base
    running: list[tuple[str, subprocess.Popen[bytes], object, object]] = []
    started = time.monotonic()
    first_edit_ms = None
    peer_observed = False
    launch_gap_ms = 0.0

    def launch(name: str) -> None:
        out = (output_stem.parent / f"{output_stem.name}-{condition}-{name}.jsonl").open("wb")
        err = tempfile.TemporaryFile()
        process = subprocess.Popen(command, cwd=workspace, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   start_new_session=True)
        running.append((name, process, out, err))

    try:
        launch("first")
        if condition == "again":
            brief_command = [str(binary), "mcp", "brief", "--workspace", str(workspace),
                             "--task-id", "calculator-fix", "--task", pair.PROMPT]
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                response = subprocess.run(brief_command, cwd=workspace, env=environment,
                                          capture_output=True, text=True, timeout=15)
                if response.returncode == 0:
                    try:
                        peer_observed = json.loads(response.stdout)["coordination"]["peerActive"] is True
                    except (ValueError, KeyError, TypeError):
                        pass
                if peer_observed:
                    break
                if running[0][1].poll() is not None:
                    break
                time.sleep(0.025)
            if not peer_observed:
                raise RuntimeError("first Again agent never held a visible task lease")
            if delay_follower:
                while running[0][1].poll() is None:
                    elapsed = time.monotonic() - started
                    if first_edit_ms is None and hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest() != original:
                        first_edit_ms = round(elapsed * 1000, 3)
                    if elapsed >= TIMEOUT_SECONDS:
                        raise RuntimeError("leader exceeded parallel diagnostic timeout")
                    time.sleep(0.02)
        launch_gap_ms = round((time.monotonic() - started) * 1000, 3)
        launch("second")
        timed_out = False
        while any(process.poll() is None for _, process, _, _ in running):
            elapsed = time.monotonic() - started
            if first_edit_ms is None and hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest() != original:
                first_edit_ms = round(elapsed * 1000, 3)
            if elapsed >= TIMEOUT_SECONDS:
                timed_out = True
                for _, process, _, _ in running:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGKILL)
                break
            time.sleep(0.02)
        agents = {}
        for name, process, out, err in running:
            code = process.wait(timeout=10)
            out.close()
            err.seek(0)
            stderr_bytes = err.read(MAX_EVENT_BYTES + 1)
            err.close()
            events_path = output_stem.parent / f"{output_stem.name}-{condition}-{name}.jsonl"
            events, captured = read_events(events_path)
            agents[name] = {
                "exitCode": code, "eventsCaptured": captured,
                "rawEventSha256": sha256(events_path),
                "rawEventFile": events_path.name,
                "stderrSha256": hashlib.sha256(stderr_bytes).hexdigest(),
                **summarize(events),
            }
        if first_edit_ms is None and hashlib.sha256((workspace / pair.TARGET).read_bytes()).digest() != original:
            first_edit_ms = round((time.monotonic() - started) * 1000, 3)
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        oracle = pair.validate_edit(workspace, before, 30)
        return {
            "condition": condition, "peerObservedBeforeSecondLaunch": peer_observed,
            "followerDelayedUntilLeaderExit": condition == "again" and delay_follower,
            "secondLaunchGapMs": launch_gap_ms, "firstEditMs": first_edit_ms,
            "elapsedMs": elapsed_ms, "timedOut": timed_out, "oracle": oracle,
            "agents": agents,
        }
    finally:
        for _, process, out, err in running:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            if not out.closed:
                out.close()
            if not err.closed:
                err.close()
        if condition == "again":
            subprocess.run([str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                           cwd=workspace, env=environment, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--model", default="gpt-6-sol")
    parser.add_argument("--source-files", type=int, default=1000)
    parser.add_argument("--order", choices=("baseline-first", "again-first"), required=True)
    parser.add_argument("--delay-follower-until-leader-exits", action="store_true",
                        help="diagnostic only: delay the second Again launch until its peer exits")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if not 0 <= args.source_files <= 1000:
        parser.error("--source-files must be between 0 and 1000")
    if args.output.exists():
        parser.error("--output must be a new path")
    binary = args.binary.resolve(strict=True)
    codex = pathlib.Path(subprocess.run(["which", "codex"], capture_output=True,
                                         text=True, check=True).stdout.strip()).resolve(strict=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    order = ("baseline", "again") if args.order == "baseline-first" else ("again", "baseline")
    observations = []
    for condition in order:
        with tempfile.TemporaryDirectory(prefix=f"again-codex-parallel-{condition}-") as temporary:
            observations.append(run_condition(condition, pathlib.Path(temporary) / "repo",
                                              binary, codex, args.model, args.source_files,
                                              args.output.with_suffix(""),
                                              args.delay_follower_until_leader_exits))
    accepted = all(
        item["oracle"]["passed"] and not item["timedOut"]
        and all(agent["exitCode"] == 0 and agent["eventsCaptured"] for agent in item["agents"].values())
        for item in observations
    )
    report = {
        "schema": "again.codex-parallel-pair-diagnostic.v1",
        "evidenceScope": "local_live_diagnostic_not_qualification",
        "accepted": accepted,
        "order": args.order,
        "model": args.model,
        "sourceFiles": args.source_files,
        "delayFollowerUntilLeaderExits": args.delay_follower_until_leader_exits,
        "againBinarySha256": sha256(binary),
        "codexBinarySha256": sha256(codex),
        "promptSha256": hashlib.sha256(pair.PROMPT.encode()).hexdigest(),
        "observations": observations,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
