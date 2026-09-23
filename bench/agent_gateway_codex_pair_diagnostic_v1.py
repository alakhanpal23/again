#!/usr/bin/env python3
"""Retain one real Codex baseline/Again editable pair and its raw events.

These fixed public fixtures are diagnostics, not a balanced cohort or an
acceleration qualification.
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
from agent_gateway_authenticated_product_e2e import Client, start_daemon, structured
from agent_gateway_codex_live_probe_v1 import sha256, source_state


MAX_EVENT_BYTES = 8 * 1024 * 1024
TIMEOUT_SECONDS = 180
TASK_IDS = {"calculator": "calculator-fix", "running-balance": "running-balance-fix"}


def configure_fixture(name: str) -> None:
    if name == "calculator":
        return
    pair.TARGET = "src/running_balance.py"
    pair.TEST = "tests/test_running_balance.py"
    pair.BUGGY = (
        "def balances(opening, changes):\n"
        "    current = opening\n"
        "    result = []\n"
        "    for change in changes:\n"
        "        result.append(current)\n"
        "        current += change\n"
        "    return result\n"
    )
    pair.FIXED = pair.BUGGY.replace(
        "        result.append(current)\n        current += change\n",
        "        current += change\n        result.append(current)\n",
    )
    pair.PROMPT = (
        "Fix src/running_balance.py so balances(opening, changes) reports each "
        "balance after applying that change. Keep the API and order. Do not edit "
        "tests or other files. Run the existing test suite, then stop."
    )
    pair.FIXTURE = {
        pair.TARGET: pair.BUGGY,
        pair.TEST: (
            "import importlib.util\n"
            "import pathlib\n"
            "import unittest\n\n"
            "ROOT = pathlib.Path(__file__).parents[1]\n"
            "SPEC = importlib.util.spec_from_file_location('running_balance', ROOT / 'src/running_balance.py')\n"
            "module = importlib.util.module_from_spec(SPEC)\n"
            "SPEC.loader.exec_module(module)\n\n"
            "class BalanceTests(unittest.TestCase):\n"
            "    def test_increases_and_decreases(self):\n"
            "        self.assertEqual(module.balances(10, [3, -2, 5]), [13, 11, 16])\n"
            "    def test_empty(self):\n"
            "        self.assertEqual(module.balances(10, []), [])\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n"
        ),
        "README.md": "# Again running balance editable benchmark fixture\n",
    }


def again_instruction(task_id: str) -> str:
    return (
        "Use Again MCP for repository reads and shared task context. Call task.start "
        f"with taskId {task_id}, includeSourcePreviews=true, and task {json.dumps(pair.PROMPT)}. "
        "Use complete digest-checked sourcePreviews in the task.start response. "
        "Call repo.read only for relevant files without a complete preview, or when current bytes "
        "are needed after an ambiguous edit. Then "
    )


def run_condition(
    condition: str, workspace: pathlib.Path, binary: pathlib.Path, model: str,
    task_id: str,
    source_files: int = 0,
    task_start_only_surface: bool = False,
    compact_task_result: bool = False,
    prebrief_with_mcp: bool = False,
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
    preparation_ms = 0.0
    initial_brief = ""
    if condition == "prebrief":
        preparation_started = time.monotonic()
        environment = os.environ.copy()
        daemon = start_daemon(binary, workspace, environment)
        client = Client(binary, workspace, environment)
        try:
            brief = structured(client.tool("task.start", {
                "taskId": task_id, "task": pair.PROMPT,
                "includeSourcePreviews": True,
                "previewOnly": True,
            }), "precomputed task brief")
        finally:
            client.close()
        previews = brief.get("sourcePreviews", [])
        if not previews or not all(item.get("complete") is True for item in previews):
            raise RuntimeError("precomputed brief lacked complete source previews")
        initial_brief = (
            "Again verified these complete source previews before this task. "
            "They are current until you edit the files. Use them to make the repair; "
            "run validation after editing.\n"
            + "\n".join(
                f"FILE {item['path']} DIGEST {item['sourceDigest']}\n{item['text']}"
                for item in previews
            )
            + "\nVALIDATION " + json.dumps(brief.get("validationPreview")) + "\n"
        )
        preparation_ms = round((time.monotonic() - preparation_started) * 1000, 3)
    codex = pathlib.Path(subprocess.run(
        ["which", "codex"], capture_output=True, text=True, check=True
    ).stdout.strip()).resolve(strict=True)
    command = [
        str(codex), "exec", "--ephemeral", "--ignore-user-config", "--json",
        "--approve-for-me", "-m", model, "-C", str(workspace),
    ]
    if condition == "product":
        command = [
            str(binary), "codex", "--workspace", str(workspace),
            "--task-id", task_id, "--task", pair.PROMPT, "--",
            "--ephemeral", "--ignore-user-config", "--json",
            "--approve-for-me", "-m", model,
        ]
    if condition == "again" or (condition == "prebrief" and prebrief_with_mcp):
        if task_start_only_surface or compact_task_result:
            bridge = pathlib.Path(__file__).with_name("agent_gateway_codex_task_start_surface_v1.py").resolve()
            server_command = sys.executable
            server_args = [str(bridge), "--binary", str(binary), "--workspace", str(workspace)]
            if task_start_only_surface:
                server_args.append("--task-start-only")
            if compact_task_result:
                server_args.append("--compact-task-result")
        else:
            server_command = str(binary)
            server_args = ["mcp", "connect", "--workspace", str(workspace)]
        command += [
            "-c", f"mcp_servers.again.command={json.dumps(server_command)}",
            "-c", f"mcp_servers.again.args={json.dumps(server_args)}",
        ]
    if condition != "product":
        command.append((again_instruction(task_id) if condition == "again" else initial_brief) + pair.PROMPT)
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
                first_edit_ms = round(elapsed * 1000 + preparation_ms, 3)
            time.sleep(0.02)
        returncode = process.wait(timeout=10)
        codex_elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        elapsed_ms = round(codex_elapsed_ms + preparation_ms, 3)
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
    if condition in ("again", "prebrief", "product"):
        subprocess.run(
            [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
            capture_output=True, text=True, timeout=10
        )
        if condition == "prebrief":
            daemon.wait(timeout=10)
            if daemon.stderr is not None:
                daemon.stderr.close()
    result = {
        "condition": condition,
        "exitCode": returncode,
        "timedOut": timed_out,
        "eventsCaptured": captured,
        "elapsedMs": elapsed_ms,
        "preparationMs": preparation_ms,
        "codexElapsedMs": codex_elapsed_ms,
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
    parser.add_argument("--fixture", choices=tuple(TASK_IDS), default="calculator")
    parser.add_argument("--source-files", type=int, default=0)
    parser.add_argument("--order", choices=("baseline-first", "again-first"), default="baseline-first")
    parser.add_argument("--prebrief", action="store_true",
                        help="diagnostic: prepare the verified task brief before launching Codex")
    parser.add_argument("--product-wrapper", action="store_true",
                        help="diagnostic: launch through the production again codex command")
    parser.add_argument("--prebrief-with-mcp", action="store_true",
                        help="diagnostic: keep the normal Again MCP connection available after prebrief")
    parser.add_argument("--task-start-only-surface", action="store_true",
                        help="diagnostic: advertise only task.start while forwarding through the authenticated daemon")
    parser.add_argument("--compact-task-result", action="store_true",
                        help="diagnostic: shorten the text payload while preserving structuredContent")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    configure_fixture(args.fixture)
    if not 0 <= args.source_files <= 1000:
        parser.error("--source-files must be between 0 and 1000")
    if args.prebrief_with_mcp and not args.prebrief:
        parser.error("--prebrief-with-mcp requires --prebrief")
    if args.product_wrapper and (args.prebrief or args.prebrief_with_mcp):
        parser.error("--product-wrapper cannot be combined with diagnostic prebrief modes")
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
    treatment = "product" if args.product_wrapper else "prebrief" if args.prebrief else "again"
    order = ("baseline", treatment) if args.order == "baseline-first" else (treatment, "baseline")
    for condition in order:
        with tempfile.TemporaryDirectory(prefix=f"again-codex-pair-{condition}-") as temporary:
            result, raw = run_condition(
                condition, pathlib.Path(temporary), binary, args.model,
                TASK_IDS[args.fixture],
                args.source_files, args.task_start_only_surface, args.compact_task_result,
                args.prebrief_with_mcp,
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
        "fixture": args.fixture,
        "sourceFiles": args.source_files,
        "approvalMode": "approve-for-me",
        "fixtureSha256": hashlib.sha256(pair.canonical_bytes(pair.FIXTURE)).hexdigest(),
        "promptSha256": hashlib.sha256(pair.PROMPT.encode()).hexdigest(),
        "order": list(order),
        "surface": ("product-wrapper" if args.product_wrapper else
                    "prebrief-with-mcp" if args.prebrief_with_mcp else
                    "prebrief-no-mcp" if args.prebrief else
                    "task-start-only-diagnostic" if args.task_start_only_surface else "full"),
        "compactTaskResult": args.compact_task_result,
        "prebrief": args.prebrief,
        "prebriefWithMcp": args.prebrief_with_mcp,
        "observations": observations,
        "accepted": accepted,
    }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
