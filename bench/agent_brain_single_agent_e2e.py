#!/usr/bin/env python3
"""Exercise Codex event capture and current cross-task brain hints in isolation."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from agent_gateway_codex_live_probe_v1 import source_state


ROOT = pathlib.Path(__file__).resolve().parents[1]


def run(binary: pathlib.Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="again-brain-e2e-") as temporary:
        root = pathlib.Path(temporary).resolve()
        workspace = root / "repo"
        workspace.mkdir()
        (workspace / "a.py").write_text("value = 1\n")
        (workspace / "helper.py").write_text("def helper():\n    return 42\n")
        (workspace / "ledger.py").write_text("def ledger_balance():\n    return 10\n")
        (workspace / "balance.py").write_text("def render_balance():\n    return '10'\n")
        subprocess.run(["git", "init", "-q", str(workspace)], check=True)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        fake_client = fake_bin / "codex"
        fake_client.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, subprocess, sys\n"
            "argv = sys.argv[1:]\n"
            "workspace = pathlib.Path(argv[argv.index('-C') + 1])\n"
            "with open(os.environ['FAKE_LOG'], 'a') as out: out.write(json.dumps(argv) + '\\n')\n"
            "if 'first task' in argv[-1]:\n"
            "    command = 'cat helper.py && cat ledger.py && git status --short'\n"
            "    read = subprocess.run(['/bin/sh', '-c', command], cwd=workspace, capture_output=True, text=True, check=True)\n"
            "    print(json.dumps({'type':'item.completed','item':{'id':'read_1','type':'command_execution','command':command,'aggregated_output':read.stdout,'exit_code':read.returncode,'status':'completed'}}), flush=True)\n"
            "    path = workspace / 'a.py'\n"
            "    path.write_text('value = 2\\n')\n"
            "    print(json.dumps({'type':'item.completed','item':{'id':'edit_1','type':'file_change','status':'completed','changes':[{'path':str(path)}]}}), flush=True)\n"
            "    print(json.dumps({'type':'item.completed','item':{'id':'test_1','type':'command_execution','command':\"/bin/zsh -lc 'python3 -m unittest discover -s tests'\",'aggregated_output':'OK\\n','exit_code':0,'status':'completed'}}), flush=True)\n"
            "    print(json.dumps({'type':'turn.completed','usage':{'input_tokens':100,'cached_input_tokens':40,'output_tokens':12}}), flush=True)\n"
            "print(json.dumps({'type':'item.completed','item':{'id':'last','type':'agent_message','text':'Done'}}), flush=True)\n"
        )
        fake_client.chmod(0o700)
        home = root / "home"
        home.mkdir()
        environment = os.environ.copy()
        environment.update(
            HOME=str(home),
            AGAIN_HOME=str(root / "state"),
            FAKE_LOG=str(root / "calls.jsonl"),
            PATH=str(fake_bin) + os.pathsep + environment["PATH"],
        )

        def launch(task_id: str, task: str) -> None:
            command = [
                str(binary), "codex", "--workspace", str(workspace),
                "--task-id", task_id, "--task", task, "--", "--ephemeral",
            ]
            result = subprocess.run(
                command, cwd=workspace, env=environment,
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                raise RuntimeError(f"launcher failed: {result.stderr}")
            if "Done" not in result.stdout:
                raise RuntimeError("structured output did not render the agent message")

        def brain() -> dict[str, object]:
            result = subprocess.run(
                [str(binary), "brain", "show", "--workspace", str(workspace)],
                cwd=workspace, env=environment, capture_output=True,
                text=True, timeout=10, check=True,
            )
            return json.loads(result.stdout)

        def brain_files_in_prompt(prompt: str) -> set[str]:
            if "AGAIN_BRAIN " not in prompt:
                return set()
            payload = prompt.split("AGAIN_BRAIN ", 1)[1].split("\n", 1)[0]
            return {item["path"] for item in json.loads(payload)["recentCurrentFiles"]}

        try:
            launch("first", "Repair ledger balance formatting in a.py first task")
            snapshot = brain()
            observed = snapshot["recentEvents"]
            if len(observed) != 5 or {row["kind"] for row in observed} != {"file_change", "test", "command"}:
                raise RuntimeError("completed compound reads, edit, and test were not retained")
            if {item["path"] for item in snapshot["fileObservations"]} != {"a.py", "helper.py", "ledger.py"}:
                raise RuntimeError("latest file observations were not materialized")
            if "aggregated_output" in json.dumps(observed):
                raise RuntimeError("raw tool output entered the brain store")
            runs = snapshot["recentRuns"]
            if len(runs) != 1 or any(runs[0].get(key) != value for key, value in {
                "exit_code": 0, "turn_completed": True, "completed_commands": 2,
                "completed_source_reads": 2, "completed_edits": 1,
                "completed_mcp_calls": 0, "successful_tests": 1,
                "input_tokens": 100, "cached_input_tokens": 40, "output_tokens": 12,
            }.items()):
                raise RuntimeError("Codex run outcome or usage was not materialized")
            interactive = subprocess.run(
                [str(binary), "mcp", "brief", "--workspace", str(workspace),
                 "--task-id", "interactive", "--task", "Inspect helper.py"],
                cwd=workspace, env=environment, capture_output=True,
                text=True, timeout=20, check=True,
            )
            interactive_brain = json.loads(interactive.stdout).get("againBrain")
            if not interactive_brain or "helper.py" not in {
                item["path"] for item in interactive_brain["recentCurrentFiles"]
            }:
                raise RuntimeError("interactive task brief did not receive current Brain history")

            launch("second", "Improve a.py second task")
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            if "--json" not in calls[0]:
                raise RuntimeError("launcher did not enable structured events")
            if "AGAIN_BRAIN" not in calls[1][-1] or "a.py" not in calls[1][-1]:
                raise RuntimeError("second task did not receive current edit history")
            if "python3 -m unittest discover -s tests" not in calls[1][-1]:
                raise RuntimeError("second task did not receive the test hint")

            (workspace / "a.py").write_text("value = 3\n")
            launch("third", "Inspect a.py third task")
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            if "a.py" in brain_files_in_prompt(calls[2][-1]):
                raise RuntimeError("stale edit history remained current")

            launch("fourth", "Improve ledger balance rendering fourth task")
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            if "helper.py" not in brain_files_in_prompt(calls[3][-1]):
                raise RuntimeError("current read observation was not in the next task")
            if "FILE helper.py DIGEST" in calls[3][-1]:
                raise RuntimeError("history-selected file was already in the initial source preview")
            (workspace / "helper.py").write_text("def helper():\n    return 0\n")
            launch("fifth", "Improve ledger balance rendering fifth task")
            calls = [json.loads(line) for line in (root / "calls.jsonl").read_text().splitlines()]
            if "helper.py" in brain_files_in_prompt(calls[4][-1]):
                raise RuntimeError("stale read observation remained current")

            subprocess.run(
                [str(binary), "brain", "clear", "--workspace", str(workspace)],
                cwd=workspace, env=environment, capture_output=True,
                text=True, timeout=10, check=True,
            )
            cleared = brain()
            if cleared["recentEvents"] or cleared["recentRuns"] or cleared["fileObservations"] or cleared["previousSuccessfulTestCommand"]:
                raise RuntimeError("brain clear retained activity")
            return {
                "schema": "again.brain-single-agent-e2e.v1",
                "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "classification": {"type": "pass", "code": "brain_event_handoff_passed"},
                "capturedCompletedEvents": len(observed),
                "capturedRunOutcomeAndUsage": True,
                "nextTaskReceivedCurrentEdit": True,
                "nextTaskReceivedUnverifiedTestHint": True,
                "staleEditWithheld": True,
                "compoundSourceReadsObservedAndStaleWithheld": True,
                "interactiveTaskStartReceivedBrain": True,
                "priorTaskOverlapSelectedFile": True,
                "clearRemovedEvents": True,
            }
        finally:
            subprocess.run(
                [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                cwd=workspace, env=environment, capture_output=True, timeout=10,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = source_state(ROOT, binary)
    if source["binarySourceBindingVerified"] is not True:
        raise RuntimeError(f"gate requires a clean source-bound binary: {source}")
    report = run(binary)
    report["source"] = source
    serialized = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized)
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
