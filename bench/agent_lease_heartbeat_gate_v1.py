#!/usr/bin/env python3
"""Prove that a long Codex task survives the daemon's 60-second MCP idle limit."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import tempfile
import time

from agent_gateway_codex_live_probe_v1 import sha256, source_state


def run(binary: pathlib.Path) -> dict:
    root = pathlib.Path(__file__).resolve().parents[1]
    source = source_state(root, binary)
    if not source["binarySourceBindingVerified"]:
        raise RuntimeError("release binary is not bound to clean source")
    with tempfile.TemporaryDirectory(prefix="again-lease-heartbeat-") as temporary:
        fixture = pathlib.Path(temporary)
        workspace = fixture / "repo"
        workspace.mkdir()
        subprocess.run(["git", "init", "-q", str(workspace)], check=True)
        fake_bin = fixture / "bin"
        fake_bin.mkdir()
        fake_codex = fake_bin / "codex"
        fake_codex.write_text(
            "#!/usr/bin/env python3\n"
            "import json, time\n"
            "time.sleep(65)\n"
            "print(json.dumps({'type':'turn.completed','usage':"
            "{'input_tokens':1,'cached_input_tokens':0,'output_tokens':1}}),flush=True)\n"
            "print(json.dumps({'type':'item.completed','item':"
            "{'id':'done','type':'agent_message','text':'Done'}}),flush=True)\n"
        )
        fake_codex.chmod(0o700)
        environment = os.environ.copy()
        environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
        environment["AGAIN_HOME"] = str(fixture / "state")
        command = [
            str(binary), "codex", "--workspace", str(workspace),
            "--task-id", "long-running-agent", "--task", "Complete the long task",
            "--", "--ephemeral",
        ]
        try:
            started = time.monotonic()
            result = subprocess.run(
                command, cwd=workspace, env=environment, capture_output=True,
                text=True, timeout=90,
            )
            elapsed = time.monotonic() - started
            brain = subprocess.run(
                [str(binary), "brain", "show", "--workspace", str(workspace)],
                cwd=workspace, env=environment, capture_output=True, text=True,
                timeout=10, check=True,
            )
            runs = [row for row in json.loads(brain.stdout)["recentRuns"]
                    if row["task_id"] == "long-running-agent"]
            if (result.returncode != 0 or elapsed < 65 or "Done" not in result.stdout
                    or len(runs) != 1 or runs[0]["exit_code"] != 0
                    or runs[0]["turn_completed"] is not True):
                raise RuntimeError(
                    f"long agent task did not survive heartbeat: exit={result.returncode}, "
                    f"elapsed={elapsed:.2f}, runs={len(runs)}, stderr={result.stderr[-300:]}"
                )
            return {
                "schema": "again.agent-lease-heartbeat-gate.v1",
                "classification": {"type": "pass", "code": "long_agent_lease_renewed"},
                "source": source,
                "binarySha256": sha256(binary),
                "elapsedSeconds": round(elapsed, 3),
                "agentExitCode": result.returncode,
                "brainRun": runs[0],
            }
        finally:
            subprocess.run(
                [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                cwd=workspace, env=environment, capture_output=True, timeout=10,
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    report = run(binary)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(args.output), "classification": report["classification"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
