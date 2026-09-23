#!/usr/bin/env python3
"""Probe task-scoped context transfer across two real Codex sessions."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import tempfile

from agent_gateway_codex_live_probe_v1 import sha256, source_state


FIXTURE = "# Again shared probe\nalpha beta gamma\n"
SUGGESTION = "README contains alpha beta gamma"
PROMPTS = [
    (
        'Use only Again MCP tools. Call task.start with taskId agent-a and task "Read README.md". '
        'Call repo.read for README.md. Then call context.publish with taskId agent-a, kind '
        f'suggestion, subject readme, statement "{SUGGESTION}". Report each tool outcome. '
        "Do not edit files or use shell."
    ),
    (
        'Use only Again MCP tools. Call task.start with taskId agent-b and task "Read README.md". '
        "Then call context.delta with taskId agent-b and afterCursor 0. Report whether the earlier "
        f'suggestion "{SUGGESTION}" is present and whether it is unverified. '
        "Do not edit files or use shell."
    ),
]
EXPECTED_TOOLS = [["task.start", "repo.read", "context.publish"], ["task.start", "context.delta"]]


def session(base: list[str], prompt: str) -> dict[str, object]:
    try:
        run = subprocess.run(base + [prompt], capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"exitCode": None, "timedOut": True, "tools": [], "final": ""}
    tools = []
    final = ""
    for line in run.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item") or {}
        if event.get("type") == "item.completed" and item.get("type") == "mcp_tool_call":
            tools.append(
                {"server": item.get("server"), "tool": item.get("tool"),
                 "status": item.get("status"), "error": item.get("error")}
            )
        if event.get("type") == "item.completed" and item.get("type") == "agent_message":
            final = item.get("text") or ""
    return {"exitCode": run.returncode, "timedOut": False, "tools": tools, "final": final}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default="target/debug/again")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = args.binary.resolve(strict=True)
    version = subprocess.run(["codex", "--version"], capture_output=True, text=True, check=True).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="again-codex-context-") as temporary:
        workspace = pathlib.Path(temporary)
        fixture = workspace / "README.md"
        fixture.write_text(FIXTURE, encoding="utf-8")
        subprocess.run(["/usr/bin/git", "init", "--quiet", str(workspace)], check=True)
        base = [
            "codex", "exec", "--ephemeral", "--ignore-user-config", "--json",
            "--approve-for-me", "-C", str(workspace),
            "-c", f'mcp_servers.again.command="{binary}"',
            "-c", f'mcp_servers.again.args=["mcp","connect","--workspace","{workspace}"]',
        ]
        sessions = [session(base, prompt) for prompt in PROMPTS]
        accepted = (
            all(
                result["exitCode"] == 0
                and [tool["tool"] for tool in result["tools"]] == expected
                and all(tool["server"] == "again" and tool["status"] == "completed" and not tool["error"] for tool in result["tools"])
                for result, expected in zip(sessions, EXPECTED_TOOLS)
            )
            and SUGGESTION in sessions[1]["final"]
            and "unverified_suggestion" in sessions[1]["final"]
            and fixture.read_text(encoding="utf-8") == FIXTURE
        )
        report = {
            "schema": "again.codex-context-transfer-probe.v1",
            "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "codexVersion": version,
            "againBinarySha256": sha256(binary),
            "harnessSha256": sha256(pathlib.Path(__file__)),
            "source": source_state(root),
            "approvalMode": "approve-for-me",
            "modelSessions": 2,
            "fixtureSha256": hashlib.sha256(FIXTURE.encode()).hexdigest(),
            "sessions": [
                {"exitCode": result["exitCode"], "timedOut": result["timedOut"],
                 "tools": result["tools"],
                 "suggestionReported": SUGGESTION in result["final"],
                 "unverifiedReported": "unverified_suggestion" in result["final"]}
                for result in sessions
            ],
            "fixtureUnchanged": fixture.read_text(encoding="utf-8") == FIXTURE,
            "accepted": accepted,
            "evidenceScope": "local live-agent cross-session diagnostic only",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
