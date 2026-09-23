#!/usr/bin/env python3
"""Run one bounded, read-only Codex session against the local Again MCP server.

This is an integration probe, not a task-quality or acceleration benchmark.
Codex uses the current user's existing authentication. The temporary repository
contains only fixed public fixture bytes; no user configuration is loaded.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import tempfile


FIXTURE = "# Again live probe\nalpha beta gamma\n"
PROMPT = (
    "Use the Again MCP tools for this read-only diagnostic. Call task.start "
    'with task id live-probe and prompt "Read README.md". Then call repo.read '
    "for README.md. Report the returned content and whether both MCP calls "
    "succeeded. Do not edit files or use shell commands."
)
REPEAT_PROMPT = (
    'Use only Again MCP tools. Call task.start with taskId repeat-probe and task "Read README.md twice". '
    "Call repo.read for README.md two separate times with identical arguments. This is a test of "
    "exact repeated calls, so perform both even if the first succeeded. Report both results. "
    "Do not edit files or use shell."
)


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_state(root: pathlib.Path) -> dict[str, object]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"], cwd=root, capture_output=True, text=True, check=True
        ).stdout
    )
    return {"head": head, "dirty": dirty, "binarySourceBindingVerified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default="target/debug/again")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--repeat-read", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = args.binary.resolve(strict=True)
    codex_version = subprocess.run(
        ["codex", "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="again-codex-live-") as temporary:
        workspace = pathlib.Path(temporary)
        fixture = workspace / "README.md"
        fixture.write_text(FIXTURE, encoding="utf-8")
        subprocess.run(
            ["/usr/bin/git", "init", "--quiet", str(workspace)], check=True
        )
        command = [
            "codex", "exec", "--ephemeral", "--ignore-user-config", "--json",
            "--approve-for-me", "-C", str(workspace),
            "-c", f'mcp_servers.again.command="{binary}"',
            "-c", f'mcp_servers.again.args=["mcp","connect","--workspace","{workspace}"]',
            REPEAT_PROMPT if args.repeat_read else PROMPT,
        ]
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=120)
            timed_out = False
        except subprocess.TimeoutExpired as error:
            run = error
            timed_out = True

        stdout = run.stdout or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        events = []
        final_text = ""
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = event.get("item") or {}
            if item.get("type") == "mcp_tool_call" and event.get("type") == "item.completed":
                events.append(
                    {
                        "server": item.get("server"),
                        "tool": item.get("tool"),
                        "status": item.get("status"),
                        "error": str(item.get("error"))[:300] if item.get("error") else None,
                    }
                )
            if item.get("type") == "agent_message" and event.get("type") == "item.completed":
                final_text = item.get("text") or ""

        stats = None
        if args.repeat_read:
            stats_run = subprocess.run(
                [str(binary), "stats", "--json"], cwd=workspace,
                capture_output=True, text=True, timeout=30
            )
            if stats_run.returncode == 0:
                observed = json.loads(stats_run.stdout)
                stats = {
                    key: observed.get(key)
                    for key in (
                        "requested", "executed", "exact_hits", "provider_calls_avoided",
                        "false_hit_quarantines"
                    )
                }
        expected_tools = ["task.start", "repo.read", "repo.read"] if args.repeat_read else ["task.start", "repo.read"]
        accepted = (
            not timed_out
            and run.returncode == 0
            and [event["tool"] for event in events] == expected_tools
            and all(event["server"] == "again" and event["status"] == "completed" and not event["error"] for event in events)
            and "alpha beta gamma" in final_text
            and fixture.read_text(encoding="utf-8") == FIXTURE
            and sorted(path.name for path in workspace.iterdir()) == [".git", "README.md"]
            and (not args.repeat_read or stats == {
                "requested": 2, "executed": 1, "exact_hits": 1,
                "provider_calls_avoided": 1, "false_hit_quarantines": 0
            })
        )
        report = {
            "schema": "again.codex-live-repeat-probe.v1" if args.repeat_read else "again.codex-live-mcp-probe.v1",
            "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "codexVersion": codex_version,
            "againBinary": str(binary),
            "againBinarySha256": sha256(binary),
            "source": source_state(root),
            "approvalMode": "approve-for-me",
            "modelSessions": 1,
            "modelCallsMeasured": False,
            "repeatRead": args.repeat_read,
            "gatewayStats": stats,
            "fixtureSha256": hashlib.sha256(FIXTURE.encode()).hexdigest(),
            "toolEvents": events,
            "readResultMarkerPresent": "alpha beta gamma" in final_text,
            "fixtureUnchanged": fixture.read_text(encoding="utf-8") == FIXTURE,
            "timedOut": timed_out,
            "exitCode": None if timed_out else run.returncode,
            "accepted": accepted,
            "evidenceScope": "local live-agent integration diagnostic only",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"accepted": accepted, "output": str(args.output), "toolEvents": events}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
