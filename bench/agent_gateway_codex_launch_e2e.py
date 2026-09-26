#!/usr/bin/env python3
"""Exercise a release agent launcher lease lifecycle with isolated fake clients."""

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

from agent_gateway_product_e2e import inspect_clean_source, pin_binary


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


def wait_for(path: pathlib.Path, process: subprocess.Popen[bytes], seconds: float = 10) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        require(process.poll() is None, "Codex launcher exited before fake client became ready")
        time.sleep(0.025)
    raise RuntimeError("fake Codex client did not become ready")


def run(binary: pathlib.Path, source_root: pathlib.Path, source_sha: str,
        client: str) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="again-codex-launch-e2e-") as temporary:
        root = pathlib.Path(temporary).resolve()
        home, state, workspace, fake_bin = (root / name for name in ("home", "state", "workspace", "bin"))
        for path in (home, state, workspace, fake_bin):
            path.mkdir(mode=0o700)
        source = inspect_clean_source(source_root, source_sha, home)
        pinned = pin_binary(binary, root / "pinned" / "again")
        (workspace / "a.py").write_text("value = 1\n")
        subprocess.run(["git", "init", "-q", str(workspace)], check=True, timeout=5)
        fake_client = fake_bin / client
        fake_client.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys, time\n"
            "pathlib.Path(os.environ['FAKE_READY']).write_text(json.dumps(sys.argv[1:]))\n"
            "while not pathlib.Path(os.environ['FAKE_RELEASE']).exists(): time.sleep(0.025)\n"
            "if 'exec' in sys.argv: print(json.dumps({'type':'turn.completed','usage':"
            "{'input_tokens':1,'cached_input_tokens':0,'output_tokens':1}}), flush=True)\n"
        )
        fake_client.chmod(0o700)
        environment = os.environ.copy()
        environment.update(HOME=str(home), AGAIN_HOME=str(state), PATH=str(fake_bin) + os.pathsep + environment["PATH"])
        task = "Repair a.py"
        command_prefix = [str(pinned.executable_path), client, "--workspace", str(workspace),
                          "--task-id", "repair", "--task", task]
        client_flags = ["--ephemeral"] if client == "codex" else ["--output-format", "json"]
        command = command_prefix + ["--"] + client_flags
        brief_command = [str(pinned.executable_path), "mcp", "brief", "--workspace", str(workspace),
                         "--task-id", "repair", "--task", task]
        processes: list[subprocess.Popen[bytes]] = []

        def launch(name: str, wait_ready: bool = True,
                   invocation_command: list[str] | None = None) -> tuple[subprocess.Popen[bytes], pathlib.Path, pathlib.Path]:
            ready, release = root / f"{name}.ready", root / f"{name}.release"
            invocation = environment | {"FAKE_READY": str(ready), "FAKE_RELEASE": str(release)}
            process = subprocess.Popen(invocation_command or command, cwd=workspace, env=invocation,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            processes.append(process)
            if wait_ready:
                wait_for(ready, process)
            return process, ready, release

        def brief() -> dict[str, object]:
            result = subprocess.run(brief_command, cwd=workspace, env=environment,
                                    capture_output=True, text=True, timeout=15, check=True)
            return json.loads(result.stdout)

        try:
            leader, leader_ready, leader_release = launch("leader")
            leader_argv = json.loads(leader_ready.read_text())
            expected_mode = "exec" if client == "codex" else "-p"
            require(leader_argv[0] == expected_mode and "leader lease" in leader_argv[-1],
                    "leader did not receive the verified lease brief")
            if client == "claude":
                config_index = leader_argv.index("--mcp-config")
                config = json.loads(leader_argv[config_index + 1])
                server = config["mcpServers"]["again"]
                require(server["command"] == str(pinned.executable_path)
                        and server["args"] == ["mcp", "connect", "--workspace", str(workspace)],
                        "Claude did not receive the exact workspace MCP connection")
            require(brief()["coordination"]["peerActive"] is True,
                    "first live launcher did not expose an active leader")
            follower, follower_ready, follower_release = launch("follower", wait_ready=False)
            time.sleep(0.5)
            require(follower.poll() is None, "waiting follower exited before leader")
            require(not follower_ready.exists(), "follower launched before the leader retired")
            require(brief()["coordination"]["peerActive"] is True,
                    "follower unexpectedly replaced the active leader")
            (workspace / "a.py").write_text("value = 2\n")
            leader_release.touch()
            require(leader.wait(timeout=10) == 0, "leader launcher failed")
            wait_for(follower_ready, follower)
            follower_argv = json.loads(follower_ready.read_text())
            require("leader lease" in follower_argv[-1]
                    and "value = 2" in follower_argv[-1],
                    "follower did not claim and refresh after the leader's edit")
            require(brief()["coordination"]["peerActive"] is True,
                    "follower did not take over the leader lease")
            follower_release.touch()
            require(follower.wait(timeout=10) == 0, "follower launcher failed")
            require(brief()["coordination"]["peerActive"] is False,
                    "follower lease remained active after follower exit")
            slow_leader, _, slow_leader_release = launch("slow-leader")
            fallback_command = command_prefix + ["--peer-wait-seconds", "1", "--"] + client_flags
            slow_follower, slow_follower_ready, slow_follower_release = launch(
                "slow-follower", invocation_command=fallback_command
            )
            slow_follower_argv = json.loads(slow_follower_ready.read_text())
            require("active peer leader" in slow_follower_argv[-1],
                    "bounded wait did not launch with peer guidance")
            require(brief()["coordination"]["peerActive"] is True,
                    "bounded follower unexpectedly replaced its active leader")
            slow_follower_release.touch()
            require(slow_follower.wait(timeout=10) == 0, "bounded follower failed")
            slow_leader_release.touch()
            require(slow_leader.wait(timeout=10) == 0, "slow leader failed")
            require(brief()["coordination"]["peerActive"] is False,
                    "slow leader lease remained active after exit")
            return {
                "schema": "again.agent-launch-e2e.v1",
                "client": client,
                "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "classification": {"type": "pass", "code": "launcher_lease_handoff_passed"},
                "source": source,
                "againBinarySha256": pinned.sha256,
                "leaderPromptSha256": hashlib.sha256(leader_argv[-1].encode()).hexdigest(),
                "followerPromptSha256": hashlib.sha256(follower_argv[-1].encode()).hexdigest(),
                "leaderVisibleDuringRun": True,
                "followerWaitedForLeader": True,
                "followerClaimedAfterLeader": True,
                "followerReceivedFreshEditedSource": True,
                "boundedWaitFallbackReportedPeer": True,
                "leaderRetiredAfterExit": True,
            }
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                if process.stderr is not None:
                    process.stderr.close()
            subprocess.run([str(pinned.executable_path), "mcp", "daemon", "stop",
                            "--workspace", str(workspace)], cwd=workspace, env=environment,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--client", choices=("codex", "claude"), default="codex")
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), "output must be a new absolute path")
    report = run(args.again_binary, args.source_root, args.source_git_sha, args.client)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "classification": report["classification"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
