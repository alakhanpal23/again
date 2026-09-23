#!/usr/bin/env python3
"""Measure task-bound MCP reuse against the same daemon's execute-only path."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import platform
import statistics
import subprocess
import tempfile
import time

from agent_gateway_codex_live_probe_v1 import sha256, source_state


SAMPLES = 40


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction + 0.5)))
    return round(ordered[index], 3)


def run_case(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    state: pathlib.Path,
    name: str,
    tool: str,
    arguments: dict[str, object],
    execute_only: bool,
    samples: int = SAMPLES,
) -> dict[str, object]:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(state / "home"), "AGAIN_HOME": str(state)}
    state.mkdir(mode=0o700)
    (state / "home").mkdir(mode=0o700)
    command = [str(binary), "mcp", "daemon", "serve", "--workspace", str(workspace)]
    if execute_only:
        command.append("--execute-only")
    daemon = subprocess.Popen(command, cwd=workspace, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    proxy = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = subprocess.run(
                [str(binary), "mcp", "daemon", "status", "--workspace", str(workspace)],
                cwd=workspace, env=env, capture_output=True, timeout=2,
            )
            if status.returncode == 0:
                break
            if daemon.poll() is not None:
                detail = daemon.stderr.read().decode(errors="replace") if daemon.stderr is not None else ""
                raise RuntimeError(f"daemon exited before readiness: {daemon.returncode}: {detail}")
            time.sleep(0.02)
        else:
            raise RuntimeError("daemon readiness timed out")
        proxy = subprocess.Popen(
            [str(binary), "mcp", "connect", "--workspace", str(workspace)],
            cwd=workspace, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True, bufsize=1,
        )

        def request(identifier: int, method: str, params: dict[str, object]) -> tuple[dict[str, object], float]:
            assert proxy is not None and proxy.stdin is not None and proxy.stdout is not None
            frame = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
            started = time.perf_counter_ns()
            proxy.stdin.write(frame + "\n")
            proxy.stdin.flush()
            line = proxy.stdout.readline()
            elapsed = (time.perf_counter_ns() - started) / 1000
            if not line:
                raise RuntimeError("proxy exited before responding")
            value = json.loads(line)
            if value.get("id") != identifier or "error" in value:
                raise RuntimeError(f"MCP request failed: {value.get('error')}")
            return value, elapsed

        request(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "task-reuse-value-probe", "version": "1"},
        })
        started, task_start_micros = request(2, "tools/call", {
            "name": "task.start", "arguments": {"taskId": "value-probe", "task": "Inspect this fixture"},
        })
        if started["result"].get("isError"):
            raise RuntimeError(f"task.start refused: {started['result']}")
        values: list[float] = []
        digests: list[str] = []
        for index in range(samples + 1):
            result, elapsed = request(index + 3, "tools/call", {"name": tool, "arguments": arguments})
            if result["result"].get("isError"):
                raise RuntimeError(f"{tool} refused: {result['result']}")
            values.append(elapsed)
            comparable = {key: result["result"].get(key) for key in ("content", "structuredContent", "isError") if key in result["result"]}
            digests.append(hashlib.sha256(json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        if len(set(digests)) != 1:
            raise RuntimeError("repeated calls returned different results")
    finally:
        if proxy is not None:
            if proxy.stdin is not None:
                proxy.stdin.close()
            proxy.wait(timeout=10)
        if daemon.poll() is None:
            subprocess.run(
                [str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                cwd=workspace, env=env, capture_output=True, timeout=5,
            )
        daemon.wait(timeout=10)
        if daemon.stderr is not None:
            daemon.stderr.close()
    stats = subprocess.run([str(binary), "stats", "--json"], cwd=workspace, env=env, capture_output=True, text=True, timeout=10, check=True)
    counters = json.loads(stats.stdout)
    return {
        "case": name,
        "mode": "execute-only" if execute_only else "automatic",
        "samples": samples,
        "taskStartMicros": round(task_start_micros, 3),
        "coldMicros": round(values[0], 3),
        "warmP50Micros": percentile(values[1:], 0.5),
        "warmP95Micros": percentile(values[1:], 0.95),
        "warmMeanMicros": round(statistics.fmean(values[1:]), 3),
        "resultSha256": digests[0],
        "requested": counters["requested"],
        "executed": counters["executed"],
        "exactHits": counters["exact_hits"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, default="target/debug/again")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--source-files", type=int, default=1000)
    parser.add_argument("--samples", type=int, default=SAMPLES)
    args = parser.parse_args()
    if not 1 <= args.source_files <= 10000:
        parser.error("--source-files must be between 1 and 10000")
    if not 3 <= args.samples <= 100:
        parser.error("--samples must be between 3 and 100")
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="again-task-value-probe-") as temporary:
        base = pathlib.Path(temporary)
        workspace = base / "workspace"
        workspace.mkdir()
        (workspace / "small.txt").write_text("small fixture\n")
        (workspace / "large.txt").write_text(("0123456789abcdef" * 8192) + "\n")
        source = workspace / "src"
        source.mkdir()
        for index in range(args.source_files):
            (source / f"module_{index:03}.py").write_text(f"def item_{index:03}():\n    return 'needle-{index:03}'\n")
        subprocess.run(["/usr/bin/git", "init", "--quiet", str(workspace)], check=True)
        subprocess.run(["/usr/bin/git", "add", "--", "small.txt", "large.txt", "src"], cwd=workspace, check=True)
        subprocess.run([
            "/usr/bin/git", "-c", "user.name=Again Probe", "-c", "user.email=probe@example.invalid",
            "commit", "--quiet", "-m", "fixture",
        ], cwd=workspace, check=True)
        cases = [
            ("read-small", "repo.read", {"path": "small.txt"}),
            ("read-large", "repo.read", {"path": "large.txt"}),
            (f"search-{args.source_files}", "repo.search", {"path": "src", "pattern": "needle", "maxResults": 200}),
            (f"tree-{args.source_files}", "repo.tree", {"path": "src", "maxResults": 200}),
            ("git-status", "git.status", {}),
        ]
        observations = []
        for name, tool, arguments in cases:
            for execute_only in (True, False):
                state = base / f"state-{name}-{'direct' if execute_only else 'reuse'}"
                observations.append(run_case(binary, workspace, state, name, tool, arguments, execute_only, args.samples))
        pairs = []
        for index in range(0, len(observations), 2):
            direct, automatic = observations[index:index + 2]
            if direct["resultSha256"] != automatic["resultSha256"]:
                raise RuntimeError(f"direct and automatic results differ for {direct['case']}")
            pairs.append({
                "case": direct["case"],
                "directWarmP50Micros": direct["warmP50Micros"],
                "automaticWarmP50Micros": automatic["warmP50Micros"],
                "warmP50DeltaMicros": round(direct["warmP50Micros"] - automatic["warmP50Micros"], 3),
            })
    report = {
        "schema": "again.gateway-task-reuse-value-probe.v1",
        "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidenceScope": "local authenticated daemon task diagnostic; not a live-agent speed result",
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "againBinarySha256": sha256(binary),
        "harnessSha256": sha256(pathlib.Path(__file__)),
        "source": source_state(root),
        "sourceFiles": args.source_files,
        "observations": observations,
        "pairs": pairs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "pairs": pairs}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
