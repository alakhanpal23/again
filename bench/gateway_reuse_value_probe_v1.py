#!/usr/bin/env python3
"""Compare MCP warm reuse with execute-only on identical repository tools."""

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
SMALL = "small fixture\n"
LARGE = ("0123456789abcdef" * 8192) + "\n"


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction + 0.5)))
    return round(ordered[index], 3)


def probe(
    binary: pathlib.Path, workspace: pathlib.Path, state: pathlib.Path,
    name: str, tool: str, arguments: dict[str, object], execute_only: bool,
) -> dict[str, object]:
    command = [str(binary), "mcp", "serve", "--workspace", str(workspace)]
    if execute_only:
        command.append("--execute-only")
    process = subprocess.Popen(
        command, cwd=workspace, env={"PATH": "/usr/bin:/bin", "AGAIN_HOME": str(state)},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1,
    )
    try:
        def request(identifier: int, method: str, params: dict[str, object]) -> tuple[dict[str, object], float]:
            frame = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
            started = time.perf_counter_ns()
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(frame + "\n")
            process.stdin.flush()
            line = process.stdout.readline()
            elapsed = (time.perf_counter_ns() - started) / 1000
            if not line:
                raise RuntimeError("MCP server exited before responding")
            value = json.loads(line)
            if value.get("id") != identifier or "error" in value:
                raise RuntimeError(f"MCP request failed: {value.get('error')}")
            return value, elapsed

        request(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "reuse-value-probe", "version": "1"},
        })
        values = []
        digests = []
        for index in range(SAMPLES + 1):
            result, elapsed = request(index + 2, "tools/call", {"name": tool, "arguments": arguments})
            values.append(elapsed)
            comparable = {
                key: result["result"].get(key)
                for key in ("content", "structuredContent", "isError")
                if key in result["result"]
            }
            digests.append(hashlib.sha256(
                json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest())
    finally:
        assert process.stdin is not None
        process.stdin.close()
        process.wait(timeout=10)
    if len(set(digests)) != 1:
        raise RuntimeError("repeated calls returned different results")
    stats = subprocess.run(
        [str(binary), "stats", "--json"], cwd=workspace,
        env={"PATH": "/usr/bin:/bin", "AGAIN_HOME": str(state)},
        capture_output=True, text=True, timeout=10, check=True,
    )
    counters = json.loads(stats.stdout)
    return {
        "case": name,
        "mode": "execute-only" if execute_only else "automatic",
        "samples": SAMPLES,
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
    parser.add_argument("--source-files", type=int, default=200)
    args = parser.parse_args()
    if not 1 <= args.source_files <= 1000:
        parser.error("--source-files must be between 1 and 1000")
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="again-value-probe-") as temporary:
        base = pathlib.Path(temporary)
        workspace = base / "workspace"
        workspace.mkdir()
        (workspace / "small.txt").write_text(SMALL)
        (workspace / "large.txt").write_text(LARGE)
        source = workspace / "src"
        source.mkdir()
        for index in range(args.source_files):
            (source / f"module_{index:03}.py").write_text(
                f"def item_{index:03}():\n    return 'needle-{index:03}'\n"
            )
        subprocess.run(["/usr/bin/git", "init", "--quiet", str(workspace)], check=True)
        subprocess.run(["/usr/bin/git", "add", "--", "small.txt", "large.txt", "src"], cwd=workspace, check=True)
        subprocess.run([
            "/usr/bin/git", "-c", "user.name=Again Probe", "-c", "user.email=probe@example.invalid",
            "commit", "--quiet", "-m", "fixture",
        ], cwd=workspace, check=True)
        cases = [
            ("stat-small", "repo.stat", {"path": "small.txt"}),
            ("read-small", "repo.read", {"path": "small.txt"}),
            ("read-large", "repo.read", {"path": "large.txt"}),
            (f"search-{args.source_files}", "repo.search", {"path": "src", "pattern": "needle", "maxResults": 200}),
            (f"tree-{args.source_files}", "repo.tree", {"path": "src", "maxResults": 200}),
            (f"list-{args.source_files}", "repo.list", {"path": "src", "maxResults": 200}),
            (f"glob-{args.source_files}", "repo.glob", {"path": "src", "pattern": "*.py", "maxResults": 200}),
            ("manifest-root", "repo.manifest", {"path": "."}),
            ("git-status", "git.status", {}),
        ]
        observations = []
        for name, tool, arguments in cases:
            for execute_only in (True, False):
                state = base / f"state-{name}-{'direct' if execute_only else 'reuse'}"
                observations.append(probe(binary, workspace, state, name, tool, arguments, execute_only))
        pairs = []
        for index in range(0, len(observations), 2):
            direct, automatic = observations[index:index + 2]
            if direct["resultSha256"] != automatic["resultSha256"]:
                raise RuntimeError("direct and automatic results differ")
            pairs.append({
                "case": direct["case"],
                "directWarmP50Micros": direct["warmP50Micros"],
                "automaticWarmP50Micros": automatic["warmP50Micros"],
                "warmP50DeltaMicros": round(direct["warmP50Micros"] - automatic["warmP50Micros"], 3),
            })
    report = {
        "schema": "again.gateway-reuse-value-probe.v1",
        "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidenceScope": "local stdio diagnostic; not a live-agent task-speed result",
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "againBinarySha256": sha256(binary),
        "harnessSha256": sha256(pathlib.Path(__file__)),
        "source": source_state(root),
        "smallFixtureSha256": hashlib.sha256(SMALL.encode()).hexdigest(),
        "largeFixtureSha256": hashlib.sha256(LARGE.encode()).hexdigest(),
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
