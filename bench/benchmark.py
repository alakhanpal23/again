#!/usr/bin/env python3
"""Reproducible local product benchmark for Again.

The harness reports measurements and validation outcomes; it does not assert
performance claims. A non-zero exit means a correctness or safety check failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import platform
import shlex
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any


def run(
    command: list[str],
    *,
    cwd: pathlib.Path,
    env: dict[str, str],
    stdin: bytes | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], float]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return completed, (time.perf_counter_ns() - started) / 1_000_000


def percentile(samples: list[float], fraction: float) -> float:
    """Nearest-rank percentile, deterministic for short benchmark sample sets."""
    if not samples:
        raise ValueError("cannot calculate a percentile without samples")
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def distribution(samples: list[float]) -> dict[str, Any]:
    return {
        "samples_ms": samples,
        "p50_ms": percentile(samples, 0.50),
        "p95_ms": percentile(samples, 0.95),
        "mean_ms": statistics.fmean(samples),
    }


def checked_output(
    command: list[str], *, cwd: pathlib.Path, env: dict[str, str]
) -> str | None:
    completed, _ = run(command, cwd=cwd, env=env)
    if completed.returncode:
        return None
    return completed.stdout.decode("utf-8", errors="replace").strip()


def repository_metadata(source_root: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    commit = checked_output(["git", "rev-parse", "HEAD"], cwd=source_root, env=env)
    dirty = checked_output(["git", "status", "--porcelain"], cwd=source_root, env=env)
    return {
        "source_root": str(source_root),
        "commit": commit,
        "dirty": None if dirty is None else bool(dirty),
        "dirty_entries": None if dirty is None else dirty.splitlines(),
    }


def binary_metadata(binary: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    version = checked_output([str(binary), "--version"], cwd=binary.parent, env=env)
    digest = hashlib.sha256()
    with binary.open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return {
        "path": str(binary),
        "version": version,
        "digest": {"algorithm": "sha256", "hex": digest.hexdigest()},
    }


def host_metadata() -> dict[str, Any]:
    return {
        "machine": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "build": list(platform.python_build()),
            "executable": sys.executable,
        },
    }


def hook_call(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    env: dict[str, str],
    command: str,
    session: str,
) -> tuple[str | None, float, subprocess.CompletedProcess[bytes]]:
    event = {
        "session_id": session,
        "transcript_path": None,
        "cwd": str(workspace),
        "hook_event_name": "PreToolUse",
        "model": "benchmark",
        "permission_mode": "default",
        "turn_id": "benchmark-turn",
        "tool_name": "Bash",
        "tool_use_id": "benchmark-call",
        "tool_input": {"command": command},
    }
    hook, hook_ms = run(
        [str(binary), "hook"],
        cwd=workspace,
        env=env,
        stdin=json.dumps(event, separators=(",", ":")).encode(),
    )
    if hook.returncode:
        raise RuntimeError(f"hook failed: {hook.stderr.decode(errors='replace')}")
    if not hook.stdout:
        return None, hook_ms, hook
    output = json.loads(hook.stdout)
    rewritten = output["hookSpecificOutput"]["updatedInput"]["command"]
    argv = shlex.split(rewritten)
    if len(argv) < 3 or argv[-2] != "--call":
        raise RuntimeError(f"unexpected rewrite: {rewritten}")
    return argv[-1], hook_ms, hook


def execute_call(
    binary: pathlib.Path, call_id: str, workspace: pathlib.Path, env: dict[str, str]
) -> tuple[subprocess.CompletedProcess[bytes], float]:
    return run([str(binary), "exec", "--call", call_id], cwd=workspace, env=env)


def result_id_from_last_event(
    binary: pathlib.Path, workspace: pathlib.Path, env: dict[str, str]
) -> str:
    completed, _ = run(
        [str(binary), "explain", "--json"], cwd=workspace, env=env
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode(errors="replace"))
    result_id = json.loads(completed.stdout).get("result_id")
    if not isinstance(result_id, str) or not result_id:
        raise RuntimeError("last Again event did not expose a result id")
    return result_id


def exact_show_recovery_check(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    env: dict[str, str],
    expected_stdout: bytes,
) -> dict[str, Any]:
    result_id = result_id_from_last_event(binary, workspace, env)
    recovered, recovery_ms = run(
        [str(binary), "show", result_id], cwd=workspace, env=env
    )
    exact = (
        recovered.returncode == 0
        and recovered.stdout == expected_stdout
        and recovered.stderr == b""
    )
    if not exact:
        raise RuntimeError("again show did not recover exact stored stdout/stderr")
    return {"result_id": result_id, "exact": exact, "elapsed_ms": recovery_ms}


def no_rewrite_matrix(
    binary: pathlib.Path, workspace: pathlib.Path, env: dict[str, str], session: str
) -> list[dict[str, Any]]:
    commands = [
        "curl https://example.com",
        "touch should-not-be-created",
        "git status --short",
        "echo unhandled",
        "cat payload.txt | wc -c",
        "cat /etc/passwd",
        "cat -",
    ]
    results = []
    for command in commands:
        call_id, hook_ms, hook = hook_call(binary, workspace, env, command, session)
        rewritten = call_id is not None or bool(hook.stdout)
        results.append(
            {
                "command": command,
                "hook_ms": hook_ms,
                "rewritten": rewritten,
                "returncode": hook.returncode,
            }
        )
        if rewritten:
            raise RuntimeError(f"unsafe/unhandled command was rewritten: {command}")
    if (workspace / "should-not-be-created").exists():
        raise RuntimeError("hook executed a mutation command")
    return results


def gate(name: str, observed: float, threshold: float) -> dict[str, Any]:
    return {
        "name": name,
        "observed": observed,
        "threshold": threshold,
        "comparison": "<" if name != "output_reduction" else ">=",
        "status": "pass"
        if (observed >= threshold if name == "output_reduction" else observed < threshold)
        else "fail",
    }


def gates(
    *, hook_p95: float, hit_p95: float, output_reduction: float, baseline_p50: float
) -> dict[str, Any]:
    evaluated: dict[str, Any] = {
        "hook_p95_ms": gate("hook_p95_ms", hook_p95, 10.0),
        "hit_p95_ms": gate("hit_p95_ms", hit_p95, 100.0),
        "output_reduction": gate("output_reduction", output_reduction, 0.50),
    }
    # A sub-500ms baseline is too short for this harness to make a product-speed
    # claim. When it is long enough, require warm p95 to beat baseline p50.
    if baseline_p50 < 500.0:
        evaluated["speed"] = {
            "status": "not_applicable",
            "reason": "baseline_p50_ms_below_500",
            "baseline_p50_ms": baseline_p50,
        }
    else:
        evaluated["speed"] = gate("speed", hit_p95, baseline_p50)
    return evaluated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--iterations", type=int, default=7)
    parser.add_argument("--payload-kib", type=int, default=2048)
    parser.add_argument(
        "--json-out",
        type=pathlib.Path,
        help="write JSON to a new path; refuses to overwrite an existing file",
    )
    arguments = parser.parse_args()
    if arguments.iterations < 1:
        raise SystemExit("--iterations must be at least 1")
    if arguments.payload_kib < 1:
        raise SystemExit("--payload-kib must be at least 1")
    if arguments.json_out is not None and arguments.json_out.exists():
        raise SystemExit(f"refusing to overwrite existing JSON output: {arguments.json_out}")

    binary = arguments.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Again binary not found: {binary}")

    inherited_env = os.environ.copy()
    source_root = pathlib.Path(__file__).resolve().parents[1]
    provenance = {
        "repository": repository_metadata(source_root, inherited_env),
        "binary": binary_metadata(binary, inherited_env),
        "host": host_metadata(),
    }

    with tempfile.TemporaryDirectory(prefix="again-bench-") as temporary:
        root = pathlib.Path(temporary)
        workspace = root / "workspace"
        state = root / "state"
        workspace.mkdir()
        (workspace / ".git").mkdir()
        line = b"needle: deterministic benchmark payload\n"
        repeats = max(1, arguments.payload_kib * 1024 // len(line))
        payload = line * repeats
        (workspace / "payload.txt").write_bytes(payload)

        env = inherited_env.copy()
        env["AGAIN_HOME"] = str(state)
        env["LC_ALL"] = "C"
        command = "cat payload.txt"
        session = "again-benchmark-session"

        baseline_samples = []
        baseline_bytes = None
        for _ in range(arguments.iterations):
            baseline, elapsed_ms = run(["cat", "payload.txt"], cwd=workspace, env=env)
            if baseline.returncode:
                raise RuntimeError(baseline.stderr.decode(errors="replace"))
            baseline_samples.append(elapsed_ms)
            baseline_bytes = len(baseline.stdout) + len(baseline.stderr)
        assert baseline_bytes is not None

        first_id, cold_hook_ms, _ = hook_call(binary, workspace, env, command, session)
        if first_id is None:
            raise RuntimeError("eligible fixture was not rewritten")
        cold, cold_exec_ms = execute_call(binary, first_id, workspace, env)
        if cold.returncode or cold.stdout != payload or cold.stderr:
            raise RuntimeError("cold execution did not return exact payload")
        recovery = exact_show_recovery_check(binary, workspace, env, payload)

        hook_samples = []
        exec_samples = []
        end_to_end_samples = []
        warm_output_bytes = []
        compact_markers = []
        for _ in range(arguments.iterations):
            call_id, hook_ms, _ = hook_call(binary, workspace, env, command, session)
            if call_id is None:
                raise RuntimeError("warm eligible fixture was not rewritten")
            completed, exec_ms = execute_call(binary, call_id, workspace, env)
            if completed.returncode:
                raise RuntimeError(completed.stderr.decode(errors="replace"))
            hook_samples.append(hook_ms)
            exec_samples.append(exec_ms)
            end_to_end_samples.append(hook_ms + exec_ms)
            warm_output_bytes.append(len(completed.stdout) + len(completed.stderr))
            compact_markers.append(b"exact repeat" in completed.stdout)

        unsafe_matrix = no_rewrite_matrix(binary, workspace, env, session)

        (workspace / "payload.txt").write_bytes(b"changed\n")
        changed_id, mutation_hook_ms, _ = hook_call(binary, workspace, env, command, session)
        if changed_id is None:
            raise RuntimeError("mutated eligible fixture was not rewritten")
        changed, mutation_exec_ms = execute_call(binary, changed_id, workspace, env)
        mutation_invalidated = (
            changed.returncode == 0
            and changed.stdout == b"changed\n"
            and b"exact repeat" not in changed.stdout
        )
        if not mutation_invalidated:
            raise RuntimeError("input mutation did not invalidate cached output")

        baseline_distribution = distribution(baseline_samples)
        hook_distribution = distribution(hook_samples)
        exec_distribution = distribution(exec_samples)
        end_to_end_distribution = distribution(end_to_end_samples)
        output_reduction = 1 - statistics.median(warm_output_bytes) / baseline_bytes
        result = {
            "schema": "again.benchmark.v2",
            "provenance": provenance,
            "fixture": {
                "command": command,
                "payload_bytes": len(payload),
                "iterations": arguments.iterations,
            },
            "baseline": {
                **baseline_distribution,
                "output_bytes": baseline_bytes,
            },
            "again": {
                "cold": {"hook_ms": cold_hook_ms, "exec_ms": cold_exec_ms},
                "warm_hook": hook_distribution,
                "warm_exec": exec_distribution,
                "warm_end_to_end": end_to_end_distribution,
                "warm_output_bytes": warm_output_bytes,
                "all_warm_results_compact": all(compact_markers),
                "show_recovery": recovery,
                "unsafe_unhandled_matrix": unsafe_matrix,
                "mutation_invalidation": {
                    "passed": mutation_invalidated,
                    "hook_ms": mutation_hook_ms,
                    "exec_ms": mutation_exec_ms,
                },
            },
            "derived": {
                "duplicate_output_reduction_fraction": output_reduction,
                "warm_exec_speedup_vs_baseline_p50": baseline_distribution["p50_ms"]
                / exec_distribution["p50_ms"],
            },
            "gates": gates(
                hook_p95=hook_distribution["p95_ms"],
                hit_p95=exec_distribution["p95_ms"],
                output_reduction=output_reduction,
                baseline_p50=baseline_distribution["p50_ms"],
            ),
        }

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.json_out is None:
        print(rendered, end="")
    else:
        arguments.json_out.parent.mkdir(parents=True, exist_ok=True)
        try:
            with arguments.json_out.open("x", encoding="utf-8") as output:
                output.write(rendered)
        except FileExistsError as error:
            raise SystemExit(
                f"refusing to overwrite existing JSON output: {arguments.json_out}"
            ) from error
        print(f"wrote benchmark JSON to {arguments.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
