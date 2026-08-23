#!/usr/bin/env python3
"""Measure Again on a >=500 ms, low-output audited read workload.

The fixture is a sparse file with one match at the end. Apple's grep must scan
the logical bytes but emits only a short result. Again's cold path hashes and
validates the file; its warm path can use the ctime/inode-validated digest memo
and the result cache. This is intentionally separate from the output-compaction
benchmark so neither benefit hides the other's cost.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import tempfile

import benchmark as common


def write_sparse_fixture(path: pathlib.Path, size_bytes: int) -> None:
    marker = b"needle\n"
    if size_bytes < len(marker):
        raise ValueError("fixture is too small")
    with path.open("wb") as file:
        file.seek(size_bytes - len(marker))
        file.write(marker)
        file.flush()
        os.fsync(file.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--size-mib", type=int, default=1024)
    parser.add_argument("--baseline-iterations", type=int, default=5)
    parser.add_argument("--warm-iterations", type=int, default=15)
    parser.add_argument("--json-out", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.size_mib < 1:
        raise SystemExit("--size-mib must be positive")
    if arguments.baseline_iterations < 1 or arguments.warm_iterations < 1:
        raise SystemExit("iteration counts must be positive")
    if arguments.json_out is not None and arguments.json_out.exists():
        raise SystemExit(f"refusing to overwrite existing JSON output: {arguments.json_out}")

    binary = arguments.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Again binary not found: {binary}")
    inherited_env = os.environ.copy()
    source_root = pathlib.Path(__file__).resolve().parents[1]
    size_bytes = arguments.size_mib * 1024 * 1024

    with tempfile.TemporaryDirectory(prefix="again-slow-gate-") as temporary:
        root = pathlib.Path(temporary)
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / ".git").mkdir()
        payload = workspace / "payload.bin"
        write_sparse_fixture(payload, size_bytes)
        state = root / "state"
        env = inherited_env.copy()
        env["AGAIN_HOME"] = str(state)
        env["LC_ALL"] = "C"
        command = "grep needle payload.bin"
        session = "again-slow-benchmark-session"

        baseline_samples: list[float] = []
        baseline_stdout: bytes | None = None
        for _ in range(arguments.baseline_iterations):
            completed, elapsed = common.run(
                ["/usr/bin/grep", "needle", "payload.bin"], cwd=workspace, env=env
            )
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.decode(errors="replace"))
            if baseline_stdout is None:
                baseline_stdout = completed.stdout
            elif completed.stdout != baseline_stdout:
                raise RuntimeError("native baseline output changed")
            baseline_samples.append(elapsed)
        assert baseline_stdout is not None

        call_id, cold_hook_ms, _ = common.hook_call(binary, workspace, env, command, session)
        if call_id is None:
            raise RuntimeError("slow audited fixture was not rewritten")
        cold, cold_exec_ms = common.execute_call(binary, call_id, workspace, env)
        if cold.returncode != 0 or cold.stdout != baseline_stdout:
            raise RuntimeError("cold Again execution changed grep output")

        hook_samples: list[float] = []
        exec_samples: list[float] = []
        end_to_end_samples: list[float] = []
        compact = []
        for _ in range(arguments.warm_iterations):
            call_id, hook_ms, _ = common.hook_call(binary, workspace, env, command, session)
            if call_id is None:
                raise RuntimeError("warm slow fixture was not rewritten")
            completed, exec_ms = common.execute_call(binary, call_id, workspace, env)
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.decode(errors="replace"))
            hook_samples.append(hook_ms)
            exec_samples.append(exec_ms)
            end_to_end_samples.append(hook_ms + exec_ms)
            compact.append(b"exact repeat" in completed.stdout)
        if not all(compact):
            raise RuntimeError("warm slow results were not compact references")

        # Change one sparse byte while leaving the final grep output unchanged.
        # A correct cache must still miss, execute, and return the full output.
        with payload.open("r+b") as file:
            file.seek(size_bytes // 2)
            file.write(b"x")
            file.flush()
            os.fsync(file.fileno())
        changed_id, mutation_hook_ms, _ = common.hook_call(
            binary, workspace, env, command, session
        )
        if changed_id is None:
            raise RuntimeError("mutated slow fixture was not rewritten")
        changed, mutation_exec_ms = common.execute_call(binary, changed_id, workspace, env)
        mutation_invalidated = (
            changed.returncode == 0
            and changed.stdout == baseline_stdout
            and b"exact repeat" not in changed.stdout
        )
        if not mutation_invalidated:
            raise RuntimeError("same-output input mutation produced a false cache hit")

        baseline = common.distribution(baseline_samples)
        hook = common.distribution(hook_samples)
        execution = common.distribution(exec_samples)
        end_to_end = common.distribution(end_to_end_samples)
        speedup = baseline["p50_ms"] / end_to_end["p95_ms"]
        speed_gate = {
            "threshold": 3.0,
            "comparison": ">=",
            "observed_speedup": speedup,
            "status": (
                "not_applicable"
                if baseline["p50_ms"] < 500.0
                else ("pass" if speedup >= 3.0 else "fail")
            ),
        }
        if baseline["p50_ms"] < 500.0:
            speed_gate["reason"] = "baseline_p50_ms_below_500"

        result = {
            "schema": "again.slow-gate.v1",
            "provenance": {
                "repository": common.repository_metadata(source_root, inherited_env),
                "binary": common.binary_metadata(binary, inherited_env),
                "host": common.host_metadata(),
            },
            "fixture": {
                "command": command,
                "logical_size_bytes": size_bytes,
                "allocated_size_bytes": payload.stat().st_blocks * 512,
                "baseline_iterations": arguments.baseline_iterations,
                "warm_iterations": arguments.warm_iterations,
                "output_bytes": len(baseline_stdout),
            },
            "baseline": baseline,
            "again": {
                "cold_hook_ms": cold_hook_ms,
                "cold_exec_and_double_validation_ms": cold_exec_ms,
                "warm_hook": hook,
                "warm_exec": execution,
                "warm_end_to_end": end_to_end,
                "all_warm_results_compact": all(compact),
                "same_output_mutation_invalidation": {
                    "passed": mutation_invalidated,
                    "hook_ms": mutation_hook_ms,
                    "exec_ms": mutation_exec_ms,
                },
            },
            "gates": {
                "speed": speed_gate,
                "hook_p95_ms": common.gate("hook_p95_ms", hook["p95_ms"], 10.0),
                "hit_p95_ms": common.gate("hit_p95_ms", execution["p95_ms"], 100.0),
            },
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
        print(f"wrote slow-gate JSON to {arguments.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
