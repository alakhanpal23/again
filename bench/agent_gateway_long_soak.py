#!/usr/bin/env python3
"""Run repeated 100-client beta cycles for a genuine multi-hour interval."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
from typing import Any, Callable

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from bench import agent_gateway_chaos_soak as chaos


SCHEMA = "again.agent-gateway-long-soak.v1"
MIN_DURATION_SECONDS = 2 * 60 * 60
MAX_DURATION_SECONDS = 24 * 60 * 60
CYCLE_BOUND_SECONDS = 60.0


def run_long_soak(
    binary: pathlib.Path,
    output_dir: pathlib.Path,
    *,
    duration_seconds: float,
    seed: int,
    clock: Callable[[], float] = time.monotonic,
    cycle_runner: Callable[..., dict[str, Any]] = chaos.run,
) -> dict[str, Any]:
    if not MIN_DURATION_SECONDS <= duration_seconds <= MAX_DURATION_SECONDS:
        raise chaos.HarnessRefusal(
            "long_soak_duration", "long soak duration must be between two and twenty-four hours"
        )
    if isinstance(seed, bool) or not 0 <= seed < 2**64:
        raise chaos.HarnessRefusal("seed", "seed must be an unsigned 64-bit integer")
    binary = binary.resolve(strict=True)
    output_dir = output_dir.resolve(strict=False)
    if not output_dir.is_absolute() or output_dir.exists() or output_dir.is_symlink():
        raise chaos.HarnessRefusal(
            "evidence_path", "long soak output directory must be a new absolute path"
        )
    output_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.mkdir(output_dir, 0o700)
    os.chmod(output_dir, 0o700)

    started = clock()
    cycles: list[dict[str, Any]] = []
    source_git_sha: str | None = None
    binary_sha256: str | None = None
    total_operations = 0
    try:
        while not cycles or clock() - started < duration_seconds:
            index = len(cycles)
            cycle_path = output_dir / f"cycle-{index:04d}.json"
            report = cycle_runner(
                binary,
                mode="beta",
                concurrency=100,
                duration=CYCLE_BOUND_SECONDS,
                seed=(seed + index) % 2**64,
                output=cycle_path,
            )
            exact = report.get("exact_probe", {})
            resources = report.get("resource_observation", {})
            if (
                report.get("classification", {}).get("type") != "pass"
                or report.get("mode") != "beta"
                or report.get("concurrency") != 100
                or report.get("false_hit_count") != 0
                or exact.get("sessions") != 100
                or exact.get("referenced_results") != exact.get("operations")
                or exact.get("unreferenced_direct_results") != 0
                or exact.get("unique_result_ids") != 1
                or resources.get("resource_leaks") != []
                or resources.get("all_owned_process_groups_absent") is not True
            ):
                raise chaos.HarnessRefusal(
                    "long_soak_cycle", f"beta cycle {index} did not satisfy the exact soak contract"
                )
            cycle_source = report.get("source_git_sha")
            cycle_binary = report.get("binary", {}).get("sha256")
            if source_git_sha is None:
                source_git_sha = str(cycle_source)
                binary_sha256 = str(cycle_binary)
            elif cycle_source != source_git_sha or cycle_binary != binary_sha256:
                raise chaos.HarnessRefusal(
                    "long_soak_identity", "source or binary identity changed between soak cycles"
                )
            operations = int(exact["operations"])
            total_operations += operations
            cycles.append(
                {
                    "index": index,
                    "seed": (seed + index) % 2**64,
                    "report": cycle_path.name,
                    "report_sha256": report["report_sha256"],
                    "elapsed_seconds": report["elapsed_seconds"],
                    "operations": operations,
                }
            )
    except BaseException as error:
        failure = {
            "schema": SCHEMA,
            "classification": {
                "type": "failure",
                "code": getattr(error, "code", "long_soak_exception"),
            },
            "duration_requested_seconds": duration_seconds,
            "duration_observed_seconds": round(clock() - started, 6),
            "completed_cycles": len(cycles),
            "completed_operations": total_operations,
            "source_git_sha": source_git_sha,
            "binary_sha256": binary_sha256,
            "cycles": cycles,
        }
        failure["report_sha256"] = chaos.sha256_bytes(chaos.canonical_json(failure))
        chaos.write_exclusive(output_dir / "summary.json", chaos.canonical_json(failure))
        raise

    summary = {
        "schema": SCHEMA,
        "classification": {"type": "pass", "code": "multi_hour_beta_soak_passed"},
        "duration_requested_seconds": duration_seconds,
        "duration_observed_seconds": round(clock() - started, 6),
        "completed_cycles": len(cycles),
        "completed_operations": total_operations,
        "source_git_sha": source_git_sha,
        "binary_sha256": binary_sha256,
        "invariants": {
            "concurrent_clients": 100,
            "all_results_referenced": True,
            "one_canonical_result_per_cycle": True,
            "zero_false_hits": True,
            "zero_resource_leaks": True,
        },
        "cycles": cycles,
    }
    summary["report_sha256"] = chaos.sha256_bytes(chaos.canonical_json(summary))
    chaos.write_exclusive(output_dir / "summary.json", chaos.canonical_json(summary))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    parser.add_argument("--duration-seconds", type=float, default=MIN_DURATION_SECONDS)
    parser.add_argument("--seed", type=int, default=1)
    arguments = parser.parse_args()
    try:
        summary = run_long_soak(
            arguments.again_binary,
            arguments.output_dir,
            duration_seconds=arguments.duration_seconds,
            seed=arguments.seed,
        )
    except chaos.HarnessRefusal as error:
        print(json.dumps({"classification": {"type": "failure", "code": error.code}}))
        return 3
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
