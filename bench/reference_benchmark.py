#!/usr/bin/env python3
"""Benchmark explicit ``again reference --`` without claiming model-token evidence.

The harness proves that references are smaller than exact full-stream hits,
remain bound to the same validated result, and never execute on either a cold
or invalidated miss. It measures output bytes as a tokenizer-independent proxy;
it does not invoke Codex, an LLM, or a tokenizer.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import shutil
import tempfile
from typing import Any

from direct_benchmark import (
    Completed,
    distribution,
    file_sha256,
    host_metadata,
    parse_json_output,
    repository_metadata,
    run_bounded,
    write_json_exclusive,
)


SCHEMA = "again.reference-benchmark.v1"
HARNESS_VERSION = "1.0.0"
PROCESS_FILE_LIMIT_BYTES = 16 * 1024 * 1024


def sanitized_environment(state: pathlib.Path) -> tuple[dict[str, str], list[str]]:
    env = os.environ.copy()
    env["AGAIN_HOME"] = str(state)
    env["LC_ALL"] = "C"
    env["PATH"] = "/usr/bin:/bin"
    env.pop("GREP_OPTIONS", None)
    fixed = {
        "ASAN_OPTIONS",
        "GCONV_PATH",
        "LOCPATH",
        "LSAN_OPTIONS",
        "MSAN_OPTIONS",
        "NLSPATH",
        "PATH_LOCALE",
        "TERMCAP",
        "TERMINFO",
        "TERMINFO_DIRS",
        "TSAN_OPTIONS",
        "TZDIR",
        "UBSAN_OPTIONS",
    }
    removed = sorted(
        name
        for name in list(env)
        if name.startswith(("DYLD_", "LD_", "Malloc", "MALLOC_"))
        or name in fixed
    )
    for name in removed:
        env.pop(name, None)
    return env, removed


def require_failure_without_execution(completed: Completed, label: str) -> None:
    if completed.returncode == 0:
        raise RuntimeError(f"{label} unexpectedly succeeded")
    if completed.stdout:
        raise RuntimeError(
            f"{label} emitted requested-command stdout: {completed.stdout[:4096]!r}"
        )
    if b"no command was executed" not in completed.stderr:
        raise RuntimeError(
            f"{label} did not report its no-execution contract "
            f"(returncode={completed.returncode}, stderr={completed.stderr[:4096]!r})"
        )


def validate_reference(
    value: dict[str, Any], *, result_id: str, payload_bytes: int
) -> None:
    if value.get("schema") != "again.reference.v1":
        raise RuntimeError("reference schema changed")
    if value.get("result_id") != result_id or value.get("exit_code") != 0:
        raise RuntimeError("reference result identity/status changed")
    stdout = value.get("stdout")
    stderr = value.get("stderr")
    if not isinstance(stdout, dict) or not isinstance(stderr, dict):
        raise RuntimeError("reference stream metadata is malformed")
    if stdout.get("bytes") != payload_bytes or stderr.get("bytes") != 0:
        raise RuntimeError("reference stream lengths changed")
    for stream in (stdout, stderr):
        digest = stream.get("blake3")
        if not isinstance(digest, str) or len(digest) != 64:
            raise RuntimeError("reference is missing a strict BLAKE3 digest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--size-kib", type=int, default=1024)
    parser.add_argument("--iterations", type=int, default=25)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--required-byte-reduction", type=float, default=0.99)
    parser.add_argument("--max-reference-p95-ms", type=float, default=100.0)
    parser.add_argument("--json-out", type=pathlib.Path)
    arguments = parser.parse_args()
    if arguments.size_kib < 1 or arguments.size_kib >= 16 * 1024:
        raise SystemExit("--size-kib must be between 1 and 16383")
    if arguments.iterations < 1 or arguments.timeout_seconds <= 0:
        raise SystemExit("--iterations and --timeout-seconds must be positive")
    if not 0 < arguments.required_byte_reduction < 1:
        raise SystemExit("--required-byte-reduction must be between zero and one")
    if arguments.max_reference_p95_ms <= 0:
        raise SystemExit("--max-reference-p95-ms must be positive")
    if arguments.json_out is not None and arguments.json_out.exists():
        raise SystemExit(f"refusing to overwrite existing JSON output: {arguments.json_out}")

    binary = arguments.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Again binary not found: {binary}")
    cat_text = shutil.which("cat", path="/usr/bin:/bin")
    if cat_text is None:
        raise SystemExit("audited system cat was not found under /usr/bin:/bin")

    source_root = pathlib.Path(__file__).resolve().parents[1]
    script_path = pathlib.Path(__file__).resolve()
    inherited_env = os.environ.copy()
    payload_size = arguments.size_kib * 1024
    payload = (b"again-reference-benchmark-v1\n" * (payload_size // 29 + 1))[
        :payload_size
    ]

    with tempfile.TemporaryDirectory(prefix="again-reference-benchmark-") as temporary:
        root = pathlib.Path(temporary)
        workspace = root / "workspace"
        state = root / "state"
        workspace.mkdir()
        (workspace / ".git").mkdir()
        payload_path = workspace / "payload.txt"
        payload_path.write_bytes(payload)
        env, removed_ambient = sanitized_environment(state)
        run_argv = [str(binary), "run", "--", "cat", payload_path.name]
        reference_argv = [
            str(binary),
            "reference",
            "--",
            "cat",
            payload_path.name,
        ]
        options = {
            "cwd": workspace,
            "env": env,
            "timeout_seconds": arguments.timeout_seconds,
            # RLIMIT_FSIZE applies to every file the Again process writes,
            # including its SQLite state, rather than only to captured stdio.
            # Keep the product's 16 MiB file/capture ceiling here and enforce
            # the fixture-specific stdout length through exact comparisons.
            "stream_limit_bytes": PROCESS_FILE_LIMIT_BYTES,
            "memory_limit_bytes": None,
        }

        cold_miss = run_bounded(reference_argv, **options)
        require_failure_without_execution(cold_miss, "cold reference miss")
        cold_miss_event = parse_json_output(
            run_bounded([str(binary), "explain", "--json"], **options),
            "cold reference event",
        )
        if (
            cold_miss_event.get("disposition") != "passed_through"
            or cold_miss_event.get("reason") != "REFERENCE_MISS_NO_EXECUTION"
            or cold_miss_event.get("result_id") is not None
        ):
            raise RuntimeError(f"unexpected cold reference event: {cold_miss_event!r}")
        cold_miss_stats = parse_json_output(
            run_bounded([str(binary), "stats", "--json"], **options),
            "cold reference stats",
        )
        if cold_miss_stats != {
            "executions": 0,
            "full_replays": 0,
            "compact_replays": 0,
            "bypasses": 1,
            "quarantines": 0,
            "duplicate_bytes_omitted": 0,
            "estimated_execution_ms_saved": 0,
        }:
            raise RuntimeError(
                f"cold reference miss changed execution counters: {cold_miss_stats!r}"
            )
        if payload_path.read_bytes() != payload:
            raise RuntimeError("cold reference miss mutated the requested input")

        cold = run_bounded(run_argv, **options)
        if cold.returncode != 0 or cold.stdout != payload or cold.stderr:
            raise RuntimeError("cold Again run did not return exact fixture streams")
        cold_event = parse_json_output(
            run_bounded([str(binary), "explain", "--json"], **options),
            "cold event",
        )
        result_id = cold_event.get("result_id")
        if (
            cold_event.get("disposition") != "executed"
            or cold_event.get("reason") != "DOUBLE_EXECUTION_VALIDATED"
            or not isinstance(result_id, str)
        ):
            raise RuntimeError(f"unexpected cold event: {cold_event!r}")

        shown = run_bounded([str(binary), "show", result_id], **options)
        if shown.returncode != 0 or shown.stdout != payload or shown.stderr:
            raise RuntimeError("show did not recover exact referenced streams")

        full_hits: list[Completed] = []
        for index in range(arguments.iterations):
            completed = run_bounded(run_argv, **options)
            if completed.returncode != 0 or completed.stdout != payload or completed.stderr:
                raise RuntimeError(f"full hit {index + 1} changed exact streams")
            full_hits.append(completed)

        references: list[Completed] = []
        reference_values: list[dict[str, Any]] = []
        for index in range(arguments.iterations):
            completed = run_bounded(reference_argv, **options)
            value = parse_json_output(completed, f"reference {index + 1}")
            validate_reference(value, result_id=result_id, payload_bytes=payload_size)
            references.append(completed)
            reference_values.append(value)

        mutated = bytearray(payload)
        mutated[len(mutated) // 2] ^= 1
        payload_path.write_bytes(mutated)
        invalidated_miss = run_bounded(reference_argv, **options)
        require_failure_without_execution(invalidated_miss, "invalidated reference miss")
        miss_event = parse_json_output(
            run_bounded([str(binary), "explain", "--json"], **options),
            "invalidated reference event",
        )
        if (
            miss_event.get("disposition") != "passed_through"
            or miss_event.get("reason") != "REFERENCE_MISS_NO_EXECUTION"
            or miss_event.get("result_id") is not None
        ):
            raise RuntimeError(f"unexpected invalidated miss event: {miss_event!r}")

        stats = parse_json_output(
            run_bounded([str(binary), "stats", "--json"], **options), "stats"
        )
        expected = {
            "executions": 1,
            "full_replays": arguments.iterations,
            "compact_replays": arguments.iterations,
            "bypasses": 2,
            "quarantines": 0,
        }
        for key, value in expected.items():
            if stats.get(key) != value:
                raise RuntimeError(f"stats {key}={stats.get(key)!r}; expected {value}")

        full_output_bytes = sum(len(item.stdout) + len(item.stderr) for item in full_hits)
        reference_output_bytes = sum(
            len(item.stdout) + len(item.stderr) for item in references
        )
        expected_omitted = sum(
            max(0, payload_size - len(item.stdout) - len(item.stderr))
            for item in references
        )
        if stats.get("duplicate_bytes_omitted") != expected_omitted:
            raise RuntimeError(
                "stats duplicate_bytes_omitted does not match observed output reduction"
            )
        byte_reduction = 1 - reference_output_bytes / full_output_bytes
        full_distribution = distribution([item.elapsed_ms for item in full_hits])
        reference_distribution = distribution([item.elapsed_ms for item in references])
        byte_gate = byte_reduction >= arguments.required_byte_reduction
        latency_gate = (
            reference_distribution["p95_ms"] <= arguments.max_reference_p95_ms
        )

        result = {
            "schema": SCHEMA,
            "harness_version": HARNESS_VERSION,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope": {
                "product_paths": ["again run -- argv", "again reference -- argv"],
                "automatic_hooks_exercised": False,
                "codex_models_exercised": False,
                "tokenizer_exercised": False,
                "model_token_reduction_measured": False,
                "output_byte_reduction_measured": True,
            },
            "provenance": {
                "repository": repository_metadata(source_root, inherited_env),
                "binary": {
                    "path": str(binary),
                    "version": run_bounded(
                        [str(binary), "--version"], **options
                    ).stdout.decode(errors="replace").strip(),
                    "sha256": file_sha256(binary),
                },
                "harness": {
                    "path": str(script_path),
                    "sha256": file_sha256(script_path),
                },
                "host": host_metadata(),
            },
            "configuration": {
                "payload_bytes": payload_size,
                "iterations_each": arguments.iterations,
                "timeout_seconds_per_process": arguments.timeout_seconds,
                "child_file_and_capture_limit_bytes": PROCESS_FILE_LIMIT_BYTES,
                "required_byte_reduction": arguments.required_byte_reduction,
                "max_reference_p95_ms": arguments.max_reference_p95_ms,
                "environment": {
                    "AGAIN_HOME": "fresh temporary directory",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "removed_unmodeled_inputs": removed_ambient,
                },
            },
            "fixture": {
                "path": payload_path.name,
                "bytes": payload_size,
                "sha256_before_mutation": hashlib.sha256(payload).hexdigest(),
                "native_executable": str(pathlib.Path(cat_text).resolve()),
                "result_id": result_id,
            },
            "measurements": {
                "cold_run_ms": cold.elapsed_ms,
                "full_hits": full_distribution,
                "references": reference_distribution,
                "full_output_bytes_total": full_output_bytes,
                "reference_output_bytes_total": reference_output_bytes,
                "observed_bytes_omitted": expected_omitted,
                "observed_byte_reduction_fraction": byte_reduction,
                "reference_wire_example": reference_values[0],
                "stats": stats,
            },
            "correctness": {
                "cold_reference_miss_executed_command": False,
                "cold_reference_event_and_zero_execution_counters": True,
                "cold_reference_input_unchanged": True,
                "cold_run_exact": True,
                "all_full_hits_exact": True,
                "all_references_bound_to_cold_result": True,
                "show_exact": True,
                "invalidated_reference_miss_executed_command": False,
                "stats_match_observed_bytes": True,
            },
            "gates": {
                "correctness": {"status": "pass"},
                "byte_reduction": {
                    "status": "pass" if byte_gate else "fail",
                    "observed": byte_reduction,
                    "required": arguments.required_byte_reduction,
                },
                "reference_latency": {
                    "status": "pass" if latency_gate else "fail",
                    "observed_p95_ms": reference_distribution["p95_ms"],
                    "maximum_p95_ms": arguments.max_reference_p95_ms,
                },
            },
        }

    if arguments.json_out is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        write_json_exclusive(arguments.json_out, result)
        print(f"wrote reference benchmark evidence to {arguments.json_out}")
    return 0 if byte_gate and latency_gate else 2


if __name__ == "__main__":
    raise SystemExit(main())
