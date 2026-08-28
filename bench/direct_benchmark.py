#!/usr/bin/env python3
"""Reproducible benchmark for the explicit ``again run --`` product path.

This harness compares one native, noninteractive read-only command with the
same command executed through ``again run --``. It treats stream or cache-event
disagreement as a correctness failure. It does not exercise Codex hooks, models,
output compaction, or token reduction.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import resource
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable


SCHEMA = "again.direct-benchmark.v1"
HARNESS_VERSION = "1.0.1"
DEFAULT_SIZE_MIB = 2048
DEFAULT_FIXTURE_FILES = 4
DEFAULT_STREAM_LIMIT_KIB = 16 * 1024


@dataclasses.dataclass(frozen=True)
class Completed:
    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: float


def _limit_setter(
    *, stream_limit_bytes: int, memory_limit_bytes: int | None
) -> Callable[[], None]:
    """Return a child-only POSIX resource-limit installer."""

    def apply() -> None:
        file_soft, file_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        effective_file_limit = stream_limit_bytes
        if file_hard != resource.RLIM_INFINITY:
            effective_file_limit = min(effective_file_limit, file_hard)
        resource.setrlimit(resource.RLIMIT_FSIZE, (effective_file_limit, file_hard))

        if memory_limit_bytes is not None:
            memory_soft, memory_hard = resource.getrlimit(resource.RLIMIT_AS)
            del memory_soft
            effective_memory_limit = memory_limit_bytes
            if memory_hard != resource.RLIM_INFINITY:
                effective_memory_limit = min(effective_memory_limit, memory_hard)
            resource.setrlimit(
                resource.RLIMIT_AS, (effective_memory_limit, memory_hard)
            )

    return apply


def run_bounded(
    argv: list[str],
    *,
    cwd: pathlib.Path,
    env: dict[str, str],
    timeout_seconds: float,
    stream_limit_bytes: int,
    memory_limit_bytes: int | None,
) -> Completed:
    """Run without a TTY/stdin and capture streams under explicit bounds."""

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        started = time.perf_counter_ns()
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
            preexec_fn=_limit_setter(
                stream_limit_bytes=stream_limit_bytes,
                memory_limit_bytes=memory_limit_bytes,
            ),
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise RuntimeError(
                f"command exceeded {timeout_seconds:g}s timeout: {argv!r}"
            ) from error
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

        stdout_bytes = os.fstat(stdout_file.fileno()).st_size
        stderr_bytes = os.fstat(stderr_file.fileno()).st_size
        if stdout_bytes > stream_limit_bytes or stderr_bytes > stream_limit_bytes:
            raise RuntimeError(
                "command exceeded per-stream capture limit "
                f"({stream_limit_bytes} bytes): {argv!r}"
            )
        stdout_file.seek(0)
        stderr_file.seek(0)
        return Completed(
            argv=argv,
            returncode=returncode,
            stdout=stdout_file.read(),
            stderr=stderr_file.read(),
            elapsed_ms=elapsed_ms,
        )


def nearest_rank(samples: list[float], fraction: float) -> float:
    if not samples:
        raise ValueError("cannot calculate a percentile without samples")
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def distribution(samples: list[float]) -> dict[str, Any]:
    return {
        "samples_ms": samples,
        "minimum_ms": min(samples),
        "p50_ms": nearest_rank(samples, 0.50),
        "p95_ms": nearest_rank(samples, 0.95),
        "maximum_ms": max(samples),
        "mean_ms": statistics.fmean(samples),
    }


def stream_evidence(completed: Completed) -> dict[str, Any]:
    return {
        "exit_code": completed.returncode,
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def streams_equal(left: Completed, right: Completed) -> bool:
    return (
        left.returncode == right.returncode
        and left.stdout == right.stdout
        and left.stderr == right.stderr
    )


def parse_json_output(completed: Completed, label: str) -> dict[str, Any]:
    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} failed ({completed.returncode}): "
            f"{completed.stderr.decode(errors='replace')}"
        )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"{label} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} did not return a JSON object")
    return value


def require_event(
    event: dict[str, Any], *, disposition: str, reason: str, label: str
) -> None:
    if event.get("disposition") != disposition or event.get("reason") != reason:
        raise RuntimeError(
            f"{label} event was {event!r}; expected "
            f"disposition={disposition!r}, reason={reason!r}"
        )
    if not isinstance(event.get("result_id"), str) or not event["result_id"]:
        raise RuntimeError(f"{label} event did not include a result id")


def write_sparse_fixture(path: pathlib.Path, size_bytes: int) -> None:
    marker = b"needle\n"
    if size_bytes < len(marker):
        raise ValueError("fixture is smaller than its marker")
    with path.open("xb") as fixture:
        fixture.seek(size_bytes - len(marker))
        fixture.write(marker)
        fixture.flush()
        os.fsync(fixture.fileno())


def create_private_state_directory(path: pathlib.Path) -> None:
    path.mkdir(mode=0o700)
    # The configured state root has an exact 0700 contract. Apply it explicitly
    # so a caller's unusually restrictive or permissive umask cannot make the
    # benchmark fail before it reaches the product path under measurement.
    path.chmod(0o700)


def child_peak_rss_bytes() -> tuple[int, str]:
    raw = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if platform.system() == "Darwin":
        return int(raw), "ru_maxrss is bytes on Darwin"
    return int(raw * 1024), "ru_maxrss is KiB on this platform and was converted"


def read_text_command(
    argv: list[str], *, cwd: pathlib.Path, env: dict[str, str]
) -> str | None:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="replace").strip()


def repository_metadata(source_root: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    commit = read_text_command(["git", "rev-parse", "HEAD"], cwd=source_root, env=env)
    dirty = read_text_command(["git", "status", "--porcelain"], cwd=source_root, env=env)
    return {
        "source_root": str(source_root),
        "commit": commit,
        "dirty": None if dirty is None else bool(dirty),
        "dirty_entries": None if dirty is None else dirty.splitlines(),
    }


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def host_metadata() -> dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable": sys.executable,
    }


def write_json_exclusive(path: pathlib.Path, result: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    try:
        with path.open("x", encoding="utf-8") as output:
            output.write(rendered)
    except FileExistsError as error:
        raise SystemExit(f"refusing to overwrite existing JSON output: {path}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--size-mib", type=int, default=DEFAULT_SIZE_MIB)
    parser.add_argument(
        "--fixture-files",
        type=int,
        default=DEFAULT_FIXTURE_FILES,
        help="split aggregate logical bytes across this many sparse files",
    )
    parser.add_argument("--baseline-iterations", type=int, default=5)
    parser.add_argument("--warm-iterations", type=int, default=15)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument(
        "--max-stream-kib",
        type=int,
        default=DEFAULT_STREAM_LIMIT_KIB,
        help="hard RLIMIT_FSIZE and readback limit for each captured stream",
    )
    parser.add_argument(
        "--memory-limit-mib",
        type=int,
        help=(
            "optional inherited RLIMIT_AS on platforms that support lowering it; "
            "Darwin rejects this option and reports observed RSS instead"
        ),
    )
    parser.add_argument("--minimum-baseline-ms", type=float, default=500.0)
    parser.add_argument("--required-speedup", type=float, default=3.0)
    parser.add_argument(
        "--enforce-speed-gate",
        action="store_true",
        help="exit 2 after writing evidence unless the speed gate passes",
    )
    parser.add_argument(
        "--json-out",
        type=pathlib.Path,
        help="write evidence to a new path; existing files are never overwritten",
    )
    arguments = parser.parse_args()

    positive_integers = {
        "--size-mib": arguments.size_mib,
        "--fixture-files": arguments.fixture_files,
        "--baseline-iterations": arguments.baseline_iterations,
        "--warm-iterations": arguments.warm_iterations,
        "--max-stream-kib": arguments.max_stream_kib,
    }
    for name, value in positive_integers.items():
        if value < 1:
            raise SystemExit(f"{name} must be positive")
    if arguments.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    if arguments.memory_limit_mib is not None and arguments.memory_limit_mib < 1:
        raise SystemExit("--memory-limit-mib must be positive when provided")
    if arguments.memory_limit_mib is not None and platform.system() == "Darwin":
        raise SystemExit(
            "--memory-limit-mib is unavailable on Darwin because Python cannot "
            "reliably lower RLIMIT_AS there; omit it and use the recorded child RSS"
        )
    if arguments.minimum_baseline_ms < 0 or arguments.required_speedup <= 0:
        raise SystemExit("speed-gate thresholds must be non-negative/positive")
    if arguments.json_out is not None and arguments.json_out.exists():
        raise SystemExit(
            f"refusing to overwrite existing JSON output: {arguments.json_out}"
        )

    binary = arguments.binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"Again binary not found: {binary}")
    grep_path_text = shutil.which("grep", path="/usr/bin:/bin")
    if grep_path_text is None:
        raise SystemExit("audited system grep was not found under /usr/bin:/bin")
    grep_path = pathlib.Path(grep_path_text).resolve()

    source_root = pathlib.Path(__file__).resolve().parents[1]
    script_path = pathlib.Path(__file__).resolve()
    size_bytes = arguments.size_mib * 1024 * 1024
    stream_limit_bytes = arguments.max_stream_kib * 1024
    memory_limit_bytes = (
        None
        if arguments.memory_limit_mib is None
        else arguments.memory_limit_mib * 1024 * 1024
    )
    inherited_env = os.environ.copy()
    rss_before, rss_note = child_peak_rss_bytes()

    with tempfile.TemporaryDirectory(prefix="again-direct-benchmark-") as temporary:
        root = pathlib.Path(temporary)
        workspace = root / "workspace"
        state = root / "state"
        workspace.mkdir()
        create_private_state_directory(state)
        (workspace / ".git").mkdir()
        if size_bytes < arguments.fixture_files * len(b"needle\n"):
            raise SystemExit("aggregate fixture is too small for --fixture-files")
        payloads: list[pathlib.Path] = []
        payload_sizes: list[int] = []
        base_size, remainder = divmod(size_bytes, arguments.fixture_files)
        for index in range(arguments.fixture_files):
            payload = workspace / f"payload-{index:03d}.bin"
            payload_size = base_size + (1 if index < remainder else 0)
            write_sparse_fixture(payload, payload_size)
            payloads.append(payload)
            payload_sizes.append(payload_size)

        env = inherited_env.copy()
        env["AGAIN_HOME"] = str(state)
        env["LC_ALL"] = "C"
        env["PATH"] = "/usr/bin:/bin"
        env.pop("GREP_OPTIONS", None)
        rejected_ambient_names = {
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
        removed_ambient_names = sorted(
            name
            for name in list(env)
            if name.startswith(("DYLD_", "LD_", "Malloc", "MALLOC_"))
            or name in rejected_ambient_names
        )
        for name in removed_ambient_names:
            env.pop(name, None)

        payload_names = [payload.name for payload in payloads]
        native_argv = [str(grep_path), "needle", *payload_names]
        again_argv = [str(binary), "run", "--", "grep", "needle", *payload_names]
        support_argv = lambda *parts: [str(binary), *parts]
        run_options = {
            "cwd": workspace,
            "env": env,
            "timeout_seconds": arguments.timeout_seconds,
            "stream_limit_bytes": stream_limit_bytes,
            "memory_limit_bytes": memory_limit_bytes,
        }

        native_runs: list[Completed] = []
        for _ in range(arguments.baseline_iterations):
            native = run_bounded(native_argv, **run_options)
            if native.returncode != 0:
                raise RuntimeError(
                    "native fixture command failed: "
                    f"{native.stderr.decode(errors='replace')}"
                )
            if native_runs and not streams_equal(native_runs[0], native):
                raise RuntimeError("native fixture streams changed between iterations")
            native_runs.append(native)
        baseline = native_runs[0]

        cold = run_bounded(again_argv, **run_options)
        if not streams_equal(baseline, cold):
            raise RuntimeError("cold Again execution changed exit code/stdout/stderr")
        cold_event = parse_json_output(
            run_bounded(support_argv("explain", "--json"), **run_options),
            "again explain after cold run",
        )
        require_event(
            cold_event,
            disposition="executed",
            reason="DOUBLE_EXECUTION_VALIDATED",
            label="cold run",
        )

        warm_runs: list[Completed] = []
        warm_events: list[dict[str, Any]] = []
        for index in range(arguments.warm_iterations):
            warm = run_bounded(again_argv, **run_options)
            if not streams_equal(baseline, warm):
                raise RuntimeError(
                    f"warm Again run {index + 1} changed exit code/stdout/stderr"
                )
            event = parse_json_output(
                run_bounded(support_argv("explain", "--json"), **run_options),
                f"again explain after warm run {index + 1}",
            )
            require_event(
                event,
                disposition="replayed_full",
                reason="EXACT_REUSE_NET_V1",
                label=f"warm run {index + 1}",
            )
            if event["result_id"] != cold_event["result_id"]:
                raise RuntimeError("warm run replayed a result other than the cold result")
            warm_runs.append(warm)
            warm_events.append(event)

        mutated_payload = payloads[0]
        mutation_offset = payload_sizes[0] // 2
        with mutated_payload.open("r+b") as fixture:
            fixture.seek(mutation_offset)
            fixture.write(b"x")
            fixture.flush()
            os.fsync(fixture.fileno())

        mutated_native = run_bounded(native_argv, **run_options)
        if not streams_equal(baseline, mutated_native):
            raise RuntimeError(
                "controlled mutation unexpectedly changed native command streams"
            )
        mutated_again = run_bounded(again_argv, **run_options)
        if not streams_equal(mutated_native, mutated_again):
            raise RuntimeError("Again returned stale streams after an input mutation")
        mutation_event = parse_json_output(
            run_bounded(support_argv("explain", "--json"), **run_options),
            "again explain after mutation",
        )
        require_event(
            mutation_event,
            disposition="executed",
            reason="DOUBLE_EXECUTION_VALIDATED",
            label="mutation run",
        )
        if mutation_event["result_id"] == cold_event["result_id"]:
            raise RuntimeError("input mutation reused the pre-mutation result id")

        stats = parse_json_output(
            run_bounded(support_argv("stats", "--json"), **run_options),
            "again stats",
        )
        expected_stats = {
            "executions": 2,
            "full_replays": arguments.warm_iterations,
            "compact_replays": 0,
            "bypasses": 0,
            "quarantines": 0,
            "duplicate_bytes_omitted": 0,
        }
        for key, expected in expected_stats.items():
            if stats.get(key) != expected:
                raise RuntimeError(
                    f"Again stats {key}={stats.get(key)!r}; expected {expected!r}"
                )

        allocated_size_bytes = sum(payload.stat().st_blocks * 512 for payload in payloads)
        baseline_distribution = distribution([run.elapsed_ms for run in native_runs])
        warm_distribution = distribution([run.elapsed_ms for run in warm_runs])
        observed_speedup = (
            baseline_distribution["p50_ms"] / warm_distribution["p95_ms"]
        )
        if baseline_distribution["p50_ms"] < arguments.minimum_baseline_ms:
            speed_gate: dict[str, Any] = {
                "status": "not_applicable",
                "reason": "baseline_p50_below_minimum",
                "baseline_p50_ms": baseline_distribution["p50_ms"],
                "minimum_baseline_ms": arguments.minimum_baseline_ms,
                "observed_speedup": observed_speedup,
                "required_speedup": arguments.required_speedup,
            }
        else:
            speed_gate = {
                "status": (
                    "pass"
                    if observed_speedup >= arguments.required_speedup
                    else "fail"
                ),
                "comparison": ">=",
                "observed_speedup": observed_speedup,
                "required_speedup": arguments.required_speedup,
                "baseline_p50_ms": baseline_distribution["p50_ms"],
                "warm_again_p95_ms": warm_distribution["p95_ms"],
            }

        rss_after, _ = child_peak_rss_bytes()
        # Collect subprocess-based provenance only after the resource snapshot,
        # so ru_maxrss describes the benchmark and its Again support commands.
        repository = repository_metadata(source_root, inherited_env)
        binary_version = read_text_command(
            [str(binary), "--version"], cwd=source_root, env=inherited_env
        )
        result = {
            "schema": SCHEMA,
            "harness_version": HARNESS_VERSION,
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "scope": {
                "product_path": "explicit again run -- argv",
                "automatic_hooks_exercised": False,
                "codex_models_exercised": False,
                "output_compaction_exercised": False,
                "token_reduction_measured": False,
            },
            "provenance": {
                "repository": repository,
                "binary": {
                    "path": str(binary),
                    "version": binary_version,
                    "sha256": file_sha256(binary),
                },
                "harness": {
                    "path": str(script_path),
                    "sha256": file_sha256(script_path),
                },
                "host": host_metadata(),
            },
            "configuration": {
                "fixture_size_mib": arguments.size_mib,
                "fixture_files": arguments.fixture_files,
                "baseline_iterations": arguments.baseline_iterations,
                "warm_iterations": arguments.warm_iterations,
                "timeout_seconds_per_process": arguments.timeout_seconds,
                "per_stream_hard_file_and_capture_limit_bytes": stream_limit_bytes,
                "child_address_space_limit_bytes": memory_limit_bytes,
                "memory_limit_note": (
                    "RLIMIT_AS enforced for every child"
                    if memory_limit_bytes is not None
                    else "no portable hard limit; child peak RSS is recorded"
                ),
                "environment_overrides": {
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                    "GREP_OPTIONS": "unset",
                    "AGAIN_HOME": "fresh temporary directory",
                    "unmodeled_loader_locale_terminal_inputs_removed": removed_ambient_names,
                },
                "filesystem_page_cache_dropped": False,
                "speed_gate_enforced_by_exit_code": arguments.enforce_speed_gate,
            },
            "fixture": {
                "construction": (
                    "aggregate bytes split across sparse zero-filled files, each "
                    "ending in ASCII needle\\n"
                ),
                "aggregate_logical_size_bytes": size_bytes,
                "logical_size_bytes_by_file": payload_sizes,
                "allocated_size_bytes_after_mutation": allocated_size_bytes,
                "mutation": {
                    "file": mutated_payload.name,
                    "offset_bytes": mutation_offset,
                    "replacement_hex": "78",
                    "native_streams_unchanged": True,
                },
                "native_argv": native_argv,
                "again_argv": again_argv,
                "stream_evidence": stream_evidence(baseline),
            },
            "measurements": {
                "native": baseline_distribution,
                "again_cold": {
                    "elapsed_ms": cold.elapsed_ms,
                    "exact_stream_match": True,
                    "event": cold_event,
                },
                "again_warm": {
                    **warm_distribution,
                    "all_exact_full_stream_matches": True,
                    "events": warm_events,
                },
                "mutation_miss": {
                    "native_elapsed_ms": mutated_native.elapsed_ms,
                    "again_elapsed_ms": mutated_again.elapsed_ms,
                    "exact_stream_match": True,
                    "event": mutation_event,
                },
                "resource_observation": {
                    "peak_child_rss_bytes": rss_after,
                    "initial_child_rss_high_water_bytes": rss_before,
                    "scope": (
                        "high-water mark from the first native run through Again stats; "
                        "provenance subprocesses were launched afterward"
                    ),
                    "platform_interpretation": rss_note,
                },
            },
            "correctness": {
                "cold_exact": True,
                "all_warm_exact": True,
                "all_warm_events_are_full_hits": True,
                "mutation_exact": True,
                "mutation_event_is_miss": True,
                "stats": stats,
            },
            "gates": {
                "correctness": {"status": "pass"},
                "speed": speed_gate,
            },
        }

    if arguments.json_out is None:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        write_json_exclusive(arguments.json_out, result)
        print(f"wrote direct benchmark evidence to {arguments.json_out}")
    if arguments.enforce_speed_gate and result["gates"]["speed"]["status"] != "pass":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
