#!/usr/bin/env python3
"""Run the explicit Again product path across deterministic polyglot repositories.

This is a correctness corpus, not a claim that Again understands language
semantics. The current product caches a narrow set of read-only tool calls; the
five repositories make the file layouts and bytes representative of common
agent workspaces while every result is still compared with the native command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


LANGUAGES: tuple[tuple[str, str], ...] = (
    ("rust", "rs"),
    ("python", "py"),
    ("go", "go"),
    ("typescript", "ts"),
    ("shell", "sh"),
)

DENIED_ENVIRONMENT_NAMES = {
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cases-per-language", type=int, default=100)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--json-out", type=Path)
    return parser.parse_args()


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile_value * len(ordered)) - 1)
    return ordered[index]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitized_environment(state: Path, home: Path) -> tuple[dict[str, str], list[str]]:
    environment = dict(os.environ)
    removed: list[str] = []
    for name in list(environment):
        if (
            name.startswith("DYLD_")
            or name.startswith("LD_")
            or name.startswith("Malloc")
            or name.startswith("MALLOC_")
            or name in DENIED_ENVIRONMENT_NAMES
        ):
            removed.append(name)
            environment.pop(name)
    environment.update(
        {
            "AGAIN_HOME": str(state),
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }
    )
    environment.pop("AGAIN_FULL", None)
    return environment, sorted(removed)


def run(
    argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> tuple[subprocess.CompletedProcess[bytes], float]:
    started = time.perf_counter_ns()
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return completed, elapsed_ms


def command_for(index: int, relative: str) -> list[str]:
    family = index % 5
    if family == 0:
        return ["cat", relative]
    if family == 1:
        return ["head", "-n", "2", relative]
    if family == 2:
        return ["tail", "-n", "2", relative]
    if family == 3:
        return ["wc", "-l", relative]
    return ["grep", "-n", "shared-marker", relative]


def fixture_bytes(language: str, index: int, mutation: bool = False) -> bytes:
    suffix = "mutated" if mutation else "original"
    return (
        f"language={language} case={index:04d}\n"
        "shared-marker\n"
        f"payload={language}-{index:04d}-{suffix}\n"
        "end\n"
    ).encode("utf-8")


def assert_equal(
    label: str,
    expected: subprocess.CompletedProcess[bytes],
    actual: subprocess.CompletedProcess[bytes],
) -> None:
    expected_code = expected.returncode
    if (
        actual.returncode != expected_code
        or actual.stdout != expected.stdout
        or actual.stderr != expected.stderr
    ):
        raise RuntimeError(
            f"{label} diverged: native={expected_code} again={actual.returncode} "
            f"stdout_equal={expected.stdout == actual.stdout} "
            f"stderr_equal={expected.stderr == actual.stderr} "
            f"again_stdout={actual.stdout[:512]!r} again_stderr={actual.stderr[:512]!r}"
        )


def stats(
    binary: Path,
    workspace: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> dict[str, Any]:
    completed, _ = run(
        [str(binary), "stats", "--json"], workspace, environment, timeout_seconds
    )
    if completed.returncode != 0:
        raise RuntimeError(f"again stats failed: {completed.stderr.decode(errors='replace')}")
    return json.loads(completed.stdout)


def git_output(repo: Path, *args: str) -> str | None:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="strict").strip()


def main() -> int:
    arguments = parse_args()
    binary = arguments.binary.expanduser().resolve(strict=True)
    if arguments.cases_per_language < 1:
        raise SystemExit("--cases-per-language must be positive")
    if arguments.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be positive")
    if arguments.json_out is not None and arguments.json_out.exists():
        raise SystemExit(f"refusing to overwrite {arguments.json_out}")

    repository = Path(__file__).resolve().parent.parent
    aggregate = hashlib.sha256()
    language_reports: list[dict[str, Any]] = []
    all_removed_inputs: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="again-polyglot-corpus-") as temporary:
        root = Path(temporary)
        home = root / "home"
        home.mkdir(mode=0o700)

        for language, extension in LANGUAGES:
            workspace = root / f"workspace-{language}"
            source = workspace / "src"
            state = root / f"state-{language}"
            (workspace / ".git").mkdir(parents=True)
            source.mkdir()
            state.mkdir(mode=0o700)
            environment, removed = sanitized_environment(state, home)
            all_removed_inputs.update(removed)

            cases: list[tuple[Path, list[str]]] = []
            for index in range(arguments.cases_per_language):
                path = source / f"case_{index:04d}.{extension}"
                path.write_bytes(fixture_bytes(language, index))
                relative = path.relative_to(workspace).as_posix()
                cases.append((path, command_for(index, relative)))

            cold_ms: list[float] = []
            warm_ms: list[float] = []
            native_ms: list[float] = []
            for index, (_path, command) in enumerate(cases):
                native, native_elapsed = run(
                    command, workspace, environment, arguments.timeout_seconds
                )
                cold, cold_elapsed = run(
                    [str(binary), "run", "--", *command],
                    workspace,
                    environment,
                    arguments.timeout_seconds,
                )
                warm, warm_elapsed = run(
                    [str(binary), "run", "--", *command],
                    workspace,
                    environment,
                    arguments.timeout_seconds,
                )
                assert_equal(f"{language} case {index} cold", native, cold)
                assert_equal(f"{language} case {index} warm", native, warm)
                native_ms.append(native_elapsed)
                cold_ms.append(cold_elapsed)
                warm_ms.append(warm_elapsed)
                for value in (language.encode(), b"\0", *command, native.stdout, native.stderr):
                    if isinstance(value, str):
                        aggregate.update(value.encode())
                    else:
                        aggregate.update(value)
                    aggregate.update(b"\0")

            # Mutate case zero after its hit, prove the previous result is not
            # served, then prove the new epoch can itself become a hit.
            mutated_path, mutated_command = cases[0]
            mutated_path.write_bytes(fixture_bytes(language, 0, mutation=True))
            native_mutated, _ = run(
                mutated_command, workspace, environment, arguments.timeout_seconds
            )
            invalidated, _ = run(
                [str(binary), "run", "--", *mutated_command],
                workspace,
                environment,
                arguments.timeout_seconds,
            )
            rewarmed, _ = run(
                [str(binary), "run", "--", *mutated_command],
                workspace,
                environment,
                arguments.timeout_seconds,
            )
            assert_equal(f"{language} mutation miss", native_mutated, invalidated)
            assert_equal(f"{language} mutation hit", native_mutated, rewarmed)

            observed_stats = stats(
                binary, workspace, environment, arguments.timeout_seconds
            )
            expected_each = arguments.cases_per_language + 1
            if observed_stats.get("executions") != expected_each:
                raise RuntimeError(
                    f"{language} execution count was {observed_stats.get('executions')}, "
                    f"expected {expected_each}"
                )
            if observed_stats.get("full_replays") != expected_each:
                raise RuntimeError(
                    f"{language} full replay count was {observed_stats.get('full_replays')}, "
                    f"expected {expected_each}"
                )
            if observed_stats.get("compact_replays") != 0:
                raise RuntimeError(f"{language} unexpectedly compacted output")

            language_reports.append(
                {
                    "language": language,
                    "extension": extension,
                    "cases": arguments.cases_per_language,
                    "again_invocations": 2 * (arguments.cases_per_language + 1),
                    "mutation_invalidations": 1,
                    "stats": observed_stats,
                    "timing_ms": {
                        "native_p50": statistics.median(native_ms),
                        "cold_p50": statistics.median(cold_ms),
                        "warm_p50": statistics.median(warm_ms),
                        "warm_p95": percentile(warm_ms, 0.95),
                    },
                }
            )

    invocation_count = sum(item["again_invocations"] for item in language_reports)
    report = {
        "schema": "again.polyglot-reuse-corpus.v1",
        "result": "pass",
        "scope": {
            "languages": [name for name, _extension in LANGUAGES],
            "cases_per_language": arguments.cases_per_language,
            "again_invocations": invocation_count,
            "native_comparisons": len(LANGUAGES) * (arguments.cases_per_language + 1),
            "mutation_invalidations": len(LANGUAGES),
            "claim": "explicit narrow read-only product path; not language-semantic or arbitrary-command coverage",
        },
        "correctness": {
            "exact_status_stdout_stderr": True,
            "every_initial_repeat_was_full_replay": True,
            "every_modeled_mutation_forced_execution": True,
            "every_mutated_repeat_was_full_replay": True,
            "compact_replays": 0,
            "aggregate_fixture_output_sha256": aggregate.hexdigest(),
        },
        "languages": language_reports,
        "provenance": {
            "binary": str(binary),
            "binary_sha256": sha256_file(binary),
            "source_commit": git_output(repository, "rev-parse", "HEAD"),
            "source_status": git_output(repository, "status", "--short"),
            "harness_sha256": sha256_file(Path(__file__).resolve()),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "unmodeled_inputs_removed": sorted(all_removed_inputs),
        },
    }

    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.json_out is None:
        print(encoded, end="")
    else:
        output = arguments.json_out.expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(encoded, encoding="utf-8")
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
