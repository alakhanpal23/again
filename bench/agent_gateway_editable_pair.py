#!/usr/bin/env python3
"""Fail-closed paired editable-agent benchmark for Again.

``qualify`` runs a deterministic reference editor entirely offline to qualify
the fixture, oracle, mutation checks, timing recorder, and report format. It is
not real-agent or product-speed evidence. ``live`` runs user-supplied pinned
agent commands and is gated by explicit network, credential, model, settings,
timeout, and run-count inputs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import platform
import resource
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA = "again.agent-gateway-editable-pair.v1"
HARNESS_VERSION = "1.0.0"
MAX_RUNS = 16
MAX_TIMEOUT_SECONDS = 900.0
MAX_ARGUMENTS = 96
MAX_TOKEN_BYTES = 8 * 1024
MAX_CAPTURE_BYTES = 8 * 1024 * 1024
MAX_FIXTURE_FILES = 128
MAX_FIXTURE_FILE_BYTES = 1024 * 1024
MAX_BINARY_BYTES = 512 * 1024 * 1024
PLACEHOLDERS = {"{workspace}", "{prompt}", "{model}"}
TARGET = "src/calculator.py"
TEST = "tests/test_calculator.py"
BUGGY = "def total(values):\n    return sum(values) + 1\n"
FIXED = "def total(values):\n    return sum(values)\n"
PROMPT = (
    "Fix the defect in src/calculator.py so the existing tests pass. Preserve "
    "the total(values) API. Do not edit tests or any other file. Run the existing "
    "test suite, then stop."
)
FIXTURE = {
    TARGET: BUGGY,
    TEST: (
        "import importlib.util\n"
        "import pathlib\n"
        "import unittest\n\n"
        "ROOT = pathlib.Path(__file__).parents[1]\n"
        "SPEC = importlib.util.spec_from_file_location(\"calculator\", ROOT / \"src/calculator.py\")\n"
        "calculator = importlib.util.module_from_spec(SPEC)\n"
        "SPEC.loader.exec_module(calculator)\n\n"
        "class CalculatorTests(unittest.TestCase):\n"
        "    def test_total(self):\n"
        "        self.assertEqual(calculator.total([1, 2, 3]), 6)\n"
        "        self.assertEqual(calculator.total([]), 0)\n\n"
        "if __name__ == \"__main__\":\n"
        "    unittest.main()\n"
    ),
    "README.md": "# Again editable paired benchmark fixture\n",
}


class Refusal(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    if path.stat().st_size > MAX_BINARY_BYTES:
        raise Refusal("binary_byte_limit", str(path))
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot(root: pathlib.Path) -> dict[str, str]:
    observed: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_dir() or ".git" in path.parts:
            continue
        if path.is_symlink() or not path.is_file():
            raise Refusal("unsafe_fixture_entry", str(path))
        if len(observed) >= MAX_FIXTURE_FILES:
            raise Refusal("fixture_file_limit", str(root))
        if path.stat().st_size > MAX_FIXTURE_FILE_BYTES:
            raise Refusal("fixture_byte_limit", str(path))
        relative = path.relative_to(root).as_posix()
        observed[relative] = sha256_bytes(path.read_bytes())
    return observed


def create_fixture(root: pathlib.Path) -> dict[str, str]:
    for relative, contents in FIXTURE.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    subprocess.run(
        ["/usr/bin/git", "init", "--quiet", str(root)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return snapshot(root)


def parse_template(raw: str, label: str) -> tuple[str, ...]:
    if not raw:
        raise Refusal("invalid_command_template", f"{label} was not supplied")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise Refusal("invalid_command_template", f"{label}: {error}") from error
    if not isinstance(value, list) or not value or not all(isinstance(v, str) for v in value):
        raise Refusal("invalid_command_template", f"{label} must be a non-empty JSON string array")
    if len(value) > MAX_ARGUMENTS or any(len(v.encode()) > MAX_TOKEN_BYTES for v in value):
        raise Refusal("command_template_limit", label)
    executable = pathlib.Path(value[0])
    if not executable.is_absolute() or not executable.is_file() or executable.is_symlink():
        raise Refusal("invalid_executable", f"{label}: {executable}")
    sha256_file(executable)
    unknown = {v for v in value if v.startswith("{") and v.endswith("}")} - PLACEHOLDERS
    if unknown or not {"{workspace}", "{prompt}", "{model}"}.issubset(value):
        raise Refusal("template_placeholder", f"{label}: unknown={sorted(unknown)}")
    return tuple(value)


def render(template: Sequence[str], workspace: pathlib.Path, model: str) -> list[str]:
    replacements = {"{workspace}": str(workspace), "{prompt}": PROMPT, "{model}": model}
    return [replacements.get(token, token) for token in template]


def run_tests(root: pathlib.Path, timeout: float) -> tuple[bool, float, str]:
    started = time.perf_counter()
    returncode, output_sha, timed_out, output_limited, _ = run_captured(
        ["/usr/bin/python3", "-I", "-m", "unittest", "discover", "-s", "tests", "-q"],
        root,
        timeout,
    )
    elapsed = (time.perf_counter() - started) * 1000
    return returncode == 0 and not timed_out and not output_limited, elapsed, output_sha


def run_captured(
    command: Sequence[str],
    root: pathlib.Path,
    timeout: float,
    watch_path: pathlib.Path | None = None,
    initial_digest: str | None = None,
) -> tuple[int, str, bool, bool, float | None]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            preexec_fn=limit_files,
            start_new_session=True,
        )
        started = time.perf_counter()
        timed_out = False
        first_edit_ms = None
        while process.poll() is None:
            elapsed = time.perf_counter() - started
            if elapsed >= timeout:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                break
            if first_edit_ms is None and watch_path is not None and watch_path.is_file():
                current = sha256_bytes(watch_path.read_bytes())
                if current != initial_digest:
                    first_edit_ms = elapsed * 1000
            time.sleep(0.01)
        returncode = process.wait(timeout=10)
        if first_edit_ms is None and watch_path is not None and watch_path.is_file():
            if sha256_bytes(watch_path.read_bytes()) != initial_digest:
                first_edit_ms = (time.perf_counter() - started) * 1000
        sizes = (os.fstat(stdout.fileno()).st_size, os.fstat(stderr.fileno()).st_size)
        output_limited = any(size >= MAX_CAPTURE_BYTES for size in sizes)
        digest = hashlib.sha256()
        for stream in (stdout, stderr):
            stream.seek(0)
            while chunk := stream.read(64 * 1024):
                digest.update(chunk)
        return returncode, digest.hexdigest(), timed_out, output_limited, first_edit_ms


def limit_files() -> None:
    _, current_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    ceiling = min(MAX_CAPTURE_BYTES, current_hard) if current_hard >= 0 else MAX_CAPTURE_BYTES
    resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, current_hard))


def again_stats(binary: pathlib.Path, root: pathlib.Path) -> dict[str, int]:
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = subprocess.run(
            [str(binary), "stats", "--json"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=30,
            preexec_fn=limit_files,
            check=False,
        )
        if result.returncode != 0 or os.fstat(stdout.fileno()).st_size > MAX_CAPTURE_BYTES:
            raise Refusal("again_stats_unavailable", str(root))
        stdout.seek(0)
        value = json.load(stdout)
    if not isinstance(value, dict):
        raise Refusal("again_stats_malformed", str(root))
    fields = ("requested", "executed", "exact_hits", "inflight_joins", "context_events")
    if any(not isinstance(value.get(field), int) or value[field] < 0 for field in fields):
        raise Refusal("again_stats_malformed", str(root))
    return {field: value[field] for field in fields}


def validate_edit(root: pathlib.Path, before: Mapping[str, str], timeout: float) -> dict[str, Any]:
    after = snapshot(root)
    changed = sorted(set(before) | set(after))
    changed = [path for path in changed if before.get(path) != after.get(path)]
    exact_target = (root / TARGET).read_text(encoding="utf-8") == FIXED
    collateral_safe = changed == [TARGET]
    tests_passed, test_ms, output_sha = run_tests(root, timeout)
    return {
        "passed": exact_target and collateral_safe and tests_passed,
        "exact_target": exact_target,
        "collateral_safe": collateral_safe,
        "changed_paths": changed,
        "tests_passed": tests_passed,
        "test_elapsed_ms": round(test_ms, 3),
        "test_output_sha256": output_sha,
        "after_snapshot_sha256": sha256_bytes(canonical_bytes(after)),
    }


def reference_edit(root: pathlib.Path) -> tuple[int, str, bool, bool, float]:
    (root / TARGET).write_text(FIXED, encoding="utf-8")
    return 0, sha256_bytes(b""), False, False, 0.0


def command_edit(
    root: pathlib.Path, template: Sequence[str], model: str, timeout: float
) -> tuple[int, str, bool, bool, float | None]:
    target = root / TARGET
    return run_captured(
        render(template, root, model),
        root,
        timeout,
        watch_path=target,
        initial_digest=sha256_bytes(target.read_bytes()),
    )


def percentile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int((len(ordered) - 1) * fraction + 0.5)))
    return round(ordered[index], 3)


def summarize(runs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    elapsed = [float(run["elapsed_ms"]) for run in runs]
    return {
        "runs": len(runs),
        "passed": sum(bool(run["oracle"]["passed"]) for run in runs),
        "p50_ms": percentile(elapsed, 0.50),
        "p95_ms": percentile(elapsed, 0.95),
        "mean_ms": round(statistics.fmean(elapsed), 3),
    }


def run_condition(
    condition: str,
    mode: str,
    template: Sequence[str] | None,
    model: str,
    timeout: float,
    again_binary: pathlib.Path | None,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"again-editable-{condition}-") as directory:
        root = pathlib.Path(directory)
        before = create_fixture(root)
        stats_before = again_stats(again_binary, root) if again_binary is not None else None
        started = time.perf_counter()
        if mode == "qualify":
            returncode, output_sha, timed_out, output_limited, first_edit_ms = reference_edit(root)
        else:
            assert template is not None
            returncode, output_sha, timed_out, output_limited, first_edit_ms = command_edit(
                root, template, model, timeout
            )
        agent_elapsed = (time.perf_counter() - started) * 1000
        accepted_edit_ms = (
            agent_elapsed if (root / TARGET).read_text(encoding="utf-8") == FIXED else None
        )
        oracle = validate_edit(root, before, timeout)
        stats_after = again_stats(again_binary, root) if again_binary is not None else None
        stats_delta = (
            {field: stats_after[field] - stats_before[field] for field in stats_before}
            if stats_before is not None and stats_after is not None
            else None
        )
        product_observed = None
        if stats_delta is not None:
            activity = stats_delta["requested"] + stats_delta["context_events"]
            product_observed = activity > 0 if condition == "again" else activity == 0
            if not product_observed:
                oracle["passed"] = False
        final_elapsed = (time.perf_counter() - started) * 1000
        if returncode != 0 or timed_out or output_limited:
            oracle["passed"] = False
        return {
            "condition": condition,
            "elapsed_ms": round(final_elapsed, 3),
            "milestones_ms": {
                "task_started": 0.0,
                "first_edit": round(first_edit_ms, 3) if first_edit_ms is not None else None,
                "agent_completed": round(agent_elapsed, 3),
                "accepted_edit": round(accepted_edit_ms, 3) if accepted_edit_ms is not None else None,
                "validation_completed": round(final_elapsed, 3),
                "final_outcome": round(final_elapsed, 3),
            },
            "returncode": returncode,
            "timed_out": timed_out,
            "output_limited": output_limited,
            "combined_output_sha256": output_sha,
            "oracle": oracle,
            "again_stats_delta": stats_delta,
            "product_observed": product_observed,
        }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    if not 1 <= args.runs <= MAX_RUNS:
        raise Refusal("run_limit", f"runs must be between 1 and {MAX_RUNS}")
    if not 1 <= args.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise Refusal("timeout_limit", f"timeout must be between 1 and {MAX_TIMEOUT_SECONDS}")
    templates: dict[str, tuple[str, ...] | None] = {"baseline": None, "again": None}
    credential_present = False
    again_binary = None
    if args.mode == "live":
        if not args.allow_network:
            raise Refusal("network_not_authorized", "live mode requires --allow-network")
        if not args.model or not args.settings_id or not args.credential_env_name:
            raise Refusal("live_binding_incomplete", "model, settings id, and credential name are required")
        credential_present = bool(os.environ.get(args.credential_env_name))
        if not credential_present:
            raise Refusal("credential_unavailable", args.credential_env_name)
        templates["baseline"] = parse_template(args.baseline_command_json, "baseline")
        templates["again"] = parse_template(args.again_command_json, "again")
        again_binary = pathlib.Path(args.again_bin or "")
        if not again_binary.is_absolute() or not again_binary.is_file() or again_binary.is_symlink():
            raise Refusal("invalid_again_binary", str(again_binary))

    observations: list[dict[str, Any]] = []
    for run in range(args.runs):
        order = ["baseline", "again"] if run % 2 == 0 else ["again", "baseline"]
        for condition in order:
            observation = run_condition(
                condition,
                args.mode,
                templates[condition],
                args.model or "reference",
                args.timeout_seconds,
                again_binary,
            )
            observation["pair"] = run
            observation["order"] = order
            observations.append(observation)
    grouped = {
        condition: [item for item in observations if item["condition"] == condition]
        for condition in ("baseline", "again")
    }
    all_passed = all(item["oracle"]["passed"] for item in observations)
    report = {
        "schema": SCHEMA,
        "harness_version": HARNESS_VERSION,
        "harness_sha256": sha256_bytes(pathlib.Path(__file__).read_bytes()),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
        },
        "mode": args.mode,
        "evidence_class": (
            "deterministic_editable_harness_qualification"
            if args.mode == "qualify"
            else "live_paired_editable_agent"
        ),
        "claims": {
            "editable_oracle_qualified": all_passed,
            "real_agent_task_quality": args.mode == "live" and all_passed,
            "again_acceleration": False,
            "note": (
                "Qualification timings measure the deterministic reference editor and harness only."
                if args.mode == "qualify"
                else "Acceleration requires an independently reviewed sample size and timing analysis."
            ),
        },
        "binding": {
            "model": args.model,
            "settings_id": args.settings_id,
            "credential_env_name": args.credential_env_name,
            "credential_present": credential_present,
            "again_binary_sha256": (
                sha256_file(again_binary) if again_binary is not None else None
            ),
            "baseline_template_sha256": (
                sha256_bytes(canonical_bytes(templates["baseline"])) if templates["baseline"] else None
            ),
            "baseline_executable_sha256": (
                sha256_file(pathlib.Path(templates["baseline"][0]))
                if templates["baseline"]
                else None
            ),
            "again_template_sha256": (
                sha256_bytes(canonical_bytes(templates["again"])) if templates["again"] else None
            ),
            "again_executable_sha256": (
                sha256_file(pathlib.Path(templates["again"][0])) if templates["again"] else None
            ),
        },
        "fixture_sha256": sha256_bytes(canonical_bytes(FIXTURE)),
        "prompt_sha256": sha256_bytes(PROMPT.encode()),
        "limits": {"runs": args.runs, "timeout_seconds": args.timeout_seconds},
        "summary": {condition: summarize(items) for condition, items in grouped.items()},
        "observations": observations,
        "passed": all_passed,
    }
    return report


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--mode", choices=("qualify", "live"), default="qualify")
    value.add_argument("--runs", type=int, default=5)
    value.add_argument("--timeout-seconds", type=float, default=120.0)
    value.add_argument("--allow-network", action="store_true")
    value.add_argument("--model")
    value.add_argument("--settings-id")
    value.add_argument("--credential-env-name")
    value.add_argument("--baseline-command-json")
    value.add_argument("--again-command-json")
    value.add_argument("--again-bin")
    value.add_argument("--json-out", type=pathlib.Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.json_out.exists():
        print(
            json.dumps(
                {
                    "passed": False,
                    "refusal": "report_path_exists",
                    "report": str(args.json_out),
                }
            )
        )
        return 2
    try:
        report = build_report(args)
    except Refusal as error:
        report = {"schema": SCHEMA, "harness_version": HARNESS_VERSION, "passed": False, "refusal": {"code": error.code, "message": str(error)}}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_bytes(json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
    print(json.dumps({"passed": report["passed"], "report": str(args.json_out)}))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
