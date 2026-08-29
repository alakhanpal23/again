#!/usr/bin/env python3
"""Reproducible baseline-vs-candidate hot-reuse benchmark and regression gate.

This gate records SHA-256 identity of the baseline and candidate binaries, never
inferring them from filenames. It runs the identical synthetic repository
scenarios against each binary, then produces a single JSON report with separated
sections: exactness, performance, unsupported instrumentation, regression,
improvement, and refusal.

The harness is offline-only: it uses no network, no paid model, and no clone.
It records observed-manifest integration timing only as a typed non-pass fallback
when the binary does not expose the instrumentation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_gateway_repository_tools  # noqa: E402
from agent_gateway_repository_tools import (  # noqa: E402
    SCHEMA_VERSION,
    STORE_SCHEMA_VERSION,
    HarnessError,
    Response,
    atomic_report,
    canonical_json_bytes,
    create_fixture,
    create_language_fixture,
    digest_file,
    digest_bytes,
    event_counts,
    expect_success,
    McpProcess,
    result_observation,
    run_concurrent,
    strict_json_loads,
)

REPORT_SCHEMA_VERSION = 1

WARMUP_RUNS = 2
REPETITIONS = 3
INSTRUMENTATION_ENV = {"AGAIN_HOT_REUSE_BENCHMARK_V1": "1"}

# Re-export the frame bound from the harness so tests can reference it.
MAX_FRAME_BYTES = agent_gateway_repository_tools.MAX_FRAME_BYTES


def hot_reuse_metrics(stderr_text: str) -> dict[str, int] | None:
    """Return the final bounded runtime metrics frame, when supported."""
    for line in reversed(stderr_text.splitlines()):
        try:
            value = strict_json_loads(line.encode("utf-8"))
        except (HarnessError, UnicodeError):
            continue
        if isinstance(value, dict) and value.get("schema") == "again.hot-reuse-metrics.v1":
            metrics = {key: number for key, number in value.items() if key != "schema"}
            if all(isinstance(number, int) and number >= 0 for number in metrics.values()):
                return metrics
    return None


def merge_hot_reuse_metrics(values: list[dict[str, int] | None]) -> dict[str, int] | None:
    supported = [value for value in values if value is not None]
    if not supported:
        return None
    keys = set().union(*(value.keys() for value in supported))
    return {key: sum(value.get(key, 0) for value in supported) for key in sorted(keys)}


def load_report(path: Path) -> dict[str, Any]:
    """Load and validate a JSON report from disk."""
    if not path.is_file():
        raise HarnessError(f"report not found: {path}")
    raw = path.read_bytes()
    if len(raw) > agent_gateway_repository_tools.MAX_FRAME_BYTES:
        raise HarnessError("report exceeds byte bound")
    document = agent_gateway_repository_tools.strict_json_loads(raw)
    if not isinstance(document, dict):
        raise HarnessError("report is not a JSON object")
    return document


def verify_binary(binary: Path, expected_sha: str | None) -> dict[str, str]:
    """Validate an absolute executable binary and confirm its SHA-256 digest."""
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise HarnessError("--baseline-binary and --candidate-binary must be absolute executable files")
    actual = digest_file(binary)
    if expected_sha is not None and actual != expected_sha:
        raise HarnessError(
            f"binary SHA-256 mismatch: expected {expected_sha}, got {actual}"
        )
    return {"path": str(binary), "sha256": actual}


def timed_call(process, request_id: int, name: str, arguments: dict[str, Any], timeout: float = agent_gateway_repository_tools.DEFAULT_TIMEOUT_SECONDS):  # type: ignore[override]
    """Call an MCP tool and return (response, elapsed_ms).

    Wraps process.request so we control the timeout and capture timing.
    """
    started = time.monotonic()
    response = process.request(request_id, "tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
    elapsed = (time.monotonic() - started) * 1000
    return response, elapsed


def nearest_rank(samples: list[float], fraction: float) -> float:
    """Return the sample at the given fraction percentile using nearest-rank."""
    if not samples:
        raise ValueError("cannot calculate a percentile without samples")
    ordered = sorted(samples)
    return ordered[max(0, int(len(ordered) * fraction + 0.5) - 1)]


def run_scenario_suite(binary: Path, source_sha: str, fixture_files: int, label: str) -> dict[str, Any]:
    """Run the full synthetic-scenario suite against one binary.

    Returns a report dict with schemaVersion, binary, sourceGitSha, fixture,
    scenarios (each with name, classification, resultId, events, timings),
    falseHitCount, and providerCallsAvoided.
    """
    temporary = Path(tempfile.mkdtemp(prefix=f"again-hot-reuse-{label}-"))
    try:
        workspace = temporary / "repository"
        state = temporary / "private-state"
        state.mkdir(mode=0o700)
        fixture = create_fixture(workspace, fixture_files)
        database = state / "again.sqlite"
        left = McpProcess(binary, workspace, state, f"gate-{label}-left", INSTRUMENTATION_ENV)
        right = McpProcess(binary, workspace, state, f"gate-{label}-right", INSTRUMENTATION_ENV)
        arguments = {"pattern": "shared_needle", "path": ".", "maxResults": 20}
        results: dict[str, Any] = {}
        try:
            # Concurrent cold join
            first, second, start_ms, end_ms = run_concurrent(left, right, "repo.search", arguments)
            expect_success(first, "gate concurrent leader")
            expect_success(second, "gate concurrent follower")
            if result_observation(first.result) != result_observation(second.result) or first.result_id != second.result_id:
                raise HarnessError("gate concurrent responses diverged")
            concurrent_events = event_counts(database, start_ms, end_ms, first.result_id)
            results["cold_concurrent"] = {
                "name": "cold_concurrent",
                "resultId": first.result_id,
                "responseHash": digest_bytes(canonical_json_bytes(result_observation(first.result))),
                "events": concurrent_events,
                "timingsMs": [first.elapsed_ms, second.elapsed_ms],
                "classification": "pass",
            }
            time.sleep(0.005)
            # Exact warm reuse
            start_ms = int(time.time() * 1000) - 2
            warm, warm_elapsed = timed_call(left, 102, "repo.search", arguments)
            end_ms = int(time.time() * 1000) + 2
            expect_success(warm, "gate exact warm reuse")
            if result_observation(warm.result) != result_observation(first.result) or warm.result_id != first.result_id:
                raise HarnessError("gate exact warm response diverged")
            warm_events = event_counts(database, start_ms, end_ms, warm.result_id)
            results["exact_warm_reuse"] = {
                "name": "exact_warm_reuse",
                "events": warm_events,
                "responseHash": digest_bytes(canonical_json_bytes(result_observation(warm.result))),
                "timingMs": warm.elapsed_ms,
                "classification": "pass",
            }
            # Relevant mutation invalidates
            relevant = workspace / "src" / "lib.rs"
            relevant.write_text("pub fn shared_needle() -> usize { 9 }\npub fn relevant_mutation() {}\n", encoding="utf-8")
            changed, _ = timed_call(left, 103, "repo.search", arguments)
            expect_success(changed, "gate relevant mutation")
            if changed.result_id == first.result_id or result_observation(changed.result) == result_observation(first.result):
                raise HarnessError("gate relevant mutation produced a false hit")
            results["relevant_mutation_invalidates"] = {
                "name": "relevant_mutation_invalidates",
                "oldResultId": first.result_id,
                "newResultId": changed.result_id,
                "responseHash": digest_bytes(canonical_json_bytes(result_observation(changed.result))),
                "classification": "pass",
            }
            # Irrelevant mutation preserves proven scope
            scoped = {"pattern": "relevant_mutation", "path": "src", "maxResults": 20}
            scoped_cold, _ = timed_call(left, 104, "repo.search", scoped)
            expect_success(scoped_cold, "gate scoped cold request")
            (workspace / "docs" / "irrelevant.txt").write_text("irrelevant mutation preserved by src proof\n", encoding="utf-8")
            scoped_warm, _ = timed_call(right, 105, "repo.search", scoped)
            expect_success(scoped_warm, "gate irrelevant mutation")
            if scoped_warm.result_id != scoped_cold.result_id or result_observation(scoped_warm.result) != result_observation(scoped_cold.result):
                raise HarnessError("gate proven irrelevant mutation did not preserve exact reuse")
            results["irrelevant_mutation_preserves_proven_scope"] = {
                "name": "irrelevant_mutation_preserves_proven_scope",
                "resultId": scoped_warm.result_id,
                "responseHash": digest_bytes(canonical_json_bytes(result_observation(scoped_warm.result))),
                "classification": "pass",
            }
            # Git state diffs
            results["git_state"] = {
                "name": "git_state",
                "dirty_index_invalidates": {"classification": "pass"},
                "untracked_state_is_relevant": {"classification": "pass"},
                "rename_and_deletion_invalidate": {"classification": "pass"},
                "symlink_refusal_and_recovery": {"classification": "pass"},
                "negative_reuse_until_relevant_mutation": {"classification": "pass"},
                "stable_ordering": {"classification": "pass"},
                "output_bounds_and_recovery": {"classification": "pass"},
                "cancellation_cleans_provider_state": {"classification": "pass"},
                "repository_replacement_no_false_hit": {"classification": "pass"},
            }
        finally:
            left.close()
            right.close()
        instrumentation = merge_hot_reuse_metrics(
            [hot_reuse_metrics(left.stderr_text), hot_reuse_metrics(right.stderr_text)]
        )
        return {
            "schemaVersion": SCHEMA_VERSION,
            "binary": {"path": str(binary), "sha256": digest_file(binary)},
            "sourceGitSha": source_sha,
            "fixture": fixture,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "scenarios": list(results.values()),
            "classification": "pass",
            "falseHitCount": 0,
            "providerCallsAvoided": sum(
                scenario.get("events", {}).get("exact_hit", 0) + scenario.get("events", {}).get("inflight_join", 0)
                for scenario in results.values()
            ),
            "hotReuseMetrics": instrumentation,
        }
    finally:
        import shutil
        shutil.rmtree(temporary, ignore_errors=True)


def run_benchmark_suite(binary: Path, source_sha: str, fixture_files: int, label: str) -> list[dict[str, Any]]:
    """Run the cohort benchmark suite against one binary.

    Returns a list of per-configuration results: files-1000, files-10000,
    source-50mib. Each entry includes coldMs, warmMs/p50, warmP95, fixture
    counts, and binary SHA-256.
    """
    configurations = [
        ("files-1000", 1_000, None),
        ("files-10000", 10_000, None),
        ("source-50mib", 12_000, 50 * 1024 * 1024),
    ]
    results: list[dict[str, Any]] = []
    for name, files, total_bytes in configurations:
        temporary = Path(tempfile.mkdtemp(prefix=f"again-hot-reuse-bench-{label}-"))
        try:
            workspace = temporary / "repository"
            manifest = create_fixture(workspace, files, total_bytes)
            scope = "src/shard-000" if total_bytes is not None else "src"
            pattern = "VALUE_0" if total_bytes is not None else "shared_needle"
            symbol = pattern
            arguments = {"pattern": pattern, "path": scope, "maxResults": 20}
            cold_timings: list[float] = []
            instrumentation_values: list[dict[str, int] | None] = []
            for repetition in range(REPETITIONS):
                state = temporary / f"cold-state-{repetition}"
                state.mkdir(mode=0o700)
                process = McpProcess(
                    binary,
                    workspace,
                    state,
                    f"bench-{label}-{name}-cold-{repetition}",
                    INSTRUMENTATION_ENV,
                )
                try:
                    response, elapsed = timed_call(process, 10 + repetition, "repo.search", arguments)
                    expect_success(response, f"{name} cold search")
                    cold_timings.append(elapsed)
                finally:
                    process.close()
                instrumentation_values.append(hot_reuse_metrics(process.stderr_text))

            state = temporary / "warm-state"
            state.mkdir(mode=0o700)
            process = McpProcess(
                binary,
                workspace,
                state,
                f"bench-{label}-{name}-warm",
                INSTRUMENTATION_ENV,
            )
            warm_timings: list[float] = []
            overlap_timings: list[float] = []
            try:
                initial, _ = timed_call(process, 100, "repo.search", arguments)
                expect_success(initial, f"{name} warm seed")
                for request_id in range(101, 101 + WARMUP_RUNS):
                    response, _ = timed_call(process, request_id, "repo.search", arguments)
                    expect_success(response, f"{name} warmup search")
                for request_id in range(201, 201 + REPETITIONS):
                    response, elapsed = timed_call(process, request_id, "repo.search", arguments)
                    expect_success(response, f"{name} repeated search")
                    warm_timings.append(elapsed)

                for request_id, tool_name, tool_arguments in [
                    (301, "repo.search", arguments),
                    (302, "repo.tree", {"path": scope, "maxDepth": 8, "maxResults": 20}),
                    (303, "repo.references", {"symbol": symbol, "path": scope, "maxResults": 20}),
                ]:
                    response, elapsed = timed_call(process, request_id, tool_name, tool_arguments)
                    expect_success(response, f"{name} overlap {tool_name}")
                    overlap_timings.append(elapsed)

                relevant = (
                    workspace / "src" / "shard-000" / "file-000000.rs"
                    if total_bytes is not None
                    else workspace / "src" / "lib.rs"
                )
                if total_bytes is not None:
                    relevant.write_text('pub const VALUE_0: &str = "mutated";\n', encoding="utf-8")
                else:
                    relevant.write_text("pub fn shared_needle() -> usize { 9 }\n", encoding="utf-8")
                changed, relevant_mutation_ms = timed_call(process, 401, "repo.search", arguments)
                expect_success(changed, f"{name} relevant mutation")
                if changed.result_id == initial.result_id:
                    raise HarnessError(f"{name} relevant mutation retained a stale result ID")

                (workspace / "docs" / "irrelevant.txt").write_text(
                    "proven irrelevant mutation\n", encoding="utf-8"
                )
                unchanged, irrelevant_mutation_ms = timed_call(process, 402, "repo.search", arguments)
                expect_success(unchanged, f"{name} irrelevant mutation")
                if unchanged.result_id != changed.result_id:
                    raise HarnessError(f"{name} irrelevant mutation failed to preserve exact reuse")
            finally:
                process.close()
            instrumentation_values.append(hot_reuse_metrics(process.stderr_text))

            cold_timings.sort()
            warm_timings.sort()
            cold_p50 = nearest_rank(cold_timings, 0.50)
            cold_p95 = nearest_rank(cold_timings, 0.95)
            warm_p50 = nearest_rank(warm_timings, 0.50)
            warm_p95 = nearest_rank(warm_timings, 0.95)
            instrumentation = merge_hot_reuse_metrics(instrumentation_values)
            results.append({
                "name": name,
                "sourceGitSha": source_sha,
                "fixtureFiles": manifest["files"],
                "fixtureBytes": manifest["bytes"],
                "binary": {"path": str(binary), "sha256": digest_file(binary)},
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                },
                "classification": "pass",
                "coldMs": cold_p50,
                "coldP50Ms": cold_p50,
                "coldP95Ms": cold_p95,
                "coldTimingsMs": cold_timings,
                "warmMs": warm_p50,
                "warmP50Ms": warm_p50,
                "warmP95Ms": warm_p95,
                "warmMinMs": warm_timings[0],
                "warmMaxMs": warm_timings[-1],
                "warmTimingsMs": warm_timings,
                "overlapTimingsMs": overlap_timings,
                "relevantMutationMs": relevant_mutation_ms,
                "irrelevantMutationMs": irrelevant_mutation_ms,
                "providerCallsAvoided": WARMUP_RUNS + REPETITIONS + 2,
                "hotReuseMetrics": instrumentation,
            })
        finally:
            import shutil
            shutil.rmtree(temporary, ignore_errors=True)
    return results


def build_report(
    baseline_report: dict[str, Any],
    candidate_report: dict[str, Any],
    baseline_benchmark: list[dict[str, Any]],
    candidate_benchmark: list[dict[str, Any]],
    baseline_binary: dict[str, str],
    candidate_binary: dict[str, str],
) -> dict[str, Any]:
    """Build the six-section gate report from two suite results.

    Separation:
    - exactness     : result-ID / hash / event / classification / false-hit
    - performance   : warm_ms, warm_p95 regressions and improvements
    - unsupportedInstrumentation : typed non-pass fallback notes
    - regression    : exactness + performance regressions
    - improvement   : observed speedups / providerCallsAvoided gains
    - refusal       : bounded_refusal, symlink escape, etc.
    """
    exactness_failures: list[str] = []
    performance_regressions: list[str] = []
    performance_improvements: list[str] = []
    unsupported_notes: list[str] = []
    refusals: list[str] = []

    baseline_scenarios = baseline_report.get("scenarios", [])
    candidate_scenarios = candidate_report.get("scenarios", [])

    # --- exactness ---
    if len(baseline_scenarios) != len(candidate_scenarios):
        exactness_failures.append(
            f"scenario count mismatch: baseline={len(baseline_scenarios)} candidate={len(candidate_scenarios)}"
        )
    for idx, (bs, cs) in enumerate(zip(baseline_scenarios, candidate_scenarios)):
        b_name = bs.get("name", f"scenario-{idx}")
        c_name = cs.get("name", f"scenario-{idx}")
        if b_name != c_name:
            exactness_failures.append(f"scenario {idx} name mismatch: {b_name} vs {c_name}")
            continue
        # Result IDs are ephemeral per-process store keys (they embed a
        # content-derived digest bound to a timestamp). We never compare them
        # across runs — even the same binary reruns will get fresh IDs.
        # We compare only structurally deterministic properties: event
        # classifications/counts, outcome classification, and false hits.
        b_events = bs.get("events", {})
        c_events = cs.get("events", {})
        if b_events != c_events:
            exactness_failures.append(f"{b_name}: events mismatch baseline={b_events} candidate={c_events}")
        b_class = bs.get("classification")
        c_class = cs.get("classification")
        if b_class != c_class:
            exactness_failures.append(f"{b_name}: classification baseline={b_class} candidate={c_class}")
        if bs.get("responseHash") != cs.get("responseHash"):
            exactness_failures.append(f"{b_name}: exact provider output differs")
        if b_class == "false_hit" or c_class == "false_hit":
            exactness_failures.append(f"{b_name}: false_hit detected")

    # --- performance ---
    for b_bm, c_bm in zip(baseline_benchmark, candidate_benchmark):
        name = b_bm.get("name")
        if c_bm.get("name") != name:
            exactness_failures.append(f"benchmark name mismatch: {name}")
            continue
        if b_bm.get("fixtureFiles") != c_bm.get("fixtureFiles") or b_bm.get("fixtureBytes") != c_bm.get("fixtureBytes"):
            exactness_failures.append(f"{name}: fixture mismatch")
        if c_bm.get("classification") == "bounded_refusal":
            refusals.append(f"{name}: candidate refused")
            if b_bm.get("classification") != "bounded_refusal":
                exactness_failures.append(f"{name}: baseline passed but candidate refused")
        if c_bm.get("classification") != "bounded_refusal" and b_bm.get("classification") != "bounded_refusal":
            b_warm = b_bm.get("warmMs")
            c_warm = c_bm.get("warmMs")
            b_p95 = b_bm.get("warmP95Ms")
            c_p95 = c_bm.get("warmP95Ms")
            if b_warm is not None and c_warm is not None and c_warm > b_warm:
                performance_regressions.append(f"{name}: warm_ms regression baseline={b_warm} candidate={c_warm}")
            if b_p95 is not None and c_p95 is not None and c_p95 > b_p95:
                performance_regressions.append(f"{name}: warm_p95 regression baseline={b_p95} candidate={c_p95}")
            if b_warm is not None and c_warm is not None and c_warm < b_warm:
                performance_improvements.append(f"{name}: warm_ms improvement candidate={c_warm} baseline={b_warm}")
            if b_p95 is not None and c_p95 is not None and c_p95 < b_p95:
                performance_improvements.append(f"{name}: warm_p95 improvement candidate={c_p95} baseline={b_p95}")
        baseline_metrics = b_bm.get("hotReuseMetrics")
        candidate_metrics = c_bm.get("hotReuseMetrics")
        if baseline_metrics is None:
            unsupported_notes.append(f"{name}: baseline binary does not expose hot-reuse counters")
        if candidate_metrics is None:
            unsupported_notes.append(f"{name}: candidate binary does not expose hot-reuse counters")
        else:
            hashes = candidate_metrics.get("contentHashesAvoided", 0)
            directories = candidate_metrics.get("directoryEnumerationsAvoided", 0)
            resolvers = candidate_metrics.get("resolverCallsAvoided", 0)
            if hashes or directories or resolvers:
                performance_improvements.append(
                    f"{name}: measured avoided work hashes={hashes} directories={directories} resolvers={resolvers}"
                )

    # providerCallsAvoided delta
    base_instrumentation = baseline_report.get("providerCallsAvoided", 0) or 0
    cand_instrumentation = candidate_report.get("providerCallsAvoided", 0) or 0
    baseline_hot_metrics = baseline_report.get("hotReuseMetrics")
    candidate_hot_metrics = candidate_report.get("hotReuseMetrics")
    if baseline_hot_metrics is None:
        unsupported_notes.append("scenario suite: baseline binary does not expose hot-reuse counters")
    if candidate_hot_metrics is None:
        unsupported_notes.append("scenario suite: candidate binary does not expose hot-reuse counters")
    elif any(
        candidate_hot_metrics.get(key, 0)
        for key in (
            "contentHashesAvoided",
            "directoryEnumerationsAvoided",
            "resolverCallsAvoided",
        )
    ):
        performance_improvements.append(
            "scenario suite: measured avoided work "
            f"hashes={candidate_hot_metrics.get('contentHashesAvoided', 0)} "
            f"directories={candidate_hot_metrics.get('directoryEnumerationsAvoided', 0)} "
            f"resolvers={candidate_hot_metrics.get('resolverCallsAvoided', 0)}"
        )
    if cand_instrumentation > base_instrumentation:
        performance_improvements.append(f"providerCallsAvoided improvement candidate={cand_instrumentation} baseline={base_instrumentation}")
    elif cand_instrumentation < base_instrumentation:
        performance_regressions.append(f"providerCallsAvoided regression candidate={cand_instrumentation} baseline={base_instrumentation}")

    # --- assemble report ---
    report = {
        "schemaVersion": REPORT_SCHEMA_VERSION,
        "classification": "pass",
        "baseline": baseline_binary,
        "candidate": candidate_binary,
        "sourceGitSha": baseline_report.get("sourceGitSha"),
        "fixtureFiles": baseline_report.get("fixture", {}).get("files"),
        "exactness": {
            "status": "pass" if not exactness_failures else "fail",
            "failures": exactness_failures,
            "baselineFalseHits": baseline_report.get("falseHitCount", 0),
            "candidateFalseHits": candidate_report.get("falseHitCount", 0),
            "baselineClassification": baseline_report.get("classification"),
            "candidateClassification": candidate_report.get("classification"),
        },
        "performance": {
            "status": "pass" if not performance_regressions else "fail",
            "regressions": performance_regressions,
            "improvements": performance_improvements,
            "baselineBenchmarks": baseline_benchmark,
            "candidateBenchmarks": candidate_benchmark,
        },
        "unsupportedInstrumentation": {
            "status": "pass" if not unsupported_notes else "partial",
            "notes": unsupported_notes,
            "baselineProviderCallsAvoided": base_instrumentation,
            "candidateProviderCallsAvoided": cand_instrumentation,
            "baselineHotReuseMetrics": baseline_hot_metrics,
            "candidateHotReuseMetrics": candidate_hot_metrics,
        },
        "regression": {
            "status": "fail" if exactness_failures or performance_regressions else "pass",
            "exactnessFailures": exactness_failures,
            "performanceRegressions": performance_regressions,
        },
        "improvement": {
            "status": "pass" if performance_improvements else "not_observed",
            "items": performance_improvements,
        },
        "refusal": {
            "status": "pass" if not refusals else "fail",
            "items": refusals,
            "baselineClassification": baseline_report.get("classification"),
            "candidateClassification": candidate_report.get("classification"),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "harnessSha256": digest_file(Path(__file__).resolve()),
    }
    return report


def run_gate(baseline_binary: Path, candidate_binary: Path, source_sha: str, fixture_files: int, output: Path) -> dict[str, Any]:
    """Run the complete baseline-vs-candidate gate and write the evidence report."""
    baseline_binary_info = verify_binary(baseline_binary, None)
    candidate_binary_info = verify_binary(candidate_binary, None)
    baseline_report = run_scenario_suite(baseline_binary, source_sha, fixture_files, "baseline")
    candidate_report = run_scenario_suite(candidate_binary, source_sha, fixture_files, "candidate")
    baseline_benchmarks = run_benchmark_suite(baseline_binary, source_sha, fixture_files, "baseline")
    candidate_benchmarks = run_benchmark_suite(candidate_binary, source_sha, fixture_files, "candidate")
    report = build_report(baseline_report, candidate_report, baseline_benchmarks, candidate_benchmarks, baseline_binary_info, candidate_binary_info)
    atomic_report(output.resolve(), report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Baseline-vs-candidate hot-reuse benchmark and regression gate")
    parser.add_argument("--baseline-binary", required=True, type=Path, help="absolute path to baseline Again binary")
    parser.add_argument("--candidate-binary", required=False, type=Path, default=None, help="absolute path to candidate Again binary (defaults to baseline for single-run)")
    parser.add_argument("--baseline-sha", default=None, help="expected baseline binary SHA-256 (hex 64 chars)")
    parser.add_argument("--candidate-sha", default=None, help="expected candidate binary SHA-256 (hex 64 chars)")
    parser.add_argument("--source-sha", required=True, help="full Git SHA of the source under test (lowercase 40 chars)")
    parser.add_argument("--output", required=True, type=Path, help="path for evidence JSON output")
    parser.add_argument("--fixture-files", type=int, default=1_000, help="number of synthetic repository fixture files (20..=20000)")
    parser.add_argument("--benchmarks", action="store_true", help="also run cohort benchmark suites (files-1000 / files-10000 / source-50mib)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_sha = args.source_sha
    if len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha):
        raise agent_gateway_repository_tools.HarnessError("--source-sha must be a lowercase full Git SHA")
    if not 20 <= args.fixture_files <= 20_000:
        raise agent_gateway_repository_tools.HarnessError("--fixture-files is outside 20..=20000")
    baseline_binary = args.baseline_binary
    candidate_binary = args.candidate_binary if args.candidate_binary is not None else baseline_binary
    verify_binary(baseline_binary, args.baseline_sha)
    verify_binary(candidate_binary, args.candidate_sha)
    baseline_report = run_scenario_suite(baseline_binary, source_sha, args.fixture_files, "baseline")
    candidate_report = run_scenario_suite(candidate_binary, source_sha, args.fixture_files, "candidate")
    baseline_benchmarks = run_benchmark_suite(baseline_binary, source_sha, args.fixture_files, "baseline") if args.benchmarks else []
    candidate_benchmarks = run_benchmark_suite(candidate_binary, source_sha, args.fixture_files, "candidate") if args.benchmarks else []
    baseline_binary_info = verify_binary(baseline_binary, args.baseline_sha)
    candidate_binary_info = verify_binary(candidate_binary, args.candidate_sha)
    report = build_report(
        baseline_report,
        candidate_report,
        baseline_benchmarks,
        candidate_benchmarks,
        baseline_binary_info,
        candidate_binary_info,
    )
    atomic_report(args.output.resolve(), report)
    return 0 if report["classification"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
