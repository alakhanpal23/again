#!/usr/bin/env python3
"""Adversarial tests for the hot-reuse benchmark gate."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("hot_reuse_benchmark_gate.py")
SPEC = importlib.util.spec_from_file_location("hot_reuse_benchmark_gate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


class HotReuseBenchmarkGateTests(unittest.TestCase):
    def test_verify_binary_requires_absolute_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "fake"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            with self.assertRaises(GATE.HarnessError):
                GATE.verify_binary(Path("relative/fake"), None)
            with self.assertRaises(GATE.HarnessError):
                GATE.verify_binary(Path(temporary) / "missing", None)
            with self.assertRaises(GATE.HarnessError):
                GATE.verify_binary(binary, "00" * 32)
            verified = GATE.verify_binary(binary, None)
            self.assertEqual(verified["path"], str(binary))
            self.assertEqual(len(verified["sha256"]), 64)

    def test_verify_binary_checks_expected_sha(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "binary"
            binary.write_bytes(b"abc")
            binary.chmod(0o755)
            actual = GATE.digest_file(binary)
            info = GATE.verify_binary(binary, actual)
            self.assertEqual(info["sha256"], actual)
            with self.assertRaises(GATE.HarnessError):
                GATE.verify_binary(binary, "ff" * 32)

    def test_load_report_rejects_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(GATE.HarnessError):
                GATE.load_report(Path(temporary) / "missing.json")

    def test_load_report_rejects_malformed_and_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text("not json", encoding="utf-8")
            with self.assertRaises(GATE.HarnessError):
                GATE.load_report(path)
            oversize_path = Path(temporary) / "oversize.json"
            oversize_path.write_bytes(b"a" * (GATE.MAX_FRAME_BYTES + 2))
            with self.assertRaises(GATE.HarnessError):
                GATE.load_report(oversize_path)
            object_path = Path(temporary) / "object.json"
            object_path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
            with self.assertRaises(GATE.HarnessError):
                GATE.load_report(object_path)

    def test_atomic_report_writes_canonical_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            GATE.atomic_report(path, {"schemaVersion": 1, "value": "first"})
            content = path.read_text()
            expected = json.dumps({"schemaVersion": 1, "value": "first"}, sort_keys=True, separators=(",", ":")) + "\n"
            self.assertEqual(content, expected)
            with self.assertRaises(GATE.HarnessError):
                GATE.atomic_report(path, {"schemaVersion": 1, "value": "second"})

    def test_build_report_passes_on_identical_results(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=5)
        candidate = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=5)
        baseline_benchmark = _make_benchmark(warm_ms=10.0, warm_p95=12.0)
        candidate_benchmark = _make_benchmark(warm_ms=10.0, warm_p95=12.0)
        report = GATE.build_report(
            baseline,
            candidate,
            [baseline_benchmark],
            [candidate_benchmark],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["exactness"]["status"], "pass")
        self.assertEqual(report["performance"]["status"], "pass")
        self.assertEqual(report["regression"]["status"], "pass")
        self.assertEqual(report["improvement"]["status"], "not_observed")
        self.assertEqual(report["refusal"]["status"], "pass")

    def test_build_report_detects_exactness_failure(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=1, events={"requested": 1, "exact_hit": 1})
        candidate = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=1, events={"requested": 1, "executed": 1})
        report = GATE.build_report(
            baseline,
            candidate,
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["exactness"]["status"], "fail")
        self.assertTrue(any("events" in f for f in report["exactness"]["failures"]))
        self.assertEqual(report["regression"]["status"], "fail")

    def test_build_report_detects_events_mismatch(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True, events={"requested": 1, "exact_hit": 1})
        candidate = _make_report(false_hits=0, exact_warm=True, events={"requested": 1, "executed": 1})
        report = GATE.build_report(
            baseline,
            candidate,
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["exactness"]["status"], "fail")
        self.assertTrue(any("events" in f for f in report["exactness"]["failures"]))

    def test_build_report_detects_performance_regression_and_improvement(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=1)
        candidate = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=1)
        baseline_benchmark = _make_benchmark(warm_ms=10.0, warm_p95=12.0)
        regressed_benchmark = _make_benchmark(warm_ms=20.0, warm_p95=25.0)
        improved_benchmark = _make_benchmark(warm_ms=5.0, warm_p95=6.0)
        report = GATE.build_report(
            baseline,
            candidate,
            [baseline_benchmark],
            [regressed_benchmark],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["performance"]["status"], "fail")
        self.assertTrue(any("warm_ms regression" in r for r in report["performance"]["regressions"]))
        self.assertTrue(any("warm_p95 regression" in r for r in report["performance"]["regressions"]))
        improved_report = GATE.build_report(
            baseline,
            candidate,
            [baseline_benchmark],
            [improved_benchmark],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(improved_report["performance"]["status"], "pass")
        self.assertTrue(any("improvement" in i for i in improved_report["performance"]["improvements"]))
        self.assertEqual(improved_report["improvement"]["status"], "pass")

    def test_build_report_detects_provider_calls_regression(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=10)
        candidate = _make_report(false_hits=0, exact_warm=True, provider_calls_avoided=5)
        report = GATE.build_report(
            baseline,
            candidate,
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertTrue(any("providerCallsAvoided" in r for r in report["performance"]["regressions"]))

    def test_build_report_detects_bounded_refusal(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True)
        candidate = _make_report(false_hits=0, exact_warm=True, classification="bounded_refusal")
        baseline_benchmark = _make_benchmark(warm_ms=10.0, warm_p95=12.0, classification="pass")
        candidate_benchmark = _make_benchmark(warm_ms=None, warm_p95=None, classification="bounded_refusal")
        report = GATE.build_report(
            baseline,
            candidate,
            [baseline_benchmark],
            [candidate_benchmark],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["refusal"]["status"], "fail")
        self.assertTrue(any("refused" in i for i in report["refusal"]["items"]))
        self.assertTrue(any("baseline passed but candidate refused" in f for f in report["exactness"]["failures"]))

    def test_build_report_detects_scenario_count_mismatch(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True)
        candidate = _make_report(false_hits=0, exact_warm=True, extra_scenarios=1)
        report = GATE.build_report(
            baseline,
            candidate,
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertTrue(any("scenario count mismatch" in f for f in report["exactness"]["failures"]))

    def test_build_report_records_baseline_and_candidate_metadata(self) -> None:
        baseline = _make_report(false_hits=0, exact_warm=True)
        candidate = _make_report(false_hits=0, exact_warm=True)
        report = GATE.build_report(
            baseline,
            candidate,
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            [_make_benchmark(warm_ms=10.0, warm_p95=12.0)],
            {"path": "/a", "sha256": "aa" * 32},
            {"path": "/b", "sha256": "bb" * 32},
        )
        self.assertEqual(report["baseline"]["sha256"], "aa" * 32)
        self.assertEqual(report["candidate"]["sha256"], "bb" * 32)
        self.assertEqual(report["sourceGitSha"], baseline["sourceGitSha"])
        self.assertIn("system", report["platform"])
        self.assertEqual(len(report["harnessSha256"]), 64)


def _make_report(
    false_hits: int = 0,
    exact_warm: bool = True,
    provider_calls_avoided: int = 0,
    result_id: str = "r-shared",
    response_hash: str = "h-shared",
    events: dict | None = None,
    classification: str = "pass",
    extra_scenarios: int = 0,
) -> dict:
    if events is None:
        events = {"requested": 1, "exact_hit": 1} if exact_warm else {"requested": 1, "executed": 1}
    scenario = {
        "name": "scenario-0",
        "classification": classification,
        "resultId": result_id,
        "responseHash": response_hash,
        "events": events,
    }
    scenarios = [scenario] + [
        {"name": f"extra-{i}", "classification": "pass"} for i in range(extra_scenarios)
    ]
    return {
        "schemaVersion": GATE.SCHEMA_VERSION,
        "binary": {"path": "/x", "sha256": "ff" * 32},
        "sourceGitSha": "a" * 40,
        "fixture": {"files": 1000, "bytes": 100000},
        "scenarios": scenarios,
        "falseHitCount": false_hits,
        "providerCallsAvoided": provider_calls_avoided,
        "classification": classification,
    }


def _make_benchmark(warm_ms: float | None, warm_p95: float | None, classification: str = "pass") -> dict:
    return {
        "name": "files-1000",
        "sourceGitSha": "a" * 40,
        "fixtureFiles": 1000,
        "fixtureBytes": 100000,
        "binary": {"path": "/x", "sha256": "ff" * 32},
        "classification": classification,
        "coldMs": warm_ms if warm_ms is not None else 0,
        "warmMs": warm_ms,
        "warmP50Ms": warm_ms,
        "warmP95Ms": warm_p95,
        "warmMinMs": warm_ms,
        "warmMaxMs": warm_p95,
        "warmTimingsMs": [warm_ms] if warm_ms is not None else [],
        "providerCallsAvoided": 1,
    }


if __name__ == "__main__":
    unittest.main()
