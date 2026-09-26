"""The cohort scorecard must not turn surviving fast pairs into a pass."""

from __future__ import annotations

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from single_agent_cold_cohort_v1 import summarize


def observation(condition: str, elapsed_ms: float) -> dict:
    return {
        "condition": condition,
        "elapsedMs": elapsed_ms,
        "completedActions": [],
        "usage": {"input_tokens": 100, "cached_input_tokens": 0, "output_tokens": 10},
    }


def report(accepted: bool, again_ms: float) -> dict:
    return {
        "fixture": "fixture",
        "sourceFiles": 0,
        "order": ["baseline", "product"],
        "accepted": accepted,
        "requiredAgentValidation": [],
        "observations": [observation("baseline", 100.0), observation("product", again_ms)],
    }


def manifest() -> dict:
    return {"schema": "again.single-agent-cold-cohort.v1", "model": "fixture-model",
            "purpose": "test", "cases": [{}], "orders": ["baseline-first", "again-first"]}


class CohortScorecardTests(unittest.TestCase):
    def test_failed_pair_cannot_make_surviving_fast_pair_pass(self) -> None:
        manifest_path = pathlib.Path(__file__)
        result = summarize(manifest(), [report(True, 50.0), report(False, 200.0)],
                           "binary-hash", manifest_path)
        self.assertEqual(result["acceptedPairs"], 1)
        self.assertEqual(result["totalPairs"], 2)
        self.assertEqual(result["pairedMedianElapsedRatio"], 0.5)
        self.assertFalse(result["allPairsAccepted"])
        self.assertFalse(result["pairedMedianElapsedTargetMet"])

    def test_complete_accepted_pairs_can_meet_diagnostic_time_target(self) -> None:
        result = summarize(manifest(), [report(True, 50.0), report(True, 70.0)],
                           "binary-hash", pathlib.Path(__file__))
        self.assertTrue(result["allPairsAccepted"])
        self.assertTrue(result["allUsageVectorsComplete"])
        self.assertTrue(result["pairedMedianElapsedTargetMet"])

    def test_missing_usage_cannot_pass_target(self) -> None:
        incomplete = report(True, 50.0)
        incomplete["observations"][1]["usage"] = None
        result = summarize(manifest(), [incomplete, report(True, 70.0)],
                           "binary-hash", pathlib.Path(__file__))
        self.assertTrue(result["allPairsAccepted"])
        self.assertFalse(result["allUsageVectorsComplete"])
        self.assertFalse(result["pairedMedianElapsedTargetMet"])

    def test_missing_pair_cannot_pass_target(self) -> None:
        result = summarize(manifest(), [report(True, 50.0)],
                           "binary-hash", pathlib.Path(__file__))
        self.assertEqual(result["expectedPairs"], 2)
        self.assertFalse(result["allPairsAccepted"])
        self.assertFalse(result["pairedMedianElapsedTargetMet"])


if __name__ == "__main__":
    unittest.main()
