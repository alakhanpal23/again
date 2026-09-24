"""Retained accepted-task evidence must recompute and fail closed on corruption."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bench/summarize_brain_ablation_v1.py"
CARD = ROOT / "bench/rate_card_gpt6sol_standard_short_2026-09-23.json"
EVIDENCE = ROOT / "bench/results/2026-09-24-historical-brain-large-excerpt"
REPORTS = (
    EVIDENCE / "again-historical-unlocated-large-preview-cold-first-042d20a.json",
    EVIDENCE / "again-historical-unlocated-large-preview-seeded-first-8746283.json",
)


class BrainAblationSummaryTest(unittest.TestCase):
    def command(self, output: pathlib.Path, reports=REPORTS):
        command = [sys.executable, str(SCRIPT)]
        for report in reports:
            command.extend(["--report", str(report)])
        command.extend([
            "--rate-card", str(CARD),
            "--test-command", "cargo test --locked --lib historical_search_oracle",
            "--output", str(output),
        ])
        return subprocess.run(command, capture_output=True, text=True, timeout=15)

    def test_retained_historical_pairs_recompute(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "summary.json"
            result = self.command(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            calculated = json.loads(output.read_text())
            retained = json.loads((EVIDENCE / "summary.json").read_text())
            for key in (
                "acceptedPairs", "pairedMedianElapsedRatio", "apiEquivalentCostRatio",
                "coldInvestigationCommands", "seededInvestigationCommands",
            ):
                self.assertEqual(calculated[key], retained[key])

    def test_duplicate_report_cannot_stand_in_for_reverse_order(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "summary.json"
            result = self.command(output, (REPORTS[0], REPORTS[0]))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate ablation report", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
