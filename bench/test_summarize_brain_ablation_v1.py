"""Retained accepted-task evidence must recompute and fail closed on corruption."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from summarize_brain_ablation_v1 import validation_duration_ms


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bench/summarize_brain_ablation_v1.py"
CARD = ROOT / "bench/rate_card_gpt6sol_standard_short_2026-09-23.json"
EVIDENCE = ROOT / "bench/results/2026-09-24-historical-brain-large-excerpt"
REPORTS = (
    EVIDENCE / "again-historical-unlocated-large-preview-cold-first-042d20a.json",
    EVIDENCE / "again-historical-unlocated-large-preview-seeded-first-8746283.json",
)
EXACT_RANGE_EVIDENCE = ROOT / "bench/results/2026-09-24-historical-python-exact-range"
EXACT_RANGE_REPORTS = (
    EXACT_RANGE_EVIDENCE / "again-python-exact-range-cold-first-065d8c2.json",
    EXACT_RANGE_EVIDENCE / "again-python-exact-range-seeded-first-065d8c2.json",
)
FAST_PATH_EVIDENCE = ROOT / "bench/results/2026-09-24-brain-fast-path"
FAST_PATH_REPORTS = (
    FAST_PATH_EVIDENCE / "cold-first.json",
    FAST_PATH_EVIDENCE / "seeded-first.json",
)


class BrainAblationSummaryTest(unittest.TestCase):
    def command(self, output: pathlib.Path, reports=REPORTS,
                test_command="cargo test --locked --lib historical_search_oracle"):
        command = [sys.executable, str(SCRIPT)]
        for report in reports:
            command.extend(["--report", str(report)])
        command.extend([
            "--rate-card", str(CARD),
            "--test-command", test_command,
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

    def test_exact_range_pairs_recompute_validation_phase(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "summary.json"
            result = self.command(
                output, EXACT_RANGE_REPORTS,
                "cargo test --locked --lib historical_python_quote_oracle",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calculated = json.loads(output.read_text())
            retained = json.loads((EXACT_RANGE_EVIDENCE / "summary.json").read_text())
            self.assertEqual(calculated, retained)
            for pair in calculated["pairs"]:
                self.assertGreater(pair["coldRequiredValidationMs"], 0)
                self.assertGreater(pair["seededRequiredValidationMs"], 0)

    def test_fast_path_pairs_recompute(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "summary.json"
            result = self.command(
                output, FAST_PATH_REPORTS,
                "cargo test --locked --lib historical_python_quote_oracle",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            calculated = json.loads(output.read_text())
            retained = json.loads((FAST_PATH_EVIDENCE / "summary.json").read_text())
            self.assertEqual(calculated, retained)
            self.assertEqual(calculated["acceptedPairs"], 2)

    def test_required_validation_timing_requires_matching_start_and_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            raw = pathlib.Path(directory) / "events.jsonl"
            raw.write_text(json.dumps({
                "type": "item.completed",
                "item": {"id": "test-1", "type": "command_execution", "exit_code": 0,
                         "command": "cargo test --locked --lib example"},
            }) + "\n")
            timeline = [
                {"event": "item.started", "itemId": "test-1", "elapsedMs": 100.0},
                {"event": "item.completed", "itemId": "test-1", "elapsedMs": 140.5},
            ]
            self.assertEqual(validation_duration_ms({"eventTimeline": timeline}, raw,
                                                    "cargo test --locked --lib example"), 40.5)
            with self.assertRaisesRegex(RuntimeError, "lacks start/completion"):
                validation_duration_ms({"eventTimeline": timeline[1:]}, raw,
                                       "cargo test --locked --lib example")


if __name__ == "__main__":
    unittest.main()
