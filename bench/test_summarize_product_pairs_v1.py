"""Retained baseline/product task outcomes must recompute from bound traces."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "bench/summarize_product_pairs_v1.py"
CARD = ROOT / "bench/rate_card_gpt6sol_standard_short_2026-09-23.json"
EVIDENCE = ROOT / "bench/results/2026-09-24-bounded-fallback-trials"
REPORTS = {
    "2k": ("again-bounded-search-baseline-first-2263b20.json",),
    "3k": (
        "again-bounded-search-3k-baseline-first-ef8dfe1.json",
        "again-bounded-search-3k-again-first-ef8dfe1.json",
    ),
    "compact": (
        "again-bounded-search-compact-baseline-first-55a77ef.json",
        "again-bounded-search-compact-again-first-55a77ef.json",
    ),
}


class ProductPairSummaryTest(unittest.TestCase):
    def command(self, output: pathlib.Path, variant: str, names: tuple[str, ...]):
        command = [sys.executable, str(SCRIPT)]
        for name in names:
            command.extend(["--report", str(EVIDENCE / variant / name)])
        command.extend(["--rate-card", str(CARD), "--output", str(output)])
        return subprocess.run(command, capture_output=True, text=True, timeout=15)

    def test_retained_variants_recompute(self):
        with tempfile.TemporaryDirectory() as directory:
            for variant, names in REPORTS.items():
                output = pathlib.Path(directory) / f"{variant}.json"
                result = self.command(output, variant, names)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    json.loads(output.read_text()),
                    json.loads((EVIDENCE / variant / "summary.json").read_text()),
                )

    def test_duplicate_report_is_not_a_reverse_order_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "summary.json"
            name = REPORTS["compact"][0]
            result = self.command(output, "compact", (name, name))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("duplicate report", result.stderr)
            self.assertFalse(output.exists())

    def test_corrupt_raw_event_stream_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            original = EVIDENCE / "2k" / REPORTS["2k"][0]
            report = json.loads(original.read_text())
            for observation in report["observations"]:
                source = original.with_name(observation["rawEventFile"])
                (root / source.name).write_bytes(source.read_bytes())
            raw = root / report["observations"][0]["rawEventFile"]
            raw.write_bytes(raw.read_bytes() + b"\n")
            copied = root / original.name
            copied.write_text(json.dumps(report))
            output = root / "summary.json"
            result = subprocess.run([
                sys.executable, str(SCRIPT), "--report", str(copied),
                "--rate-card", str(CARD), "--output", str(output),
            ], capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("raw event digest mismatch", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
