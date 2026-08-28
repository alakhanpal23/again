import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from bench import agent_reasoning_metrics as metrics


class AgentReasoningMetricsBenchmarkTests(unittest.TestCase):
    def test_output_is_byte_deterministic(self) -> None:
        config = metrics.MetricsBenchmarkConfig(
            facts=8,
            raw_bytes_per_fact=512,
            confirmed_deliveries=4,
            authenticated_delivery=True,
        )
        self.assertEqual(metrics.benchmark(config), metrics.benchmark(config))
        self.assertEqual(
            metrics.build_presentations(config), metrics.build_presentations(config)
        )

    def test_measurement_categories_are_separate(self) -> None:
        result = metrics.benchmark(
            metrics.MetricsBenchmarkConfig(
                facts=12,
                raw_bytes_per_fact=2048,
                provider_calls_avoided=7,
                provider_duration_ms=31,
                confirmed_deliveries=3,
                authenticated_delivery=True,
            )
        )
        self.assertGreater(result["structural_context_reduction_bytes"], 0)
        self.assertEqual(result["estimated_execution_time_saved_ms"], 7 * 31)
        self.assertGreater(result["delivery_confirmed_bytes_omitted"], 0)
        self.assertEqual(
            result["confirmed_tokens_avoided"],
            result["unique_confirmed_deliveries"]
            * (result["delivery_confirmed_bytes_omitted_per_delivery"] // 4),
        )

    def test_unacknowledged_and_legacy_activity_confirms_zero_omission(self) -> None:
        result = metrics.benchmark(
            metrics.MetricsBenchmarkConfig(
                confirmed_deliveries=9,
                duplicate_receipts_per_delivery=3,
                authenticated_delivery=False,
                legacy_compact_events=11,
            )
        )
        self.assertEqual(result["unique_confirmed_deliveries"], 0)
        self.assertEqual(result["delivery_confirmed_bytes_omitted"], 0)
        self.assertEqual(result["confirmed_tokens_avoided"], 0)
        self.assertEqual(result["legacy_compact_events_ignored"], 11)

    def test_duplicate_receipts_do_not_increase_confirmed_savings(self) -> None:
        base = metrics.MetricsBenchmarkConfig(
            confirmed_deliveries=5,
            duplicate_receipts_per_delivery=1,
            authenticated_delivery=True,
        )
        duplicate = metrics.MetricsBenchmarkConfig(
            confirmed_deliveries=5,
            duplicate_receipts_per_delivery=4,
            authenticated_delivery=True,
        )
        one = metrics.benchmark(base)
        many = metrics.benchmark(duplicate)
        self.assertEqual(
            one["delivery_confirmed_bytes_omitted"],
            many["delivery_confirmed_bytes_omitted"],
        )
        self.assertGreater(many["stored_receipt_rows"], one["stored_receipt_rows"])

    def test_bounds_and_no_overwrite_output(self) -> None:
        with self.assertRaises(ValueError):
            metrics.MetricsBenchmarkConfig(facts=0).validate()
        with self.assertRaises(ValueError):
            metrics.MetricsBenchmarkConfig(duplicate_receipts_per_delivery=0).validate()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "metrics.json"
            self.assertEqual(metrics.main(["--output", str(output)]), 0)
            self.assertEqual(json.loads(output.read_text())["benchmark_version"], 1)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                metrics.main(["--output", str(output)])


if __name__ == "__main__":
    unittest.main()
