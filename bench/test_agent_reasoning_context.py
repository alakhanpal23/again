import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from bench import agent_reasoning_context as benchmark_module


class AgentReasoningContextBenchmarkTests(unittest.TestCase):
    def test_canonical_context_hashes_are_deterministic(self) -> None:
        config = benchmark_module.BenchmarkConfig(
            facts=8, raw_bytes_per_fact=512, iterations=1
        )
        first = benchmark_module.build_contexts(config)
        second = benchmark_module.build_contexts(config)
        self.assertEqual(first, second)

    def test_unconfirmed_delivery_counts_no_savings(self) -> None:
        result = benchmark_module.benchmark(
            benchmark_module.BenchmarkConfig(
                facts=12,
                raw_bytes_per_fact=1024,
                iterations=2,
                confirmed_delivery=False,
            )
        )
        self.assertGreater(result["structural_context_reduction_bytes"], 0)
        self.assertEqual(result["presentation"], "full")
        self.assertEqual(result["delivery_confirmed_bytes_omitted"], 0)
        self.assertEqual(result["confirmed_tokens_avoided"], 0)
        self.assertEqual(
            result["context_bytes_delivered"], result["reasoning_brief_bytes"]
        )

    def test_confirmed_delivery_reports_only_actual_compact_omission(self) -> None:
        result = benchmark_module.benchmark(
            benchmark_module.BenchmarkConfig(
                facts=12,
                raw_bytes_per_fact=1024,
                iterations=2,
                confirmed_delivery=True,
            )
        )
        self.assertEqual(result["presentation"], "compact_reference")
        self.assertGreater(result["delivery_confirmed_bytes_omitted"], 0)
        self.assertEqual(
            result["confirmed_tokens_avoided"],
            result["delivery_confirmed_bytes_omitted"] // 4,
        )

    def test_resource_bounds_are_typed_errors(self) -> None:
        for config in [
            benchmark_module.BenchmarkConfig(facts=0),
            benchmark_module.BenchmarkConfig(
                raw_bytes_per_fact=benchmark_module.MAX_RAW_BYTES_PER_FACT + 1
            ),
            benchmark_module.BenchmarkConfig(iterations=0),
        ]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                config.validate()

    def test_cli_output_is_json_and_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence.json"
            self.assertEqual(
                benchmark_module.main(
                    [
                        "--facts",
                        "4",
                        "--raw-bytes-per-fact",
                        "128",
                        "--iterations",
                        "1",
                        "--output",
                        str(output),
                    ]
                ),
                0,
            )
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["benchmark_version"], 1)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                benchmark_module.main(
                    [
                        "--facts",
                        "4",
                        "--raw-bytes-per-fact",
                        "128",
                        "--iterations",
                        "1",
                        "--output",
                        str(output),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
