from __future__ import annotations

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import reference_benchmark as benchmark  # noqa: E402


class ReferenceBenchmarkTest(unittest.TestCase):
    def valid_stats(self) -> dict[str, int]:
        return {field: 0 for field in benchmark.STATS_FIELDS}

    def test_current_stats_schema_and_expected_values_are_accepted(self) -> None:
        value = self.valid_stats()
        value["bypasses"] = 1
        benchmark.validate_stats(value, {"bypasses": 1}, "fixture")

    def test_missing_unknown_negative_boolean_and_unexpected_values_refuse(self) -> None:
        cases: list[dict[str, object]] = []
        missing = self.valid_stats()
        missing.pop("executions")
        cases.append(missing)
        unknown: dict[str, object] = self.valid_stats()
        unknown["future_counter"] = 0
        cases.append(unknown)
        negative: dict[str, object] = self.valid_stats()
        negative["executions"] = -1
        cases.append(negative)
        boolean: dict[str, object] = self.valid_stats()
        boolean["executions"] = False
        cases.append(boolean)
        unexpected: dict[str, object] = self.valid_stats()
        unexpected["executions"] = 1
        cases.append(unexpected)

        for value in cases:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                benchmark.validate_stats(value, {}, "fixture")  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
