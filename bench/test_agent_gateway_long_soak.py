from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from bench import agent_gateway_long_soak as soak


class LongSoakTests(unittest.TestCase):
    def test_two_hour_contract_repeats_exact_beta_cycles_and_retains_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            binary = root / "again"
            binary.write_bytes(b"binary")
            now = [0.0]

            def cycle_runner(
                _binary: pathlib.Path, **arguments: object
            ) -> dict[str, object]:
                self.assertEqual(arguments["mode"], "beta")
                self.assertEqual(arguments["concurrency"], 100)
                output = arguments["output"]
                assert isinstance(output, pathlib.Path)
                index = int(output.stem.split("-")[1])
                now[0] += 3600.0
                report = {
                    "classification": {"type": "pass"},
                    "mode": "beta",
                    "concurrency": 100,
                    "false_hit_count": 0,
                    "source_git_sha": "a" * 40,
                    "binary": {"sha256": "b" * 64},
                    "elapsed_seconds": 42.0,
                    "exact_probe": {
                        "sessions": 100,
                        "operations": 2000,
                        "referenced_results": 2000,
                        "unreferenced_direct_results": 0,
                        "unique_result_ids": 1,
                    },
                    "resource_observation": {
                        "resource_leaks": [],
                        "all_owned_process_groups_absent": True,
                    },
                    "report_sha256": f"{index:064x}",
                }
                output.write_text(json.dumps(report), encoding="utf-8")
                return report

            output_dir = root / "evidence"
            report = soak.run_long_soak(
                binary,
                output_dir,
                duration_seconds=7200,
                seed=10,
                clock=lambda: now[0],
                cycle_runner=cycle_runner,
            )
            self.assertEqual(report["completed_cycles"], 2)
            self.assertEqual(report["completed_operations"], 4000)
            self.assertEqual((output_dir.stat().st_mode & 0o777), 0o700)
            retained = json.loads((output_dir / "summary.json").read_text())
            self.assertEqual(retained["classification"]["type"], "pass")
            self.assertEqual((output_dir / "summary.json").stat().st_mode & 0o777, 0o600)

    def test_short_duration_and_existing_directory_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            binary = root / "again"
            binary.write_bytes(b"binary")
            with self.assertRaisesRegex(Exception, "between two and twenty-four hours"):
                soak.run_long_soak(
                    binary,
                    root / "new",
                    duration_seconds=7199,
                    seed=1,
                )
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(Exception, "new absolute path"):
                soak.run_long_soak(
                    binary,
                    existing,
                    duration_seconds=7200,
                    seed=1,
                )


if __name__ == "__main__":
    unittest.main()
