from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from bench import agent_gateway_chaos_soak as harness


def scenario_report() -> dict[str, object]:
    rid_a = "a" * 64
    rid_b = "b" * 64
    return {
        "false_hit_count": 0,
        "scenarios": {
            "concurrent_join": {
                "result_id": rid_a,
                "identical_responses": False,
                "identical_observations": True,
                "recipient_bound_presentations": True,
                "event_counts": {
                    "completed": 1,
                    "executed": 1,
                    "inflight_candidate": 1,
                    "inflight_join": 1,
                    "requested": 2,
                },
            },
            "exact_repeat": {
                "result_id": rid_a,
                "identical_response": False,
                "identical_observation": True,
                "event_counts": {"exact_candidate": 1, "exact_hit": 1, "requested": 1},
            },
            "relevant_mutation": {
                "baseline_result_id": rid_a,
                "new_result_id": rid_b,
                "old_result_served": False,
                "request_binding": "new",
                "baseline_window": {"request_binding": "old"},
                "event_counts": {"completed": 1, "executed": 1, "requested": 1},
            },
            "irrelevant_mutation": {
                "request_binding": "new",
                "event_counts": {"exact_candidate": 1, "exact_hit": 1, "requested": 1},
            },
            "follower_cancellation": {
                "follower_error_code": -32800,
                "leader_result_id": rid_a,
                "event_counts": {
                    "completed": 1,
                    "executed": 1,
                    "follower_cancelled": 1,
                    "inflight_candidate": 1,
                    "requested": 2,
                },
            },
            "leader_cancellation": {
                "cancel_error_code": -32800,
                "ready_results_before_retry": 0,
                "retry_result_id": rid_b,
                "event_counts": {"executed": 1, "failed": 1, "requested": 1},
            },
            "lease_owner_crash": {
                "classification": "bounded_recovery_without_stale_completion",
                "old_lease": {"lifecycle_generation": 3},
                "new_lease": {"lifecycle_generation": 4, "status": "completed"},
                "event_counts": {
                    "completed": 1,
                    "executed": 1,
                    "lease_expired": 1,
                    "requested": 1,
                },
            },
            "corrupted_evidence": {
                "served_result_id": None,
                "recomputed_output_matches": True,
                "quarantine_window": {
                    "reason": "result_corrupt",
                    "request_authority_issued": False,
                    "event_counts": {"binding_quarantined": 1},
                },
            },
        },
    }


class ChaosSoakHarnessTests(unittest.TestCase):
    def test_compact_private_root_and_shared_daemon_runtime_namespace(self) -> None:
        root = harness._create_run_root()
        try:
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertLess(len(str(root)), 64)
            state = root / "state"
            first = harness._session_environment(state, "first")
            second = harness._session_environment(state, "second")
            self.assertNotEqual(first["HOME"], second["HOME"])
            self.assertEqual(first["TMPDIR"], second["TMPDIR"])
            self.assertEqual(first["AGAIN_HOME"], second["AGAIN_HOME"])
        finally:
            shutil.rmtree(root)

    def test_canonical_json_and_digest_are_stable(self) -> None:
        self.assertEqual(
            harness.canonical_json({"z": 1, "a": "x"}), b'{"a":"x","z":1}\n'
        )
        self.assertEqual(harness.sha256_bytes(b"x"), harness.sha256_bytes(b"x"))

    def test_strict_json_rejects_duplicate_depth_oversize_and_framing(self) -> None:
        valid = b'{"jsonrpc":"2.0","id":1,"result":{}}\n'
        self.assertEqual(harness.parse_json_rpc_line(valid)["id"], 1)
        for raw, code in (
            (b'{"jsonrpc":"2.0","id":1,"id":2,"result":{}}\n', "duplicate_json_key"),
            (b'{"jsonrpc":"2.0","id":1,"result":{}}\r\n', "invalid_json_framing"),
            (b"x" * (harness.MAX_FRAME_BYTES + 1), "response_oversized"),
        ):
            with self.subTest(code=code), self.assertRaises(harness.HarnessRefusal) as refused:
                harness.parse_json_rpc_line(raw)
            self.assertEqual(refused.exception.code, code)
        deep: object = None
        for _ in range(harness.MAX_JSON_DEPTH + 1):
            deep = [deep]
        raw = harness.canonical_json({"jsonrpc": "2.0", "id": 1, "result": deep})
        with self.assertRaises(harness.HarnessRefusal) as refused:
            harness.parse_json_rpc_line(raw)
        self.assertEqual(refused.exception.code, "json_depth_limit")

    def test_selector_framing_times_out_and_accepts_split_line(self) -> None:
        read_fd, write_fd = os.pipe()
        read = os.fdopen(read_fd, "rb", buffering=0)
        fake = object.__new__(harness.Session)
        fake.stdout = read
        fake.buffer = bytearray()
        try:
            with self.assertRaises(harness.HarnessRefusal) as refused:
                fake._read_line(0.02)
            self.assertEqual(refused.exception.code, "response_timeout")

            def writer() -> None:
                os.write(write_fd, b'{"jsonrpc":"2.0",')
                time.sleep(0.01)
                os.write(write_fd, b'"id":1,"result":{}}\n')

            thread = threading.Thread(target=writer)
            thread.start()
            frame = fake._read_line(1.0)
            thread.join(1.0)
            self.assertEqual(harness.parse_json_rpc_line(frame)["id"], 1)
        finally:
            os.close(write_fd)
            read.close()

    def test_selector_resource_exhaustion_is_typed(self) -> None:
        fake = object.__new__(harness.Session)
        fake.stdout = object()
        fake.buffer = bytearray()
        with mock.patch.object(
            harness.selectors,
            "DefaultSelector",
            side_effect=OSError(24, "too many open files"),
        ):
            with self.assertRaises(harness.HarnessRefusal) as refused:
                fake._read_line(1.0)
        self.assertEqual(refused.exception.code, "host_resource_exhausted")

    def test_false_hits_are_derived_from_result_ids_outputs_and_events(self) -> None:
        report = scenario_report()
        count, cases = harness.derive_false_hits(report)
        self.assertEqual(count, 0)
        self.assertFalse(any(case["false_hit"] for case in cases))
        scenarios = report["scenarios"]
        assert isinstance(scenarios, dict)
        mutation = scenarios["relevant_mutation"]
        assert isinstance(mutation, dict)
        mutation["new_result_id"] = "a" * 64
        count, cases = harness.derive_false_hits(report)
        self.assertEqual(count, 1)
        self.assertTrue(
            next(case for case in cases if case["name"] == "mutation_invalidation")["false_hit"]
        )
        report = scenario_report()
        scenarios = report["scenarios"]
        assert isinstance(scenarios, dict)
        corruption = scenarios["corrupted_evidence"]
        assert isinstance(corruption, dict)
        corruption["served_result_id"] = "c" * 64
        self.assertEqual(harness.derive_false_hits(report)[0], 1)

    def test_atomic_evidence_refuses_overwrite_and_cleans_pending_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            path = root / "evidence.json"
            harness.write_exclusive(path, b"{}\n")
            self.assertEqual(path.read_bytes(), b"{}\n")
            with self.assertRaises(harness.HarnessRefusal) as refused:
                harness.write_exclusive(path, b'{"changed":true}\n')
            self.assertEqual(refused.exception.code, "evidence_exists")
            self.assertEqual(path.read_bytes(), b"{}\n")
            self.assertEqual(
                [item for item in root.iterdir() if item.name.endswith(".pending")], []
            )
            with self.assertRaises(harness.HarnessRefusal):
                harness.write_exclusive(
                    root / "large", b"x" * (harness.MAX_EVIDENCE_BYTES + 1)
                )

    def test_atomic_evidence_write_failure_never_publishes_final_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            path = root / "evidence.json"
            with mock.patch.object(harness.os, "write", side_effect=OSError("injected")):
                with self.assertRaises(OSError):
                    harness.write_exclusive(path, b"{}\n")
            self.assertFalse(path.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_pin_uses_stable_descriptor_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            source = root / "source"
            source.write_bytes(b"#!/bin/sh\nexit 0\n")
            source.chmod(0o700)
            pinned = harness.pin_binary_exact(source, root / "pin" / "again")
            self.assertTrue(harness.revalidate_pinned_binary(pinned)["stable"])
            pinned.executable_path.chmod(0o700)
            pinned.executable_path.write_bytes(b"changed")
            with self.assertRaises(harness.HarnessRefusal) as refused:
                harness.revalidate_pinned_binary(pinned)
            self.assertEqual(refused.exception.code, "binary_revalidation")

    def test_complete_process_group_cleanup_after_leader_exit(self) -> None:
        if os.name != "posix":
            self.skipTest("process groups require POSIX")
        process = subprocess.Popen(
            (
                sys.executable,
                "-c",
                "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        process.wait(timeout=5)
        self.assertTrue(harness._process_group_exists(process.pid))
        evidence = harness.terminate_owned_process_group(process.pid)
        self.assertTrue(evidence["absent_after_cleanup"])

    def test_bounds_and_network_nonclaim_are_explicit(self) -> None:
        self.assertEqual(harness.SCHEMA, "again.agent-gateway-chaos-soak.v3")
        self.assertEqual(harness.MAX_PROCESSES, 128)
        self.assertIn(100, harness.VALID_CONCURRENCIES)
        self.assertEqual(harness.LEASE_SECONDS, 30)
        self.assertEqual(harness.STDIO_MAX_INFLIGHT, 16)
        self.assertEqual(harness.DAEMON_RESPONSE_TIMEOUT_SECONDS, 15.0)
        self.assertGreater(harness.TRANSPORT_FIXTURE_BYTES, 8 * 1024 * 1024)
        self.assertGreater(harness.MAX_CPU_SECONDS, 0)
        self.assertGreater(harness.MAX_RSS_BYTES, 0)
        self.assertEqual(
            harness.EXPECTED_DAEMON_TOOLS,
            frozenset(harness.product.EXPECTED_ADVERTISED_TOOLS),
        )
        self.assertEqual(
            json.loads(harness.canonical_json({"mode": "quick"})), {"mode": "quick"}
        )

    def test_transport_frames_and_exact_refusals_are_stable(self) -> None:
        frame = harness._tool_frame("request-7", "TOKEN")
        value = json.loads(frame)
        self.assertTrue(frame.endswith(b"\n"))
        self.assertEqual(value["id"], "request-7")
        self.assertEqual(value["params"]["arguments"]["pattern"], "TOKEN")
        response = {
            "jsonrpc": "2.0",
            "id": "request-7",
            "error": {
                "code": -32021,
                "message": "bounded refusal",
                "data": {"reason": "bounded"},
            },
        }
        harness._require_error(
            response,
            "request-7",
            -32021,
            "bounded refusal",
            {"reason": "bounded"},
        )
        with self.assertRaises(harness.HarnessRefusal) as refused:
            harness._require_error(
                response, "request-7", -32021, "changed", {"reason": "bounded"}
            )
        self.assertEqual(refused.exception.code, "transport_error_mismatch")

    def test_invalid_seed_is_refused_before_environmental_work(self) -> None:
        for seed in (-1, 2**64, True):
            with self.subTest(seed=seed), self.assertRaises(
                harness.HarnessRefusal
            ) as refused:
                harness.run(pathlib.Path("/does/not/exist"), seed=seed)
            self.assertEqual(refused.exception.code, "seed")

    def test_beta_mode_requires_exactly_100_clients_before_environmental_work(self) -> None:
        for concurrency in (32, 64, 128):
            with self.subTest(concurrency=concurrency), self.assertRaises(
                harness.HarnessRefusal
            ) as refused:
                harness.run(
                    pathlib.Path("/does/not/exist"),
                    mode="beta",
                    concurrency=concurrency,
                )
            self.assertEqual(refused.exception.code, "concurrency")

    def test_cli_exposes_beta_mode_and_forwards_its_exact_defaults(self) -> None:
        expected = {
            "schema": harness.SCHEMA,
            "classification": {"type": "pass", "code": "test"},
        }
        with mock.patch.object(harness, "run", return_value=expected) as run:
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                status = harness.main(
                    ["--again-binary", "/tmp/again", "--mode", "beta"]
                )
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(stream.getvalue()), expected)
        run.assert_called_once_with(
            pathlib.Path("/tmp/again"),
            mode="beta",
            concurrency=None,
            duration=45.0,
            seed=1,
            output=None,
        )

    def test_main_separates_unsupported_environment_from_failure(self) -> None:
        cases = (
            (
                harness.HarnessUnsupported("missing_procfs", "unsupported host"),
                2,
                "unsupported_environment",
            ),
            (harness.HarnessRefusal("false_hit", "product mismatch"), 3, "failure"),
        )
        for error, expected_status, classification in cases:
            with self.subTest(classification=classification), mock.patch.object(
                harness, "run", side_effect=error
            ):
                stream = io.StringIO()
                with contextlib.redirect_stdout(stream):
                    status = harness.main(["--again-binary", "/missing/again"])
                evidence = json.loads(stream.getvalue())
            self.assertEqual(status, expected_status)
            self.assertEqual(evidence["classification"]["type"], classification)
            self.assertEqual(
                evidence["unsupported_environmental_conditions"],
                ["missing_procfs"] if classification == "unsupported_environment" else [],
            )

    def test_probe_cleanup_requires_exact_zero_exit(self) -> None:
        self.assertTrue(harness._clean_exit_code(0))
        for value in (1, -9, True, None, "0"):
            with self.subTest(value=value):
                self.assertFalse(harness._clean_exit_code(value))
        self.assertTrue(
            harness._cleanup_absent(
                {"process_group": {"absent_after_cleanup": True}}
            )
        )
        for value in (
            {},
            {"absent_after_cleanup": True},
            {"process_group": {"absent_after_cleanup": False}},
        ):
            with self.subTest(cleanup=value):
                self.assertFalse(harness._cleanup_absent(value))


if __name__ == "__main__":
    unittest.main()
