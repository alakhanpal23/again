from __future__ import annotations

import copy
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from bench import agent_gateway_product_e2e as harness


class GatewayProductE2ETest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-product-e2e-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_expected_catalog_includes_local_alpha_task_start_once(self) -> None:
        self.assertEqual(len(harness.EXPECTED_ADVERTISED_TOOLS), 14)
        self.assertEqual(harness.EXPECTED_ADVERTISED_TOOLS.count("again.task_start"), 1)
        self.assertIn("again.task_start", harness.E2E_EXERCISED_TOOLS)

    def database(self, *, version: int = harness.EXPECTED_DATABASE_SCHEMA) -> pathlib.Path:
        path = self.root / f"gateway-{time.time_ns()}.sqlite"
        connection = sqlite3.connect(path)
        connection.executescript(
            """
            CREATE TABLE gateway_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                call_id TEXT,
                lease_id TEXT,
                gateway_result_id TEXT,
                event_type TEXT NOT NULL,
                reason TEXT,
                estimated_tokens_avoided INTEGER NOT NULL DEFAULT 0,
                created_ms INTEGER NOT NULL
            );
            CREATE TABLE gateway_requests (
                call_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL,
                state_digest TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                binding_digest TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE TABLE gateway_results (
                gateway_result_id TEXT PRIMARY KEY,
                binding_digest TEXT NOT NULL,
                stdout_digest TEXT,
                status TEXT NOT NULL
            );
            CREATE TABLE inflight_leases (
                lease_id TEXT PRIMARY KEY,
                call_id TEXT,
                binding_digest TEXT,
                owner TEXT,
                status TEXT,
                reason TEXT,
                acquired_ms INTEGER,
                heartbeat_ms INTEGER,
                expires_ms INTEGER,
                execution_started_ms INTEGER,
                completed_ms INTEGER,
                lifecycle_generation INTEGER,
                gateway_result_id TEXT
            );
            CREATE TABLE results (id TEXT PRIMARY KEY);
            """
        )
        connection.execute(f"PRAGMA user_version = {version}")
        connection.commit()
        connection.close()
        return path

    @staticmethod
    def insert_event_fixture(path: pathlib.Path, event_types: list[str]) -> None:
        connection = sqlite3.connect(path)
        connection.execute(
            "INSERT INTO gateway_requests VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("call", "r" * 64, "s" * 64, "p" * 64, "b" * 64, "leader", "ready"),
        )
        for offset, event_type in enumerate(event_types):
            connection.execute(
                """
                INSERT INTO gateway_events
                    (call_id, event_type, estimated_tokens_avoided, created_ms)
                VALUES ('call', ?1, 0, ?2)
                """,
                (event_type, 1_000 + offset),
            )
        connection.commit()
        connection.close()

    def test_strict_json_rpc_parsing_rejects_malformed_duplicate_and_nonfinite(self) -> None:
        valid = harness.parse_json_rpc_line(
            b'{"jsonrpc":"2.0","id":1,"result":{"value":true}}\n'
        )
        self.assertEqual(valid["result"], {"value": True})

        cases = (
            (b'{"jsonrpc":"2.0","id":1,"result":}\n', "malformed_json"),
            (
                b'{"jsonrpc":"2.0","id":1,"id":2,"result":{}}\n',
                "duplicate_json_key",
            ),
            (b'{"jsonrpc":"2.0","id":1,"result":NaN}\n', "nonfinite_json_number"),
            (b'{"jsonrpc":"2.0","id":1,"result":{},"extra":1}\n', "invalid_json_rpc"),
            (b'{"jsonrpc":"2.0","id":1,"result":{}}\ntrailing\n', "truncated_output"),
        )
        for raw, code in cases:
            with self.subTest(code=code), self.assertRaises(harness.HarnessRefusal) as refused:
                harness.parse_json_rpc_line(raw)
            self.assertEqual(refused.exception.code, code)

    def test_json_response_size_depth_and_node_bounds_fail_closed(self) -> None:
        with self.assertRaises(harness.HarnessRefusal) as size:
            harness.parse_json_rpc_line(
                b'{"jsonrpc":"2.0","id":1,"result":{}}\n', maximum=8
            )
        self.assertEqual(size.exception.code, "response_oversized")

        deep: object = None
        for _ in range(harness.MAX_JSON_DEPTH + 1):
            deep = [deep]
        with self.assertRaises(harness.HarnessRefusal) as depth:
            harness.parse_json_rpc_line(
                harness.canonical_json_bytes(
                    {"jsonrpc": "2.0", "id": 1, "result": deep}
                )
            )
        self.assertEqual(depth.exception.code, "json_depth_limit")

        wide = [0] * harness.MAX_JSON_NODES
        with self.assertRaises(harness.HarnessRefusal) as nodes:
            harness.parse_json_rpc_line(
                harness.canonical_json_bytes(
                    {"jsonrpc": "2.0", "id": 1, "result": wide}
                )
            )
        self.assertEqual(nodes.exception.code, "json_node_limit")

    def test_report_canonicalization_is_stable(self) -> None:
        left = {"z": [3, {"b": 2, "a": 1}], "a": "雪"}
        right = {"a": "雪", "z": [3, {"a": 1, "b": 2}]}
        first = harness.canonical_json_bytes(left)
        self.assertEqual(first, harness.canonical_json_bytes(right))
        self.assertEqual(first, b'{"a":"\xe9\x9b\xaa","z":[3,{"a":1,"b":2}]}\n')
        self.assertEqual(json.loads(first), left)

    def test_output_is_exclusive_and_never_overwritten(self) -> None:
        output = self.root / "evidence.json"
        harness.write_json_exclusive(output, {"first": True})
        before = output.read_bytes()
        with self.assertRaises(harness.HarnessRefusal) as refused:
            harness.write_json_exclusive(output, {"second": True})
        self.assertEqual(refused.exception.code, "output_exists")
        self.assertEqual(output.read_bytes(), before)

    def test_binary_pinning_records_and_preserves_exact_sha256(self) -> None:
        source = pathlib.Path(sys.executable).resolve()
        pinned = harness.pin_binary(source, self.root / "pinned" / "binary")
        self.assertEqual(pinned.requested_path, source)
        self.assertEqual(pinned.sha256, harness.sha256_file(source))
        self.assertEqual(pinned.sha256, harness.sha256_file(pinned.executable_path))
        self.assertTrue(os.access(pinned.executable_path, os.X_OK))

    def test_event_reconciliation_is_bound_to_time_and_request(self) -> None:
        database = self.database()
        self.insert_event_fixture(database, ["requested", "executed", "completed"])
        reader = harness.GatewayEvents(database)
        window = harness.EventWindow(999, 2_000, 1, 3)
        bindings = reader.bindings(window)
        self.assertEqual([item["binding_digest"] for item in bindings], ["b" * 64])
        events = reader.events("b" * 64, window)
        self.assertEqual(
            harness.reconcile_events(
                events, {"requested": 1, "executed": 1, "completed": 1}
            ),
            {"completed": 1, "executed": 1, "requested": 1},
        )
        self.assertEqual(reader.events("x" * 64, window), [])
        self.assertEqual(reader.events("b" * 64, harness.EventWindow(2_001, 3_000, 1, 3)), [])

    def test_result_event_reconciliation_includes_pre_request_quarantine(self) -> None:
        database = self.database()
        result_id = "a" * 64
        connection = sqlite3.connect(database)
        connection.execute(
            """
            INSERT INTO gateway_events
                (call_id, gateway_result_id, event_type, reason,
                 estimated_tokens_avoided, created_ms)
            VALUES ('quarantine-audit-call', ?1, 'binding_quarantined',
                    'result_corrupt', 0, 1000)
            """,
            (result_id,),
        )
        connection.commit()
        connection.close()
        reader = harness.GatewayEvents(database)
        events = reader.result_events(result_id, harness.EventWindow(999, 2000, 1, 1))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["call_id"], "quarantine-audit-call")
        self.assertIsNone(events[0]["request_row_call_id"])
        self.assertEqual(events[0]["reason"], "result_corrupt")
        self.assertEqual(
            harness.reconcile_events(events, {"binding_quarantined": 1}),
            {"binding_quarantined": 1},
        )

    def test_unknown_database_schema_is_refused(self) -> None:
        reader = harness.GatewayEvents(self.database(version=999))
        with self.assertRaises(harness.HarnessRefusal) as refused:
            reader.max_event_id()
        self.assertEqual(refused.exception.code, "unknown_database_schema")

    def test_missing_and_extra_events_are_both_refused(self) -> None:
        events = [{"event_type": "requested"}, {"event_type": "executed"}]
        with self.assertRaises(harness.HarnessRefusal) as missing:
            harness.reconcile_events(events, {"requested": 1, "executed": 1, "completed": 1})
        self.assertEqual(missing.exception.code, "event_reconciliation_failed")
        with self.assertRaises(harness.HarnessRefusal) as extra:
            harness.reconcile_events(events, {"requested": 1})
        self.assertEqual(extra.exception.code, "event_reconciliation_failed")

    def test_response_timeout_is_typed(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.assertIsNotNone(process.stdout)
        session = harness.McpSession.__new__(harness.McpSession)
        session.label = "timeout-test"
        session._stdout = process.stdout
        session._stdout_buffer = bytearray()
        try:
            with self.assertRaises(harness.HarnessRefusal) as refused:
                session._read_line(0.02)
            self.assertEqual(refused.exception.code, "response_timeout")
        finally:
            harness.terminate_process_group(process, timeout=0.2)
            process.stdout.close()

    def test_process_group_cleanup_terminates_child(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        harness.terminate_process_group(process, timeout=0.2)
        self.assertIsNotNone(process.poll())

    def test_truncated_process_output_is_refused(self) -> None:
        script = "import os; os.write(1, b'{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":1')"
        process = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.assertIsNotNone(process.stdout)
        session = harness.McpSession.__new__(harness.McpSession)
        session.label = "truncated-test"
        session._stdout = process.stdout
        session._stdout_buffer = bytearray()
        with self.assertRaises(harness.HarnessRefusal) as refused:
            session._read_line(1.0)
        process.wait(timeout=1)
        process.stdout.close()
        self.assertEqual(refused.exception.code, "truncated_output")

    def test_corrupted_copied_blob_changes_bytes_at_content_address(self) -> None:
        digest = "ab" * 32
        blob = self.root / "state" / "blobs" / digest[:2] / digest[2:]
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"exact evidence bytes")
        evidence = harness.corrupt_copied_blob(self.root / "state", digest)
        self.assertNotEqual(evidence["sha256_before"], evidence["sha256_after"])
        self.assertEqual(evidence["bytes"], len(b"exact evidence bytes"))
        self.assertNotEqual(blob.read_bytes(), b"exact evidence bytes")

    def test_corrupted_evidence_missing_empty_and_malformed_are_refused(self) -> None:
        with self.assertRaises(harness.HarnessRefusal) as malformed:
            harness.corrupt_copied_blob(self.root, "nope")
        self.assertEqual(malformed.exception.code, "blob_digest_malformed")
        digest = "cd" * 32
        with self.assertRaises(harness.HarnessRefusal) as missing:
            harness.corrupt_copied_blob(self.root, digest)
        self.assertEqual(missing.exception.code, "blob_missing")
        blob = self.root / "blobs" / digest[:2] / digest[2:]
        blob.parent.mkdir(parents=True)
        blob.write_bytes(b"")
        with self.assertRaises(harness.HarnessRefusal) as empty:
            harness.corrupt_copied_blob(self.root, digest)
        self.assertEqual(empty.exception.code, "blob_empty")

    def test_false_hit_detection_covers_reuse_invalidation_failure_and_corruption(self) -> None:
        clean = [
            {"classification": "reuse", "same_result": True},
            {"classification": "invalidation", "same_result": False},
            {"classification": "cancelled", "published": False},
            {"classification": "crashed", "published": False},
            {"classification": "corrupt_refusal", "served_result_id": None},
        ]
        self.assertEqual(harness.detect_false_hits(clean), 0)
        bad = [
            {"classification": "reuse", "same_result": False},
            {"classification": "invalidation", "same_result": True},
            {"classification": "cancelled", "published": True},
            {"classification": "crashed", "published": True},
            {"classification": "corrupt_refusal", "served_result_id": "a" * 64},
        ]
        self.assertEqual(harness.detect_false_hits(bad), 5)

    def test_result_reference_extraction_is_strict(self) -> None:
        valid = {"_meta": {"again": {"resultId": "a" * 64}}}
        self.assertEqual(harness.result_id(valid), "a" * 64)
        self.assertIsNone(harness.result_id({"_meta": {"again": {"resultId": "A" * 64}}}))
        self.assertEqual(harness.result_without_reference(valid), {})

    def test_observation_projection_ignores_recipient_bound_metadata_only(self) -> None:
        first = {
            "content": [{"type": "text", "text": "same"}],
            "structuredContent": {"schemaVersion": 1, "matches": []},
            "_meta": {"again": {"resultId": "a" * 64, "recipient": "agent-a"}},
        }
        second = copy.deepcopy(first)
        second["_meta"]["again"]["recipient"] = "agent-b"
        self.assertEqual(
            harness.result_without_reference(first),
            harness.result_without_reference(second),
        )
        second["content"][0]["text"] = "different"
        self.assertNotEqual(
            harness.result_without_reference(first),
            harness.result_without_reference(second),
        )


if __name__ == "__main__":
    unittest.main()
