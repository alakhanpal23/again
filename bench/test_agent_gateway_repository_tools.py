import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("agent_gateway_repository_tools.py")
SPEC = importlib.util.spec_from_file_location("repository_tools_harness", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


class RepositoryToolsHarnessTests(unittest.TestCase):
    def test_strict_json_rejects_duplicates_malformed_utf8_and_bounds(self):
        self.assertEqual(HARNESS.strict_json_loads(b'{"a":1}'), {"a": 1})
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.strict_json_loads(b'{"a":1,"a":2}')
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.strict_json_loads(b"\xff")
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.strict_json_loads(b"{}", maximum=1)

    def test_report_canonicalization_is_stable_and_unicode_preserving(self):
        left = {"z": [3, {"b": 2, "a": "λ"}], "a": 1}
        right = {"a": 1, "z": [3, {"a": "λ", "b": 2}]}
        self.assertEqual(
            HARNESS.canonical_json_bytes(left), HARNESS.canonical_json_bytes(right)
        )
        self.assertIn("λ".encode(), HARNESS.canonical_json_bytes(left))

    def test_evidence_write_is_atomic_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            HARNESS.atomic_report(path, {"schemaVersion": 1, "value": "first"})
            self.assertEqual(json.loads(path.read_text()), {"schemaVersion": 1, "value": "first"})
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.atomic_report(path, {"schemaVersion": 1, "value": "second"})
            self.assertEqual(json.loads(path.read_text())["value"], "first")

    def test_event_reconciliation_is_schema_window_and_binding_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "again.sqlite"
            connection = sqlite3.connect(database)
            connection.executescript(
                f"""
                PRAGMA user_version = {HARNESS.STORE_SCHEMA_VERSION};
                CREATE TABLE gateway_results (
                    gateway_result_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL
                );
                CREATE TABLE gateway_requests (
                    call_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL
                );
                CREATE TABLE gateway_events (
                    event_type TEXT NOT NULL,
                    call_id TEXT,
                    gateway_result_id TEXT,
                    created_ms INTEGER NOT NULL
                );
                INSERT INTO gateway_results VALUES ('result-a', 'binding-a');
                INSERT INTO gateway_results VALUES ('result-b', 'binding-b');
                INSERT INTO gateway_requests VALUES ('call-a', 'binding-a');
                INSERT INTO gateway_requests VALUES ('call-b', 'binding-b');
                INSERT INTO gateway_events VALUES ('requested', 'call-a', NULL, 101);
                INSERT INTO gateway_events VALUES ('executed', 'call-a', 'result-a', 102);
                INSERT INTO gateway_events VALUES ('requested', 'call-b', NULL, 101);
                INSERT INTO gateway_events VALUES ('exact_hit', 'call-a', 'result-a', 999);
                """
            )
            connection.commit()
            connection.close()
            counts = HARNESS.event_counts(database, 100, 200, "result-a")
            self.assertEqual(counts, {"executed": 1, "requested": 1})
            HARNESS.require_counts(counts, {"requested": 1, "executed": 1})
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.require_counts(counts, {"requested": 1})

    def test_bad_schema_and_missing_result_metadata_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "again.sqlite"
            connection = sqlite3.connect(database)
            connection.executescript(
                """
                PRAGMA user_version = 999;
                CREATE TABLE gateway_results (
                    gateway_result_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL
                );
                CREATE TABLE gateway_requests (
                    call_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL
                );
                CREATE TABLE gateway_events (
                    event_type TEXT NOT NULL,
                    call_id TEXT,
                    gateway_result_id TEXT,
                    created_ms INTEGER NOT NULL
                );
                """
            )
            connection.close()
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.event_counts(database, 0, 1, None)

            connection = sqlite3.connect(database)
            connection.execute(
                f"PRAGMA user_version = {HARNESS.STORE_SCHEMA_VERSION}"
            )
            connection.commit()
            connection.close()
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.event_counts(database, 0, 1, "missing-result")

    def test_fixture_contains_all_languages_and_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "fixture"
            manifest = HARNESS.create_fixture(root, 30)
            paths = {entry["path"] for entry in manifest["entries"]}
            self.assertTrue(
                {"src/lib.rs", "python/app.py", "go/main.go", "web/index.ts"}.issubset(paths)
            )
            self.assertEqual(manifest["files"], 30)
            self.assertFalse(any(path.startswith(".git/") for path in paths))

    def test_digest_and_false_hit_classification_inputs_are_content_bound(self):
        first = {"result": {"structuredContent": {"path": "a", "bytes": 1}}}
        second = {"result": {"structuredContent": {"path": "a", "bytes": 2}}}
        self.assertNotEqual(
            HARNESS.digest_bytes(HARNESS.canonical_json_bytes(first)),
            HARNESS.digest_bytes(HARNESS.canonical_json_bytes(second)),
        )

    def test_mcp_close_terminates_a_live_process(self):
        process = subprocess_for_cleanup_test()
        client = HARNESS.McpProcess.__new__(HARNESS.McpProcess)
        client.process = process
        client._stdout_thread = _FinishedThread()
        client._stderr_thread = _FinishedThread()
        client.close()
        self.assertIsNotNone(process.poll())
        process.stdout.close()
        process.stderr.close()


class _FinishedThread:
    def join(self, timeout=None):
        del timeout


def subprocess_for_cleanup_test():
    import subprocess

    return subprocess.Popen(
        ["/bin/sleep", "30"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C"},
    )


if __name__ == "__main__":
    unittest.main()
