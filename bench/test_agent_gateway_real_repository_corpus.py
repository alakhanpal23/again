#!/usr/bin/env python3
"""Offline unit tests for the real-repository gateway corpus."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Mapping
from typing import Any
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("agent_gateway_real_repository_corpus.py")
SPEC = importlib.util.spec_from_file_location("agent_gateway_real_repository_corpus", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
corpus = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpus
SPEC.loader.exec_module(corpus)


class RepositoryFixture:
    def __init__(self, root: pathlib.Path, suffix: str = ".rs"):
        self.root = root
        self.suffix = suffix
        self.git("init", "-q")
        self.git("config", "user.name", "Again Tests")
        self.git("config", "user.email", "again-tests@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *arguments: str, check: bool = True) -> str:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            env={
                **os.environ,
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and completed.returncode != 0:
            raise AssertionError(completed.stderr.decode(errors="replace"))
        return completed.stdout.decode(errors="surrogateescape").strip()

    def write(self, relative: str, value: bytes) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def commit(self) -> str:
        self.git("add", "--all")
        self.git("commit", "-q", "-m", "fixture")
        return self.git("rev-parse", "HEAD")


class FakeSession:
    def __init__(self, responses: list[dict[str, Any]]):
        self.responses = responses
        self.calls: list[tuple[str, str, Mapping[str, Any]]] = []

    def tool_call(self, request_id: str, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.calls.append((request_id, tool, arguments))
        return self.responses.pop(0)


class FakeAudit:
    def __init__(self, windows: list[dict[str, Any]]):
        self.windows = windows

    def begin(self) -> corpus.EventCursor:
        return corpus.EventCursor(0, 0)

    def end(self, _cursor: corpus.EventCursor) -> dict[str, Any]:
        return self.windows.pop(0)


class EvidenceSession:
    def __init__(self, label: str, pid: int):
        self.label = label
        self.pid = pid

    def evidence(self) -> dict[str, Any]:
        return {"label": self.label, "pid": self.pid}


def mcp_result(value: Mapping[str, Any], result_id: str = "a" * 64) -> dict[str, Any]:
    result = dict(value)
    result["_meta"] = {
        "again": {
            "experimental": True,
            "resultId": result_id,
            "fullRetrievalAvailable": False,
        }
    }
    return {"jsonrpc": "2.0", "id": "test", "result": result}


class RealRepositoryGatewayCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-real-gateway-corpus-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repository(
        self, name: str = "repository", suffix: str = ".rs", language: str = "rust"
    ) -> tuple[RepositoryFixture, corpus.RepositoryInput]:
        root = self.root / name
        root.mkdir()
        fixture = RepositoryFixture(root, suffix)
        return fixture, corpus.RepositoryInput(language, root)

    @staticmethod
    def two_files(fixture: RepositoryFixture) -> None:
        fixture.write(f"src/a{fixture.suffix}", b"alpha\n")
        fixture.write(f"src/b{fixture.suffix}", b"beta\n")
        fixture.commit()

    def test_repository_argument_requires_explicit_absolute_supported_language(self) -> None:
        parsed = corpus.parse_repository_argument(f"rust={self.root}")
        self.assertEqual(parsed, corpus.RepositoryInput("rust", self.root))
        cases = (
            "rust=relative",
            f"java={self.root}",
            f"rust:{self.root}",
            "rust=",
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.parse_repository_argument(raw)
            self.assertIn(refused.exception.code, {"repository_argument", "path_not_absolute"})

    def test_clean_branch_repository_is_selected_deterministically(self) -> None:
        fixture, requested = self.repository()
        fixture.write("src/z.rs", b"zeta\n")
        fixture.write("src/a.rs", b"alpha\n")
        fixture.write("src/m.rs", b"middle\n")
        commit = fixture.commit()
        snapshot = corpus.inspect_input_repository(requested)
        self.assertEqual(snapshot.git_sha, commit)
        self.assertEqual([item.path for item in snapshot.selected], ["src/a.rs", "src/m.rs"])
        self.assertFalse(snapshot.dirty)

    def test_dirty_detached_shallow_sparse_and_operation_states_are_non_pass(self) -> None:
        dirty, requested = self.repository("dirty")
        self.two_files(dirty)
        dirty.write("untracked", b"dirty")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(requested)
        self.assertEqual(refused.exception.code, "unsupported_git_dirty")

        detached, detached_input = self.repository("detached")
        self.two_files(detached)
        detached.git("checkout", "--detach", "-q")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(detached_input)
        self.assertEqual(refused.exception.code, "unsupported_git_detached")

        sparse, sparse_input = self.repository("sparse")
        self.two_files(sparse)
        sparse.git("config", "core.sparseCheckout", "true")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(sparse_input)
        self.assertEqual(refused.exception.code, "unsupported_git_sparse")

        operation, operation_input = self.repository("operation")
        self.two_files(operation)
        (operation.root / ".git" / "MERGE_HEAD").write_text(operation.git("rev-parse", "HEAD") + "\n")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(operation_input)
        self.assertEqual(refused.exception.code, "unsupported_git_operation")

        normal, shallow_input = self.repository("shallow")
        self.two_files(normal)
        real_probe = corpus._git_probe

        def shallow_probe(root: pathlib.Path, arguments: tuple[str, ...]) -> Any:
            if arguments == ("rev-parse", "--is-shallow-repository"):
                return subprocess.CompletedProcess(arguments, 0, b"true\n", b"")
            return real_probe(root, arguments)

        with mock.patch.object(corpus, "_git_probe", side_effect=shallow_probe):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.inspect_input_repository(shallow_input)
        self.assertEqual(refused.exception.code, "unsupported_git_shallow")

    def test_symlink_special_sparse_oversized_and_binary_selection_are_refused(self) -> None:
        symlink, requested = self.repository("symlink")
        symlink.write("target", b"target\n")
        os.symlink("target", symlink.root / "a.rs")
        symlink.write("b.rs", b"beta\n")
        symlink.commit()
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(requested)
        self.assertEqual(refused.exception.code, "selected_input_symlink")

        oversized, oversized_input = self.repository("oversized")
        oversized.write("a.rs", b"a" * 32)
        oversized.write("b.rs", b"b" * 32)
        oversized.commit()
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(
                oversized_input,
                limits=corpus.repository_support.Limits(max_selected_file_bytes=16),
            )
        self.assertEqual(refused.exception.code, "selected_input_oversized")

        binary, binary_input = self.repository("binary")
        binary.write("a.rs", b"\xff\xfe")
        binary.write("b.rs", b"valid\n")
        binary.commit()
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_input_repository(binary_input)
        self.assertEqual(refused.exception.code, "selected_input_binary")

        sparse, sparse_input = self.repository("sparse-input")
        self.two_files(sparse)
        with mock.patch.object(corpus.repository_support, "is_sparse", return_value=True):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.inspect_input_repository(sparse_input)
        self.assertEqual(refused.exception.code, "selected_input_sparse")

    def test_workspace_copy_preserves_source_and_builds_all_private_cases(self) -> None:
        fixture, requested = self.repository()
        self.two_files(fixture)
        snapshot = corpus.inspect_input_repository(requested)
        source_before = corpus.snapshot_identity(snapshot)
        workspace = self.root / "workspace"
        record = corpus.prepare_workspace(snapshot, workspace)
        source_after = corpus.inspect_input_repository(requested)
        self.assertEqual(corpus.snapshot_identity(source_after), source_before)
        self.assertEqual(record["first_path"], "src/a.rs")
        self.assertTrue((workspace / "edge/\u96ea-\u03bb.txt").is_file())
        self.assertEqual((workspace / "edge/empty.txt").read_bytes(), b"")
        self.assertGreater((workspace / "edge/large.txt").stat().st_size, 700_000)
        self.assertIn(b"\xff", (workspace / "edge/binary.dat").read_bytes())
        self.assertEqual(
            fixture.git("status", "--porcelain=v1", "--untracked-files=all"), ""
        )
        copied_status = subprocess.run(
            ("git", "status", "--porcelain=v1", "--ignored"),
            cwd=workspace,
            stdout=subprocess.PIPE,
            check=True,
        ).stdout
        self.assertIn(b"?? status/untracked.txt", copied_status)
        self.assertIn(b"!! status/ignored.txt", copied_status)

    def test_copy_refuses_a_source_change_during_materialization(self) -> None:
        fixture, requested = self.repository()
        self.two_files(fixture)
        snapshot = corpus.inspect_input_repository(requested)
        selected = fixture.root / snapshot.selected[0].path
        real_copy = corpus.repository_support.copy_selected_files

        def changing_copy(*args: Any, **kwargs: Any) -> Any:
            selected.write_bytes(b"changed\n")
            return real_copy(*args, **kwargs)

        with mock.patch.object(corpus.repository_support, "copy_selected_files", changing_copy):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.prepare_workspace(snapshot, self.root / "changed-workspace")
        self.assertEqual(refused.exception.code, "source_changed_during_copy")

    def test_native_read_covers_unicode_empty_large_binary_missing_and_symlink(self) -> None:
        workspace = self.root / "native"
        workspace.mkdir()
        (workspace / "\u96ea.txt").write_text("hello \u96ea\n", encoding="utf-8")
        (workspace / "empty").write_bytes(b"")
        (workspace / "large").write_bytes(b"x" * corpus.LARGE_FIXTURE_BYTES)
        (workspace / "binary").write_bytes(b"\x00\xff")
        os.symlink("empty", workspace / "link")
        unicode = corpus.native_read(workspace, "\u96ea.txt")
        self.assertEqual(unicode.status, "ok")
        self.assertEqual(unicode.value["structuredContent"]["bytes"], len("hello \u96ea\n".encode()))
        self.assertEqual(corpus.native_read(workspace, "empty").status, "ok")
        self.assertEqual(corpus.native_read(workspace, "large").status, "ok")
        for relative in ("binary", "missing", "link", "../escape"):
            with self.subTest(relative=relative):
                observation = corpus.native_read(workspace, relative)
                self.assertEqual(observation.status, "error")
                self.assertEqual(observation.error_code, -32602)

    def test_native_search_has_exact_path_line_content_and_order(self) -> None:
        workspace = self.root / "search"
        workspace.mkdir()
        for relative, value in (
            ("z.txt", "MARK z\n"),
            ("a.txt", "first\nMARK a\n"),
            ("\u96ea.txt", "MARK unicode\n"),
        ):
            (workspace / relative).write_text(value, encoding="utf-8")
        (workspace / "binary").write_bytes(b"MARK\xff")
        observation = corpus.native_search(workspace, "MARK", ".", 20)
        self.assertEqual(observation.status, "ok")
        structured = observation.value["structuredContent"]
        self.assertEqual(
            [item["path"] for item in structured["matches"]],
            ["a.txt", "z.txt", "\u96ea.txt"],
        )
        self.assertEqual(structured["matches"][0]["line"], 2)
        self.assertEqual(
            observation.value["content"][0]["text"],
            "a.txt:2:MARK a\nz.txt:1:MARK z\n\u96ea.txt:1:MARK unicode",
        )
        limited = corpus.native_search(workspace, "MARK", ".", 1)
        self.assertTrue(limited.value["structuredContent"]["truncated"])
        self.assertEqual(len(limited.value["structuredContent"]["matches"]), 1)

    def test_native_search_refuses_bad_arguments_and_scan_bounds(self) -> None:
        workspace = self.root / "search-bounds"
        workspace.mkdir()
        (workspace / "file").write_text("text\n")
        for pattern, maximum in (("", 1), ("x" * 4097, 1), ("x", 0), ("x", 501)):
            self.assertEqual(
                corpus.native_search(workspace, pattern, ".", maximum).error_code,
                -32602,
            )
        with mock.patch.object(corpus, "MAX_REPOSITORY_SCAN_BYTES", 1):
            self.assertEqual(corpus.native_search(workspace, "text").error_code, -32021)

    def test_observation_comparison_requires_exact_status_content_and_order(self) -> None:
        workspace = self.root / "compare"
        workspace.mkdir()
        (workspace / "a").write_text("value\n")
        native = corpus.native_read(workspace, "a")
        response = mcp_result(native.value)
        compared = corpus.compare_observation(response, native)
        self.assertEqual(compared["status"], "ok")
        self.assertEqual(compared["result_id"], "a" * 64)
        changed = json.loads(json.dumps(response))
        changed["result"]["content"][0]["text"] = "other"
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.compare_observation(changed, native)
        self.assertEqual(refused.exception.code, "content_or_order_mismatch")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.compare_observation(
                {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602}}, native
            )
        self.assertEqual(refused.exception.code, "status_mismatch")

        binary = corpus.native_read(workspace, "missing")
        refusal = corpus.compare_observation(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "typed"}},
            binary,
        )
        self.assertEqual(refusal["status"], "error")
        self.assertIsNone(refusal["result_id"])

    def test_cold_warm_requires_executed_then_exact_hit_and_same_result(self) -> None:
        workspace = self.root / "pair"
        workspace.mkdir()
        (workspace / "a").write_text("value\n")
        native = corpus.native_read(workspace, "a")
        first = FakeSession([mcp_result(native.value)])
        second = FakeSession([mcp_result(native.value)])
        audit = FakeAudit(
            [
                {"event_counts": {"requested": 1, "executed": 1}},
                {"event_counts": {"requested": 1, "exact_hit": 1}},
            ]
        )
        pair = corpus.run_cold_warm(
            first, second, audit, "pair", "repo.read", {"path": "a"}, native
        )
        self.assertEqual(pair["cold"]["comparison"]["result_id"], "a" * 64)
        self.assertEqual(len(first.calls), 1)
        self.assertEqual(len(second.calls), 1)

        wrong_second = FakeSession([mcp_result(native.value, "b" * 64)])
        audit = FakeAudit(
            [
                {"event_counts": {"executed": 1}},
                {"event_counts": {"exact_hit": 1}},
            ]
        )
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.run_cold_warm(
                FakeSession([mcp_result(native.value)]),
                wrong_second,
                audit,
                "bad",
                "repo.read",
                {"path": "a"},
                native,
            )
        self.assertEqual(refused.exception.code, "reuse_identity")

    def test_gateway_audit_is_schema_pinned_ordered_and_counted(self) -> None:
        database = self.root / "again.sqlite"
        connection = sqlite3.connect(database)
        connection.executescript(
            """
            CREATE TABLE gateway_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                call_id TEXT,
                lease_id TEXT,
                gateway_result_id TEXT,
                reason TEXT,
                created_ms INTEGER NOT NULL
            );
            PRAGMA user_version=7;
            """
        )
        now = int(corpus.time.time() * 1000)
        connection.execute(
            "INSERT INTO gateway_events(event_type,created_ms) VALUES('executed',?1)", (now,)
        )
        connection.commit()
        connection.close()
        audit = corpus.GatewayAudit(database)
        self.assertEqual(audit.totals(), {"executed": 1})
        cursor = audit.begin()
        connection = sqlite3.connect(database)
        connection.execute(
            "INSERT INTO gateway_events(event_type,created_ms) VALUES('exact_hit',?1)",
            (int(corpus.time.time() * 1000),),
        )
        connection.commit()
        connection.close()
        window = audit.end(cursor)
        self.assertEqual(window["event_counts"], {"exact_hit": 1})
        connection = sqlite3.connect(database)
        connection.execute("PRAGMA user_version=99")
        connection.commit()
        connection.close()
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            audit.totals()
        self.assertEqual(refused.exception.code, "database_schema")

    def test_gateway_counters_reconcile_all_requests_and_provider_terminals(self) -> None:
        counters = corpus.reconcile_gateway_counters(
            {
                "requested": 39,
                "executed": 21,
                "inflight_join": 1,
                "exact_hit": 17,
                "completed": 17,
                "failed": 4,
            }
        )
        self.assertEqual(counters["provider_executions"], 21)
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.reconcile_gateway_counters(
                {
                    "requested": 40,
                    "executed": 21,
                    "inflight_join": 1,
                    "exact_hit": 17,
                    "completed": 17,
                    "failed": 4,
                }
            )
        self.assertEqual(refused.exception.code, "gateway_counter_mismatch")

    def test_latency_analysis_is_bounded_and_flags_only_real_outliers(self) -> None:
        scenarios = {
            "fast": {
                "label": "fast",
                "command": {"tool": "repo.read"},
                "elapsed_ms": 10.0,
            },
            "bulk": [
                {
                    "label": "bulk",
                    "command": {"tool": "repo.search"},
                    "elapsed_ms": 500.0,
                },
                {
                    "label": "outlier",
                    "command": {"tool": "repo.search"},
                    "elapsed_ms": 9000.0,
                },
            ],
        }
        analysis = corpus.latency_analysis(scenarios, timeout_seconds=90)
        self.assertEqual(analysis["count"], 3)
        self.assertEqual(analysis["maximum_ms"], 9000.0)
        self.assertEqual(analysis["anomalous"], [])
        many = {
            str(index): {
                "label": str(index),
                "command": {"tool": "repo.read"},
                "elapsed_ms": 10.0 if index < 20 else 3000.0,
            }
            for index in range(21)
        }
        flagged = corpus.latency_analysis(many, timeout_seconds=90)
        self.assertEqual([item["label"] for item in flagged["anomalous"]], ["20"])

    def test_process_ledger_retains_all_unique_launched_processes(self) -> None:
        sessions = [
            EvidenceSession("first", 101),
            EvidenceSession("retired-before-restart", 102),
            EvidenceSession("restarted", 103),
        ]
        records = corpus.process_evidence(sessions)
        self.assertEqual([item["pid"] for item in records], [101, 102, 103])
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.process_evidence([EvidenceSession("same", 1), EvidenceSession("same", 2)])
        self.assertEqual(refused.exception.code, "process_ledger")

    def test_workspace_manifest_rejects_symlinks_and_is_stable(self) -> None:
        workspace = self.root / "manifest"
        workspace.mkdir()
        (workspace / "a").write_text("a")
        first = corpus.workspace_manifest_sha256(workspace)
        self.assertEqual(first, corpus.workspace_manifest_sha256(workspace))
        os.symlink("a", workspace / "link")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.workspace_manifest_sha256(workspace)
        self.assertEqual(refused.exception.code, "workspace_special_file")

    def test_exclusive_bounded_evidence_never_overwrites(self) -> None:
        output = self.root / "evidence.json"
        corpus.write_json_exclusive(output, {"a": "\u96ea", "z": [2, 1]})
        before = output.read_bytes()
        self.assertEqual(json.loads(before), {"a": "\u96ea", "z": [2, 1]})
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.write_json_exclusive(output, {"changed": True})
        self.assertEqual(refused.exception.code, "output_exists")
        self.assertEqual(output.read_bytes(), before)
        with mock.patch.object(corpus, "MAX_EVIDENCE_BYTES", 8):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.write_json_exclusive(self.root / "large.json", {"large": "value"})
        self.assertEqual(refused.exception.code, "evidence_oversized")

    def test_output_location_is_new_canonical_and_outside_every_source(self) -> None:
        source = self.root / "source"
        source.mkdir()
        output = self.root / "evidence.json"
        self.assertEqual(corpus.validate_output_location(output, [source]), output)
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.validate_output_location(source / "evidence.json", [source])
        self.assertEqual(refused.exception.code, "output_inside_source")
        output.write_text("existing")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.validate_output_location(output, [source])
        self.assertEqual(refused.exception.code, "output_exists")

    def test_server_environment_is_offline_minimal_and_state_scoped(self) -> None:
        environment = corpus._server_environment(
            self.root / "state", self.root / "home", self.root / "tmp"
        )
        self.assertEqual(environment["AGAIN_HOME"], str(self.root / "state"))
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(environment["https_proxy"], corpus.NETWORK_BLOCK_ENDPOINT)
        self.assertEqual(environment["NO_PROXY"], "")
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)

    def test_records_contain_hashes_not_native_source_payloads(self) -> None:
        native = corpus.NativeObservation(
            "ok",
            {"content": [{"type": "text", "text": "PRIVATE-SOURCE-CONTENT"}]},
        )
        response = mcp_result(native.value)
        record = corpus.invocation_record(
            label="privacy",
            tool="repo.read",
            arguments={"path": "src/a.rs"},
            response=response,
            native=native,
            elapsed_ms=1.0,
            audit={"event_counts": {"executed": 1}},
        )
        encoded = corpus.canonical_json_bytes(record)
        self.assertNotIn(b"PRIVATE-SOURCE-CONTENT", encoded)
        self.assertIn(b"payload_sha256", encoded)
        self.assertIn(b"response_sha256", encoded)

    def test_evaluate_refuses_missing_repositories_before_product_execution(self) -> None:
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.evaluate(
                again_binary=self.root / "again",
                source_root=self.root,
                source_git_sha="0" * 40,
                repositories=[],
                timeout_seconds=90,
            )
        self.assertEqual(refused.exception.code, "repositories_missing")

    def test_refusal_record_is_explicitly_non_pass(self) -> None:
        requested = corpus.RepositoryInput("go", self.root)
        record = corpus.refusal_record(
            requested, corpus.HarnessRefusal("unsupported_host", "not available")
        )
        self.assertEqual(record["outcome"], "non_pass")
        self.assertEqual(record["refusal"]["code"], "unsupported_host")
        self.assertNotIn("passed", record)


if __name__ == "__main__":
    unittest.main()
