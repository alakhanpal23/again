#!/usr/bin/env python3
"""Network-avoiding unit tests for the real-repository gateway corpus."""

from __future__ import annotations

import importlib.util
import io
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
        return {
            "label": self.label,
            "pid": self.pid,
            "return_code": 0,
            "process_group_reaped": True,
            "stderr_complete": True,
            "cleanup_complete": True,
        }


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

    def test_explicit_go_search_is_read_only_and_requires_two_clean_regular_files(self) -> None:
        search_root = self.root / "development-root"
        search_root.mkdir()
        fixture_root = search_root / "go-project"
        fixture_root.mkdir()
        fixture = RepositoryFixture(fixture_root)
        fixture.write("cmd/main.go", b"package main\nfunc main() {}\n")
        fixture.write("internal/value.go", b"package internal\n\nconst Value = 1\n")
        commit = fixture.commit()
        before_status = fixture.git("status", "--porcelain=v1", "--untracked-files=all")

        found = corpus.discover_go_repository((search_root,))
        self.assertTrue(found["go_repository_eligible"])
        self.assertEqual(found["selected_repository"], str(fixture_root))
        self.assertEqual(found["candidate_count"], 1)
        candidate = found["eligibility_checks"][0]
        self.assertEqual(candidate["tracked_go_file_count"], 2)
        self.assertTrue(candidate["checks"]["at_least_two_tracked_go_files"])
        self.assertTrue(candidate["checks"]["tracked_files_regular_non_symlink"])
        self.assertTrue(candidate["checks"]["clean_worktree"])
        self.assertEqual(fixture.git("rev-parse", "HEAD"), commit)
        self.assertEqual(
            fixture.git("status", "--porcelain=v1", "--untracked-files=all"), before_status
        )

    def test_go_search_preserves_typed_non_pass_for_dirty_or_insufficient_candidates(self) -> None:
        search_root = self.root / "development-root"
        search_root.mkdir()
        dirty_root = search_root / "dirty-go"
        dirty_root.mkdir()
        dirty = RepositoryFixture(dirty_root)
        dirty.write("a.go", b"package a\n")
        dirty.write("b.go", b"package b\n")
        dirty.commit()
        dirty.write("untracked.go", b"package dirty\n")

        insufficient_root = search_root / "one-go"
        insufficient_root.mkdir()
        insufficient = RepositoryFixture(insufficient_root)
        insufficient.write("only.go", b"package only\n")
        insufficient.commit()

        found = corpus.discover_go_repository((search_root,))
        self.assertFalse(found["go_repository_eligible"])
        self.assertIsNone(found["selected_repository"])
        by_root = {item["repository_root"]: item for item in found["eligibility_checks"]}
        self.assertEqual(by_root[str(dirty_root)]["refusal_code"], "unsupported_git_dirty")
        self.assertFalse(by_root[str(insufficient_root)]["checks"]["at_least_two_tracked_go_files"])

    def test_go_search_bounds_duplicate_roots_and_traversal_are_fail_closed(self) -> None:
        search_root = self.root / "bounded-root"
        search_root.mkdir()
        with self.assertRaises(corpus.HarnessRefusal) as duplicate:
            corpus.discover_go_repository((search_root, search_root))
        self.assertEqual(duplicate.exception.code, "duplicate_search_root")

        with self.assertRaises(corpus.HarnessRefusal) as depth:
            corpus.discover_go_repository((search_root,), max_depth=corpus.MAX_SEARCH_DEPTH + 1)
        self.assertEqual(depth.exception.code, "search_depth_bound")

        with self.assertRaises(corpus.HarnessRefusal) as candidates:
            corpus.discover_go_repository((search_root,), max_candidates=0)
        self.assertEqual(candidates.exception.code, "search_candidate_bound")

        with self.assertRaises(corpus.HarnessRefusal) as traversal:
            corpus.discover_go_repository((self.root / "bounded-root" / "..",))
        self.assertEqual(traversal.exception.code, "search_root_not_canonical")

        with self.assertRaises(corpus.HarnessRefusal) as unavailable:
            corpus.discover_go_repository((self.root / "missing-root",))
        self.assertEqual(unavailable.exception.code, "search_root_unavailable")

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
            PRAGMA user_version=9;
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
        raw = [session.evidence() for session in sessions]
        records = corpus.process_evidence(
            raw, ["first", "retired-before-restart", "restarted"]
        )
        self.assertEqual([item["pid"] for item in records], [101, 102, 103])
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.process_evidence(
                [EvidenceSession("same", 1).evidence(), EvidenceSession("same", 2).evidence()],
                ["same", "same"],
            )
        self.assertEqual(refused.exception.code, "process_ledger")
        live = EvidenceSession("live", 4).evidence()
        live["return_code"] = None
        with self.assertRaises(corpus.HarnessRefusal):
            corpus.process_evidence([live], ["live"])
        invalid = EvidenceSession("invalid", 5).evidence()
        invalid["return_code"] = True
        with self.assertRaises(corpus.HarnessRefusal):
            corpus.process_evidence([invalid], ["invalid"])
        failed = EvidenceSession("failed", 6).evidence()
        failed["return_code"] = 1
        with self.assertRaises(corpus.HarnessRefusal):
            corpus.process_evidence([failed], ["failed"])

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

    def test_server_environment_is_network_avoiding_and_state_scoped(self) -> None:
        environment = corpus._server_environment(
            self.root / "state", self.root / "home", self.root / "tmp"
        )
        self.assertEqual(environment["AGAIN_HOME"], str(self.root / "state"))
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")
        self.assertEqual(environment["https_proxy"], corpus.NETWORK_BLOCK_ENDPOINT)
        self.assertEqual(environment["NO_PROXY"], "")
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)

    def test_network_boundary_does_not_claim_socket_containment(self) -> None:
        boundary = corpus.network_boundary_record()
        self.assertFalse(boundary["harness_clone_download_or_network_client_path"])
        self.assertFalse(boundary["network_namespace_sandbox"])
        self.assertFalse(boundary["fresh_socket_creation_blocked"])
        self.assertEqual(boundary["trusted_product_operations"], ["repo.read", "repo.search"])

    def test_repository_count_language_and_root_bounds_precede_execution(self) -> None:
        roots = []
        for index in range(5):
            root = self.root / f"repository-{index}"
            root.mkdir()
            roots.append(root)
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.validate_repository_inputs(
                [corpus.RepositoryInput("rust", root) for root in roots]
            )
        self.assertEqual(refused.exception.code, "repository_count_bound")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.validate_repository_inputs(
                [
                    corpus.RepositoryInput("rust", roots[0]),
                    corpus.RepositoryInput("rust", roots[1]),
                ]
            )
        self.assertEqual(refused.exception.code, "duplicate_repository_language")
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.validate_repository_inputs(
                [
                    corpus.RepositoryInput("rust", roots[0]),
                    corpus.RepositoryInput("python", roots[0]),
                ]
            )
        self.assertEqual(refused.exception.code, "duplicate_repository_root")

    def test_handshake_failure_is_registered_and_cleaned_immediately(self) -> None:
        workspace = self.root / "workspace-session"
        state = self.root / "state-session"
        workspace.mkdir()
        state.mkdir()
        sessions: list[Any] = []

        class FailingSession:
            close_calls = 0

            def __init__(self, **arguments: Any):
                self.label = arguments["label"]
                self.environment = corpus._server_environment(
                    arguments["state"], arguments["home"], arguments["temporary"]
                )

            def handshake(self, _name: str) -> None:
                raise corpus.HarnessRefusal("handshake_failed", "injected")

            def close_and_evidence(self) -> tuple[dict[str, Any], tuple[str, ...]]:
                type(self).close_calls += 1
                return {"cleanup_complete": True}, ()

        with mock.patch.object(corpus, "CorpusMcpSession", FailingSession):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.start_session(
                    self.root / "again",
                    workspace,
                    state,
                    self.root,
                    "failure",
                    10,
                    sessions,
                )
        self.assertEqual(refused.exception.code, "handshake_failed")
        self.assertEqual(len(sessions), 1)
        self.assertEqual(FailingSession.close_calls, 1)
        self.assertTrue(refused.exception.cleanup_complete)

    def test_process_group_cleanup_handles_an_exited_leader_with_descendant(self) -> None:
        if os.name != "posix":
            self.skipTest("process-group cleanup requires POSIX")
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
        self.assertTrue(corpus._process_group_exists(process.pid))
        corpus._terminate_process_group(process, process.pid)
        self.assertFalse(corpus._process_group_exists(process.pid))

    def test_session_allows_bounded_natural_process_group_teardown(self) -> None:
        class ExitedProcess:
            pid = 81
            returncode = 0

            def poll(self) -> int:
                return 0

        class FinishedThread:
            def join(self, timeout: float) -> None:
                self.timeout = timeout

            def is_alive(self) -> bool:
                return False

        session = corpus.CorpusMcpSession.__new__(corpus.CorpusMcpSession)
        session.label = "natural-exit"
        session.argv = ("/pinned/again", "mcp", "serve")
        session.process = ExitedProcess()
        session.process_group = session.process.pid
        session._stdin = io.BytesIO()
        session._stdout = io.BytesIO()
        session._stderr = io.BytesIO()
        session._stderr_thread = FinishedThread()
        session._stderr_capture = bytearray()
        session._stderr_overflow = False
        session.request_hashes = []
        session.response_hashes = []
        session._closed_record = None
        with (
            mock.patch.object(corpus, "_wait_for_process_group_exit", return_value=True),
            mock.patch.object(corpus, "_process_group_exists", return_value=False),
            mock.patch.object(corpus, "_terminate_process_group") as terminate,
        ):
            record, failures = session.close_and_evidence()
        terminate.assert_not_called()
        self.assertEqual(failures, ())
        self.assertTrue(record["cleanup_complete"])

    def test_pinned_executable_is_revalidated_after_mutation(self) -> None:
        binary = self.root / "pinned-again"
        binary.write_bytes(b"first executable bytes")
        binary.chmod(0o500)
        identity = corpus.pinned_executable_identity(binary)
        corpus.verify_pinned_executable_unchanged(binary, identity)
        binary.chmod(0o700)
        binary.write_bytes(b"second executable bytes")
        binary.chmod(0o500)
        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.verify_pinned_executable_unchanged(binary, identity)
        self.assertEqual(refused.exception.code, "pinned_binary_changed")

    def test_evidence_is_staged_before_atomic_no_replace_publication(self) -> None:
        output = self.root / "staged-evidence.json"
        real_link = os.link
        observed = {"called": False}

        def checked_link(source: str, target: str, **arguments: Any) -> None:
            observed["called"] = True
            self.assertFalse(output.exists())
            self.assertTrue((output.parent / source).is_file())
            real_link(source, target, **arguments)

        with mock.patch.object(corpus.os, "link", side_effect=checked_link):
            corpus.write_json_exclusive(output, {"stable": True})
        self.assertTrue(observed["called"])
        metadata = output.stat()
        self.assertEqual(metadata.st_mode & 0o777, 0o600)
        self.assertEqual(metadata.st_nlink, 1)

    def test_effect_then_error_publication_removes_only_created_identity(self) -> None:
        output = self.root / "ambiguous-evidence.json"
        real_link = os.link

        def link_then_error(source: str, target: str, **arguments: Any) -> None:
            real_link(source, target, **arguments)
            raise OSError("injected post-effect error")

        with mock.patch.object(corpus.os, "link", side_effect=link_then_error):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.write_json_exclusive(output, {"never": "published"})
        self.assertEqual(refused.exception.code, "output_publish")
        self.assertTrue(refused.exception.cleanup_complete)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".again-evidence-*.tmp")), [])

    def test_refusal_retains_primary_and_independent_cleanup_codes(self) -> None:
        refusal = corpus.HarnessRefusal(
            "primary_failure",
            "primary",
            cleanup_complete=False,
            cleanup_codes=("wait_failed", "stream_close_failed"),
        )
        record = corpus.refusal_record(corpus.RepositoryInput("go", self.root), refusal)
        self.assertEqual(record["refusal"]["code"], "primary_failure")
        self.assertFalse(record["cleanup"]["complete"])
        self.assertEqual(record["cleanup"]["codes"], ["wait_failed", "stream_close_failed"])

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
        self.assertEqual(refused.exception.code, "repository_count_bound")

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
