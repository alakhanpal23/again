#!/usr/bin/env python3
"""Unit tests for the offline agent gateway evaluation harness."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import Any


MODULE_PATH = pathlib.Path(__file__).with_name("agent_gateway_eval.py")
SPEC = importlib.util.spec_from_file_location("agent_gateway_eval", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
gateway_eval = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gateway_eval
SPEC.loader.exec_module(gateway_eval)


class DuplicateKey(ValueError):
    pass


def strict_decode(value: bytes) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise DuplicateKey(key)
            result[key] = item
        return result

    return json.loads(value, object_pairs_hook=object_pairs)


def json_depth(value: Any) -> int:
    if isinstance(value, dict):
        return 1 + max((json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((json_depth(item) for item in value), default=0)
    return 0


class FakeMcpServer:
    MESSAGE_LIMIT = 1024 * 1024

    def __init__(self) -> None:
        self.root = pathlib.Path.cwd().resolve()
        self.output_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.active_lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.active: dict[Any, threading.Event] = {}
        self.cache: dict[str, dict[str, Any]] = {}
        self.inflight: dict[str, dict[str, Any]] = {}
        self.stats = {
            "executions": 0,
            "full_replays": 0,
            "compact_replays": 0,
            "bypasses": 0,
            "quarantines": 0,
            "duplicate_bytes_omitted": 0,
            "estimated_execution_ms_saved": 0,
            "requested": 0,
            "executed": 0,
            "exact_hits": 0,
            "coverage_hits": 0,
            "inflight_joins": 0,
            "compact_deliveries": 0,
            "estimated_tokens_avoided": 0,
            "stale_or_divergent_quarantines": 0,
        }

    def emit(self, value: dict[str, Any]) -> None:
        encoded = gateway_eval.canonical_json_bytes(value)
        with self.output_lock:
            sys.stdout.buffer.write(encoded + b"\n")
            sys.stdout.buffer.flush()

    def success(self, request_id: Any, result: Any) -> None:
        self.emit({"jsonrpc": "2.0", "id": request_id, "result": result})

    def error(self, request_id: Any, code: int, message: str) -> None:
        self.emit(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": message},
            }
        )

    def catalog(self) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "repository.read",
                    "description": "Read one repository file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"],
                    },
                },
                {
                    "name": "repository.search",
                    "description": "Search repository files",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "query": {"type": "string"},
                        },
                        "required": ["path", "query"],
                    },
                },
            ]
        }

    def resolve(self, raw: str) -> pathlib.Path:
        relative = pathlib.PurePosixPath(raw)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe fixture path")
        resolved = (self.root / pathlib.Path(*relative.parts)).resolve(strict=True)
        resolved.relative_to(self.root)
        return resolved

    def state_key(self, name: str, arguments: dict[str, Any]) -> str:
        digest = hashlib.sha256()
        digest.update(name.encode("ascii"))
        digest.update(gateway_eval.canonical_json_bytes(arguments))
        if name == "repository.read":
            path = self.resolve(arguments["path"])
            digest.update(path.read_bytes())
        elif name == "repository.search":
            root = self.resolve(arguments["path"])
            for path in sorted(item for item in root.rglob("*") if item.is_file()):
                digest.update(path.relative_to(self.root).as_posix().encode("utf-8"))
                digest.update(path.read_bytes())
        else:
            raise ValueError("unknown tool")
        return digest.hexdigest()

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "repository.read":
            path = self.resolve(arguments["path"])
            contents = path.read_text(encoding="utf-8")
            return {
                "content": [{"type": "text", "text": contents}],
                "isError": False,
                "structuredContent": {
                    "path": arguments["path"],
                    "sha256": hashlib.sha256(contents.encode()).hexdigest(),
                },
            }
        root = self.resolve(arguments["path"])
        query = arguments["query"]
        matches: list[dict[str, Any]] = []
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                if query in line:
                    matches.append(
                        {
                            "line": line_number,
                            "path": path.relative_to(self.root).as_posix(),
                            "text": line,
                        }
                    )
        text = "\n".join(
            f"{item['path']}:{item['line']}:{item['text']}" for item in matches
        )
        return {
            "content": [{"type": "text", "text": text}],
            "isError": False,
            "structuredContent": {"matches": matches},
        }

    def account_reuse(self, result: dict[str, Any], *, join: bool) -> None:
        encoded_bytes = len(gateway_eval.canonical_json_bytes(result))
        self.stats["duplicate_bytes_omitted"] += encoded_bytes
        self.stats["estimated_tokens_avoided"] += encoded_bytes // 4
        self.stats["estimated_execution_ms_saved"] += 100
        if join:
            self.stats["inflight_joins"] += 1
        else:
            self.stats["exact_hits"] += 1

    def cached_call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        key = self.state_key(name, arguments)
        with self.state_lock:
            self.stats["requested"] += 1
            cached = self.cache.get(key)
            if cached is not None:
                self.account_reuse(cached, join=False)
                return cached
            pending = self.inflight.get(key)
            if pending is None:
                pending = {"event": threading.Event(), "result": None}
                self.inflight[key] = pending
                self.stats["executed"] += 1
                leader = True
            else:
                self.stats["inflight_joins"] += 1
                leader = False
        if not leader:
            pending["event"].wait(timeout=5)
            result = pending["result"]
            if not isinstance(result, dict):
                raise RuntimeError("fake in-flight leader failed")
            with self.state_lock:
                encoded_bytes = len(gateway_eval.canonical_json_bytes(result))
                self.stats["duplicate_bytes_omitted"] += encoded_bytes
                self.stats["estimated_tokens_avoided"] += encoded_bytes // 4
                self.stats["estimated_execution_ms_saved"] += 100
            return result

        time.sleep(0.12)
        result = self.execute(name, arguments)
        with self.state_lock:
            self.cache[key] = result
            pending["result"] = result
            pending["event"].set()
            self.inflight.pop(key, None)
        return result

    def call_worker(
        self,
        request_id: Any,
        name: str,
        arguments: dict[str, Any],
        cancellation: threading.Event,
    ) -> None:
        try:
            if name == "repository.search" and arguments.get("query") == gateway_eval.CANCELLATION_QUERY:
                with self.state_lock:
                    self.stats["requested"] += 1
                    self.stats["executed"] += 1
                cancellation.wait(timeout=5)
                if cancellation.is_set():
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32_800, "message": "request cancelled"},
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "result": self.execute(name, arguments),
                    }
            else:
                result = self.cached_call(name, arguments)
                response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, TypeError, ValueError):
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32_602, "message": "invalid params"},
            }
        with self.active_lock:
            if self.active.get(request_id) is cancellation:
                self.active.pop(request_id, None)
        self.emit(response)

    def handle(self, message: dict[str, Any]) -> None:
        request_id = message.get("id")
        method = message.get("method")
        if method == "notifications/initialized" and request_id is None:
            return
        if method == "notifications/cancelled" and request_id is None:
            params = message.get("params")
            target = params.get("requestId") if isinstance(params, dict) else None
            with self.active_lock:
                cancellation = self.active.get(target)
            if cancellation is not None:
                cancellation.set()
            return
        if method == "initialize":
            self.success(
                request_id,
                {
                    "protocolVersion": gateway_eval.MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "fake-eval-server", "version": "1"},
                },
            )
            return
        if method == "tools/list":
            self.success(request_id, self.catalog())
            return
        if method == "ping":
            self.success(request_id, {})
            return
        if method == "again/eval-stats":
            with self.state_lock:
                snapshot = dict(self.stats)
            self.success(request_id, snapshot)
            return
        if method != "tools/call":
            self.error(request_id, -32_601, "method not found")
            return
        params = message.get("params")
        if not isinstance(params, dict):
            self.error(request_id, -32_602, "invalid params")
            return
        name = params.get("name")
        arguments = params.get("arguments")
        if name not in {"repository.read", "repository.search"} or not isinstance(arguments, dict):
            self.error(request_id, -32_602, "invalid params")
            return
        cancellation = threading.Event()
        with self.active_lock:
            if request_id in self.active:
                self.error(request_id, -32_600, "request id is already in flight")
                return
            self.active[request_id] = cancellation
        thread = threading.Thread(
            target=self.call_worker,
            args=(request_id, name, arguments, cancellation),
        )
        self.threads.append(thread)
        thread.start()

    def run(self) -> int:
        while True:
            line = sys.stdin.buffer.readline(self.MESSAGE_LIMIT + 2)
            if not line:
                break
            if not line.endswith(b"\n") and len(line) > self.MESSAGE_LIMIT:
                while line and not line.endswith(b"\n"):
                    line = sys.stdin.buffer.readline(self.MESSAGE_LIMIT + 2)
                self.error(None, -32_021, "message limit exceeded")
                continue
            payload = line.rstrip(b"\r\n")
            if len(payload) > self.MESSAGE_LIMIT:
                self.error(None, -32_021, "message limit exceeded")
                continue
            try:
                message = strict_decode(payload)
            except DuplicateKey:
                self.error(None, -32_700, "duplicate key")
                continue
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.error(None, -32_700, "malformed JSON")
                continue
            if json_depth(message) > 48:
                self.error(None, -32_021, "depth limit exceeded")
                continue
            if not isinstance(message, dict):
                self.error(None, -32_600, "invalid request")
                continue
            self.handle(message)
        for thread in self.threads:
            thread.join(timeout=6)
        return 0


def fake_oversized_output() -> int:
    sys.stdin.buffer.readline()
    sys.stdout.buffer.write(b"{" + b"x" * 4096 + b"}\n")
    sys.stdout.buffer.flush()
    return 0


class GatewayEvalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-gateway-eval-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Again Gateway Eval Tests")
        self.git("config", "user.email", "gateway-eval@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.repository / "README").write_text("temporary evaluation repository\n")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "fixture")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=self.repository,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        return completed.stdout.decode().strip()

    def fake_server_argv(self) -> tuple[str, ...]:
        return (
            str(pathlib.Path(sys.executable).resolve()),
            str(pathlib.Path(__file__).resolve()),
            "--fake-server",
        )

    @staticmethod
    def fake_stats_reader() -> Any:
        counter = 0

        def read(client: gateway_eval.McpStdioClient) -> dict[str, Any]:
            nonlocal counter
            counter += 1
            frame = client.request(f"fake-stats-{counter}", "again/eval-stats")
            return frame.value["result"]

        return read

    def evaluate(self) -> dict[str, Any]:
        return gateway_eval.evaluate(
            gateway_eval.EvalConfig(
                binary=pathlib.Path(sys.executable).resolve(),
                repository=self.repository,
            ),
            state_root=self.root / "state",
            home=self.root / "home",
            limits=gateway_eval.EvalLimits(timeout_seconds=4),
            server_argv=self.fake_server_argv(),
            stats_reader=self.fake_stats_reader(),
            source_root=pathlib.Path(__file__).resolve().parents[1],
        )

    def test_complete_scenario_matrix_uses_fake_stdio_server(self) -> None:
        evidence = self.evaluate()
        self.assertEqual(evidence["schema"], gateway_eval.SCHEMA)
        self.assertEqual(
            evidence["provenance"]["fixture_repository_git_sha"],
            self.git("rev-parse", "HEAD"),
        )
        self.assertRegex(evidence["provenance"]["source_git_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(evidence["configuration"]["read_tool"], "repository.read")
        self.assertEqual(evidence["configuration"]["search_tool"], "repository.search")
        self.assertEqual(evidence["measurements"]["provider_executions"], 4)
        self.assertEqual(evidence["measurements"]["exact_hits"], 3)
        self.assertEqual(evidence["measurements"]["inflight_joins"], 1)
        self.assertGreater(evidence["measurements"]["bytes_omitted"], 0)
        self.assertGreater(evidence["measurements"]["estimated_tokens_avoided"], 0)
        self.assertGreater(evidence["measurements"]["observed_wall_time_saved_ms"], 0)
        scenarios = evidence["scenarios"]
        shared_hash = scenarios["concurrent_identical_calls"]["response_sha256"]
        self.assertEqual(scenarios["later_exact_reuse"]["response_sha256"], shared_hash)
        self.assertEqual(
            scenarios["irrelevant_mutation_preservation"]["response_sha256"], shared_hash
        )
        self.assertNotEqual(
            scenarios["relevant_mutation_invalidation"]["response_sha256"], shared_hash
        )
        self.assertTrue(scenarios["cancellation_cleanup"]["cancellation_won_race"])
        self.assertEqual(
            scenarios["cancellation_cleanup"]["cleanup_stats_delta"]["exact_hits"], 1
        )
        self.assertFalse((self.repository / gateway_eval.FIXTURE_DIRECTORY).exists())

    def test_evidence_encoding_is_stable_and_exclusive(self) -> None:
        evidence = self.evaluate()
        output = self.root / "evidence.json"
        gateway_eval.write_json_exclusive(output, evidence)
        encoded = output.read_bytes()
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(json.loads(encoded), evidence)
        with self.assertRaises(gateway_eval.HarnessRefusal) as refused:
            gateway_eval.write_json_exclusive(output, evidence)
        self.assertEqual(refused.exception.code, "evidence_exists")
        self.assertEqual(output.read_bytes(), encoded)

    def test_existing_fixture_is_never_overwritten(self) -> None:
        fixture = self.repository / gateway_eval.FIXTURE_DIRECTORY
        fixture.mkdir()
        sentinel = fixture / "sentinel"
        sentinel.write_text("user-owned\n")
        with self.assertRaises(gateway_eval.HarnessRefusal) as refused:
            self.evaluate()
        self.assertEqual(refused.exception.code, "fixture_exists")
        self.assertEqual(sentinel.read_text(), "user-owned\n")

    def test_response_bound_terminates_fake_server(self) -> None:
        state = self.root / "bounded-state"
        home = self.root / "bounded-home"
        environment = gateway_eval.sanitized_environment(state, home)
        client = gateway_eval.McpStdioClient(
            (
                str(pathlib.Path(sys.executable).resolve()),
                str(pathlib.Path(__file__).resolve()),
                "--fake-oversized-output",
            ),
            cwd=self.repository,
            environment=environment,
            limits=gateway_eval.EvalLimits(
                timeout_seconds=2,
                max_response_bytes=128,
                fixture_payload_bytes=32,
            ),
        )
        client.send_json({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        with self.assertRaises(gateway_eval.HarnessRefusal) as refused:
            client.receive(1)
        self.assertEqual(refused.exception.code, "response_limit")
        client.close(require_clean=False)

    def test_duplicate_response_keys_and_invalid_limits_are_refused(self) -> None:
        with self.assertRaises(gateway_eval.HarnessRefusal) as duplicate:
            gateway_eval.strict_json_loads(b'{"id":1,"id":2}')
        self.assertEqual(duplicate.exception.code, "duplicate_response_key")
        with self.assertRaises(gateway_eval.HarnessRefusal) as non_finite:
            gateway_eval.strict_json_loads(b'{"result":NaN}')
        self.assertEqual(non_finite.exception.code, "malformed_response")
        with self.assertRaises(gateway_eval.HarnessRefusal) as invalid:
            gateway_eval.EvalLimits(gateway_message_limit_bytes=10, max_request_bytes=10).validate()
        self.assertEqual(invalid.exception.code, "invalid_limits")

        raw = b'{"jsonrpc":"2.0","id":1,"result": {"b": 1, "a": 2}}'
        frame = gateway_eval.RpcFrame(
            raw=raw,
            value=gateway_eval.strict_json_loads(raw),
            elapsed_ms=0,
        )
        self.assertEqual(frame.result_bytes(), b'{"b": 1, "a": 2}')

    def test_stats_are_strict_and_monotonic(self) -> None:
        complete = {
            "executed": 2,
            "exact_hits": 3,
            "inflight_joins": 1,
            "duplicate_bytes_omitted": 100,
            "estimated_tokens_avoided": 25,
            "estimated_execution_ms_saved": 7,
        }
        normalized = gateway_eval.normalize_stats(complete)
        self.assertEqual(normalized["provider_executions"], 2)
        with self.assertRaises(gateway_eval.HarnessRefusal) as rollback:
            gateway_eval.stats_delta(normalized, {**normalized, "exact_hits": 2})
        self.assertEqual(rollback.exception.code, "stats_rollback")
        with self.assertRaises(gateway_eval.HarnessRefusal) as missing:
            gateway_eval.normalize_stats({})
        self.assertEqual(missing.exception.code, "stats_invalid")

    def test_binary_and_repository_symlinks_are_refused(self) -> None:
        binary_link = self.root / "python-link"
        binary_link.symlink_to(pathlib.Path(sys.executable).resolve())
        environment = gateway_eval.sanitized_environment(
            self.root / "config-state", self.root / "config-home"
        )
        with self.assertRaises(gateway_eval.HarnessRefusal) as binary:
            gateway_eval.validate_configuration(
                gateway_eval.EvalConfig(binary=binary_link, repository=self.repository),
                environment,
                gateway_eval.EvalLimits(),
            )
        self.assertEqual(binary.exception.code, "binary_invalid")

        repository_link = self.root / "repository-link"
        repository_link.symlink_to(self.repository, target_is_directory=True)
        with self.assertRaises(gateway_eval.HarnessRefusal) as repository:
            gateway_eval.validate_configuration(
                gateway_eval.EvalConfig(
                    binary=pathlib.Path(sys.executable).resolve(),
                    repository=repository_link,
                ),
                environment,
                gateway_eval.EvalLimits(),
            )
        self.assertEqual(repository.exception.code, "repository_invalid")


if __name__ == "__main__":
    if "--fake-server" in sys.argv:
        raise SystemExit(FakeMcpServer().run())
    if "--fake-oversized-output" in sys.argv:
        raise SystemExit(fake_oversized_output())
    unittest.main()
