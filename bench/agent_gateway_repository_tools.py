#!/usr/bin/env python3
"""Deterministic product-binary E2E and benchmark harness for repository tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import queue
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
STORE_SCHEMA_VERSION = 10
MAX_FRAME_BYTES = 2 * 1024 * 1024
MAX_STDERR_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 15.0
EXPECTED_ADVERTISED_TOOLS = frozenset(
    {
        "again.task_start",
        "repo.read",
        "repo.search",
        "repo.list",
        "repo.tree",
        "repo.stat",
        "repo.glob",
        "repo.references",
        "repo.manifest",
        "git.status",
        "git.diff",
        "git.log",
        "git.show",
        "git.blame",
    }
)


class HarnessError(RuntimeError):
    """A typed non-pass condition in the product harness."""


def strict_json_loads(data: bytes, maximum: int = MAX_FRAME_BYTES) -> Any:
    if len(data) > maximum:
        raise HarnessError("JSON frame exceeds its byte bound")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HarnessError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HarnessError("malformed JSON frame") from error


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_report(path: Path, report: dict[str, Any]) -> None:
    if path.exists():
        raise HarnessError(f"refusing to overwrite evidence: {path}")
    encoded = canonical_json_bytes(report) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_checked(arguments: list[str], cwd: Path) -> str:
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise HarnessError(
            f"command failed ({arguments[0]}): "
            + completed.stderr[:4096].decode("utf-8", "replace")
        )
    return completed.stdout.decode("utf-8")


def create_fixture(root: Path, files: int, total_bytes: int | None = None) -> dict[str, Any]:
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "python").mkdir()
    (root / "go").mkdir()
    (root / "web").mkdir()
    (root / "docs").mkdir()
    language_files = {
        "src/lib.rs": "pub fn shared_needle() -> usize { 7 }\n",
        "python/app.py": "def shared_needle():\n    return 7\n",
        "go/main.go": "package main\nfunc shared_needle() int { return 7 }\n",
        "web/index.ts": "export const shared_needle = (): number => 7;\n",
        "Cargo.toml": '[package]\nname = "e2e-fixture"\nversion = "0.1.0"\n',
        "pyproject.toml": '[project]\nname = "e2e-fixture"\nversion = "0.1.0"\n',
        "go.mod": "module example.invalid/e2e\ngo 1.23\n",
        "package.json": '{"name":"e2e-fixture","private":true}\n',
        "docs/irrelevant.txt": "outside source dependency\n",
    }
    for relative, content in language_files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    generated_count = max(0, files - len(language_files))
    target_payload = 128
    if total_bytes is not None and generated_count:
        target_payload = max(32, total_bytes // generated_count)
    payload = "x" * max(1, target_payload - 48)
    for index in range(generated_count):
        shard = root / "src" / f"shard-{index // 1000:03d}"
        shard.mkdir(exist_ok=True)
        (shard / f"file-{index:06d}.rs").write_text(
            f"pub const VALUE_{index}: &str = \"{payload}\";\n", encoding="utf-8"
        )

    run_checked(["/usr/bin/git", "init", "-q"], root)
    run_checked(
        ["/usr/bin/git", "config", "user.name", "Again Product E2E"], root
    )
    run_checked(
        [
            "/usr/bin/git",
            "config",
            "user.email",
            "again-product-e2e@example.invalid",
        ],
        root,
    )
    run_checked(["/usr/bin/git", "add", "--all"], root)
    run_checked(
        ["/usr/bin/git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture"],
        root,
    )
    manifest = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_file() and ".git" not in path.parts:
            size = path.stat().st_size
            total += size
            manifest.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": size,
                    "sha256": digest_file(path),
                }
            )
    return {"files": len(manifest), "bytes": total, "entries": manifest}


def create_language_fixture(root: Path, language: str) -> dict[str, str]:
    definitions = {
        "rust": {
            "Cargo.toml": '[package]\nname = "rust-e2e"\nversion = "0.1.0"\n',
            "src/lib.rs": "pub fn language_needle() -> usize { 1 }\n",
        },
        "python": {
            "pyproject.toml": '[project]\nname = "python-e2e"\nversion = "0.1.0"\n',
            "python/app.py": "def language_needle():\n    return 1\n",
        },
        "go": {
            "go.mod": "module example.invalid/language-e2e\ngo 1.23\n",
            "go/main.go": "package main\nfunc language_needle() int { return 1 }\n",
        },
        "typescript": {
            "package.json": '{"name":"typescript-e2e","private":true}\n',
            "web/index.ts": "export const language_needle = (): number => 1;\n",
        },
    }
    files = definitions.get(language)
    if files is None:
        raise HarnessError(f"unsupported language fixture: {language}")
    root.mkdir(parents=True)
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    run_checked(["/usr/bin/git", "init", "-q"], root)
    run_checked(["/usr/bin/git", "config", "user.name", "Again Language E2E"], root)
    run_checked(
        [
            "/usr/bin/git",
            "config",
            "user.email",
            "again-language-e2e@example.invalid",
        ],
        root,
    )
    run_checked(["/usr/bin/git", "add", "--all"], root)
    run_checked(
        ["/usr/bin/git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", language],
        root,
    )
    return {"language": language, "head": run_checked(["/usr/bin/git", "rev-parse", "HEAD"], root).strip()}


@dataclass
class Response:
    value: dict[str, Any]
    elapsed_ms: float

    @property
    def result(self) -> Any:
        return self.value.get("result")

    @property
    def error(self) -> Any:
        return self.value.get("error")

    @property
    def result_id(self) -> str | None:
        try:
            return self.value["result"]["_meta"]["again"]["resultId"]
        except (KeyError, TypeError):
            return None

    @property
    def result_hash(self) -> str:
        return digest_bytes(canonical_json_bytes(self.result))


class McpProcess:
    def __init__(
        self,
        binary: Path,
        workspace: Path,
        state: Path,
        name: str,
        extra_environment: dict[str, str] | None = None,
        authorization_scope: str = "repository-intelligence-e2e",
    ):
        environment = {
            "AGAIN_HOME": str(state),
            "LANG": "C",
            "LC_ALL": "C",
            "TMPDIR": tempfile.gettempdir(),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
        }
        if extra_environment:
            environment.update(extra_environment)
        self.name = name
        self.process = subprocess.Popen(
            [
                str(binary),
                "mcp",
                "serve",
                "--workspace",
                str(workspace),
                "--authorization-scope",
                authorization_scope,
            ],
            cwd=workspace,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        if self.process.stdin is None or self.process.stdout is None or self.process.stderr is None:
            raise HarnessError("failed to create MCP pipes")
        self._responses: queue.Queue[bytes | BaseException | None] = queue.Queue()
        self._stderr = bytearray()
        self._write_lock = threading.Lock()
        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()
        self.handshake()

    def _read_stdout(self) -> None:
        assert self.process.stdout is not None
        try:
            while True:
                line = self.process.stdout.readline(MAX_FRAME_BYTES + 2)
                if not line:
                    self._responses.put(None)
                    return
                if len(line) > MAX_FRAME_BYTES + 1 or not line.endswith(b"\n"):
                    self._responses.put(HarnessError("truncated or oversized MCP stdout frame"))
                    return
                self._responses.put(line[:-1])
        except BaseException as error:  # pragma: no cover - defensive thread boundary
            self._responses.put(error)

    def _read_stderr(self) -> None:
        assert self.process.stderr is not None
        while True:
            chunk = self.process.stderr.read(8192)
            if not chunk:
                return
            remaining = MAX_STDERR_BYTES - len(self._stderr)
            self._stderr.extend(chunk[: max(0, remaining)])

    def send(self, value: dict[str, Any]) -> None:
        encoded = canonical_json_bytes(value)
        if len(encoded) > MAX_FRAME_BYTES:
            raise HarnessError("outbound MCP frame exceeds its byte bound")
        assert self.process.stdin is not None
        with self._write_lock:
            self.process.stdin.write(encoded + b"\n")
            self.process.stdin.flush()

    def receive(self, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> dict[str, Any]:
        try:
            item = self._responses.get(timeout=timeout)
        except queue.Empty as error:
            raise HarnessError("MCP response timeout") from error
        if item is None:
            raise HarnessError(
                "MCP process exited before a response: "
                + self._stderr[:4096].decode("utf-8", "replace")
            )
        if isinstance(item, BaseException):
            raise HarnessError(str(item)) from item
        value = strict_json_loads(item)
        if not isinstance(value, dict):
            raise HarnessError("MCP response is not an object")
        return value

    def request(
        self, request_id: int, method: str, params: dict[str, Any], timeout: float = DEFAULT_TIMEOUT_SECONDS
    ) -> Response:
        started = time.monotonic()
        self.send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        )
        value = self.receive(timeout)
        if value.get("id") != request_id:
            raise HarnessError("MCP response ID mismatch")
        return Response(value=value, elapsed_ms=(time.monotonic() - started) * 1000)

    def call(self, request_id: int, name: str, arguments: dict[str, Any]) -> Response:
        return self.request(
            request_id, "tools/call", {"name": name, "arguments": arguments}
        )

    def handshake(self) -> None:
        initialized = self.request(
            1,
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": self.name, "version": "1"},
            },
        )
        if initialized.error:
            raise HarnessError("MCP initialize failed")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        tools = self.request(2, "tools/list", {})
        advertised = {entry["name"] for entry in tools.result["tools"]}
        if advertised != EXPECTED_ADVERTISED_TOOLS:
            raise HarnessError(f"unexpected MCP tool catalog: {sorted(advertised)}")

    def close(self) -> None:
        if self.process.poll() is None:
            if self.process.stdin is not None:
                self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        self._stdout_thread.join(timeout=1)
        self._stderr_thread.join(timeout=1)

    @property
    def stderr_text(self) -> str:
        return self._stderr.decode("utf-8", "replace")

    def __enter__(self) -> "McpProcess":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def event_counts(
    database: Path,
    start_ms: int,
    end_ms: int,
    gateway_result_id: str | None,
) -> dict[str, int]:
    uri = f"file:{database}?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != STORE_SCHEMA_VERSION:
            raise HarnessError(f"unsupported store schema: {version}")
        binding: str | None = None
        if gateway_result_id is not None:
            row = connection.execute(
                "SELECT binding_digest FROM gateway_results WHERE gateway_result_id = ?",
                (gateway_result_id,),
            ).fetchone()
            if row is None:
                raise HarnessError("result metadata is missing from the store")
            binding = row[0]
        rows = connection.execute(
            """
            SELECT event.event_type, COUNT(*)
            FROM gateway_events AS event
            LEFT JOIN gateway_requests AS request ON request.call_id = event.call_id
            WHERE event.created_ms BETWEEN ? AND ?
              AND (? IS NULL OR request.binding_digest = ? OR event.gateway_result_id = ?)
            GROUP BY event.event_type
            """,
            (start_ms, end_ms, binding, binding, gateway_result_id),
        ).fetchall()
        return {str(event): int(count) for event, count in rows}
    finally:
        connection.close()


def require_counts(actual: dict[str, int], expected: dict[str, int]) -> None:
    classification_events = {"requested", "executed", "exact_hit", "inflight_join"}
    observed = {
        name: actual.get(name, 0)
        for name in classification_events
        if actual.get(name, 0) != 0
    }
    wanted = {name: count for name, count in expected.items() if count != 0}
    if observed != wanted:
        raise HarnessError(f"event reconciliation failed: {observed} != {wanted}")


def run_concurrent(
    left: McpProcess, right: McpProcess, name: str, arguments: dict[str, Any]
) -> tuple[Response, Response, int, int]:
    barrier = threading.Barrier(3)
    output: list[Response | None] = [None, None]

    def worker(index: int, process: McpProcess, request_id: int) -> None:
        barrier.wait()
        output[index] = process.call(request_id, name, arguments)

    started_ms = int(time.time() * 1000) - 2
    threads = [
        threading.Thread(target=worker, args=(0, left, 100)),
        threading.Thread(target=worker, args=(1, right, 101)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(DEFAULT_TIMEOUT_SECONDS + 2)
        if thread.is_alive():
            raise HarnessError("concurrent MCP call timed out")
    ended_ms = int(time.time() * 1000) + 2
    if output[0] is None or output[1] is None:
        raise HarnessError("concurrent MCP worker failed")
    return output[0], output[1], started_ms, ended_ms


def expect_success(response: Response, scenario: str) -> None:
    if response.error is not None or response.result is None:
        raise HarnessError(f"{scenario} did not return successful product output")


def result_observation(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Project away recipient-bound presentation metadata, never observation bytes."""

    if result is None:
        return None
    return {key: value for key, value in result.items() if key != "_meta"}


HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def task_start_observation(
    response: Response, workspace: Path, scenario: str
) -> dict[str, Any]:
    """Validate the live task-start wire binding without treating it as authority."""

    expect_success(response, scenario)
    try:
        again = response.result["_meta"]["again"]
        context = again["reasoningContext"]
        brief = context["brief"]
        identity = brief["identity"]
        metrics = context["metrics"]
    except (KeyError, TypeError) as error:
        raise HarnessError(f"{scenario} omitted its reasoning-context binding") from error
    if again.get("maturity") != "local_alpha" or again.get("experimental") is not True:
        raise HarnessError(f"{scenario} omitted its explicit local-alpha maturity")
    if again.get("fullRetrievalAvailable") is not False:
        raise HarnessError(f"{scenario} unexpectedly enabled bearer-style retrieval")
    if context.get("presentation") != "full":
        raise HarnessError(f"{scenario} was not delivered in full")
    required_identity = {
        "workspace_id",
        "session_id",
        "authorization_scope_digest",
        "state_digest",
        "dependency_digest",
        "connection_generation",
        "task_id",
    }
    if not required_identity.issubset(identity):
        raise HarnessError(f"{scenario} omitted required identity fields")
    if not str(identity["workspace_id"]).startswith("workspace:"):
        raise HarnessError(f"{scenario} returned a malformed workspace identity")
    if not str(identity["session_id"]).startswith("task-start-session-"):
        raise HarnessError(f"{scenario} returned a malformed session identity")
    for field in (
        "authorization_scope_digest",
        "state_digest",
        "dependency_digest",
        "connection_generation",
        "task_id",
    ):
        if not HEX_DIGEST_RE.fullmatch(str(identity[field])):
            raise HarnessError(f"{scenario} returned a malformed {field}")
    authority = brief.get("authority")
    if not isinstance(authority, dict) or not authority or any(
        value is not False for value in authority.values()
    ):
        raise HarnessError(f"{scenario} unexpectedly granted authority")
    if metrics.get("external_model_calls") != 0:
        raise HarnessError(f"{scenario} unexpectedly invoked a model")
    if metrics.get("false_hit_count") != 0:
        raise HarnessError(f"{scenario} reported a false hit")
    truncation = brief.get("truncation")
    if not isinstance(truncation, dict) or truncation.get("complete_within_budget") is not True:
        raise HarnessError(f"{scenario} truncated its edit brief")
    current_facts = list(brief.get("task_specific_current_facts", [])) + list(
        brief.get("relevant_repository_current_facts", [])
    )
    for fact in current_facts:
        sources = fact.get("sources") if isinstance(fact, dict) else None
        if not isinstance(sources, list) or not sources:
            raise HarnessError(f"{scenario} returned a current fact without a source")
        for source in sources:
            locator = source.get("locator") if isinstance(source, dict) else None
            if not isinstance(locator, str) or ":" not in locator:
                raise HarnessError(f"{scenario} returned an unresolved source locator")
            relative, _, line_text = locator.rpartition(":")
            try:
                line = int(line_text)
            except ValueError as error:
                raise HarnessError(f"{scenario} returned an invalid source line") from error
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or line < 1:
                raise HarnessError(f"{scenario} returned an unsafe source locator")
            target = workspace / path
            if not target.is_file():
                raise HarnessError(f"{scenario} returned a missing source locator")
    return {
        "resultId": response.result_id,
        "workspaceId": identity["workspace_id"],
        "sessionId": identity["session_id"],
        "authorizationScopeDigest": identity["authorization_scope_digest"],
        "taskId": identity["task_id"],
        "providerCallsAvoided": metrics.get("provider_calls_avoided"),
        "repositoryToolCallsDisplaced": metrics.get("repository_tool_calls_displaced"),
        "currentFactCount": len(current_facts),
        "responseHash": response.result_hash,
    }


def scenario_suite(binary: Path, source_sha: str, fixture_files: int) -> dict[str, Any]:
    temporary = Path(tempfile.mkdtemp(prefix="again-repository-tools-e2e-"))
    false_hits = 0
    scenarios: list[dict[str, Any]] = []
    try:
        workspace = temporary / "repository"
        state = temporary / "private-state"
        state.mkdir(mode=0o700)
        fixture = create_fixture(workspace, fixture_files)
        database = state / "again.sqlite"
        language_evidence = []
        for language_index, language in enumerate(
            ["rust", "python", "go", "typescript"]
        ):
            language_workspace = temporary / f"language-{language}"
            language_state = temporary / f"language-{language}-state"
            language_state.mkdir(mode=0o700)
            identity = create_language_fixture(language_workspace, language)
            with McpProcess(
                binary, language_workspace, language_state, f"e2e-{language}"
            ) as language_process:
                manifest_response = language_process.call(
                    10 + language_index * 2, "repo.manifest", {}
                )
                search_response = language_process.call(
                    11 + language_index * 2,
                    "repo.search",
                    {"pattern": "language_needle", "path": "."},
                )
                expect_success(manifest_response, f"{language} manifest")
                expect_success(search_response, f"{language} search")
                if not manifest_response.result["structuredContent"]["manifests"]:
                    raise HarnessError(f"{language} manifest was not discovered")
                if not search_response.result["structuredContent"]["matches"]:
                    raise HarnessError(f"{language} source search returned no match")
                language_evidence.append(
                    {
                        **identity,
                        "manifestHash": manifest_response.result_hash,
                        "searchHash": search_response.result_hash,
                    }
                )
        scenarios.append(
            {
                "name": "independent_language_repositories",
                "classification": "pass",
                "repositories": language_evidence,
            }
        )
        task_workspace = temporary / "task-start-repository"
        task_workspace_other = temporary / "task-start-repository-other"
        task_state = temporary / "task-start-state"
        task_state.mkdir(mode=0o700)
        create_fixture(task_workspace, 40)
        create_fixture(task_workspace_other, 40)
        task_arguments = {
            "task": "change shared needle behavior",
            "constraints": ["preserve exact output"],
            "changedPaths": ["src/lib.rs"],
            "validationIntent": "run focused tests",
        }
        with McpProcess(binary, task_workspace, task_state, "task-start") as task_process:
            task_cold = task_process.call(30, "again.task_start", task_arguments)
            task_warm = task_process.call(31, "again.task_start", task_arguments)
            cold_observation = task_start_observation(
                task_cold, task_workspace, "task-start cold"
            )
            warm_observation = task_start_observation(
                task_warm, task_workspace, "task-start warm"
            )
            if task_cold.result_id != task_warm.result_id:
                raise HarnessError("task-start warm call did not reuse its exact result")
            if warm_observation["providerCallsAvoided"] != 1:
                raise HarnessError("task-start warm call did not report provider avoidance")
            if cold_observation["sessionId"] == warm_observation["sessionId"]:
                raise HarnessError("task-start recipient session was not call-bound")

            (task_workspace / "docs" / "irrelevant.txt").write_text(
                "proven irrelevant task-start mutation\n", encoding="utf-8"
            )
            task_irrelevant = task_process.call(32, "again.task_start", task_arguments)
            irrelevant_observation = task_start_observation(
                task_irrelevant, task_workspace, "task-start irrelevant mutation"
            )
            if task_irrelevant.result_id != task_warm.result_id:
                raise HarnessError("task-start invalidated a proven-irrelevant content change")

            (task_workspace / "src" / "lib.rs").write_text(
                "pub fn shared_needle() -> usize { 9 }\n", encoding="utf-8"
            )
            task_relevant = task_process.call(33, "again.task_start", task_arguments)
            relevant_observation = task_start_observation(
                task_relevant, task_workspace, "task-start relevant mutation"
            )
            if task_relevant.result_id == task_irrelevant.result_id:
                raise HarnessError("task-start served a false hit after source mutation")
            task_relevant_warm = task_process.call(34, "again.task_start", task_arguments)
            relevant_warm_observation = task_start_observation(
                task_relevant_warm, task_workspace, "task-start post-mutation warm"
            )
            if task_relevant_warm.result_id != task_relevant.result_id:
                raise HarnessError("task-start did not reuse the current post-mutation result")
            if relevant_warm_observation["providerCallsAvoided"] != 1:
                raise HarnessError("task-start post-mutation warm call was not observable")

        with McpProcess(
            binary,
            task_workspace,
            task_state,
            "task-start-other-scope",
            authorization_scope="repository-intelligence-e2e-other",
        ) as other_scope_process:
            other_scope = other_scope_process.call(35, "again.task_start", task_arguments)
            other_scope_observation = task_start_observation(
                other_scope, task_workspace, "task-start other authorization scope"
            )
        if (
            other_scope_observation["authorizationScopeDigest"]
            == relevant_observation["authorizationScopeDigest"]
            or other_scope.result_id == task_relevant.result_id
        ):
            raise HarnessError("task-start crossed authorization scopes")

        with McpProcess(
            binary, task_workspace_other, task_state, "task-start-other-workspace"
        ) as other_workspace_process:
            other_workspace = other_workspace_process.call(
                36, "again.task_start", task_arguments
            )
            other_workspace_observation = task_start_observation(
                other_workspace, task_workspace_other, "task-start other workspace"
            )
        if (
            other_workspace_observation["workspaceId"]
            == relevant_observation["workspaceId"]
            or other_workspace.result_id == task_relevant.result_id
        ):
            raise HarnessError("task-start crossed workspace identities")
        scenarios.append(
            {
                "name": "task_start_full_identity_hot_reuse_and_isolation",
                "classification": "pass",
                "cold": cold_observation,
                "warm": warm_observation,
                "irrelevantMutation": irrelevant_observation,
                "relevantMutation": relevant_observation,
                "postMutationWarm": relevant_warm_observation,
                "otherAuthorizationScope": other_scope_observation,
                "otherWorkspace": other_workspace_observation,
            }
        )
        left = McpProcess(binary, workspace, state, "e2e-left")
        right = McpProcess(binary, workspace, state, "e2e-right")
        try:
            arguments = {"pattern": "shared_needle", "path": ".", "maxResults": 20}
            first, second, start_ms, end_ms = run_concurrent(
                left, right, "repo.search", arguments
            )
            expect_success(first, "concurrent leader")
            expect_success(second, "concurrent follower")
            if (
                result_observation(first.result) != result_observation(second.result)
                or first.result_id != second.result_id
            ):
                raise HarnessError("concurrent responses diverged")
            concurrent_events = event_counts(
                database, start_ms, end_ms, first.result_id
            )
            require_counts(
                concurrent_events, {"requested": 2, "executed": 1, "inflight_join": 1}
            )
            scenarios.append(
                {
                    "name": "cold_concurrent_join",
                    "classification": "pass",
                    "resultId": first.result_id,
                    "responseHash": first.result_hash,
                    "events": concurrent_events,
                    "timingsMs": [first.elapsed_ms, second.elapsed_ms],
                }
            )

            time.sleep(0.005)
            start_ms = int(time.time() * 1000) - 2
            warm = left.call(102, "repo.search", arguments)
            end_ms = int(time.time() * 1000) + 2
            expect_success(warm, "exact warm reuse")
            if (
                result_observation(warm.result) != result_observation(first.result)
                or warm.result_id != first.result_id
            ):
                false_hits += 1
                raise HarnessError("exact warm response diverged")
            warm_events = event_counts(database, start_ms, end_ms, warm.result_id)
            require_counts(warm_events, {"requested": 1, "exact_hit": 1})
            scenarios.append(
                {
                    "name": "exact_warm_reuse",
                    "classification": "pass",
                    "events": warm_events,
                    "timingMs": warm.elapsed_ms,
                }
            )

            relevant = workspace / "src" / "lib.rs"
            relevant.write_text(
                "pub fn shared_needle() -> usize { 9 }\npub fn relevant_mutation() {}\n",
                encoding="utf-8",
            )
            changed = left.call(103, "repo.search", arguments)
            expect_success(changed, "relevant mutation")
            if (
                changed.result_id == first.result_id
                or result_observation(changed.result) == result_observation(first.result)
            ):
                false_hits += 1
                raise HarnessError("relevant mutation produced a false hit")
            scenarios.append(
                {
                    "name": "relevant_mutation_invalidates",
                    "classification": "pass",
                    "oldResultId": first.result_id,
                    "newResultId": changed.result_id,
                }
            )

            scoped = {"pattern": "relevant_mutation", "path": "src", "maxResults": 20}
            scoped_cold = left.call(104, "repo.search", scoped)
            expect_success(scoped_cold, "scoped cold request")
            (workspace / "docs" / "irrelevant.txt").write_text(
                "irrelevant mutation preserved by src proof\n", encoding="utf-8"
            )
            scoped_warm = right.call(105, "repo.search", scoped)
            expect_success(scoped_warm, "irrelevant mutation")
            if (
                scoped_warm.result_id != scoped_cold.result_id
                or result_observation(scoped_warm.result)
                != result_observation(scoped_cold.result)
            ):
                raise HarnessError("proven irrelevant mutation did not preserve exact reuse")
            scenarios.append(
                {
                    "name": "irrelevant_mutation_preserves_proven_scope",
                    "classification": "pass",
                    "resultId": scoped_warm.result_id,
                }
            )

            status_before = left.call(106, "git.status", {"path": "src"})
            run_checked(["/usr/bin/git", "add", "src/lib.rs"], workspace)
            status_after = left.call(107, "git.status", {"path": "src"})
            if status_before.result_id == status_after.result_id:
                false_hits += 1
                raise HarnessError("dirty index produced a false Git status hit")
            scenarios.append(
                {"name": "dirty_index_invalidates", "classification": "pass"}
            )

            untracked = workspace / "src" / "untracked.rs"
            untracked.write_text("pub fn untracked_state() {}\n", encoding="utf-8")
            untracked_status = left.call(108, "git.status", {"path": "src"})
            if "src/untracked.rs" not in canonical_json_bytes(untracked_status.result).decode():
                raise HarnessError("relevant untracked file is absent from Git status")
            scenarios.append(
                {"name": "untracked_state_is_relevant", "classification": "pass"}
            )

            run_checked(
                ["/usr/bin/git", "mv", "python/app.py", "python/moved.py"], workspace
            )
            renamed = left.call(109, "git.status", {"path": "python"})
            (workspace / "go" / "main.go").unlink()
            deleted = left.call(110, "git.status", {"path": "go"})
            if "python/moved.py" not in canonical_json_bytes(renamed.result).decode():
                raise HarnessError("rename is absent from Git status")
            if "go/main.go" not in canonical_json_bytes(deleted.result).decode():
                raise HarnessError("deletion is absent from Git status")
            scenarios.append(
                {"name": "rename_and_deletion_invalidate", "classification": "pass"}
            )

            outside = temporary / "outside.txt"
            outside.write_text("secret\n", encoding="utf-8")
            symlink = workspace / "src" / "escape"
            symlink.symlink_to(outside)
            refused = left.call(111, "repo.read", {"path": "src/escape"})
            if refused.error is None:
                false_hits += 1
                raise HarnessError("symlink escape was not refused")
            symlink.unlink()
            fresh = left.call(112, "repo.stat", {"path": "src/lib.rs"})
            expect_success(fresh, "fresh request after symlink refusal")
            scenarios.append(
                {"name": "symlink_refusal_and_recovery", "classification": "pass"}
            )

            negative_args = {"pattern": "negative_needle", "path": "web"}
            negative = left.call(113, "repo.search", negative_args)
            negative_warm = right.call(114, "repo.search", negative_args)
            if (
                negative.result_id != negative_warm.result_id
                or result_observation(negative.result)
                != result_observation(negative_warm.result)
            ):
                raise HarnessError("negative search was not exactly reusable")
            (workspace / "web" / "new.ts").write_text(
                "export const negative_needle = true;\n", encoding="utf-8"
            )
            negative_changed = left.call(115, "repo.search", negative_args)
            if negative_changed.result_id == negative.result_id:
                false_hits += 1
                raise HarnessError("negative search survived a relevant mutation")
            scenarios.append(
                {"name": "negative_reuse_until_relevant_mutation", "classification": "pass"}
            )

            ordered_first = left.call(116, "repo.tree", {"path": "web"})
            ordered_second = right.call(117, "repo.tree", {"path": "web"})
            if result_observation(ordered_first.result) != result_observation(
                ordered_second.result
            ):
                raise HarnessError("stable ordering changed across repeated runs")
            scenarios.append(
                {"name": "stable_ordering", "classification": "pass"}
            )

            too_large = workspace / "src" / "too-large.rs"
            with too_large.open("wb") as handle:
                handle.truncate(4 * 1024 * 1024 + 1)
            bounded = left.call(118, "repo.read", {"path": "src/too-large.rs"})
            if bounded.error is None:
                raise HarnessError("oversized output did not fail safely")
            too_large.unlink()
            recovery = left.call(119, "repo.read", {"path": "Cargo.toml"})
            expect_success(recovery, "fresh request after output-bound refusal")
            scenarios.append(
                {"name": "output_bounds_and_recovery", "classification": "pass"}
            )

            left.send(
                {
                    "jsonrpc": "2.0",
                    "id": 120,
                    "method": "tools/call",
                    "params": {
                        "name": "repo.search",
                        "arguments": {"pattern": "never-found", "path": "src"},
                    },
                }
            )
            left.send(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/cancelled",
                    "params": {"requestId": 120},
                }
            )
            cancelled_value = left.receive(DEFAULT_TIMEOUT_SECONDS)
            cancellation = "cancelled" if cancelled_value.get("error") else "completed_before_cancel"
            after_cancel = left.call(121, "repo.read", {"path": "Cargo.toml"})
            expect_success(after_cancel, "fresh request after cancellation")
            scenarios.append(
                {
                    "name": "cancellation_cleans_provider_state",
                    "classification": "pass",
                    "outcome": cancellation,
                }
            )

            replacement_old = temporary / "repository-old"
            workspace.rename(replacement_old)
            create_fixture(workspace, 20)
            replacement_response = left.call(
                122, "repo.read", {"path": "src/lib.rs"}
            )
            expect_success(replacement_response, "live repository replacement")
            old_ids = {
                first.result_id,
                changed.result_id,
                scoped_cold.result_id,
                negative.result_id,
            }
            if replacement_response.result_id in old_ids:
                false_hits += 1
                raise HarnessError("live repository replacement reused old authority")
            scenarios.append(
                {"name": "repository_replacement_no_false_hit", "classification": "pass"}
            )
        finally:
            left.close()
            right.close()

        return {
            "schemaVersion": SCHEMA_VERSION,
            "classification": "pass" if false_hits == 0 else "false_hit",
            "binary": {"path": str(binary), "sha256": digest_file(binary)},
            "sourceGitSha": source_sha,
            "fixture": fixture,
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "scenarios": scenarios,
            "providerCallsAvoided": sum(
                scenario.get("events", {}).get("exact_hit", 0)
                + scenario.get("events", {}).get("inflight_join", 0)
                for scenario in scenarios
            ),
            "falseHitCount": false_hits,
        }
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def benchmark_suite(binary: Path, source_sha: str) -> list[dict[str, Any]]:
    configurations = [
        ("files-1000", 1_000, None),
        ("files-10000", 10_000, None),
        ("source-50mib", 12_000, 50 * 1024 * 1024),
    ]
    results = []
    for name, files, total_bytes in configurations:
        temporary = Path(tempfile.mkdtemp(prefix="again-repository-benchmark-"))
        try:
            workspace = temporary / "repository"
            state = temporary / "state"
            state.mkdir(mode=0o700)
            manifest = create_fixture(workspace, files, total_bytes)
            with McpProcess(binary, workspace, state, f"benchmark-{name}") as process:
                cold = process.call(
                    10,
                    "repo.search",
                    {"pattern": "shared_needle", "path": ".", "maxResults": 20},
                    # type: ignore[arg-type]
                )
                if cold.error is None:
                    warm = process.call(
                        11,
                        "repo.search",
                        {"pattern": "shared_needle", "path": ".", "maxResults": 20},
                    )
                    outcome = "pass"
                    warm_ms: float | None = warm.elapsed_ms
                    avoided = int(warm.result_id == cold.result_id)
                else:
                    outcome = "bounded_refusal"
                    warm_ms = None
                    avoided = 0
                results.append(
                    {
                        "name": name,
                        "sourceGitSha": source_sha,
                        "fixtureFiles": manifest["files"],
                        "fixtureBytes": manifest["bytes"],
                        "classification": outcome,
                        "coldMs": cold.elapsed_ms,
                        "warmMs": warm_ms,
                        "providerCallsAvoided": avoided,
                    }
                )
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--again-binary", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture-files", type=int, default=1_000)
    parser.add_argument("--benchmarks", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    binary = args.again_binary
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise HarnessError("--again-binary must be an absolute executable file")
    if len(args.source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in args.source_sha
    ):
        raise HarnessError("--source-sha must be a lowercase full Git SHA")
    if not 20 <= args.fixture_files <= 20_000:
        raise HarnessError("--fixture-files is outside 20..=20000")
    report = scenario_suite(binary, args.source_sha, args.fixture_files)
    report["benchmarks"] = benchmark_suite(binary, args.source_sha) if args.benchmarks else []
    report["harnessSha256"] = digest_file(Path(__file__).resolve())
    atomic_report(args.output.resolve(), report)
    return 0 if report["classification"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
