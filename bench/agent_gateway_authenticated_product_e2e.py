#!/usr/bin/env python3
"""Exercise source-backed task context through the production daemon binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import select
import subprocess
import tempfile
import threading
import time
from collections import Counter
from typing import Any

from agent_gateway_product_e2e import (
    GatewayEvents,
    corrupt_copied_blob,
    inspect_clean_source,
    pin_binary,
    result_id,
)


PROTOCOL = "2025-06-18"
SCHEMA = "again.authenticated-product-e2e.v1"


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError(reason)


class Client:
    def __init__(self, binary: pathlib.Path, workspace: pathlib.Path, environment: dict[str, str]):
        self.process = subprocess.Popen(
            [str(binary), "mcp", "connect", "--workspace", str(workspace)],
            cwd=workspace,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.next_id = 0
        self.request("initialize", {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "again-authenticated-e2e", "version": "1"},
        })

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        require(self.process.stdin is not None and self.process.stdout is not None, "client pipes missing")
        self.next_id += 1
        identifier = self.next_id
        frame = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}, separators=(",", ":"))
        self.process.stdin.write(frame.encode() + b"\n")
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 15)
        require(bool(ready), f"{method} timed out")
        line = self.process.stdout.readline()
        require(bool(line), f"{method} ended without response")
        response = json.loads(line)
        require(response.get("id") == identifier, f"{method} response ID mismatch")
        return response

    def tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()


def structured(response: dict[str, Any], label: str) -> dict[str, Any]:
    require("error" not in response, f"{label} failed: {response.get('error')}")
    result = response.get("result")
    require(isinstance(result, dict) and result.get("isError") is not True, f"{label} refused: {result}")
    content = result.get("structuredContent")
    require(isinstance(content, dict), f"{label} has no structured content")
    return content


def tool_text(result: dict[str, Any]) -> str | None:
    content = result.get("content")
    if isinstance(content, list) and content and isinstance(content[0], dict):
        value = content[0].get("text")
        return value if isinstance(value, str) else None
    return None


def start_daemon(binary: pathlib.Path, workspace: pathlib.Path, environment: dict[str, str]) -> subprocess.Popen[bytes]:
    daemon = subprocess.Popen(
        [str(binary), "mcp", "daemon", "serve", "--workspace", str(workspace)],
        cwd=workspace, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    for _ in range(250):
        status = subprocess.run(
            [str(binary), "mcp", "daemon", "status", "--workspace", str(workspace)],
            cwd=workspace, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=2,
        )
        if status.returncode == 0:
            return daemon
        if daemon.poll() is not None:
            detail = daemon.stderr.read().decode(errors="replace") if daemon.stderr else ""
            raise RuntimeError(f"daemon exited: {detail[:1000]}")
        time.sleep(0.02)
    raise RuntimeError("daemon readiness timed out")


def run(binary: pathlib.Path, source_root: pathlib.Path, source_sha: str) -> dict[str, Any]:
    require(binary.is_absolute() and binary.resolve() == binary, "binary path must be canonical")
    require(binary.is_file(), "binary missing")
    with tempfile.TemporaryDirectory(prefix="again-authenticated-product-") as temporary:
        root = pathlib.Path(temporary).resolve()
        home = root / "home"
        state = root / "state"
        workspace = root / "workspace"
        for path in (home, state, workspace):
            path.mkdir(mode=0o700)
        source = inspect_clean_source(source_root, source_sha, home)
        pinned = pin_binary(binary, root / "pinned" / "again")
        binary = pinned.executable_path
        (workspace / "input.txt").write_text("ALPHA_SOURCE\n")
        (workspace / "other.txt").write_text("unrelated\n")
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(home), "AGAIN_HOME": str(state)}
        daemon = start_daemon(binary, workspace, environment)
        clients: list[Client] = []
        try:
            solo = Client(binary, workspace, environment)
            clients.append(solo)
            standalone = solo.tool("repo.read", {"path": "input.txt"})
            structured(standalone, "standalone read")
            require(result_id(standalone["result"]) is None, "cheap standalone read unexpectedly stored a result")
            require(tool_text(standalone["result"]) == "ALPHA_SOURCE\n", "standalone bytes differ")

            first = Client(binary, workspace, environment)
            second = Client(binary, workspace, environment)
            clients.extend((first, second))
            task_arguments = {"taskId": "shared-source-task", "task": "inspect input.txt"}
            first_start = structured(first.tool("task.start", task_arguments), "first task.start")
            second_start = structured(second.tool("task.start", task_arguments), "second task.start")
            require(first_start.get("presentation") == "full", "first task brief missing")
            require(second_start.get("presentation") == "full", "second task brief missing")
            reader = GatewayEvents(state / "again.sqlite")
            window_start = reader.begin()
            barrier = threading.Barrier(3)
            reads: list[dict[str, Any] | None] = [None, None]
            failures: list[BaseException] = []

            def read_once(index: int, client: Client) -> None:
                try:
                    barrier.wait(timeout=5)
                    reads[index] = client.tool("repo.read", {"path": "input.txt"})
                except BaseException as error:
                    failures.append(error)

            workers = [threading.Thread(target=read_once, args=(0, first)),
                       threading.Thread(target=read_once, args=(1, second))]
            for worker in workers:
                worker.start()
            barrier.wait(timeout=5)
            for worker in workers:
                worker.join(timeout=15)
            require(not failures and all(not worker.is_alive() for worker in workers),
                    f"concurrent reads failed: {failures}")
            first_read = reads[0]
            second_read = reads[1]
            require(isinstance(first_read, dict) and isinstance(second_read, dict), "read response missing")
            structured(first_read, "task-bound read")
            structured(second_read, "peer task-bound read")
            original_id = result_id(first_read["result"])
            require(original_id is not None, "task-bound read has no result reference")
            require(result_id(second_read["result"]) == original_id, "duplicate read did not share the exact result")
            event_window = reader.end(window_start)
            bindings = reader.bindings(event_window)
            require(len(bindings) == 1, "duplicate read used different authority bindings")
            event_counts = Counter(event["event_type"] for event in reader.events(bindings[0]["binding_digest"], event_window))
            require(event_counts["requested"] == 2 and event_counts["executed"] == 1 and
                    event_counts["completed"] == 1 and event_counts["exact_hit"] + event_counts["inflight_join"] == 1,
                    f"duplicate read execution was not avoided: {dict(event_counts)}")
            observer = Client(binary, workspace, environment)
            clients.append(observer)
            joined = structured(observer.tool("task.start", task_arguments), "joined task.start")
            context = joined.get("context", {})
            require(any(fact.get("sources", [{}])[0].get("locator") == "repo.read:input.txt"
                        for fact in context.get("current_facts", [])), "peer did not receive verified source fact")
            require(any(ref.get("result_id") == original_id for ref in context.get("result_references", [])),
                    "peer did not receive result reference")
            retrieved = structured(second.tool("context.retrieve", {
                "taskId": "shared-source-task", "resultId": original_id,
            }), "peer retrieval")
            require(tool_text(retrieved.get("toolResult", {})) == "ALPHA_SOURCE\n",
                    "peer retrieved wrong source bytes")

            (workspace / "other.txt").write_text("changed unrelated\n")
            unaffected_client = Client(binary, workspace, environment)
            clients.append(unaffected_client)
            unaffected = structured(unaffected_client.tool("task.start", task_arguments), "unrelated edit task.start")
            require(any(ref.get("result_id") == original_id for ref in unaffected.get("context", {}).get("result_references", [])),
                    "unrelated edit retired source reference")

            (workspace / "input.txt").write_text("BETA_SOURCE\n")
            invalidated_client = Client(binary, workspace, environment)
            clients.append(invalidated_client)
            invalidated = structured(invalidated_client.tool("task.start", task_arguments), "relevant edit task.start")
            require(not any(ref.get("result_id") == original_id for ref in invalidated.get("context", {}).get("result_references", [])),
                    "stale reference survived unobserved edit")
            denied = second.tool("context.retrieve", {"taskId": "shared-source-task", "resultId": original_id})
            require(denied.get("error", {}).get("data", {}).get("reason") == "retrieval_refused",
                    "stale retrieval was not refused")
            replacement = first.tool("repo.read", {"path": "input.txt"})
            structured(replacement, "replacement read")
            replacement_id = result_id(replacement["result"])
            require(tool_text(replacement["result"]) == "BETA_SOURCE\n" and replacement_id != original_id,
                    "edited source did not get a new exact result")

            large = workspace / "large-ledger"
            large.mkdir()
            for index in range(257):
                (large / f"source-{index:03}.txt").write_text(f"source {index}\n")
            large_agent = Client(binary, workspace, environment)
            clients.append(large_agent)
            large_task = {"taskId": "large-ledger-task", "task": "inspect the large ledger"}
            large_start = structured(large_agent.tool("task.start", large_task), "large task.start")
            require(large_start.get("presentation") == "full", "large task initial brief missing")
            large_cursor = large_start.get("cursor")
            require(isinstance(large_cursor, int), "large task cursor missing")
            first_large_id = None
            for index in range(257):
                read = large_agent.tool("repo.read", {"path": f"large-ledger/source-{index:03}.txt"})
                structured(read, f"large read {index}")
                admitted_id = result_id(read["result"])
                require(admitted_id is not None, f"large source {index} was not admitted")
                if index == 0:
                    first_large_id = admitted_id
            require(first_large_id is not None, "first large source ID missing")
            (large / "source-000.txt").write_text("changed\n")
            large_delta = structured(large_agent.tool("context.delta", {
                "taskId": "large-ledger-task", "afterCursor": large_cursor, "limit": 64,
            }), "large context.delta")
            require(large_delta.get("presentation") == "incomplete" and
                    large_delta.get("delta", {}).get("events") == [],
                    "large delta exposed unchecked events")
            large_peer = Client(binary, workspace, environment)
            clients.append(large_peer)
            large_brief = structured(large_peer.tool("task.start", large_task), "large peer task.start")
            require(large_brief.get("presentation") == "full" and
                    large_brief.get("contextFreshness", {}).get("reason") == "context_freshness_capacity_exceeded",
                    "large brief did not explain the freshness bound")
            require(large_brief.get("context", {}).get("current_facts") == [] and
                    large_brief.get("context", {}).get("result_references") == [] and
                    large_brief.get("relevantCode", {}).get("candidates") == [],
                    "large brief exposed unchecked context")
            repeated_brief = structured(large_peer.tool("task.start", large_task), "repeated large task.start")
            require(repeated_brief.get("presentation") == "full",
                    "incomplete brief incorrectly granted compact delivery")
            stale_large = large_peer.tool("context.retrieve", {
                "taskId": "large-ledger-task", "resultId": first_large_id,
            })
            require(stale_large.get("error", {}).get("data", {}).get("reason") == "retrieval_refused",
                    "stale large-ledger source was retrievable")

            large_code = workspace / "large-code"
            large_code.mkdir()
            for index in range(1000):
                (large_code / f"module_{index:04}.py").write_text(f"value = {index}\n")
            (workspace / "tests").mkdir()
            (workspace / "tests" / "test_module_0001.py").write_text(
                "import unittest\n\nclass ModuleTests(unittest.TestCase):\n    pass\n"
            )
            mid_agent = Client(binary, workspace, environment)
            clients.append(mid_agent)
            mid_task = structured(mid_agent.tool("task.start", {
                "taskId": "mid-code-task",
                "task": "Edit `large-code/module_0001.py` safely and run tests",
                "includeSourcePreviews": True,
            }), "mid code task.start")
            require(mid_task.get("relevantCode", {}).get("unknowns", [{}])[0].get("kind") ==
                    "index_skipped_for_complete_explicit_preview" and
                    mid_task.get("sourcePreviews", [{}])[0].get("text") == "value = 1\n",
                    "mid-sized explicit source preview route failed")
            require(len(mid_task.get("sourcePreviews", [])) == 2 and
                    mid_task["sourcePreviews"][1].get("path") == "tests/test_module_0001.py" and
                    mid_task["sourcePreviews"][1].get("origin") == "test_path_convention_candidate" and
                    mid_task["sourcePreviews"][1].get("relevance") == "unverified" and
                    mid_task["sourcePreviews"][1].get("complete") is True,
                    "bounded test candidate preview was missing or claimed verified relevance")
            for index in range(1000, 4097):
                (large_code / f"module_{index:04}.py").write_text(f"value = {index}\n")
            code_agent = Client(binary, workspace, environment)
            clients.append(code_agent)
            code_task = structured(code_agent.tool("task.start", {
                "taskId": "large-code-task",
                "task": "Edit `large-code/module_0001.py` safely",
                "includeSourcePreviews": True,
            }), "large code task.start")
            require(code_task.get("relevantCode", {}).get("incomplete") is True and
                    code_task.get("relevantCode", {}).get("unknowns", [{}])[0].get("kind") ==
                    "index_preflight_file_budget_exceeded", "large code index was not bounded")
            previews = code_task.get("sourcePreviews", [])
            require(len(previews) == 1 and
                    previews[0].get("path") == "large-code/module_0001.py" and
                    previews[0].get("text") == "value = 1\n" and
                    previews[0].get("complete") is True,
                    "explicit source preview was missing from bounded brief")
            (workspace / "cancel.txt").write_text("CANCEL_SOURCE\n")
            cancel_owner = Client(binary, workspace, environment)
            cancel_peer = Client(binary, workspace, environment)
            clients.extend((cancel_owner, cancel_peer))
            cancel_task = {"taskId": "cancel-source-task", "task": "inspect cancel.txt"}
            structured(cancel_owner.tool("task.start", cancel_task), "cancel owner task.start")
            structured(cancel_peer.tool("task.start", cancel_task), "cancel peer task.start")
            cancel_read = cancel_owner.tool("repo.read", {"path": "cancel.txt"})
            structured(cancel_read, "cancel source read")
            cancel_id = result_id(cancel_read["result"])
            require(cancel_id is not None, "cancel source was not admitted")
            cancel_result = structured(cancel_peer.tool("context.cancel", {
                "taskId": "cancel-source-task",
            }), "peer context.cancel")
            require(cancel_result.get("status") == "retired", "cancel did not retire task")
            cancelled_retrieval = cancel_peer.tool("context.retrieve", {
                "taskId": "cancel-source-task", "resultId": cancel_id,
            })
            require(cancelled_retrieval.get("error", {}).get("data", {}).get("reason") in
                    {"invalid_agent_context", "retrieval_refused"},
                    f"retired recipient reference remained retrievable: {cancelled_retrieval}")
            owner_retrieval = structured(cancel_owner.tool("context.retrieve", {
                "taskId": "cancel-source-task", "resultId": cancel_id,
            }), "owner retrieval after peer cancellation")
            require(tool_text(owner_retrieval.get("toolResult", {})) == "CANCEL_SOURCE\n",
                    "peer cancellation retired the surviving owner's source reference")
            (workspace / "corruption.txt").write_text("TRUSTED_SOURCE\n")
            corrupt_agent = Client(binary, workspace, environment)
            clients.append(corrupt_agent)
            corrupt_task = {"taskId": "corrupt-source-task", "task": "inspect corruption.txt"}
            structured(corrupt_agent.tool("task.start", corrupt_task), "corrupt task.start")
            corrupt_read = corrupt_agent.tool("repo.read", {"path": "corruption.txt"})
            structured(corrupt_read, "corruption source read")
            corrupt_id = result_id(corrupt_read["result"])
            require(corrupt_id is not None, "corruption source was not admitted")
            stdout_digest = reader.stdout_digest_for_result(corrupt_id)
            corruption = corrupt_copied_blob(state, stdout_digest)
            corruption_start = reader.begin()
            refused = corrupt_agent.tool("context.retrieve", {
                "taskId": "corrupt-source-task", "resultId": corrupt_id,
            })
            require(refused.get("error", {}).get("data", {}).get("reason") == "retrieval_refused",
                    "corrupted source bytes were retrievable")
            corruption_events = reader.result_events(corrupt_id, reader.end(corruption_start))
            require(any(event["event_type"] == "binding_quarantined" and
                        event["reason"] == "result_corrupt" for event in corruption_events),
                    f"corrupt evidence was not quarantined: {corruption_events}")
            reread = corrupt_agent.tool("repo.read", {"path": "corruption.txt"})
            structured(reread, "read after corruption")
            require(tool_text(reread["result"]) == "TRUSTED_SOURCE\n",
                    "corruption recovery did not execute a clean source read")
            require(result_id(reread["result"]) != corrupt_id,
                    "corrupted result reference was returned after quarantine")
            lease_dir = workspace / "lease"
            lease_dir.mkdir()
            marker = b"TOKEN_LEASE_RECOVERY\n"
            for index in range(56):
                (lease_dir / f"payload-{index:03}.txt").write_bytes(
                    (marker if index == 0 else b"bounded fixture\n") + b"x" * (256 * 1024 - (len(marker) if index == 0 else len(b"bounded fixture\n")))
                )
            lease_agent = Client(binary, workspace, environment)
            clients.append(lease_agent)
            lease_task = {"taskId": "lease-recovery-task", "task": "search lease directory"}
            structured(lease_agent.tool("task.start", lease_task), "lease task.start")
            lease_window_start = reader.begin()
            lease_outcome: dict[str, Any] = {}

            def execute_lease_owner() -> None:
                try:
                    lease_outcome["response"] = lease_agent.tool("repo.search", {
                        "path": "lease", "pattern": "TOKEN_LEASE_RECOVERY",
                    })
                except BaseException as error:
                    lease_outcome["error"] = str(error)

            lease_worker = threading.Thread(target=execute_lease_owner)
            lease_worker.start()
            lease_binding = reader.wait_for_binding(lease_window_start, 5)
            reader.wait_for_event(lease_binding, lease_window_start, "executed", 5)
            old_lease = reader.lease(lease_binding, "active")
            require("response" not in lease_outcome, "lease owner completed before crash")
            daemon.kill()
            daemon.wait(timeout=5)
            lease_worker.join(timeout=5)
            require(not lease_worker.is_alive() and "response" not in lease_outcome,
                    "crashed lease owner returned a result")
            require(reader.result_count(lease_binding, reader.end(lease_window_start)) == 0,
                    "crashed lease owner published a result")
            for client in clients:
                client.close()
            clients.clear()
            deadline_ms = int(old_lease["expires_ms"]) + 25
            remaining = max(0.0, (deadline_ms - int(time.time() * 1000)) / 1000)
            require(remaining <= 31.0, "lease expiry exceeded declared TTL")
            if remaining:
                time.sleep(remaining)
            daemon = start_daemon(binary, workspace, environment)
            recovered_agent = Client(binary, workspace, environment)
            clients.append(recovered_agent)
            structured(recovered_agent.tool("task.start", lease_task), "recovered task.start")
            recovery_start = reader.begin()
            recovered = recovered_agent.tool("repo.search", {
                "path": "lease", "pattern": "TOKEN_LEASE_RECOVERY",
            })
            structured(recovered, "lease recovery search")
            recovery_events = Counter(event["event_type"] for event in reader.events(
                lease_binding, reader.end(recovery_start)))
            new_lease = reader.lease(lease_binding)
            require(result_id(recovered["result"]) is not None and
                    recovery_events["lease_expired"] == 1 and
                    recovery_events["executed"] == 1 and
                    recovery_events["completed"] == 1 and
                    new_lease["status"] == "completed" and
                    int(new_lease["lifecycle_generation"]) == int(old_lease["lifecycle_generation"]) + 1,
                    f"lease owner recovery was not complete: events={dict(recovery_events)} lease={new_lease}")
            return {
                "schema": SCHEMA,
                "classification": {"type": "pass", "code": "task_source_lifecycle_passed"},
                "source": source,
                "binary_sha256": pinned.sha256,
                "scenarios": ["standalone_direct", "duplicate_read_avoided", "peer_fact", "peer_retrieval", "unrelated_edit", "unobserved_relevant_edit", "large_ledger_incomplete", "mid_index_explicit_preview", "large_index_explicit_preview", "recipient_cancel_scoped", "corrupt_result_refused", "lease_owner_crash_recovered"],
                "duplicate_read_events": dict(event_counts),
                "large_ledger_sources": 257,
                "mid_index_source_files": 1000,
                "large_index_source_files": 4097,
                "old_result_id": original_id,
                "new_result_id": replacement_id,
                "corrupted_result_id": corrupt_id,
                "corruption": corruption,
                "corruption_events": corruption_events,
                "cancelled_result_id": cancel_id,
                "lease_recovery_events": dict(recovery_events),
                "old_lease": old_lease,
                "new_lease": new_lease,
            }
        finally:
            for client in clients:
                client.close()
            if daemon.poll() is None:
                subprocess.run([str(binary), "mcp", "daemon", "stop", "--workspace", str(workspace)],
                               cwd=workspace, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            daemon.wait(timeout=5)
            if daemon.stderr:
                daemon.stderr.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-root", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), "output must be a new absolute path")
    report = run(args.again_binary, args.source_root, args.source_git_sha)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "classification": report["classification"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
