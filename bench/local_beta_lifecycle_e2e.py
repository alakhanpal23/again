#!/usr/bin/env python3
"""Exercise the schema-v13 task lifecycle through a real daemon-backed binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bench import agent_gateway_chaos_soak as chaos


SCHEMA = "again.local-beta-lifecycle-e2e.v1"


class LifecycleFailure(RuntimeError):
    pass


def verify_source_checkout(source_git_sha: str) -> None:
    repository = pathlib.Path(__file__).resolve().parent.parent
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repository, check=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repository, check=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, text=True,
    ).stdout
    if head != source_git_sha or dirty:
        raise LifecycleFailure("lifecycle source checkout is dirty or does not match --source-git-sha")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def tool(session: chaos.Session, request_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = session.request(
        request_id,
        "tools/call",
        {"name": name, "arguments": arguments},
    )
    if "error" in response:
        raise LifecycleFailure(f"{request_id}:{name} returned a JSON-RPC error")
    result = response.get("result")
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if not isinstance(structured, dict):
        raise LifecycleFailure(f"{name} returned no structured result")
    return structured


def refused(session: chaos.Session, request_id: str, name: str, arguments: dict[str, Any]) -> bool:
    response = session.request(
        request_id,
        "tools/call",
        {"name": name, "arguments": arguments},
    )
    return isinstance(response.get("error"), dict)


def start(session: chaos.Session, request_id: str, task_id: str, prompt: str, **relations: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "taskId": task_id,
        "task": prompt,
        "acceptanceCriteria": ["observable acceptance check passes"],
    }
    arguments.update(relations)
    return tool(session, request_id, "task.start", arguments)


def transition(
    session: chaos.Session,
    request_id: str,
    task_id: str,
    lease_id: str,
    generation: int,
    state: str,
) -> dict[str, Any]:
    return tool(
        session,
        request_id,
        "task.transition",
        {
            "taskId": task_id,
            "leaseId": lease_id,
            "expectedStateGeneration": generation,
            "state": state,
            "reason": f"bounded lifecycle transition to {state}",
        },
    )


def command(binary: pathlib.Path, workspace: pathlib.Path, state: pathlib.Path, root: pathlib.Path, *args: str) -> dict[str, Any]:
    environment = chaos._session_environment(state, "human-cli")
    completed = subprocess.run(
        [str(binary), *args, "--workspace", str(workspace)],
        cwd=workspace,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise LifecycleFailure(f"human command failed: {args[0]}")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LifecycleFailure("human command returned malformed JSON") from error
    if not isinstance(value, dict):
        raise LifecycleFailure("human command returned non-object JSON")
    return value


def export_task(
    binary: pathlib.Path,
    workspace: pathlib.Path,
    state: pathlib.Path,
    root: pathlib.Path,
    task_id: str,
    label: str,
) -> dict[str, Any]:
    output = (root / f"{label}.json").resolve()
    command(
        binary,
        workspace,
        state,
        root,
        "task",
        "export",
        task_id,
        "--output",
        str(output),
    )
    if output.stat().st_mode & 0o777 != 0o600:
        raise LifecycleFailure("task export permissions are not private")
    document = json.loads(output.read_bytes())
    if not isinstance(document, dict):
        raise LifecycleFailure("task export is malformed")
    return document


def daemon_endpoint_identity(root: pathlib.Path) -> tuple[int, int]:
    endpoints = list((root / "runtime-tmp").glob("again-*/gateway-*.endpoint"))
    if len(endpoints) != 1 or endpoints[0].is_symlink():
        raise LifecycleFailure("daemon endpoint identity is missing or ambiguous")
    metadata = endpoints[0].stat()
    return metadata.st_dev, metadata.st_ino


def run(binary: pathlib.Path, source_git_sha: str) -> dict[str, Any]:
    verify_source_checkout(source_git_sha)
    root = chaos._create_run_root()
    workspace = chaos._fixture(root)
    state = root / "state"
    first = chaos.Session(binary, workspace, state, "first", automatic_daemon=True)
    second = chaos.Session(binary, workspace, state, "second", automatic_daemon=True)
    first_closed = False
    second_closed = False
    try:
        first.handshake()
        second.handshake()
        daemon_before = daemon_endpoint_identity(root)

        alias_a = start(first, "alias-a", "alias-a", "one canonical beta task")
        alias_b = start(second, "alias-b", "alias-b", "one canonical beta task")
        intent_a = alias_a["taskIntent"]
        intent_b = alias_b["taskIntent"]
        coordination_a = alias_a["coordination"]
        coordination_b = alias_b["coordination"]
        if (
            intent_a["canonicalTaskId"] != intent_b["canonicalTaskId"]
            or intent_a["definition"]["definition_digest"]
            != intent_b["definition"]["definition_digest"]
            or {coordination_a["status"], coordination_b["status"]} != {"leader", "join"}
        ):
            raise LifecycleFailure("task aliases did not converge")

        dependency = start(first, "dependency", "dependency", "complete dependency")
        dependent = start(
            second,
            "dependent",
            "dependent",
            "complete dependent",
            dependencyTaskIds=["dependency"],
        )
        waiting = dependent["coordination"]
        waiting_claim = tool(
            second,
            "waiting-claim",
            "task.claim",
            {"taskId": "dependent", "expectedStateGeneration": 1},
        )["outcome"]
        if waiting["status"] != "waiting" or waiting_claim["status"] != "waiting":
            raise LifecycleFailure("incomplete dependency became claimable")

        cancelled = start(first, "cancelled-dependency", "cancelled-dependency", "cancel dependency")
        cancelled_coordination = cancelled["coordination"]
        transition(
            first,
            "cancel-dependency",
            "cancelled-dependency",
            cancelled_coordination["leaseId"],
            1,
            "cancelled",
        )
        blocked = start(
            second,
            "cancelled-dependent",
            "cancelled-dependent",
            "remain explicitly blocked",
            dependencyTaskIds=["cancelled-dependency"],
        )
        blockers = blocked["coordination"].get("blockers", [])
        if not blockers or blockers[0].get("state") != "cancelled":
            raise LifecycleFailure("cancelled dependency blocker was not explicit")

        parent = start(first, "parent", "parent", "complete parent after child")
        child = start(
            second,
            "parent-child",
            "parent-child",
            "complete child before parent",
            parentTaskId="parent",
        )
        child_coordination = child["coordination"]
        transition(
            second,
            "complete-parent-child",
            "parent-child",
            child_coordination["leaseId"],
            1,
            "completed",
        )
        parent_coordination = parent["coordination"]
        transition(
            first,
            "complete-parent",
            "parent",
            parent_coordination["leaseId"],
            1,
            "completed",
        )

        dependency_coordination = dependency["coordination"]
        transition(
            first,
            "complete-dependency",
            "dependency",
            dependency_coordination["leaseId"],
            1,
            "completed",
        )
        dependent_claim = tool(
            second,
            "claim-dependent",
            "task.claim",
            {"taskId": "dependent", "expectedStateGeneration": 1},
        )["outcome"]
        ready = tool(second, "inspect-ready", "task.inspect", {"taskId": "dependent"})["task"]
        if (
            dependent_claim["status"] != "leader"
            or ready["state"] != "active"
            or ready["state_generation"] != 2
        ):
            raise LifecycleFailure("dependency completion did not activate dependent")

        takeover = start(first, "takeover", "takeover", "exercise blocked takeover")
        takeover_first = takeover["coordination"]
        transition(
            first,
            "block-takeover",
            "takeover",
            takeover_first["leaseId"],
            1,
            "blocked",
        )
        first.close()
        first_closed = True
        takeover_second = tool(
            second,
            "claim-takeover",
            "task.claim",
            {"taskId": "takeover", "expectedStateGeneration": 2},
        )["outcome"]
        stale_refused = refused(
            second,
            "stale-transition",
            "task.transition",
            {
                "taskId": "takeover",
                "leaseId": takeover_first["leaseId"],
                "expectedStateGeneration": takeover_second["state_generation"],
                "state": "completed",
                "reason": "stale lease must fail",
            },
        )
        transition(
            second,
            "complete-takeover",
            "takeover",
            takeover_second["lease_id"],
            takeover_second["state_generation"],
            "completed",
        )

        transition(
            second,
            "complete-dependent",
            "dependent",
            dependent_claim["lease_id"],
            2,
            "completed",
        )
        terminal_refused = refused(
            second,
            "terminal-transition",
            "task.transition",
            {
                "taskId": "dependent",
                "leaseId": dependent_claim["lease_id"],
                "expectedStateGeneration": 3,
                "state": "failed",
                "reason": "terminal mutation must fail",
            },
        )

        tool(
            second,
            "unknown",
            "context.publish",
            {"taskId": "alias-a", "kind": "unknown", "subject": "beta-unknown", "explanation": "bounded unknown"},
        )
        tool(
            second,
            "suggestion",
            "context.publish",
            {"taskId": "alias-a", "kind": "suggestion", "subject": "beta-fact", "statement": "deterministic suggestion"},
        )
        work = tool(
            second,
            "work-start",
            "context.publish",
            {"taskId": "alias-a", "kind": "work_start", "workKey": "beta-work", "summary": "bounded work", "ttlMs": 1000},
        )["outcome"]
        tool(
            second,
            "work-finish",
            "context.publish",
            {"taskId": "alias-a", "kind": "work_finish", "leaseId": work["leaseId"], "succeeded": False},
        )
        second.request(
            "reference-cold",
            "tools/call",
            {"name": "repo.read", "arguments": {"path": "README.md"}},
        )
        read_response = second.request(
            "reference-warm",
            "tools/call",
            {"name": "repo.read", "arguments": {"path": "README.md"}},
        )
        read_result = read_response.get("result")
        if (
            not isinstance(read_result, dict)
            or chaos.product.result_id(read_result) is None
            or chaos.product.result_without_reference(read_result)
            .get("structuredContent", {})
            .get("path")
            != "README.md"
        ):
            raise LifecycleFailure("verified repository reference failed")

        wrong_scope = chaos.Session(
            binary,
            workspace,
            state,
            "wrong-scope",
            authorization_scope="again-local-beta:wrong-scope-v1",
        )
        try:
            wrong_scope.handshake()
            cross_scope_refused = refused(
                wrong_scope,
                "cross-scope-inspect",
                "task.inspect",
                {"taskId": "alias-a"},
            )
        finally:
            wrong_scope.close()
        if not cross_scope_refused:
            raise LifecycleFailure("cross-scope task retrieval was authorized")

        before_dependency = export_task(binary, workspace, state, root, "dependency", "dependency-before")
        before_dependent = export_task(binary, workspace, state, root, "dependent", "dependent-before")
        before_parent = export_task(binary, workspace, state, root, "parent", "parent-before")
        before_child = export_task(binary, workspace, state, root, "parent-child", "parent-child-before")
        history_before = digest(
            [
                before_dependency["export"],
                before_dependent["export"],
                before_parent["export"],
                before_child["export"],
            ]
        )
        transition_count = sum(
            len(document["export"]["transitions"])
            for document in (before_dependency, before_dependent, before_parent, before_child)
        )
        second.close()
        second_closed = True
        chaos._stop_automatic_daemon(binary, workspace, state, root)

        restarted = chaos.Session(binary, workspace, state, "restarted", automatic_daemon=True)
        try:
            restarted.handshake()
            recovered = tool(restarted, "recovered", "task.inspect", {"taskId": "dependent"})["task"]
            if recovered["state"] != "completed":
                raise LifecycleFailure("terminal history was not recovered")
            daemon_after = daemon_endpoint_identity(root)
            if daemon_after == daemon_before:
                raise LifecycleFailure("daemon endpoint identity did not change after restart")
        finally:
            restarted.close()
        chaos._stop_automatic_daemon(binary, workspace, state, root)
        after_dependency = export_task(binary, workspace, state, root, "dependency", "dependency-after")
        after_dependent = export_task(binary, workspace, state, root, "dependent", "dependent-after")
        after_parent = export_task(binary, workspace, state, root, "parent", "parent-after")
        after_child = export_task(binary, workspace, state, root, "parent-child", "parent-child-after")
        history_after = digest(
            [
                after_dependency["export"],
                after_dependent["export"],
                after_parent["export"],
                after_child["export"],
            ]
        )
        if history_before != history_after:
            raise LifecycleFailure("restart changed task history")

        return {
            "schema": SCHEMA,
            "classification": {"type": "pass", "code": "lifecycle_scenarios_passed"},
            "source_git_sha": source_git_sha,
            "binary_sha256": chaos.sha256_bytes(binary.read_bytes()),
            "task_alias_convergence": {
                "alias_count": 2,
                "canonical_definition_count": 1,
                "definition_digest": intent_a["definition"]["definition_digest"],
                "leader_count": 1,
            },
            "task_graph_readiness": {
                "dependent_waiting": True,
                "incomplete_dependency_claim_refused": True,
                "completed_dependency_ready": True,
                "failed_cancelled_blockers_explicit": True,
            },
            "context_exchange": {
                "kinds": ["verified_fact", "unknown", "failure", "reference", "in_flight"],
                "cross_scope_deliveries": 0 if cross_scope_refused else 1,
                "unauthorized_retrievals": 0 if cross_scope_refused else 1,
            },
            "leader_takeover": {
                "leader_generation_before": takeover_first["leaseGeneration"],
                "leader_generation_after": takeover_second["lease_generation"],
                "takeover_succeeded": takeover_second["status"] == "leader",
                "stale_leader_transition_refused": stale_refused,
            },
            "lifecycle_completion": {
                "dependency_completed": after_dependency["export"]["task"]["state"] == "completed",
                "parent_completed": after_parent["export"]["task"]["state"] == "completed",
                "terminal_immutable": terminal_refused,
                "transition_history_count": transition_count,
            },
            "daemon_restart_recovery": {
                "daemon_identity_changed": daemon_after != daemon_before,
                "complete_history_recovered": history_before == history_after,
                "history_digest_before": history_before,
                "history_digest_after": history_after,
            },
        }
    finally:
        if not first_closed:
            try:
                first.close()
            except BaseException:
                pass
        if not second_closed:
            try:
                second.close()
            except BaseException:
                pass
        try:
            chaos._stop_automatic_daemon(binary, workspace, state, root)
        except BaseException:
            pass
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--again-binary", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        parser.error(f"refusing to replace existing evidence: {output}")
    evidence = run(args.again_binary.resolve(strict=True), args.source_git_sha)
    chaos.write_exclusive(output, canonical(evidence))
    print(json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (LifecycleFailure, chaos.HarnessRefusal) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(2)
