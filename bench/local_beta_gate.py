#!/usr/bin/env python3
"""Fail-closed aggregation for the Again local-beta release gate.

This program does not manufacture product evidence.  It accepts retained,
machine-readable observations from the black-box product scenario, the
100-client chaos run, four native package jobs, signed-release verification,
and an outside-user Codex/Claude comparison.  It validates their invariants,
binds every input to one source commit, and emits a compact release decision.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import stat
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA = "again.local-beta-gate.v1"
SCENARIO_SCHEMA = "again.local-beta-product-scenario.v1"
NATIVE_SCHEMA = "again.local-beta-native-smoke.v1"
REAL_AGENT_SCHEMA = "again.local-beta-real-agent-review.v1"
CHAOS_SCHEMA = "again.agent-gateway-chaos-soak.v3"
RELEASE_SCHEMA = "again.release-verification-summary.v2"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 500_000
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)
SCENARIO_STEPS = (
    "isolated_install",
    "client_setup",
    "automatic_daemon_clients",
    "task_alias_convergence",
    "task_graph_readiness",
    "context_exchange",
    "leader_takeover",
    "lifecycle_completion",
    "daemon_restart_recovery",
    "repository_mutations",
    "quota_maintenance",
    "upgrade_remove_uninstall",
)
ADVERSARIAL_PROBES = (
    "aba_workspace_replacement",
    "cancellation_storms",
    "clock_anomalies",
    "compaction",
    "corrupt_cas",
    "corrupt_sqlite",
    "disk_exhaustion",
    "graph_properties",
    "hostile_inputs",
    "mcp_fuzz",
    "migration_differential",
    "oversized_inputs",
    "partial_writes",
    "permission_changes",
    "restart_loops",
    "reused_json_rpc_ids",
    "slow_readers",
    "stale_endpoints",
    "symlink_swaps",
    "transition_properties",
)
ZERO_SAFETY_COUNTERS = (
    "cross_scope_hits",
    "duplicated_completions",
    "false_hits",
    "secret_leaks",
    "silent_evictions",
    "unauthorized_retrievals",
)
FORBIDDEN_DIAGNOSTIC_KEYS = {
    "config_document",
    "context",
    "credential_value",
    "endpoint_path",
    "prompt",
    "raw_context",
    "raw_prompt",
    "result_content",
    "secret",
    "secrets",
    "socket_authority",
    "stderr",
    "stdout",
}
SENSITIVE_TEXT = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}={0,2}\b", re.IGNORECASE),
)


class GateRefusal(RuntimeError):
    """Typed non-pass; messages must not contain untrusted evidence values."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_json(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError) as error:
        raise GateRefusal("json_canonicalization", "report is not canonical JSON") from error


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateRefusal("duplicate_json_key", "evidence contains a duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise GateRefusal("nonfinite_json", "evidence contains a non-finite number")


def _validate_json_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise GateRefusal("json_node_limit", "evidence exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            raise GateRefusal("json_depth_limit", "evidence exceeds the JSON depth limit")
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise GateRefusal("nonfinite_json", "evidence contains a non-finite number")


def read_json(path: pathlib.Path) -> dict[str, Any]:
    """Read one stable, bounded, regular non-symlink UTF-8 JSON object."""

    try:
        before = path.lstat()
    except OSError as error:
        raise GateRefusal("evidence_unavailable", "required evidence is unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_INPUT_BYTES
    ):
        raise GateRefusal("evidence_unsafe", "evidence is not a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise GateRefusal("evidence_unavailable", "required evidence cannot be opened") from error
    content = bytearray()
    try:
        opened = os.fstat(descriptor)
        if _stat_identity(before) != _stat_identity(opened):
            raise GateRefusal("evidence_race", "evidence changed while opening")
        while len(content) <= MAX_INPUT_BYTES:
            block = os.read(descriptor, min(64 * 1024, MAX_INPUT_BYTES + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        final = path.lstat()
    except OSError as error:
        raise GateRefusal("evidence_race", "evidence disappeared while reading") from error
    if (
        len(content) > MAX_INPUT_BYTES
        or len(content) != before.st_size
        or _stat_identity(before) != _stat_identity(after)
        or _stat_identity(before) != _stat_identity(final)
    ):
        raise GateRefusal("evidence_race", "evidence changed while reading")
    try:
        value = json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except GateRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise GateRefusal("evidence_json", "evidence is not strict UTF-8 JSON") from error
    _validate_json_bounds(value)
    if not isinstance(value, dict):
        raise GateRefusal("evidence_shape", "evidence root is not an object")
    return value


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def write_exclusive(path: pathlib.Path, value: Mapping[str, Any]) -> None:
    content = canonical_json(dict(value))
    if (
        not path.is_absolute()
        or ".." in path.parts
        or path.name in {"", ".", ".."}
        or len(content) > MAX_OUTPUT_BYTES
    ):
        raise GateRefusal("output_path", "output must be bounded, absolute, and traversal-free")
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(path.parent, directory_flags)
    except OSError as error:
        raise GateRefusal("output_directory", "output directory is unavailable") from error
    temporary_name = f".{path.name}.{secrets.token_hex(16)}.transaction"
    descriptor = -1
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise GateRefusal(
                "output_temporary_exists", "gate output transaction already exists"
            ) from error
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise GateRefusal("output_write", "gate output write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError as error:
            raise GateRefusal(
                "output_exists", "refusing to overwrite existing gate output"
            ) from error
        os.fsync(parent_descriptor)
        os.unlink(temporary_name, dir_fd=parent_descriptor)
        temporary_name = ""
        os.fsync(parent_descriptor)
    except GateRefusal:
        raise
    except OSError as error:
        raise GateRefusal("output_write", "gate output could not be committed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def _mapping(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GateRefusal(code, "required evidence object is absent")
    return value


def _sequence(value: Any, code: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise GateRefusal(code, "required evidence sequence is absent")
    return value


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise GateRefusal(code, message)


def _is_int(value: Any, minimum: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _source_sha(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _pass_classification(value: Any) -> bool:
    classification = _mapping(value, "classification")
    return classification.get("type") == "pass" and isinstance(
        classification.get("code"), str
    )


def _scan_scenario_diagnostics(value: Any) -> None:
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            for key, item in current.items():
                if not isinstance(key, str):
                    raise GateRefusal("diagnostic_key", "scenario diagnostic key is invalid")
                if key.casefold() in FORBIDDEN_DIAGNOSTIC_KEYS:
                    raise GateRefusal(
                        "diagnostic_content",
                        "scenario evidence contains a forbidden content-bearing field",
                    )
                stack.append(item)
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            stack.extend(current)
        elif isinstance(current, str):
            if any(pattern.search(current) for pattern in SENSITIVE_TEXT):
                raise GateRefusal(
                    "diagnostic_sensitive_text",
                    "scenario evidence contains credential-shaped text",
                )


def validate_scenario(report: Mapping[str, Any]) -> dict[str, str]:
    _require(report.get("schema") == SCENARIO_SCHEMA, "scenario_schema", "scenario schema differs")
    _require(_pass_classification(report.get("classification")), "scenario_nonpass", "scenario did not pass")
    provenance = _mapping(report.get("provenance"), "scenario_provenance")
    source = provenance.get("source_git_sha")
    initial_binary = provenance.get("initial_binary_sha256")
    upgraded_binary = provenance.get("upgraded_binary_sha256")
    target = provenance.get("target")
    _require(_source_sha(source), "scenario_source", "scenario source identity is invalid")
    _require(_digest(initial_binary) and _digest(upgraded_binary), "scenario_binary", "scenario binary identity is invalid")
    _require(initial_binary != upgraded_binary, "upgrade_identity", "upgrade did not change binary identity")
    _require(target in TARGETS, "scenario_target", "scenario target is unsupported")
    privacy = _mapping(report.get("privacy"), "scenario_privacy")
    _require(
        privacy.get("deterministic_screening") is True
        and privacy.get("raw_payloads_retained") is False
        and privacy.get("diagnostic_content_scan_passed") is True,
        "scenario_privacy",
        "scenario privacy evidence is incomplete",
    )
    _scan_scenario_diagnostics(report)

    steps = _sequence(report.get("steps"), "scenario_steps")
    names = [step.get("name") if isinstance(step, Mapping) else None for step in steps]
    _require(tuple(names) == SCENARIO_STEPS, "scenario_steps", "scenario step set or order differs")
    evidence_by_name: dict[str, Mapping[str, Any]] = {}
    for item in steps:
        step = _mapping(item, "scenario_step")
        _require(step.get("status") == "pass", "scenario_step_nonpass", "a scenario step did not pass")
        evidence_by_name[str(step["name"])] = _mapping(step.get("evidence"), "scenario_step_evidence")

    install = evidence_by_name["isolated_install"]
    _require(
        install.get("installer_verified") is True
        and install.get("isolated_home") is True
        and install.get("private_permissions") is True
        and install.get("installed_binary_sha256") == initial_binary
        and _digest(install.get("archive_sha256")),
        "isolated_install",
        "isolated install evidence is incomplete",
    )
    setup = evidence_by_name["client_setup"]
    clients = _mapping(setup.get("clients"), "client_setup")
    _require(set(clients) == {"claude", "codex"}, "client_setup", "both clients were not exercised")
    for client in clients.values():
        item = _mapping(client, "client_setup")
        _require(
            all(item.get(field) is True for field in ("fake_probe", "real_probe", "applied", "verified")),
            "client_setup",
            "a client setup probe is incomplete",
        )
    _require(setup.get("direct_config_edits") == 0, "client_setup", "client setup edited configuration directly")
    daemon = evidence_by_name["automatic_daemon_clients"]
    _require(
        daemon.get("automatic_start") is True
        and daemon.get("client_count") == 2
        and daemon.get("daemon_process_count") == 1
        and daemon.get("authenticated_handshakes") == 2,
        "automatic_daemon",
        "automatic daemon evidence is incomplete",
    )
    aliases = evidence_by_name["task_alias_convergence"]
    _require(
        _is_int(aliases.get("alias_count"), 2)
        and aliases.get("canonical_definition_count") == 1
        and aliases.get("leader_count") == 1
        and _digest(aliases.get("definition_digest")),
        "task_aliases",
        "task alias convergence failed",
    )
    graph = evidence_by_name["task_graph_readiness"]
    _require(
        graph.get("dependent_waiting") is True
        and graph.get("incomplete_dependency_claim_refused") is True
        and graph.get("completed_dependency_ready") is True
        and graph.get("failed_cancelled_blockers_explicit") is True,
        "task_graph",
        "task dependency readiness evidence is incomplete",
    )
    exchange = evidence_by_name["context_exchange"]
    _require(
        set(_sequence(exchange.get("kinds"), "context_exchange"))
        == {"failure", "in_flight", "reference", "unknown", "verified_fact"}
        and exchange.get("cross_scope_deliveries") == 0
        and exchange.get("unauthorized_retrievals") == 0,
        "context_exchange",
        "context exchange safety evidence is incomplete",
    )
    takeover = evidence_by_name["leader_takeover"]
    before = takeover.get("leader_generation_before")
    after = takeover.get("leader_generation_after")
    _require(
        _is_int(before, 1)
        and _is_int(after, 2)
        and int(after) > int(before)
        and takeover.get("takeover_succeeded") is True
        and takeover.get("stale_leader_transition_refused") is True,
        "leader_takeover",
        "leader takeover evidence is incomplete",
    )
    completion = evidence_by_name["lifecycle_completion"]
    _require(
        completion.get("dependency_completed") is True
        and completion.get("parent_completed") is True
        and completion.get("terminal_immutable") is True
        and _is_int(completion.get("transition_history_count"), 4),
        "lifecycle_completion",
        "completion transition evidence is incomplete",
    )
    restart = evidence_by_name["daemon_restart_recovery"]
    _require(
        restart.get("daemon_identity_changed") is True
        and restart.get("complete_history_recovered") is True
        and _digest(restart.get("history_digest_before"))
        and restart.get("history_digest_before") == restart.get("history_digest_after"),
        "daemon_restart",
        "daemon restart did not preserve history",
    )
    mutation = evidence_by_name["repository_mutations"]
    _require(
        mutation.get("relevant_task_delivery_retired") is True
        and mutation.get("relevant_leases_retired") is True
        and mutation.get("unrelated_verified_facts_preserved") is True,
        "repository_mutation",
        "repository invalidation evidence is incomplete",
    )
    quota = evidence_by_name["quota_maintenance"]
    maintenance = _mapping(quota.get("maintenance_operations"), "quota_maintenance")
    _require(
        quota.get("maintenance_mode") is True
        and quota.get("new_durable_write_refused") is True
        and quota.get("export_private_0600") is True
        and quota.get("export_no_overwrite") is True
        and quota.get("automatic_evictions") == 0
        and set(maintenance) == {"delete", "doctor", "export", "gc", "inspect", "prune", "stats"}
        and all(value is True for value in maintenance.values()),
        "quota_maintenance",
        "quota maintenance evidence is incomplete",
    )
    upgrade = evidence_by_name["upgrade_remove_uninstall"]
    _require(
        upgrade.get("binary_mismatch_refused_or_drained") is True
        and upgrade.get("active_sessions_silently_killed") == 0
        and upgrade.get("codex_removed_exact") is True
        and upgrade.get("claude_removed_exact") is True
        and upgrade.get("uninstalled") is True
        and upgrade.get("upgraded_binary_sha256") == upgraded_binary,
        "upgrade_cleanup",
        "upgrade or cleanup evidence is incomplete",
    )

    adversarial = _mapping(report.get("adversarial"), "adversarial")
    probes = _mapping(adversarial.get("probes"), "adversarial")
    counters = _mapping(adversarial.get("safety_counters"), "adversarial")
    _require(
        _is_int(adversarial.get("concurrent_clients"), 100)
        and _is_int(adversarial.get("repository_count"), 2)
        and _is_int(adversarial.get("retained_soak_seconds"), 1)
        and set(probes) == set(ADVERSARIAL_PROBES)
        and all(value is True for value in probes.values())
        and set(counters) == set(ZERO_SAFETY_COUNTERS)
        and all(value == 0 for value in counters.values()),
        "adversarial",
        "adversarial matrix is incomplete or unsafe",
    )
    return {
        "source_git_sha": str(source),
        "initial_binary_sha256": str(initial_binary),
        "upgraded_binary_sha256": str(upgraded_binary),
        "target": str(target),
        "report_sha256": sha256(canonical_json(report)),
    }


def validate_native(report: Mapping[str, Any]) -> dict[str, str]:
    _require(report.get("schema") == NATIVE_SCHEMA, "native_schema", "native smoke schema differs")
    _require(_pass_classification(report.get("classification")), "native_nonpass", "native smoke did not pass")
    target = report.get("target")
    source = report.get("source_git_sha")
    archive = report.get("archive_sha256")
    binary = report.get("installed_binary_sha256")
    _require(target in TARGETS, "native_target", "native smoke target is unsupported")
    _require(
        _source_sha(source) and _digest(archive) and _digest(binary),
        "native_identity",
        "native smoke identity is invalid",
    )
    checks = _mapping(report.get("checks"), "native_checks")
    required = {"authenticated_mcp", "daemon_started", "doctor_passed", "installed", "uninstalled"}
    _require(
        set(checks) == required and all(value is True for value in checks.values()),
        "native_checks",
        "native smoke is incomplete",
    )
    return {
        "target": str(target),
        "source_git_sha": str(source),
        "archive_sha256": str(archive),
        "installed_binary_sha256": str(binary),
        "report_sha256": sha256(canonical_json(report)),
    }


def validate_chaos(report: Mapping[str, Any]) -> dict[str, str]:
    _require(report.get("schema") == CHAOS_SCHEMA, "chaos_schema", "chaos schema differs")
    _require(_pass_classification(report.get("classification")), "chaos_nonpass", "chaos evidence did not pass")
    source = report.get("source_git_sha")
    binary = _mapping(report.get("binary"), "chaos_binary").get("sha256")
    resources = _mapping(report.get("resource_observation"), "chaos_resources")
    exact_probe = _mapping(report.get("exact_probe"), "chaos_exact_probe")
    _require(_source_sha(source) and _digest(binary), "chaos_identity", "chaos identity is invalid")
    _require(
        report.get("mode") == "beta"
        and report.get("concurrency") == 100
        and report.get("false_hit_count") == 0
        and exact_probe.get("automatic_daemon") is True
        and exact_probe.get("sessions") == 100
        and _mapping(exact_probe.get("daemon_stop"), "chaos_daemon_stop").get(
            "absent_after_stop"
        )
        is True
        and resources.get("new_or_changed_open_fds") == 0
        and resources.get("all_owned_process_groups_absent") is True
        and resources.get("temporary_state_absent") is True
        and resources.get("resource_leaks") == [],
        "chaos_scope",
        "100-client beta chaos evidence is incomplete",
    )
    return {
        "source_git_sha": str(source),
        "binary_sha256": str(binary),
        "report_sha256": sha256(canonical_json(report)),
    }


def validate_real_agent(report: Mapping[str, Any]) -> dict[str, str]:
    _require(report.get("schema") == REAL_AGENT_SCHEMA, "agent_schema", "real-agent review schema differs")
    _require(_pass_classification(report.get("classification")), "agent_nonpass", "real-agent review did not pass")
    source = report.get("source_git_sha")
    binary = report.get("binary_sha256")
    _require(_source_sha(source) and _digest(binary), "agent_identity", "real-agent identity is invalid")
    _require(
        report.get("outside_user") is True
        and report.get("deterministic_harness_only") is False,
        "outside_user",
        "outside-user real-agent evidence is absent",
    )
    quality = _mapping(report.get("quality"), "agent_quality")
    _require(
        quality.get("incorrect_hits") == 0
        and quality.get("quality_regressions") == 0
        and quality.get("stale_or_incorrect_facts") == 0
        and quality.get("patches_independently_reviewed") is True,
        "agent_quality",
        "real-agent quality gate failed",
    )
    clients = _mapping(report.get("clients"), "agent_clients")
    _require(set(clients) == {"claude", "codex"}, "agent_clients", "both real clients are required")
    metric_names = {
        "cost_usd_micros",
        "duplicate_investigations",
        "duplicate_reads",
        "first_correct_edit_ms",
        "input_tokens",
        "output_tokens",
        "patch_quality_score",
        "response_bytes",
        "tool_calls",
        "validated_completion_ms",
    }
    for client in clients.values():
        pair = _mapping(client, "agent_pair")
        _require(_is_int(pair.get("paired_runs"), 1), "agent_pair", "real-agent pair count is invalid")
        baseline = _mapping(pair.get("baseline"), "agent_metrics")
        enabled = _mapping(pair.get("again_enabled"), "agent_metrics")
        _require(
            set(baseline) == metric_names
            and set(enabled) == metric_names
            and all(_is_int(value) for value in baseline.values())
            and all(_is_int(value) for value in enabled.values())
            and 0 <= int(baseline["patch_quality_score"]) <= 100
            and 0 <= int(enabled["patch_quality_score"]) <= 100
            and int(enabled["patch_quality_score"]) >= int(baseline["patch_quality_score"]),
            "agent_metrics",
            "real-agent metrics are incomplete or show a quality regression",
        )
    return {
        "source_git_sha": str(source),
        "binary_sha256": str(binary),
        "report_sha256": sha256(canonical_json(report)),
    }


def _release_subjects(tag: str) -> set[str]:
    return {
        "SHA256SUMS",
        "again-alpha.rb",
        f"again-{tag}-aarch64-apple-darwin.tar.gz",
        f"again-{tag}-aarch64-unknown-linux-gnu.tar.gz",
        f"again-{tag}-source.cdx.json",
        f"again-{tag}-x86_64-apple-darwin.tar.gz",
        f"again-{tag}-x86_64-unknown-linux-gnu.tar.gz",
    }


def validate_release(report: Mapping[str, Any]) -> dict[str, Any]:
    _require(report.get("schema") == RELEASE_SCHEMA, "release_schema", "release evidence schema differs")
    release = _mapping(report.get("release"), "release_identity")
    source = release.get("source_commit")
    tag = release.get("tag")
    _require(
        _source_sha(source)
        and isinstance(tag, str)
        and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag) is not None
        and release.get("draft") is False
        and release.get("immutable") is True,
        "release_identity",
        "signed release identity is invalid",
    )
    artifacts = _sequence(report.get("artifacts"), "release_assets")
    _require(len(artifacts) == 7, "release_assets", "release does not contain seven signed subjects")
    bundle_names: set[str] = set()
    subject_names: set[str] = set()
    archive_sha256: dict[str, str] = {}
    binary_sha256: dict[str, str] = {}
    for value in artifacts:
        artifact = _mapping(value, "release_asset")
        name = artifact.get("name")
        artifact_sha256 = artifact.get("sha256")
        attestation = _mapping(artifact.get("attestation"), "release_attestation")
        _require(
            isinstance(name, str)
            and name not in subject_names
            and _digest(artifact_sha256)
            and attestation.get("status") == "verified"
            and attestation.get("certificate_present") is True
            and _digest(attestation.get("bundle_sha256"))
            and isinstance(attestation.get("bundle_name"), str),
            "release_attestation",
            "release subject attestation is incomplete",
        )
        subject_names.add(name)
        bundle_names.add(str(attestation["bundle_name"]))
        if name.endswith(".tar.gz"):
            target = artifact.get("target")
            packaged_binary = artifact.get("binary_sha256")
            _require(
                target in TARGETS and _digest(packaged_binary),
                "release_archive",
                "release archive identity is incomplete",
            )
            archive_sha256[str(target)] = str(artifact_sha256)
            binary_sha256[str(target)] = str(packaged_binary)
    expected_subjects = _release_subjects(str(tag))
    _require(
        subject_names == expected_subjects
        and bundle_names == {f"{name}.sigstore.json" for name in expected_subjects}
        and set(archive_sha256) == set(TARGETS)
        and not subject_names.intersection(bundle_names),
        "release_assets",
        "release does not prove the exact 14-asset subject and bundle inventory",
    )
    publisher = _mapping(report.get("publisher"), "release_publisher")
    _require(publisher.get("status") == "authenticated", "release_publisher", "release publisher is unauthenticated")
    return {
        "source_git_sha": str(source),
        "tag": str(tag),
        "asset_count": "14",
        "archive_sha256": archive_sha256,
        "binary_sha256": binary_sha256,
        "report_sha256": sha256(canonical_json(report)),
    }


def build_gate(
    *,
    scenario: Mapping[str, Any],
    chaos: Mapping[str, Any],
    real_agent: Mapping[str, Any],
    release: Mapping[str, Any],
    native: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    scenario_summary = validate_scenario(scenario)
    chaos_summary = validate_chaos(chaos)
    agent_summary = validate_real_agent(real_agent)
    release_summary = validate_release(release)
    native_summaries = [validate_native(item) for item in native]
    _require(
        sorted(item["target"] for item in native_summaries) == list(TARGETS),
        "native_matrix",
        "exactly one native smoke for each release target is required",
    )
    source = scenario_summary["source_git_sha"]
    _require(
        all(
            item["source_git_sha"] == source
            for item in [chaos_summary, agent_summary, release_summary, *native_summaries]
        ),
        "source_mismatch",
        "gate evidence does not bind to one source commit",
    )
    initial_binary = scenario_summary["initial_binary_sha256"]
    _require(
        chaos_summary["binary_sha256"] == initial_binary
        and agent_summary["binary_sha256"] == initial_binary,
        "binary_mismatch",
        "product, chaos, and real-agent evidence used different binaries",
    )
    release_archives = _mapping(release_summary["archive_sha256"], "release_archives")
    release_binaries = _mapping(release_summary["binary_sha256"], "release_binaries")
    _require(
        all(
            item["archive_sha256"] == release_archives[item["target"]]
            and item["installed_binary_sha256"] == release_binaries[item["target"]]
            for item in native_summaries
        )
        and initial_binary == release_binaries[scenario_summary["target"]],
        "release_binary_mismatch",
        "native or product evidence does not match the signed release archives",
    )
    report = {
        "schema": SCHEMA,
        "classification": {"type": "pass", "code": "local_beta_release_gate_passed"},
        "source_git_sha": source,
        "release_tag": release_summary["tag"],
        "binary": {
            "qualified_sha256": initial_binary,
            "upgrade_sha256": scenario_summary["upgraded_binary_sha256"],
        },
        "coverage": {
            "product_scenario_steps": len(SCENARIO_STEPS),
            "native_targets": list(TARGETS),
            "release_asset_count": 14,
            "chaos_concurrent_clients": 100,
            "real_agent_clients": ["claude", "codex"],
            "outside_user_evidence": True,
        },
        "evidence_sha256": {
            "scenario": scenario_summary["report_sha256"],
            "chaos": chaos_summary["report_sha256"],
            "real_agent": agent_summary["report_sha256"],
            "release": release_summary["report_sha256"],
            "native": {
                item["target"]: item["report_sha256"] for item in native_summaries
            },
        },
        "release_authority": {
            "tag_creation_performed_by_gate": False,
            "human_release_authority_required": True,
        },
    }
    report["report_sha256"] = sha256(canonical_json(report))
    return report


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--chaos-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--real-agent-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--release-evidence", required=True, type=pathlib.Path)
    parser.add_argument(
        "--native-evidence",
        required=True,
        action="append",
        type=pathlib.Path,
        help="repeat exactly four times, once per native target",
    )
    parser.add_argument("--output", required=True, type=pathlib.Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _arguments(argv)
    try:
        _require(len(args.native_evidence) == 4, "native_matrix", "exactly four native evidence files are required")
        report = build_gate(
            scenario=read_json(args.scenario_evidence.resolve(strict=False)),
            chaos=read_json(args.chaos_evidence.resolve(strict=False)),
            real_agent=read_json(args.real_agent_evidence.resolve(strict=False)),
            release=read_json(args.release_evidence.resolve(strict=False)),
            native=[read_json(path.resolve(strict=False)) for path in args.native_evidence],
        )
        write_exclusive(args.output.resolve(strict=False), report)
    except GateRefusal as error:
        failure = {
            "schema": SCHEMA,
            "classification": {"type": "failure", "code": error.code},
            "message": str(error),
        }
        print(json.dumps(failure, separators=(",", ":"), sort_keys=True))
        return 3
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
