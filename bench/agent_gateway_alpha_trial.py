#!/usr/bin/env python3
"""Fail-closed recorder and aggregator for the Again outside-user alpha trial.

This program never runs an agent, contacts a service, or mutates a source
repository.  It validates a participant-produced trial against one frozen
ten-scenario specification, records a canonical local verification report, and
can aggregate exactly five such reports.  Participant independence and the
publisher-verification statement remain external attestations; the aggregate
labels that provenance instead of presenting caller-supplied JSON as a
cryptographic identity proof.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import os
import pathlib
import platform
import re
import stat
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any


SPEC_SCHEMA = "again.agent-gateway-alpha-trial-spec.v1"
TRIAL_SCHEMA = "again.agent-gateway-alpha-trial-input.v1"
VERIFIED_SCHEMA = "again.agent-gateway-alpha-trial-verified.v1"
AGGREGATE_SCHEMA = "again.agent-gateway-alpha-trial-aggregate.v1"
SPEC_VERSION = "1.0.0"
HARNESS_VERSION = "1.0.0"
EXPECTED_USERS = 5
EXPECTED_SCENARIOS = 10
EXPECTED_ATTEMPTS = EXPECTED_USERS * EXPECTED_SCENARIOS
MINIMUM_ADMITTED_SUCCESSES = 35
MINIMUM_MEDIAN_WARM_SPEEDUP = 3.0
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 50_000
MAX_STRING_BYTES = 64 * 1024
MAX_ELAPSED_MS = 24 * 60 * 60 * 1000
MAX_COUNTER = 1_000_000
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class TrialRefusal(RuntimeError):
    """A typed malformed/refused outcome, never trial evidence."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclasses.dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    expectation: str
    require_stream_equality: bool
    eligible_for_speedup: bool
    requires_dependency_proof: bool = False


SCENARIOS = (
    ScenarioSpec("read_small_exact", "exact_reuse", True, True),
    ScenarioSpec("read_nested_exact", "exact_reuse", True, True),
    ScenarioSpec("search_single_exact", "exact_reuse", True, True),
    ScenarioSpec("search_multiple_exact", "exact_reuse", True, True),
    ScenarioSpec("search_empty_exact", "exact_reuse", True, True),
    ScenarioSpec("concurrent_read_join", "inflight_join", True, False),
    ScenarioSpec("concurrent_search_join", "inflight_join", True, False),
    ScenarioSpec(
        "irrelevant_mutation_exact",
        "exact_reuse",
        True,
        True,
        requires_dependency_proof=True,
    ),
    ScenarioSpec("relevant_mutation_invalidates", "execute_after_change", False, False),
    ScenarioSpec("cancellation_retry_recovers", "cancellation_recovery", True, False),
)
SCENARIO_BY_ID = {item.scenario_id: item for item in SCENARIOS}

TERMINAL_CLASSIFICATIONS = {
    "admitted_success",
    "safe_refusal",
    "incorrect_hit",
    "incomplete_trial",
    "unsupported_host_profile",
}
OBSERVED_OUTCOMES = {"correct", "incorrect", "incomplete", "not_observed"}
PUBLISHER_STATUSES = {"verified", "unverified", "unsupported"}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path, maximum: int) -> str:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            total += len(block)
            if total > maximum:
                raise TrialRefusal("file_oversized", f"file exceeds byte bound: {path}")
            digest.update(block)
    return digest.hexdigest()


def harness_sha256() -> str:
    return sha256_file(pathlib.Path(__file__).resolve(), MAX_INPUT_BYTES)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii") + b"\n"
    except (TypeError, ValueError) as error:
        raise TrialRefusal("noncanonical_json", "value is not canonical JSON") from error
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise TrialRefusal("output_oversized", "canonical output exceeds byte bound")
    return encoded


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise TrialRefusal("duplicate_json_key", f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise TrialRefusal("nonfinite_json_number", f"invalid JSON number: {value}")


def _validate_json_bounds(value: Any) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise TrialRefusal("json_node_limit", "JSON node limit exceeded")
        if depth > MAX_JSON_DEPTH:
            raise TrialRefusal("json_depth_limit", "JSON depth limit exceeded")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_STRING_BYTES:
                raise TrialRefusal("json_string_limit", "JSON string exceeds byte bound")
        elif isinstance(current, float) and not math.isfinite(current):
            raise TrialRefusal("nonfinite_json_number", "non-finite JSON number")


def _canonical_existing_path(path: pathlib.Path, kind: str) -> pathlib.Path:
    if not path.is_absolute():
        raise TrialRefusal(f"{kind}_not_absolute", f"{kind} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise TrialRefusal(f"{kind}_unavailable", f"{kind} path is unavailable") from error
    if resolved != path:
        raise TrialRefusal(f"{kind}_not_canonical", f"{kind} path must be canonical")
    return resolved


def read_json_file(path: pathlib.Path) -> tuple[dict[str, Any], str]:
    path = _canonical_existing_path(path, "input")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TrialRefusal("input_open_failed", "could not open input safely") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise TrialRefusal("input_not_private_regular", "input must be a single-link file")
        if before.st_size > MAX_INPUT_BYTES:
            raise TrialRefusal("input_oversized", "input exceeds byte bound")
        chunks: list[bytes] = []
        total = 0
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_INPUT_BYTES + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
            if total > MAX_INPUT_BYTES:
                raise TrialRefusal("input_oversized", "input exceeds byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after or total != before.st_size:
        raise TrialRefusal("input_changed", "input changed while being read")
    raw = b"".join(chunks)
    try:
        parsed = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except TrialRefusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrialRefusal("malformed_json", "input is not strict UTF-8 JSON") from error
    _validate_json_bounds(parsed)
    if not isinstance(parsed, dict):
        raise TrialRefusal("invalid_top_level", "input must be one JSON object")
    return parsed, sha256_bytes(raw)


def write_json_exclusive(path: pathlib.Path, value: Any) -> None:
    if not path.is_absolute():
        raise TrialRefusal("output_not_absolute", "output path must be absolute")
    parent = _canonical_existing_path(path.parent, "output_parent")
    if parent != path.parent:
        raise TrialRefusal("output_parent_not_canonical", "output parent must be canonical")
    rendered = canonical_json_bytes(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise TrialRefusal("output_exists", "refusing to overwrite existing output") from error
    except OSError as error:
        raise TrialRefusal("output_open_failed", "could not create output safely") from error
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _require_object(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise TrialRefusal("invalid_schema", f"{name} must be an object")
    if set(value) != keys:
        raise TrialRefusal("invalid_schema", f"{name} has missing or unknown fields")
    return value


def _require_string(value: Any, name: str, *, identifier: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise TrialRefusal("invalid_schema", f"{name} must be a non-empty string")
    if len(value.encode("utf-8")) > MAX_STRING_BYTES:
        raise TrialRefusal("invalid_schema", f"{name} exceeds its byte bound")
    if identifier and not IDENTIFIER_RE.fullmatch(value):
        raise TrialRefusal("invalid_schema", f"{name} is not a bounded identifier")
    return value


def _require_sha256(value: Any, name: str) -> str:
    text = _require_string(value, name)
    if not SHA256_RE.fullmatch(text):
        raise TrialRefusal("invalid_schema", f"{name} must be lowercase SHA-256")
    return text


def _require_git_sha(value: Any, name: str) -> str:
    text = _require_string(value, name)
    if not GIT_SHA_RE.fullmatch(text):
        raise TrialRefusal("invalid_schema", f"{name} must be a lowercase Git SHA")
    return text


def _require_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise TrialRefusal("invalid_schema", f"{name} must be boolean")
    return value


def _require_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TrialRefusal("invalid_schema", f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise TrialRefusal("invalid_schema", f"{name} is outside its bound")
    return value


def _run_git(root: pathlib.Path, arguments: Sequence[str]) -> str:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
    }
    try:
        completed = subprocess.run(
            ["git", "-c", "protocol.allow=never", *arguments],
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10.0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrialRefusal("repository_inspection_failed", "bounded Git inspection failed") from error
    if completed.returncode != 0 or len(completed.stdout) > MAX_INPUT_BYTES:
        raise TrialRefusal("repository_inspection_failed", "bounded Git inspection refused")
    try:
        return completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise TrialRefusal("repository_inspection_failed", "Git output was not UTF-8") from error


def observe_repository(root_text: str, expected_git_sha: str) -> dict[str, Any]:
    root = _canonical_existing_path(pathlib.Path(root_text), "repository")
    before = root.stat()
    if not stat.S_ISDIR(before.st_mode):
        raise TrialRefusal("repository_not_directory", "repository must be a directory")
    top = _run_git(root, ["rev-parse", "--show-toplevel"]).strip()
    head = _run_git(root, ["rev-parse", "--verify", "HEAD"]).strip()
    dirty = _run_git(root, ["status", "--porcelain=v1", "--untracked-files=all"])
    after = root.stat()
    if pathlib.Path(top).resolve(strict=True) != root:
        raise TrialRefusal("repository_not_root", "repository path must be its Git root")
    if head != expected_git_sha:
        raise TrialRefusal("repository_git_sha_mismatch", "repository Git SHA changed")
    if dirty:
        raise TrialRefusal("repository_dirty", "repository must be clean")
    if (before.st_dev, before.st_ino, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_mtime_ns,
    ):
        raise TrialRefusal("repository_changed", "repository root changed during inspection")
    identity = {
        "canonical_path": str(root),
        "device": before.st_dev,
        "inode": before.st_ino,
        "git_sha": head,
    }
    return {
        "canonical_path": str(root),
        "git_sha": head,
        "dirty": False,
        "identity_sha256": sha256_bytes(canonical_json_bytes(identity)),
    }


def _observe_executable(path_text: str, expected_sha256: str, name: str) -> dict[str, Any]:
    path = _canonical_existing_path(pathlib.Path(path_text), name)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise TrialRefusal(f"{name}_not_regular", f"{name} must be a single-link regular file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_EXECUTABLE_BYTES:
        raise TrialRefusal(f"{name}_size", f"{name} is outside its byte bound")
    actual = sha256_file(path, MAX_EXECUTABLE_BYTES)
    if actual != expected_sha256:
        raise TrialRefusal(f"{name}_sha256_mismatch", f"{name} SHA-256 changed")
    return {"canonical_path": str(path), "sha256": actual, "size": metadata.st_size}


def trial_specification() -> dict[str, Any]:
    return {
        "schema": SPEC_SCHEMA,
        "spec_version": SPEC_VERSION,
        "harness_version": HARNESS_VERSION,
        "harness_sha256": harness_sha256(),
        "scenario_count": EXPECTED_SCENARIOS,
        "scenarios": [dataclasses.asdict(item) for item in SCENARIOS],
        "gate": {
            "users": EXPECTED_USERS,
            "attempts": EXPECTED_ATTEMPTS,
            "minimum_admitted_successes": MINIMUM_ADMITTED_SUCCESSES,
            "minimum_median_warm_speedup": MINIMUM_MEDIAN_WARM_SPEEDUP,
            "maximum_incorrect_hits": 0,
            "publisher_authentication_required": True,
            "local_simulation_is_outside_user_evidence": False,
        },
    }


def _validate_observation(value: Any, name: str) -> dict[str, Any]:
    item = _require_object(
        value,
        name,
        {"exit_status", "stdout_sha256", "stderr_sha256", "elapsed_ms"},
    )
    return {
        "exit_status": _require_int(item["exit_status"], f"{name}.exit_status", -255, 255),
        "stdout_sha256": _require_sha256(item["stdout_sha256"], f"{name}.stdout_sha256"),
        "stderr_sha256": _require_sha256(item["stderr_sha256"], f"{name}.stderr_sha256"),
        "elapsed_ms": _require_int(item["elapsed_ms"], f"{name}.elapsed_ms", 1, MAX_ELAPSED_MS),
    }


def _validate_counters(value: Any, name: str) -> dict[str, int]:
    keys = {
        "provider_executions",
        "exact_reuse_hits",
        "inflight_joins",
        "cancellations",
        "false_hits",
    }
    item = _require_object(value, name, keys)
    return {key: _require_int(item[key], f"{name}.{key}", 0, MAX_COUNTER) for key in sorted(keys)}


def _validate_bindings(
    value: Any,
    *,
    participant_id: str,
    binary_sha256: str,
    repository_identity: str,
    name: str,
) -> dict[str, str]:
    item = _require_object(
        value,
        name,
        {"participant_id", "binary_sha256", "repository_identity_sha256"},
    )
    normalized = {
        "participant_id": _require_sha256(item["participant_id"], f"{name}.participant_id"),
        "binary_sha256": _require_sha256(item["binary_sha256"], f"{name}.binary_sha256"),
        "repository_identity_sha256": _require_sha256(
            item["repository_identity_sha256"], f"{name}.repository_identity_sha256"
        ),
    }
    expected = {
        "participant_id": participant_id,
        "binary_sha256": binary_sha256,
        "repository_identity_sha256": repository_identity,
    }
    if normalized != expected:
        raise TrialRefusal("conflicting_identity", f"{name} conflicts with trial identity")
    return normalized


def _validate_scenario(
    value: Any,
    spec: ScenarioSpec,
    *,
    participant_id: str,
    binary_sha256: str,
    repository_identity: str,
) -> tuple[dict[str, Any], float | None]:
    name = f"scenario[{spec.scenario_id}]"
    item = _require_object(
        value,
        name,
        {
            "scenario_id",
            "bindings",
            "request_digest",
            "classification",
            "admitted",
            "cold",
            "warm",
            "counters",
            "user_observed_outcome",
            "dependency_proof_sha256",
            "notes",
        },
    )
    scenario_id = _require_string(item["scenario_id"], f"{name}.scenario_id", identifier=True)
    if scenario_id != spec.scenario_id:
        raise TrialRefusal("scenario_mismatch", f"unexpected scenario ID {scenario_id}")
    classification = _require_string(item["classification"], f"{name}.classification")
    if classification not in TERMINAL_CLASSIFICATIONS:
        raise TrialRefusal("invalid_classification", f"invalid classification for {scenario_id}")
    admitted = _require_bool(item["admitted"], f"{name}.admitted")
    outcome = _require_string(item["user_observed_outcome"], f"{name}.user_observed_outcome")
    if outcome not in OBSERVED_OUTCOMES:
        raise TrialRefusal("invalid_outcome", f"invalid user outcome for {scenario_id}")
    notes = item["notes"]
    if not isinstance(notes, str) or len(notes.encode("utf-8")) > 4096:
        raise TrialRefusal("invalid_schema", f"{name}.notes is not bounded text")
    dependency = item["dependency_proof_sha256"]
    if dependency is not None:
        dependency = _require_sha256(dependency, f"{name}.dependency_proof_sha256")
    if spec.requires_dependency_proof and classification == "admitted_success" and dependency is None:
        raise TrialRefusal("dependency_proof_missing", f"{scenario_id} requires a dependency proof")

    counters = _validate_counters(item["counters"], f"{name}.counters")
    bindings = _validate_bindings(
        item["bindings"],
        participant_id=participant_id,
        binary_sha256=binary_sha256,
        repository_identity=repository_identity,
        name=f"{name}.bindings",
    )
    request_digest = _require_sha256(item["request_digest"], f"{name}.request_digest")
    cold = None if item["cold"] is None else _validate_observation(item["cold"], f"{name}.cold")
    warm = None if item["warm"] is None else _validate_observation(item["warm"], f"{name}.warm")
    speedup: float | None = None

    if classification == "admitted_success":
        if not admitted or outcome != "correct" or cold is None or warm is None:
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} success is inconsistent")
        if counters["false_hits"] != 0:
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} success contains a false hit")
        if spec.require_stream_equality:
            stream_fields = ("exit_status", "stdout_sha256", "stderr_sha256")
            if any(cold[field] != warm[field] for field in stream_fields):
                raise TrialRefusal("cold_warm_mismatch", f"{scenario_id} changed status or streams")
        if spec.expectation == "exact_reuse":
            if counters["provider_executions"] != 1 or counters["exact_reuse_hits"] < 1:
                raise TrialRefusal("counter_inconsistent", f"{scenario_id} lacks exact reuse evidence")
        elif spec.expectation == "inflight_join":
            if counters["provider_executions"] != 1 or counters["inflight_joins"] < 1:
                raise TrialRefusal("counter_inconsistent", f"{scenario_id} lacks join evidence")
        elif spec.expectation == "execute_after_change":
            if counters["provider_executions"] < 2 or counters["exact_reuse_hits"] != 0:
                raise TrialRefusal("counter_inconsistent", f"{scenario_id} did not invalidate")
        elif spec.expectation == "cancellation_recovery":
            if counters["provider_executions"] < 1 or counters["cancellations"] < 1:
                raise TrialRefusal("counter_inconsistent", f"{scenario_id} lacks recovery evidence")
        if spec.eligible_for_speedup:
            speedup = cold["elapsed_ms"] / warm["elapsed_ms"]
    elif classification == "incorrect_hit":
        if counters["false_hits"] < 1 or outcome != "incorrect":
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} incorrect hit is inconsistent")
    elif classification == "safe_refusal":
        if admitted or counters["false_hits"] != 0 or outcome != "not_observed":
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} refusal is inconsistent")
    elif classification == "incomplete_trial":
        if admitted or outcome != "incomplete":
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} incomplete state is inconsistent")
    elif classification == "unsupported_host_profile":
        if admitted or outcome != "not_observed":
            raise TrialRefusal("classification_inconsistent", f"{scenario_id} unsupported state is inconsistent")

    return (
        {
            "scenario_id": scenario_id,
            "bindings": bindings,
            "request_digest": request_digest,
            "classification": classification,
            "admitted": admitted,
            "cold": cold,
            "warm": warm,
            "counters": counters,
            "user_observed_outcome": outcome,
            "dependency_proof_sha256": dependency,
            "notes": notes,
        },
        speedup,
    )


def validate_trial(value: Any, *, inspect_local: bool) -> tuple[dict[str, Any], dict[str, Any], str]:
    trial = _require_object(
        value,
        "trial",
        {
            "schema",
            "spec_version",
            "trial_id",
            "participant",
            "release",
            "repository",
            "platform",
            "agent",
            "scenarios",
            "authenticated_delivery_receipts",
        },
    )
    if trial["schema"] != TRIAL_SCHEMA or trial["spec_version"] != SPEC_VERSION:
        raise TrialRefusal("unknown_schema", "trial schema or specification version is unsupported")
    trial_id = _require_sha256(trial["trial_id"], "trial.trial_id")

    participant = _require_object(
        trial["participant"],
        "trial.participant",
        {"participant_id", "outside_user", "local_simulation"},
    )
    participant_id = _require_sha256(participant["participant_id"], "participant.participant_id")
    outside_user = _require_bool(participant["outside_user"], "participant.outside_user")
    local_simulation = _require_bool(participant["local_simulation"], "participant.local_simulation")
    if local_simulation and outside_user:
        raise TrialRefusal("participant_inconsistent", "a local simulation cannot be an outside user")

    release = _require_object(
        trial["release"],
        "trial.release",
        {
            "binary_path",
            "binary_sha256",
            "source_git_sha",
            "harness_sha256",
            "publisher_authentication",
        },
    )
    binary_path = _require_string(release["binary_path"], "release.binary_path")
    binary_sha256 = _require_sha256(release["binary_sha256"], "release.binary_sha256")
    source_git_sha = _require_git_sha(release["source_git_sha"], "release.source_git_sha")
    supplied_harness_sha = _require_sha256(release["harness_sha256"], "release.harness_sha256")
    if supplied_harness_sha != harness_sha256():
        raise TrialRefusal("harness_sha256_mismatch", "trial was not produced for these harness bytes")
    if inspect_local:
        binary_observation = _observe_executable(binary_path, binary_sha256, "again_binary")
    else:
        binary_observation = {"canonical_path": binary_path, "sha256": binary_sha256, "size": None}

    publisher = _require_object(
        release["publisher_authentication"],
        "publisher_authentication",
        {"status", "artifact_sha256", "source_git_sha", "attestation_sha256", "verifier", "issuer", "workflow"},
    )
    publisher_status = _require_string(publisher["status"], "publisher_authentication.status")
    if publisher_status not in PUBLISHER_STATUSES:
        raise TrialRefusal("invalid_publisher_status", "publisher status is unsupported")
    normalized_publisher = {
        "status": publisher_status,
        "artifact_sha256": _require_sha256(publisher["artifact_sha256"], "publisher.artifact_sha256"),
        "source_git_sha": _require_git_sha(publisher["source_git_sha"], "publisher.source_git_sha"),
        "attestation_sha256": _require_sha256(publisher["attestation_sha256"], "publisher.attestation_sha256"),
        "verifier": _require_string(publisher["verifier"], "publisher.verifier"),
        "issuer": _require_string(publisher["issuer"], "publisher.issuer"),
        "workflow": _require_string(publisher["workflow"], "publisher.workflow"),
    }
    if (
        normalized_publisher["artifact_sha256"] != binary_sha256
        or normalized_publisher["source_git_sha"] != source_git_sha
    ):
        raise TrialRefusal("publisher_binding_mismatch", "publisher statement is not bound to the release")

    repository = _require_object(
        trial["repository"],
        "trial.repository",
        {"canonical_path", "git_sha", "dirty", "identity_sha256"},
    )
    repository_path = _require_string(repository["canonical_path"], "repository.canonical_path")
    repository_git_sha = _require_git_sha(repository["git_sha"], "repository.git_sha")
    repository_dirty = _require_bool(repository["dirty"], "repository.dirty")
    repository_identity = _require_sha256(repository["identity_sha256"], "repository.identity_sha256")
    if repository_dirty:
        raise TrialRefusal("repository_dirty", "dirty repositories are not trial evidence")
    if inspect_local:
        observed_repository = observe_repository(repository_path, repository_git_sha)
        if observed_repository["identity_sha256"] != repository_identity:
            raise TrialRefusal("repository_identity_mismatch", "repository identity changed")

    host = _require_object(trial["platform"], "trial.platform", {"system", "machine", "release"})
    normalized_host = {
        key: _require_string(host[key], f"platform.{key}") for key in ("system", "machine", "release")
    }
    if inspect_local:
        current_host = {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        }
        if normalized_host != current_host:
            raise TrialRefusal("platform_binding_mismatch", "trial platform does not match this host")

    agent = _require_object(
        trial["agent"],
        "trial.agent",
        {"client", "version", "executable_path", "executable_sha256"},
    )
    agent_client = _require_string(agent["client"], "agent.client", identifier=True)
    agent_version = _require_string(agent["version"], "agent.version")
    agent_path = _require_string(agent["executable_path"], "agent.executable_path")
    agent_sha256 = _require_sha256(agent["executable_sha256"], "agent.executable_sha256")
    if inspect_local:
        agent_observation = _observe_executable(agent_path, agent_sha256, "agent_binary")
    else:
        agent_observation = {"canonical_path": agent_path, "sha256": agent_sha256, "size": None}

    receipts = trial["authenticated_delivery_receipts"]
    if not isinstance(receipts, list):
        raise TrialRefusal("invalid_schema", "authenticated_delivery_receipts must be a list")
    if receipts:
        raise TrialRefusal(
            "delivery_receipt_authority_unsupported",
            "this harness has no authenticated production receipt verifier",
        )

    scenarios = trial["scenarios"]
    if not isinstance(scenarios, list) or len(scenarios) != EXPECTED_SCENARIOS:
        raise TrialRefusal("scenario_count", "trial must contain exactly ten scenarios")
    indexed: dict[str, Any] = {}
    for raw in scenarios:
        if not isinstance(raw, dict):
            raise TrialRefusal("invalid_schema", "each scenario must be an object")
        scenario_id = raw.get("scenario_id")
        if not isinstance(scenario_id, str) or scenario_id not in SCENARIO_BY_ID:
            raise TrialRefusal("unknown_scenario", "trial contains an unknown scenario")
        if scenario_id in indexed:
            raise TrialRefusal("duplicate_scenario", f"duplicate scenario: {scenario_id}")
        indexed[scenario_id] = raw

    normalized_scenarios: list[dict[str, Any]] = []
    speedups: list[float] = []
    for spec in SCENARIOS:
        if spec.scenario_id not in indexed:
            raise TrialRefusal("missing_scenario", f"missing scenario: {spec.scenario_id}")
        normalized, speedup = _validate_scenario(
            indexed[spec.scenario_id],
            spec,
            participant_id=participant_id,
            binary_sha256=binary_sha256,
            repository_identity=repository_identity,
        )
        normalized_scenarios.append(normalized)
        if speedup is not None:
            speedups.append(speedup)

    classifications = Counter(item["classification"] for item in normalized_scenarios)
    counters = Counter()
    for scenario in normalized_scenarios:
        counters.update(scenario["counters"])
    classification = "pass"
    if (
        not outside_user
        or local_simulation
        or publisher_status != "verified"
        or classifications["incorrect_hit"]
        or classifications["incomplete_trial"]
    ):
        classification = "non_pass"

    normalized_trial = {
        "schema": TRIAL_SCHEMA,
        "spec_version": SPEC_VERSION,
        "trial_id": trial_id,
        "participant": {
            "participant_id": participant_id,
            "outside_user": outside_user,
            "local_simulation": local_simulation,
        },
        "release": {
            "binary_path": binary_observation["canonical_path"],
            "binary_sha256": binary_sha256,
            "source_git_sha": source_git_sha,
            "harness_sha256": supplied_harness_sha,
            "publisher_authentication": normalized_publisher,
        },
        "repository": {
            "canonical_path": repository_path,
            "git_sha": repository_git_sha,
            "dirty": False,
            "identity_sha256": repository_identity,
        },
        "platform": normalized_host,
        "agent": {
            "client": agent_client,
            "version": agent_version,
            "executable_path": agent_observation["canonical_path"],
            "executable_sha256": agent_sha256,
        },
        "scenarios": normalized_scenarios,
        "authenticated_delivery_receipts": [],
    }
    summary = {
        "scenario_count": len(normalized_scenarios),
        "classifications": dict(sorted(classifications.items())),
        "admitted_successes": classifications["admitted_success"],
        "safe_refusals": classifications["safe_refusal"],
        "incorrect_hits": classifications["incorrect_hit"],
        "provider_executions": counters["provider_executions"],
        "exact_reuse_hits": counters["exact_reuse_hits"],
        "inflight_joins": counters["inflight_joins"],
        "cancellations": counters["cancellations"],
        "false_hits": counters["false_hits"],
        "eligible_speedups": [round(item, 9) for item in speedups],
        "delivery_confirmed_bytes_saved": 0,
        "delivery_confirmed_tokens_saved": 0,
        "delivery_savings_reason": "no_authenticated_production_receipt_verifier",
    }
    return normalized_trial, summary, classification


def verify_trial_document(value: Any, input_sha256: str, *, inspect_local: bool = True) -> dict[str, Any]:
    normalized, summary, classification = validate_trial(value, inspect_local=inspect_local)
    return {
        "schema": VERIFIED_SCHEMA,
        "harness_version": HARNESS_VERSION,
        "harness_sha256": harness_sha256(),
        "input_sha256": _require_sha256(input_sha256, "input_sha256"),
        "classification": classification,
        "trial": normalized,
        "summary": summary,
        "authority": {
            "participant_identity_cryptographically_verified": False,
            "outside_user_independence_cryptographically_verified": False,
            "publisher_statement_independently_reverified": False,
            "delivery_receipt_authority": False,
            "token_savings_authority": False,
            "production_qualification": False,
        },
    }


def _median(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def aggregate_verified_documents(documents: Sequence[Any], input_hashes: Sequence[str]) -> dict[str, Any]:
    if len(documents) != EXPECTED_USERS or len(input_hashes) != EXPECTED_USERS:
        raise TrialRefusal("participant_count", "aggregate requires exactly five verified reports")
    participants: set[str] = set()
    trials: set[str] = set()
    release_bindings: set[tuple[str, str, str]] = set()
    classifications: Counter[str] = Counter()
    counters: Counter[str] = Counter()
    speedups: list[float] = []
    trial_records: list[dict[str, Any]] = []
    publisher_verified = True
    outside_users = True

    for index, raw in enumerate(documents):
        report = _require_object(
            raw,
            f"verified[{index}]",
            {"schema", "harness_version", "harness_sha256", "input_sha256", "classification", "trial", "summary", "authority"},
        )
        if report["schema"] != VERIFIED_SCHEMA or report["harness_version"] != HARNESS_VERSION:
            raise TrialRefusal("unknown_verified_schema", "verified report schema is unsupported")
        if report["harness_sha256"] != harness_sha256():
            raise TrialRefusal("harness_sha256_mismatch", "verified report uses different harness bytes")
        _require_sha256(input_hashes[index], f"verified[{index}].file_sha256")
        _require_sha256(report["input_sha256"], f"verified[{index}].input_sha256")
        normalized, expected_summary, expected_classification = validate_trial(
            report["trial"], inspect_local=False
        )
        if report["summary"] != expected_summary or report["classification"] != expected_classification:
            raise TrialRefusal("verified_report_mismatch", "verified report does not reconcile")
        authority = _require_object(
            report["authority"],
            f"verified[{index}].authority",
            {
                "participant_identity_cryptographically_verified",
                "outside_user_independence_cryptographically_verified",
                "publisher_statement_independently_reverified",
                "delivery_receipt_authority",
                "token_savings_authority",
                "production_qualification",
            },
        )
        if any(value is not False for value in authority.values()):
            raise TrialRefusal("authority_claim", "verified input claims unsupported authority")

        participant = normalized["participant"]
        participant_id = participant["participant_id"]
        trial_id = normalized["trial_id"]
        if participant_id in participants:
            raise TrialRefusal("duplicate_participant", "participant IDs must be distinct")
        if trial_id in trials:
            raise TrialRefusal("duplicate_trial", "trial IDs must be distinct")
        participants.add(participant_id)
        trials.add(trial_id)
        outside_users &= participant["outside_user"] and not participant["local_simulation"]
        release = normalized["release"]
        release_bindings.add(
            (release["binary_sha256"], release["source_git_sha"], release["harness_sha256"])
        )
        publisher_verified &= release["publisher_authentication"]["status"] == "verified"
        classifications.update(expected_summary["classifications"])
        for key in (
            "provider_executions",
            "exact_reuse_hits",
            "inflight_joins",
            "cancellations",
            "false_hits",
        ):
            counters[key] += expected_summary[key]
        speedups.extend(expected_summary["eligible_speedups"])
        trial_records.append(
            {
                "participant_id": participant_id,
                "trial_id": trial_id,
                "verified_report_sha256": input_hashes[index],
                "classification": expected_classification,
            }
        )

    if len(release_bindings) != 1:
        raise TrialRefusal("conflicting_release_identity", "all users must test the exact same release")
    attempts = sum(classifications.values())
    if attempts != EXPECTED_ATTEMPTS:
        raise TrialRefusal("attempt_count", "aggregate did not reconcile exactly 50 attempts")
    median_speedup = _median(speedups)
    admitted = classifications["admitted_success"]
    false_hits = counters["false_hits"]
    gate_passed = (
        outside_users
        and publisher_verified
        and admitted >= MINIMUM_ADMITTED_SUCCESSES
        and median_speedup is not None
        and median_speedup >= MINIMUM_MEDIAN_WARM_SPEEDUP
        and classifications["incorrect_hit"] == 0
        and false_hits == 0
        and classifications["incomplete_trial"] == 0
    )
    release_binary, source_sha, bound_harness = next(iter(release_bindings))
    return {
        "schema": AGGREGATE_SCHEMA,
        "spec_version": SPEC_VERSION,
        "harness_version": HARNESS_VERSION,
        "harness_sha256": harness_sha256(),
        "classification": "pass" if gate_passed else "non_pass",
        "reason": "gate_thresholds_satisfied" if gate_passed else "gate_thresholds_not_satisfied",
        "release": {
            "binary_sha256": release_binary,
            "source_git_sha": source_sha,
            "harness_sha256": bound_harness,
            "publisher_authentication_attested_verified": publisher_verified,
        },
        "trial_reports": sorted(trial_records, key=lambda item: item["participant_id"]),
        "summary": {
            "users": len(participants),
            "attempts": attempts,
            "admitted_successes": admitted,
            "safe_refusals": classifications["safe_refusal"],
            "incorrect_hits": classifications["incorrect_hit"],
            "incomplete_trials": classifications["incomplete_trial"],
            "unsupported_host_profiles": classifications["unsupported_host_profile"],
            "provider_executions": counters["provider_executions"],
            "exact_reuse_hits": counters["exact_reuse_hits"],
            "inflight_joins": counters["inflight_joins"],
            "cancellations": counters["cancellations"],
            "false_hits": false_hits,
            "eligible_speedup_samples": len(speedups),
            "median_warm_speedup": None if median_speedup is None else round(median_speedup, 9),
            "delivery_confirmed_bytes_saved": 0,
            "delivery_confirmed_tokens_saved": 0,
        },
        "gate": {
            "required_users": EXPECTED_USERS,
            "required_attempts": EXPECTED_ATTEMPTS,
            "minimum_admitted_successes": MINIMUM_ADMITTED_SUCCESSES,
            "minimum_median_warm_speedup": MINIMUM_MEDIAN_WARM_SPEEDUP,
            "maximum_incorrect_hits": 0,
        },
        "authority": {
            "participant_independence_basis": "distinct_participant_attestations_not_cryptographic_identity",
            "publisher_authentication_basis": "participant_supplied_external_verifier_statement",
            "local_simulation_is_outside_user_evidence": False,
            "delivery_receipt_authority": False,
            "token_savings_authority": False,
            "production_qualification": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    spec = subparsers.add_parser("spec", help="write the frozen ten-scenario specification")
    spec.add_argument("--output", type=pathlib.Path, required=True)
    verify = subparsers.add_parser("verify", help="verify one local participant trial")
    verify.add_argument("--input", type=pathlib.Path, required=True)
    verify.add_argument("--output", type=pathlib.Path, required=True)
    aggregate = subparsers.add_parser("aggregate", help="aggregate exactly five verified trials")
    aggregate.add_argument("--input", type=pathlib.Path, action="append", required=True)
    aggregate.add_argument("--output", type=pathlib.Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "spec":
            write_json_exclusive(arguments.output, trial_specification())
            return 0
        if arguments.command == "verify":
            value, input_sha = read_json_file(arguments.input)
            report = verify_trial_document(value, input_sha, inspect_local=True)
            write_json_exclusive(arguments.output, report)
            return 0 if report["classification"] == "pass" else 77
        if arguments.command == "aggregate":
            documents: list[dict[str, Any]] = []
            input_hashes: list[str] = []
            for path in arguments.input:
                document, document_sha = read_json_file(path)
                documents.append(document)
                input_hashes.append(document_sha)
            report = aggregate_verified_documents(documents, input_hashes)
            write_json_exclusive(arguments.output, report)
            return 0 if report["classification"] == "pass" else 77
        raise TrialRefusal("unknown_command", "unknown command")
    except TrialRefusal as error:
        refusal = {"classification": "malformed", "code": error.code, "message": str(error)}
        sys.stderr.buffer.write(canonical_json_bytes(refusal))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
