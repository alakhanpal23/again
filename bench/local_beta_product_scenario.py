#!/usr/bin/env python3
"""Compose and verify the 12-step packaged-product beta scenario.

The producer accepts only concrete reports from the native package smoke,
daemon lifecycle driver, product E2E, and 100-client chaos harness. It also
runs the locked Rust qualification suite before publishing one private,
validator-clean scenario report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping

if __package__ in {None, ""}:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from bench import agent_gateway_chaos_soak as chaos
from bench import local_beta_gate as gate


class ScenarioFailure(RuntimeError):
    pass


def verify_source_checkout(repository: pathlib.Path, source_git_sha: str) -> None:
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
        raise ScenarioFailure("scenario source checkout is dirty or does not match --source-git-sha")


def load(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024 * 1024:
        raise ScenarioFailure("evidence input is not a bounded regular file")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ScenarioFailure("evidence input is malformed") from error
    if not isinstance(value, dict):
        raise ScenarioFailure("evidence input is not an object")
    return value


def passed(report: Mapping[str, Any], schema: str) -> None:
    classification = report.get("classification")
    if (
        report.get("schema") != schema
        or not isinstance(classification, Mapping)
        or classification.get("type") != "pass"
    ):
        raise ScenarioFailure(f"non-pass evidence for {schema}")


def sha256_file(path: pathlib.Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ScenarioFailure("archive is not a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def checked(command: list[str], *, cwd: pathlib.Path, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=900,
        check=False,
    )
    if completed.returncode != 0:
        raise ScenarioFailure(f"qualification command failed: {pathlib.Path(command[0]).name}")
    return completed


def install_upgrade_uninstall(
    repository: pathlib.Path,
    initial_archive: pathlib.Path,
    upgraded_archive: pathlib.Path,
    initial_digest: str,
    upgraded_digest: str,
) -> dict[str, Any]:
    root = pathlib.Path(tempfile.mkdtemp(prefix="again-beta-upgrade-", dir="/tmp")).resolve()
    root.chmod(0o700)
    destination = root / "install" / "again"
    destination.parent.mkdir(mode=0o700)
    environment = os.environ.copy()
    environment["HOME"] = str(root / "home")
    environment["AGAIN_HOME"] = str(root / "state")
    pathlib.Path(environment["HOME"]).mkdir(mode=0o700)
    try:
        observed: list[str] = []
        for index, (archive, expected_binary) in enumerate(
            ((initial_archive, initial_digest), (upgraded_archive, upgraded_digest))
        ):
            artifacts = root / f"artifacts-{index}"
            artifacts.mkdir(mode=0o700)
            copied = artifacts / archive.name
            shutil.copyfile(archive, copied)
            archive_digest = sha256_file(copied)
            (artifacts / "SHA256SUMS").write_text(
                f"{archive_digest}  {copied.name}\n", encoding="ascii"
            )
            checked(
                [
                    "sh",
                    str(repository / "scripts" / "install.sh"),
                    "--version",
                    "v" + archive.name.split("again-v", 1)[1].split("-aarch64-", 1)[0]
                    if "-aarch64-" in archive.name
                    else "v" + archive.name.split("again-v", 1)[1].split("-x86_64-", 1)[0],
                    "--artifact-dir",
                    str(artifacts),
                    "--dest",
                    str(destination),
                ],
                cwd=root,
                environment=environment,
            )
            observed_digest = sha256_file(destination)
            if observed_digest != expected_binary:
                raise ScenarioFailure("installed binary identity differs from native evidence")
            observed.append(observed_digest)
        checked(
            ["sh", str(repository / "scripts" / "uninstall.sh"), "--dest", str(destination)],
            cwd=root,
            environment=environment,
        )
        if destination.exists() or destination.is_symlink():
            raise ScenarioFailure("uninstall retained the managed binary")
        return {
            "initial_binary_sha256": observed[0],
            "upgraded_binary_sha256": observed[1],
            "isolated_home": True,
            "private_permissions": root.stat().st_mode & 0o777 == 0o700,
            "uninstalled": True,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


def step(name: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {"name": name, "status": "pass", "evidence": dict(evidence)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--initial-archive", required=True, type=pathlib.Path)
    parser.add_argument("--upgraded-archive", required=True, type=pathlib.Path)
    parser.add_argument("--initial-native-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--upgraded-native-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--lifecycle-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--product-e2e-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--chaos-evidence", required=True, type=pathlib.Path)
    parser.add_argument("--source-git-sha", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        parser.error(f"refusing to replace existing evidence: {output}")

    repository = pathlib.Path(__file__).resolve().parent.parent
    verify_source_checkout(repository, args.source_git_sha)
    initial = load(args.initial_native_evidence.resolve(strict=True))
    upgraded = load(args.upgraded_native_evidence.resolve(strict=True))
    lifecycle = load(args.lifecycle_evidence.resolve(strict=True))
    product = load(args.product_e2e_evidence.resolve(strict=True))
    chaos_report = load(args.chaos_evidence.resolve(strict=True))
    gate.validate_native(initial)
    gate.validate_native(upgraded)
    gate.validate_chaos(chaos_report)
    passed(lifecycle, "again.local-beta-lifecycle-e2e.v1")
    passed(product, "again.agent-gateway-product-e2e.v1")

    # The v1 subordinate reports do not yet carry executable observations for
    # client apply/remove, quota maintenance, daemon upgrade draining, and the
    # complete adversarial matrix. Never manufacture those release claims from
    # a successful unit-test command or setup-plan-only evidence.
    raise ScenarioFailure(
        "executable 12-step evidence is incomplete: client apply/remove, quota "
        "maintenance, upgrade draining, and adversarial probe reports are required"
    )

    upgraded_binary = upgraded["installed_binary_sha256"]
    initial_binary = initial["installed_binary_sha256"]
    initial_archive = args.initial_archive.resolve(strict=True)
    upgraded_archive = args.upgraded_archive.resolve(strict=True)
    if (
        initial.get("target") != upgraded.get("target")
        or sha256_file(initial_archive) != initial.get("archive_sha256")
        or sha256_file(upgraded_archive) != upgraded.get("archive_sha256")
    ):
        raise ScenarioFailure("native archives do not match their retained evidence")
    if initial_binary == upgraded_binary:
        raise ScenarioFailure("upgrade evidence did not change binary identity")
    if not all(
        value == upgraded_binary
        for value in (
            lifecycle.get("binary_sha256"),
            product.get("binary", {}).get("sha256"),
            chaos_report.get("binary", {}).get("sha256"),
        )
    ):
        raise ScenarioFailure("integrated evidence refers to different binaries")
    if not all(
        value == args.source_git_sha
        for value in (
            upgraded.get("source_git_sha"),
            lifecycle.get("source_git_sha"),
            product.get("source", {}).get("git_sha"),
            chaos_report.get("source_git_sha"),
        )
    ):
        raise ScenarioFailure("integrated evidence refers to different source revisions")

    upgrade = install_upgrade_uninstall(
        repository,
        initial_archive,
        upgraded_archive,
        initial_binary,
        upgraded_binary,
    )
    cargo = shutil.which("cargo")
    if cargo is None:
        raise ScenarioFailure("cargo is required for locked adversarial qualification")
    checked([cargo, "test", "--locked", "--all-features"], cwd=repository)
    checked(
        [
            cargo,
            "test",
            "--locked",
            "--test",
            "generated_differential",
            "generated_differential_100k",
            "--",
            "--ignored",
            "--exact",
        ],
        cwd=repository,
    )

    scenarios = product.get("scenarios", {})
    if not all(name in scenarios for name in ("relevant_mutation", "irrelevant_mutation")):
        raise ScenarioFailure("repository mutation evidence is incomplete")
    lifecycle_completion = lifecycle["lifecycle_completion"]
    if lifecycle_completion.get("transition_history_count") != 5:
        raise ScenarioFailure("lifecycle transition history is incomplete")
    timeout_seconds = chaos_report.get("product_measurements", {}).get("timings", {}).get(
        "timeout_seconds"
    )
    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds < 600:
        raise ScenarioFailure("retained chaos qualification is shorter than 600 seconds")

    report = {
        "schema": gate.SCENARIO_SCHEMA,
        "classification": {"type": "pass", "code": "all_beta_scenarios_passed"},
        "provenance": {
            "source_git_sha": args.source_git_sha,
            "initial_binary_sha256": initial_binary,
            "upgraded_binary_sha256": upgraded_binary,
            "target": upgraded["target"],
        },
        "privacy": {
            "deterministic_screening": True,
            "raw_payloads_retained": False,
            "diagnostic_content_scan_passed": True,
        },
        "steps": [
            step(
                "isolated_install",
                {
                    "archive_sha256": initial["archive_sha256"],
                    "installed_binary_sha256": initial_binary,
                    "installer_verified": upgrade["initial_binary_sha256"] == initial_binary,
                    "isolated_home": upgrade["isolated_home"],
                    "private_permissions": upgrade["private_permissions"],
                },
            ),
            step(
                "client_setup",
                {
                    "clients": {
                        name: {"fake_probe": True, "real_probe": True, "applied": True, "verified": True}
                        for name in ("claude", "codex")
                    },
                    "direct_config_edits": 0,
                },
            ),
            step(
                "automatic_daemon_clients",
                {
                    "automatic_start": True,
                    "client_count": 2,
                    "daemon_process_count": 1,
                    "authenticated_handshakes": 2,
                },
            ),
            step("task_alias_convergence", lifecycle["task_alias_convergence"]),
            step("task_graph_readiness", lifecycle["task_graph_readiness"]),
            step("context_exchange", lifecycle["context_exchange"]),
            step("leader_takeover", lifecycle["leader_takeover"]),
            step("lifecycle_completion", lifecycle_completion),
            step("daemon_restart_recovery", lifecycle["daemon_restart_recovery"]),
            step(
                "repository_mutations",
                {
                    "relevant_task_delivery_retired": scenarios["relevant_mutation"].get("old_result_served") is False,
                    "relevant_leases_retired": True,
                    "unrelated_verified_facts_preserved": scenarios["irrelevant_mutation"].get("classification")
                    == "reuse_supported_by_dependency_proof",
                },
            ),
            step(
                "quota_maintenance",
                {
                    "maintenance_mode": True,
                    "new_durable_write_refused": True,
                    "export_private_0600": True,
                    "export_no_overwrite": True,
                    "automatic_evictions": 0,
                    "maintenance_operations": {
                        name: True
                        for name in ("delete", "doctor", "export", "gc", "inspect", "prune", "stats")
                    },
                },
            ),
            step(
                "upgrade_remove_uninstall",
                {
                    "binary_mismatch_refused_or_drained": True,
                    "active_sessions_silently_killed": 0,
                    "codex_removed_exact": True,
                    "claude_removed_exact": True,
                    "uninstalled": upgrade["uninstalled"],
                    "upgraded_binary_sha256": upgraded_binary,
                },
            ),
        ],
        "adversarial": {
            "concurrent_clients": chaos_report["concurrency"],
            "repository_count": 2,
            "retained_soak_seconds": int(timeout_seconds),
            "probes": {name: True for name in gate.ADVERSARIAL_PROBES},
            "safety_counters": {name: 0 for name in gate.ZERO_SAFETY_COUNTERS},
        },
        "source_reports": {
            "initial_native": hashlib.sha256(args.initial_native_evidence.read_bytes()).hexdigest(),
            "upgraded_native": hashlib.sha256(args.upgraded_native_evidence.read_bytes()).hexdigest(),
            "lifecycle": hashlib.sha256(args.lifecycle_evidence.read_bytes()).hexdigest(),
            "product_e2e": hashlib.sha256(args.product_e2e_evidence.read_bytes()).hexdigest(),
            "chaos": hashlib.sha256(args.chaos_evidence.read_bytes()).hexdigest(),
        },
    }
    gate.validate_scenario(report)
    chaos.write_exclusive(output, gate.canonical_json(report))
    print(json.dumps(gate.validate_scenario(report), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ScenarioFailure, gate.GateRefusal, chaos.HarnessRefusal) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(2)
