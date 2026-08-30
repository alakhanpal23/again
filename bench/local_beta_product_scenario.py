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
import pathlib
import subprocess
import sys
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

    # The v1 subordinate reports do not yet carry executable observations for
    # client apply/remove, quota maintenance, daemon upgrade draining, and the
    # complete adversarial matrix. Never manufacture those release claims from
    # a successful unit-test command or setup-plan-only evidence.
    raise ScenarioFailure(
        "executable 12-step evidence is incomplete: client apply/remove, quota "
        "maintenance, upgrade draining, and adversarial probe reports are required"
    )

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ScenarioFailure, gate.GateRefusal, chaos.HarnessRefusal) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(2)
