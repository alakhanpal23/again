#!/usr/bin/env python3
"""Fail closed unless Cargo metadata matches Again's reviewed license policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


SCHEMA = "again.dependency-license-audit.v1"
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_PACKAGES = 4096
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
WORKSPACE_LICENSE = "Apache-2.0"

# Exact expressions are intentional: a new spelling or licensing choice gets
# explicit review even when it appears equivalent to an already accepted one.
APPROVED_REGISTRY_LICENSE_EXPRESSIONS = frozenset(
    {
        "(MIT OR Apache-2.0) AND Unicode-3.0",
        "Apache-2.0",
        "Apache-2.0 AND ISC",
        "Apache-2.0 OR BSL-1.0",
        "Apache-2.0 OR ISC OR MIT",
        "Apache-2.0 OR MIT",
        "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
        "BSD-3-Clause",
        "CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception",
        "CC0-1.0 OR MIT-0 OR Apache-2.0",
        "CDLA-Permissive-2.0",
        "ISC",
        "MIT",
        "MIT OR Apache-2.0",
        "MIT OR Apache-2.0 OR BSD-1-Clause",
        "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
        "MIT OR Apache-2.0 OR Zlib",
        "MIT/Apache-2.0",
        "Unicode-3.0",
        "Unlicense OR MIT",
        "Zlib",
        "Zlib OR Apache-2.0 OR MIT",
    }
)


class AuditFailure(ValueError):
    """Cargo metadata is malformed or outside the reviewed policy."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    return parser.parse_args()


def bounded_string(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise AuditFailure(f"invalid bounded {field}")
    return value


def audit_metadata(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict) or document.get("version") != 1:
        raise AuditFailure("Cargo metadata version is not exactly 1")
    packages = document.get("packages")
    workspace_members = document.get("workspace_members")
    if (
        not isinstance(packages, list)
        or not packages
        or len(packages) > MAX_PACKAGES
        or not isinstance(workspace_members, list)
        or not workspace_members
        or len(workspace_members) > MAX_PACKAGES
    ):
        raise AuditFailure("Cargo package or workspace-member bounds are invalid")
    member_ids = {
        bounded_string(member, "workspace member", 2048) for member in workspace_members
    }
    if len(member_ids) != len(workspace_members):
        raise AuditFailure("Cargo metadata repeats a workspace member")

    observed_ids: set[str] = set()
    observed_licenses: set[str] = set()
    registry_count = 0
    workspace_count = 0
    for package in packages:
        if not isinstance(package, dict):
            raise AuditFailure("Cargo metadata contains a non-object package")
        package_id = bounded_string(package.get("id"), "package id", 2048)
        name = bounded_string(package.get("name"), "package name")
        version = bounded_string(package.get("version"), "package version")
        if package_id in observed_ids:
            raise AuditFailure("Cargo metadata repeats a package id")
        observed_ids.add(package_id)
        license_expression = bounded_string(package.get("license"), "license expression")
        observed_licenses.add(license_expression)
        source = package.get("source")
        if package_id in member_ids:
            workspace_count += 1
            if source is not None or license_expression != WORKSPACE_LICENSE:
                raise AuditFailure(
                    f"workspace package {name} {version} violates the license policy"
                )
        else:
            registry_count += 1
            if source != CRATES_IO_SOURCE:
                raise AuditFailure(
                    f"dependency {name} {version} does not come from reviewed crates.io"
                )
            if license_expression not in APPROVED_REGISTRY_LICENSE_EXPRESSIONS:
                raise AuditFailure(
                    f"dependency {name} {version} has an unreviewed license expression"
                )

    if not member_ids.issubset(observed_ids):
        raise AuditFailure("Cargo metadata omits a workspace package")
    return {
        "schema": SCHEMA,
        "status": "pass",
        "packages": len(packages),
        "workspacePackages": workspace_count,
        "registryPackages": registry_count,
        "licenseExpressions": len(observed_licenses),
        "gitDependencies": 0,
        "unlicensedDependencies": 0,
    }


def load_metadata(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise AuditFailure("metadata input is not a regular non-symlink file")
    size = path.stat().st_size
    if size <= 0 or size > MAX_METADATA_BYTES:
        raise AuditFailure("metadata input is empty or exceeds the byte limit")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AuditFailure(f"metadata input repeats JSON key {key}")
            result[key] = value
        return result

    try:
        payload = path.read_bytes().decode("utf-8")
        return json.loads(payload, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditFailure("metadata input is not strict UTF-8 JSON") from error


def main() -> int:
    args = parse_args()
    report = audit_metadata(load_metadata(args.metadata))
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AuditFailure as error:
        print(f"error: dependency license audit refused: {error}", file=sys.stderr)
        sys.exit(1)
