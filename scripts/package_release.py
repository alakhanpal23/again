#!/usr/bin/env python3
"""Create a release archive with normalized metadata.

The compiled binary itself is not claimed to be bit-for-bit reproducible. This
only removes runner UID/GID, path, mode, gzip timestamp, and tar timestamp from
the packaging layer.
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
from typing import Any
import zlib


MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_TAR_BYTES = MAX_BINARY_BYTES + 1024 * 1024
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
SOURCE_COMMIT = re.compile(r"[0-9a-f]{40}")
SEMVER_TAG = re.compile(
    r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
WORKFLOW_PATH = ".github/workflows/release.yml"
BUILD_TYPE = "https://github.com/Attestations/GitHubActionsWorkflow@v1"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-date-epoch", type=int)
    parser.add_argument("--verify-archive", type=Path)
    parser.add_argument("--verify-sbom", type=Path)
    parser.add_argument("--version")
    parser.add_argument("--provenance-output", type=Path)
    parser.add_argument("--repository")
    parser.add_argument("--tag")
    parser.add_argument("--source-commit")
    parser.add_argument("--workflow-run-id", type=int)
    parser.add_argument("--workflow-run-attempt", type=int)
    return parser.parse_args()


def regular_file(path: Path, maximum: int, description: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise SystemExit(f"{description} is unavailable: {error}") from error
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise SystemExit(f"{description} must be a regular non-symlink file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise SystemExit(f"{description} size is outside the release limit")
    return info


def verify_archive(path: Path) -> None:
    regular_file(path, MAX_BINARY_BYTES, "release archive")
    try:
        compressed_bytes = path.read_bytes()
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = decompressor.decompress(compressed_bytes, MAX_TAR_BYTES + 1)
    except (OSError, EOFError, zlib.error) as error:
        raise SystemExit("release archive is not a complete gzip stream") from error
    if (
        len(payload) > MAX_TAR_BYTES
        or decompressor.unconsumed_tail
        or not decompressor.eof
    ):
        raise SystemExit("release archive expands beyond its fixed limit")
    if decompressor.unused_data:
        raise SystemExit("release archive contains trailing or concatenated gzip data")
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != 1:
                raise SystemExit("release archive must contain exactly one member")
            member = members[0]
            if (
                member.name != "again"
                or not member.isreg()
                or member.linkname
                or member.size <= 0
                or member.size > MAX_BINARY_BYTES
                or member.mode != 0o755
                or member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
                or member.pax_headers
            ):
                raise SystemExit("release archive member metadata is not normalized")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise SystemExit("release archive member is unreadable")
            total = 0
            while block := extracted.read(1024 * 1024):
                total += len(block)
                if total > MAX_BINARY_BYTES:
                    raise SystemExit("release archive member exceeds its fixed limit")
            if total != member.size:
                raise SystemExit("release archive member is truncated")
            padded_size = ((member.size + 511) // 512) * 512
            minimum_end = member.offset_data + padded_size + 1024
    except (tarfile.TarError, OSError) as error:
        raise SystemExit("release archive is not a valid tar stream") from error
    if len(payload) % tarfile.RECORDSIZE != 0 or len(payload) < minimum_end:
        raise SystemExit("release tar stream has invalid record padding")
    if any(payload[minimum_end:]):
        raise SystemExit("release tar stream has trailing non-padding bytes")


def reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def release_core_version(tag: str) -> str:
    if not tag.startswith("v") or len(tag) > 128:
        raise SystemExit("release version must be a bounded v-prefixed tag")
    version = tag[1:]
    core = version.split("-", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise SystemExit("release version core is malformed")
    return core


def verify_sbom(path: Path, version: str) -> None:
    regular_file(path, MAX_SBOM_BYTES, "CycloneDX SBOM")
    try:
        with path.open("r", encoding="utf-8") as source:
            document = json.load(source, object_pairs_hook=reject_duplicate_json_pairs)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit("CycloneDX SBOM is not strict UTF-8 JSON") from error
    if not isinstance(document, dict):
        raise SystemExit("CycloneDX SBOM root must be an object")
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if (
        document.get("bomFormat") != "CycloneDX"
        or document.get("specVersion") != "1.5"
        or not isinstance(component, dict)
        or component.get("name") != "again-cli"
        or component.get("version") != release_core_version(version)
    ):
        raise SystemExit("CycloneDX SBOM identity or version is inconsistent")


def package(binary_path: Path, output: Path, source_date_epoch: int) -> None:
    info = regular_file(binary_path, MAX_BINARY_BYTES, "binary")
    if source_date_epoch < 0:
        raise SystemExit("source date epoch must be non-negative")
    if output.exists() or output.is_symlink():
        raise SystemExit("output already exists; refusing to overwrite it")

    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=source_date_epoch,
            ) as compressed:
                with tarfile.open(
                    mode="w", fileobj=compressed, format=tarfile.USTAR_FORMAT
                ) as archive:
                    member = tarfile.TarInfo("again")
                    member.size = info.st_size
                    member.mode = 0o755
                    member.uid = 0
                    member.gid = 0
                    member.uname = "root"
                    member.gname = "root"
                    member.mtime = source_date_epoch
                    with binary_path.open("rb") as binary:
                        archive.addfile(member, binary)
            raw.flush()
            os.fsync(raw.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise SystemExit("output appeared during packaging; refusing to overwrite it") from error
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def write_provenance(
    output: Path,
    repository: str,
    tag: str,
    source_commit: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> None:
    if (
        REPOSITORY.fullmatch(repository) is None
        or SEMVER_TAG.fullmatch(tag) is None
        or SOURCE_COMMIT.fullmatch(source_commit) is None
        or workflow_run_id <= 0
        or workflow_run_attempt <= 0
    ):
        raise SystemExit("release provenance identity is invalid")
    if output.exists() or output.is_symlink():
        raise SystemExit("provenance output already exists; refusing to overwrite it")
    source_ref = f"refs/tags/{tag}"
    workflow_identity = (
        f"https://github.com/{repository}/{WORKFLOW_PATH}@{source_ref}"
    )
    provenance = {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "repository": repository,
                "sourceRef": source_ref,
                "workflow": WORKFLOW_PATH,
            },
            "internalParameters": {},
            "resolvedDependencies": [
                {
                    "digest": {"gitCommit": source_commit},
                    "uri": f"git+https://github.com/{repository}@{source_ref}",
                }
            ],
        },
        "runDetails": {
            "builder": {"id": workflow_identity},
            "metadata": {
                "invocationId": (
                    f"https://github.com/{repository}/actions/runs/"
                    f"{workflow_run_id}/attempts/{workflow_run_attempt}"
                )
            },
        },
    }
    payload = (json.dumps(provenance, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as raw:
            raw.write(payload)
            raw.flush()
            os.fsync(raw.fileno())
        try:
            os.link(temporary, output)
        except FileExistsError as error:
            raise SystemExit(
                "provenance output appeared; refusing to overwrite it"
            ) from error
        output.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    args = parse_args()
    modes = sum(
        (
            args.binary is not None,
            args.verify_archive is not None,
            args.verify_sbom is not None,
            args.provenance_output is not None,
        )
    )
    if modes != 1:
        raise SystemExit("select exactly one packaging or verification mode")
    if args.binary is not None:
        if (
            args.output is None
            or args.source_date_epoch is None
            or args.version is not None
            or args.repository is not None
            or args.tag is not None
            or args.source_commit is not None
            or args.workflow_run_id is not None
            or args.workflow_run_attempt is not None
        ):
            raise SystemExit("packaging requires --binary, --output, and --source-date-epoch")
        package(args.binary, args.output, args.source_date_epoch)
    elif args.verify_archive is not None:
        if any(
            value is not None
            for value in (
                args.output,
                args.source_date_epoch,
                args.version,
                args.repository,
                args.tag,
                args.source_commit,
                args.workflow_run_id,
                args.workflow_run_attempt,
            )
        ):
            raise SystemExit("archive verification accepts only --verify-archive")
        verify_archive(args.verify_archive)
    elif args.verify_sbom is not None:
        if (
            args.version is None
            or any(
                value is not None
                for value in (
                    args.output,
                    args.source_date_epoch,
                    args.repository,
                    args.tag,
                    args.source_commit,
                    args.workflow_run_id,
                    args.workflow_run_attempt,
                )
            )
        ):
            raise SystemExit("SBOM verification requires --verify-sbom and --version")
        verify_sbom(args.verify_sbom, args.version)
    else:
        if (
            args.repository is None
            or args.tag is None
            or args.source_commit is None
            or args.workflow_run_id is None
            or args.workflow_run_attempt is None
            or any(
                value is not None
                for value in (
                    args.binary,
                    args.output,
                    args.source_date_epoch,
                    args.verify_archive,
                    args.verify_sbom,
                    args.version,
                )
            )
        ):
            raise SystemExit("provenance generation requires its complete identity")
        write_provenance(
            args.provenance_output,
            args.repository,
            args.tag,
            args.source_commit,
            args.workflow_run_id,
            args.workflow_run_attempt,
        )


if __name__ == "__main__":
    main()
