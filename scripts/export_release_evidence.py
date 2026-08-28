#!/usr/bin/env python3
"""Validate compact release inputs and emit a bounded workflow-local summary.

The emitted JSON is deliberately non-authoritative when detached from the
GitHub Actions run that performed the cryptographic verification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any


SCHEMA = "again.release-verification-summary.v1"
ATTESTATION_SCHEMA = "again.attestation-verification.v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024
SEMVER_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$"
)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)

    attestation = commands.add_parser("attestation")
    attestation.add_argument("--input", required=True, type=Path)
    attestation.add_argument("--subject-name", required=True)
    attestation.add_argument("--subject-digest", required=True)
    attestation.add_argument("--output", required=True, type=Path)

    evidence = commands.add_parser("evidence")
    evidence.add_argument("--release-metadata", required=True, type=Path)
    evidence.add_argument("--attestation-dir", required=True, type=Path)
    evidence.add_argument("--artifact-dir", required=True, type=Path)
    evidence.add_argument("--repository", required=True)
    evidence.add_argument("--tag", required=True)
    evidence.add_argument("--source-commit", required=True)
    evidence.add_argument("--verified-at", required=True)
    evidence.add_argument("--github-cli-version", required=True)
    evidence.add_argument("--output", required=True, type=Path)
    return root


def duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def open_regular(path: Path, maximum: int, description: str) -> tuple[int, os.stat_result]:
    if not path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"{description} path must be absolute and traversal-free")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{description} is unavailable: {error}") from error
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode):
        os.close(descriptor)
        raise SystemExit(f"{description} must be a regular non-symlink file")
    if info.st_size <= 0 or info.st_size > maximum:
        os.close(descriptor)
        raise SystemExit(f"{description} size is outside the fixed limit")
    return descriptor, info


def stable_identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def read_regular(path: Path, maximum: int, description: str) -> bytes:
    descriptor, before = open_regular(path, maximum, description)
    try:
        content = bytearray()
        while len(content) <= maximum:
            block = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        after = os.fstat(descriptor)
    except OSError as error:
        raise SystemExit(f"{description} cannot be read: {error}") from error
    finally:
        os.close(descriptor)
    if (
        len(content) > maximum
        or len(content) != before.st_size
        or stable_identity(before) != stable_identity(after)
    ):
        raise SystemExit(f"{description} changed while it was read")
    return bytes(content)


def strict_json(path: Path, maximum: int, description: str) -> Any:
    try:
        content = read_regular(path, maximum, description).decode("utf-8")
        return json.loads(content, object_pairs_hook=duplicate_rejecting_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"{description} is not strict UTF-8 JSON: {error}") from error


def validate_name(name: str) -> None:
    if (
        not name
        or len(name.encode("utf-8")) > 255
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise SystemExit("artifact name is unsafe")


def validate_digest(digest: str, description: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise SystemExit(f"{description} must be 64 lowercase hexadecimal characters")


def attestation_name_matches(statement_name: Any, release_name: str) -> bool:
    if not isinstance(statement_name, str) or "\\" in statement_name:
        return False
    parts = statement_name.split("/")
    return (
        bool(parts)
        and parts[-1] == release_name
        and all(part not in {"", ".", ".."} for part in parts)
        and not any(
            ord(character) < 32 or ord(character) == 127 for character in statement_name
        )
    )


def write_exclusive(path: Path, content: bytes) -> None:
    if len(content) > MAX_EVIDENCE_BYTES:
        raise SystemExit("evidence output exceeds the fixed size limit")
    if not path.is_absolute() or ".." in path.parts:
        raise SystemExit("output path must be absolute and traversal-free")
    if path.name in {"", ".", ".."}:
        raise SystemExit("output name is invalid")
    directory_flags = os.O_RDONLY
    directory_flags |= getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_descriptor = os.open(path.parent, directory_flags)
    except OSError as error:
        raise SystemExit(f"output directory is unavailable: {error}") from error
    temporary_name = f".{path.name}.{secrets.token_hex(16)}"
    temporary_descriptor = -1
    try:
        try:
            temporary_descriptor = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            view = memoryview(content)
            while view:
                written = os.write(temporary_descriptor, view)
                if written <= 0:
                    raise OSError("short evidence write")
                view = view[written:]
            os.fsync(temporary_descriptor)
            os.close(temporary_descriptor)
            temporary_descriptor = -1
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.fsync(parent_descriptor)
        except FileExistsError as error:
            raise SystemExit("output appeared during generation; refusing to overwrite it") from error
        except OSError as error:
            raise SystemExit(f"evidence output cannot be installed: {error}") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=parent_descriptor)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent_descriptor)


def directory_entries(path: Path, description: str) -> list[Path]:
    try:
        return list(path.iterdir())
    except OSError as error:
        raise SystemExit(f"{description} cannot be read: {error}") from error


def artifact_hash(path: Path) -> str:
    return hashlib.sha256(
        read_regular(path, MAX_ARTIFACT_BYTES, f"release artifact {path.name}")
    ).hexdigest()


def expected_names(tag: str) -> list[str]:
    return sorted(
        [
            "SHA256SUMS",
            "again-alpha.rb",
            f"again-{tag}-aarch64-apple-darwin.tar.gz",
            f"again-{tag}-aarch64-unknown-linux-gnu.tar.gz",
            f"again-{tag}-source.cdx.json",
            f"again-{tag}-x86_64-apple-darwin.tar.gz",
            f"again-{tag}-x86_64-unknown-linux-gnu.tar.gz",
        ]
    )


def summarize_attestation(args: argparse.Namespace) -> None:
    validate_name(args.subject_name)
    validate_digest(args.subject_digest, "subject digest")
    document = strict_json(args.input, MAX_JSON_BYTES, "attestation verification output")
    if not isinstance(document, list) or not document or len(document) > 30:
        raise SystemExit("attestation verification output must be a bounded non-empty array")
    timestamp_count = 0
    for entry in document:
        result = entry.get("verificationResult") if isinstance(entry, dict) else None
        signature = result.get("signature") if isinstance(result, dict) else None
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        timestamps = result.get("verifiedTimestamps") if isinstance(result, dict) else None
        statement = result.get("statement") if isinstance(result, dict) else None
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if (
            not isinstance(certificate, dict)
            or not certificate
            or not isinstance(timestamps, list)
            or not timestamps
            or not all(isinstance(timestamp, dict) and timestamp for timestamp in timestamps)
            or not isinstance(subjects, list)
            or statement.get("predicateType") != PREDICATE_TYPE
        ):
            raise SystemExit("attestation verification result lacks required verified fields")
        matching = False
        for subject in subjects:
            subject_digest = subject.get("digest") if isinstance(subject, dict) else None
            if (
                isinstance(subject_digest, dict)
                and attestation_name_matches(subject.get("name"), args.subject_name)
                and subject_digest.get("sha256") == args.subject_digest
            ):
                matching = True
        if not matching:
            raise SystemExit("attestation subject identity or digest is inconsistent")
        timestamp_count += len(timestamps)
    summary = {
        "certificate_present": True,
        "name": args.subject_name,
        "predicate_type": PREDICATE_TYPE,
        "schema": ATTESTATION_SCHEMA,
        "sha256": args.subject_digest,
        "status": "verified",
        "verified_attestations": len(document),
        "verified_timestamps": timestamp_count,
    }
    write_exclusive(
        args.output,
        (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def release_asset_names(document: Any, tag: str) -> list[str]:
    if not isinstance(document, dict) or set(document) != {
        "assets",
        "isDraft",
        "isImmutable",
        "isPrerelease",
        "tagName",
    }:
        raise SystemExit("release metadata has an unexpected shape")
    expected_prerelease = "-" in tag
    if (
        document["tagName"] != tag
        or document["isDraft"] is not False
        or document["isImmutable"] is not True
        or document["isPrerelease"] is not expected_prerelease
        or not isinstance(document["assets"], list)
    ):
        raise SystemExit("release identity, immutability, or kind is inconsistent")
    names: list[str] = []
    for asset in document["assets"]:
        name = asset.get("name") if isinstance(asset, dict) else None
        if not isinstance(name, str):
            raise SystemExit("release metadata contains an invalid asset")
        validate_name(name)
        names.append(name)
    if len(names) != len(set(names)) or sorted(names) != expected_names(tag):
        raise SystemExit("release metadata does not contain the exact asset inventory")
    return sorted(names)


def validate_identity(args: argparse.Namespace) -> None:
    if SEMVER_TAG.fullmatch(args.tag) is None or len(args.tag) > 128:
        raise SystemExit("release tag is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None:
        raise SystemExit("source commit must be 40 lowercase hexadecimal characters")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is None:
        raise SystemExit("GitHub repository is invalid")
    try:
        timestamp = datetime.strptime(args.verified_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise SystemExit("verification timestamp must be canonical UTC") from error
    if timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") != args.verified_at:
        raise SystemExit("verification timestamp must be canonical UTC")
    try:
        gh_version = args.github_cli_version.encode("ascii")
    except UnicodeEncodeError as error:
        raise SystemExit("GitHub CLI version must be ASCII") from error
    if (
        len(gh_version) > 128
        or re.fullmatch(r"gh version [0-9]+\.[0-9]+\.[0-9]+[^\r\n]*", args.github_cli_version)
        is None
    ):
        raise SystemExit("GitHub CLI version is malformed")


def export_evidence(args: argparse.Namespace) -> None:
    validate_identity(args)
    metadata = strict_json(args.release_metadata, MAX_JSON_BYTES, "release metadata")
    names = release_asset_names(metadata, args.tag)
    if not args.artifact_dir.is_dir() or args.artifact_dir.is_symlink():
        raise SystemExit("artifact directory must be a regular directory")
    observed = sorted(
        path.name for path in directory_entries(args.artifact_dir, "artifact directory")
    )
    if observed != names:
        raise SystemExit("artifact directory does not contain the exact release inventory")
    digests = {name: artifact_hash(args.artifact_dir / name) for name in names}

    if not args.attestation_dir.is_dir() or args.attestation_dir.is_symlink():
        raise SystemExit("attestation summary directory must be a regular directory")
    summary_paths = sorted(
        directory_entries(args.attestation_dir, "attestation summary directory")
    )
    if len(summary_paths) != len(names):
        raise SystemExit("attestation summary count is inconsistent")
    summaries: dict[str, dict[str, Any]] = {}
    for path in summary_paths:
        summary = strict_json(path, MAX_SUMMARY_BYTES, "attestation summary")
        if not isinstance(summary, dict) or set(summary) != {
            "certificate_present",
            "name",
            "predicate_type",
            "schema",
            "sha256",
            "status",
            "verified_attestations",
            "verified_timestamps",
        }:
            raise SystemExit("attestation summary has an unexpected shape")
        name = summary["name"]
        if not isinstance(name, str):
            raise SystemExit("attestation summary name is invalid")
        validate_name(name)
        if (
            name in summaries
            or name not in digests
            or summary["schema"] != ATTESTATION_SCHEMA
            or summary["sha256"] != digests[name]
            or summary["predicate_type"] != PREDICATE_TYPE
            or summary["status"] != "verified"
            or summary["certificate_present"] is not True
            or not isinstance(summary["verified_attestations"], int)
            or isinstance(summary["verified_attestations"], bool)
            or summary["verified_attestations"] <= 0
            or not isinstance(summary["verified_timestamps"], int)
            or isinstance(summary["verified_timestamps"], bool)
            or summary["verified_timestamps"] <= 0
        ):
            raise SystemExit("attestation summary identity or verification state is invalid")
        summaries[name] = summary
    if sorted(summaries) != names:
        raise SystemExit("attestation summaries do not match the release inventory")

    artifacts = []
    for name in names:
        summary = summaries[name]
        artifacts.append(
            {
                "attestation": {
                    "certificate_present": True,
                    "status": "verified",
                    "verified_attestations": summary["verified_attestations"],
                    "verified_timestamps": summary["verified_timestamps"],
                },
                "name": name,
                "sha256": digests[name],
            }
        )
    evidence = {
        "authority": {
            "independent_release_verification": False,
            "requires_enclosing_github_actions_run": True,
        },
        "artifacts": artifacts,
        "publisher_policy": {
            "cert_oidc_issuer": OIDC_ISSUER,
            "deny_self_hosted_runners": True,
            "predicate_type": PREDICATE_TYPE,
            "repository": args.repository,
            "signer_digest": args.source_commit,
            "signer_workflow": f"{args.repository}/.github/workflows/release.yml",
            "source_digest": args.source_commit,
            "source_ref": f"refs/tags/{args.tag}",
        },
        "release": {
            "draft": False,
            "immutable": True,
            "prerelease": "-" in args.tag,
            "repository": args.repository,
            "source_commit": args.source_commit,
            "tag": args.tag,
        },
        "schema": SCHEMA,
        "verification": {
            "evidence_exporter": SCHEMA,
            "github_cli": args.github_cli_version,
            "release_verifier": "again.release-verifier.v1",
            "verification_completed_at": args.verified_at,
        },
    }
    write_exclusive(
        args.output,
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def main() -> None:
    args = parser().parse_args()
    if args.command == "attestation":
        summarize_attestation(args)
    else:
        export_evidence(args)


if __name__ == "__main__":
    main()
