#!/usr/bin/env python3
"""Validate compact release inputs and emit a bounded workflow-local summary.

The emitted JSON is deliberately non-authoritative when detached from the
GitHub Actions run that performed the cryptographic verification.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import tarfile
from typing import Any
import zlib


SCHEMA = "again.release-verification-summary.v1"
ATTESTATION_SCHEMA = "again.attestation-verification.v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_SUMMARY_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = MAX_ARTIFACT_BYTES + 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
WORKFLOW_PATH = ".github/workflows/release.yml"
HARNESS_PATHS = (
    "packaging/homebrew/generate_formula.py",
    "scripts/export_release_evidence.py",
    "scripts/package_release.py",
    "scripts/verify_published_release.sh",
    "scripts/verify_release.sh",
)
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
    attestation.add_argument("--repository", required=True)
    attestation.add_argument("--tag", required=True)
    attestation.add_argument("--source-commit", required=True)
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
    evidence.add_argument("--harness-root", required=True, type=Path)
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
        document = json.loads(content, object_pairs_hook=duplicate_rejecting_object)
        validate_json_shape(document, description)
        return document
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise SystemExit(f"{description} is not strict UTF-8 JSON: {error}") from error


def validate_json_shape(document: Any, description: str) -> None:
    nodes = 0
    stack = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError(f"{description} exceeds the JSON node limit")
        if depth > MAX_JSON_DEPTH:
            raise ValueError(f"{description} exceeds the JSON depth limit")
        if isinstance(value, dict):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


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


def bounded_string(value: Any, description: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SystemExit(f"{description} is invalid")
    return value


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


def archive_member_evidence(compressed: bytes) -> dict[str, Any]:
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        payload = decompressor.decompress(compressed, MAX_TAR_BYTES + 1)
    except (EOFError, zlib.error) as error:
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
                or member.size > MAX_ARTIFACT_BYTES
                or member.mode != 0o755
                or member.uid != 0
                or member.gid != 0
                or member.uname != "root"
                or member.gname != "root"
                or member.pax_headers
            ):
                raise SystemExit("release archive member metadata is not normalized")
            source = archive.extractfile(member)
            if source is None:
                raise SystemExit("release archive member is unreadable")
            digest = hashlib.sha256()
            total = 0
            while block := source.read(1024 * 1024):
                total += len(block)
                if total > MAX_ARTIFACT_BYTES:
                    raise SystemExit("release archive member exceeds its fixed limit")
                digest.update(block)
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
    return {
        "mode": "0755",
        "name": "again",
        "sha256": digest.hexdigest(),
        "size_bytes": total,
    }


def certificate_identity(
    certificate: Any, repository: str, tag: str, source_commit: str
) -> dict[str, str]:
    if not isinstance(certificate, dict) or not certificate:
        raise SystemExit("attestation verification result lacks a certificate")
    owner = repository.split("/", 1)[0]
    source_ref = f"refs/tags/{tag}"
    expected = {
        "githubWorkflowRef": source_ref,
        "githubWorkflowRepository": repository,
        "githubWorkflowSHA": source_commit,
        "githubWorkflowTrigger": "push",
        "issuer": OIDC_ISSUER,
        "runnerEnvironment": "github-hosted",
        "sourceRepositoryDigest": source_commit,
        "sourceRepositoryOwnerURI": f"https://github.com/{owner}",
        "sourceRepositoryRef": source_ref,
        "sourceRepositoryURI": f"https://github.com/{repository}",
        "subjectAlternativeName": (
            f"https://github.com/{repository}/{WORKFLOW_PATH}@{source_ref}"
        ),
    }
    for key, expected_value in expected.items():
        if bounded_string(certificate.get(key), f"certificate {key}") != expected_value:
            raise SystemExit(f"certificate {key} is inconsistent")
    invocation = bounded_string(
        certificate.get("buildInvocationID"), "certificate buildInvocationID"
    )
    invocation_pattern = re.compile(
        rf"^https://github\.com/{re.escape(repository)}/actions/runs/"
        r"([1-9][0-9]*)/attempts/([1-9][0-9]*)$"
    )
    if invocation_pattern.fullmatch(invocation) is None:
        raise SystemExit("certificate build invocation identity is inconsistent")
    repository_identifier = bounded_string(
        certificate.get("sourceRepositoryIdentifier"),
        "certificate sourceRepositoryIdentifier",
        32,
    )
    owner_identifier = bounded_string(
        certificate.get("sourceRepositoryOwnerIdentifier"),
        "certificate sourceRepositoryOwnerIdentifier",
        32,
    )
    visibility = bounded_string(
        certificate.get("sourceRepositoryVisibilityAtSigning"),
        "certificate sourceRepositoryVisibilityAtSigning",
        16,
    )
    if (
        re.fullmatch(r"[1-9][0-9]*", repository_identifier) is None
        or re.fullmatch(r"[1-9][0-9]*", owner_identifier) is None
        or visibility not in {"internal", "private", "public"}
    ):
        raise SystemExit("certificate immutable repository identity is invalid")
    return {
        "build_invocation_id": invocation,
        "github_workflow_ref": expected["githubWorkflowRef"],
        "github_workflow_repository": expected["githubWorkflowRepository"],
        "github_workflow_sha": expected["githubWorkflowSHA"],
        "github_workflow_trigger": expected["githubWorkflowTrigger"],
        "issuer": expected["issuer"],
        "runner_environment": expected["runnerEnvironment"],
        "source_repository_digest": expected["sourceRepositoryDigest"],
        "source_repository_identifier": repository_identifier,
        "source_repository_owner_identifier": owner_identifier,
        "source_repository_owner_uri": expected["sourceRepositoryOwnerURI"],
        "source_repository_ref": expected["sourceRepositoryRef"],
        "source_repository_uri": expected["sourceRepositoryURI"],
        "source_repository_visibility_at_signing": visibility,
        "subject_alternative_name": expected["subjectAlternativeName"],
    }


def harness_evidence(root: Path) -> dict[str, Any]:
    if (
        not root.is_absolute()
        or ".." in root.parts
        or not root.is_dir()
        or root.is_symlink()
    ):
        raise SystemExit("harness root must be an absolute non-symlink directory")
    components = []
    aggregate = hashlib.sha256()
    for relative in HARNESS_PATHS:
        path = root / relative
        content = read_regular(path, MAX_ARTIFACT_BYTES, f"release harness {relative}")
        digest = hashlib.sha256(content).hexdigest()
        components.append({"path": relative, "sha256": digest})
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\0")
    return {"components": components, "sha256": aggregate.hexdigest()}


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
    validate_release_identity(args.repository, args.tag, args.source_commit)
    document = strict_json(args.input, MAX_JSON_BYTES, "attestation verification output")
    if not isinstance(document, list) or not document or len(document) > 30:
        raise SystemExit("attestation verification output must be a bounded non-empty array")
    timestamp_count = 0
    publisher: dict[str, str] | None = None
    for entry in document:
        result = entry.get("verificationResult") if isinstance(entry, dict) else None
        signature = result.get("signature") if isinstance(result, dict) else None
        certificate = signature.get("certificate") if isinstance(signature, dict) else None
        timestamps = result.get("verifiedTimestamps") if isinstance(result, dict) else None
        statement = result.get("statement") if isinstance(result, dict) else None
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if (
            not isinstance(timestamps, list)
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
        observed_publisher = certificate_identity(
            certificate, args.repository, args.tag, args.source_commit
        )
        if publisher is not None and observed_publisher != publisher:
            raise SystemExit("verified attestations disagree on publisher identity")
        publisher = observed_publisher
        timestamp_count += len(timestamps)
    if publisher is None:
        raise SystemExit("attestation verification did not authenticate a publisher")
    summary = {
        "certificate_present": True,
        "name": args.subject_name,
        "predicate_type": PREDICATE_TYPE,
        "publisher": publisher,
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


def validate_release_identity(repository: str, tag: str, source_commit: str) -> None:
    if SEMVER_TAG.fullmatch(tag) is None or len(tag) > 128:
        raise SystemExit("release tag is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise SystemExit("source commit must be 40 lowercase hexadecimal characters")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise SystemExit("GitHub repository is invalid")


def validate_identity(args: argparse.Namespace) -> None:
    validate_release_identity(args.repository, args.tag, args.source_commit)
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
    artifacts_by_name: dict[str, dict[str, Any]] = {}
    for name in names:
        path = args.artifact_dir / name
        content = read_regular(path, MAX_ARTIFACT_BYTES, f"release artifact {name}")
        detail: dict[str, Any] = {
            "name": name,
            "sha256": hashlib.sha256(content).hexdigest(),
            "size_bytes": len(content),
        }
        if name.endswith(".tar.gz"):
            prefix = f"again-{args.tag}-"
            target = name[len(prefix) : -len(".tar.gz")]
            member = archive_member_evidence(content)
            detail["binary_sha256"] = member["sha256"]
            detail["members"] = [member]
            detail["target"] = target
        artifacts_by_name[name] = detail
    digests = {name: detail["sha256"] for name, detail in artifacts_by_name.items()}

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
            "publisher",
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
            or not isinstance(summary["publisher"], dict)
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

    publishers = {
        json.dumps(summary["publisher"], sort_keys=True)
        for summary in summaries.values()
    }
    if len(publishers) != 1:
        raise SystemExit("attestation summaries disagree on publisher identity")
    publisher = next(iter(summaries.values()))["publisher"]
    authenticated_publisher = certificate_identity(
        {
            "buildInvocationID": publisher.get("build_invocation_id"),
            "githubWorkflowRef": publisher.get("github_workflow_ref"),
            "githubWorkflowRepository": publisher.get("github_workflow_repository"),
            "githubWorkflowSHA": publisher.get("github_workflow_sha"),
            "githubWorkflowTrigger": publisher.get("github_workflow_trigger"),
            "issuer": publisher.get("issuer"),
            "runnerEnvironment": publisher.get("runner_environment"),
            "sourceRepositoryDigest": publisher.get("source_repository_digest"),
            "sourceRepositoryIdentifier": publisher.get(
                "source_repository_identifier"
            ),
            "sourceRepositoryOwnerIdentifier": publisher.get(
                "source_repository_owner_identifier"
            ),
            "sourceRepositoryOwnerURI": publisher.get("source_repository_owner_uri"),
            "sourceRepositoryRef": publisher.get("source_repository_ref"),
            "sourceRepositoryURI": publisher.get("source_repository_uri"),
            "sourceRepositoryVisibilityAtSigning": publisher.get(
                "source_repository_visibility_at_signing"
            ),
            "subjectAlternativeName": publisher.get("subject_alternative_name"),
        },
        args.repository,
        args.tag,
        args.source_commit,
    )
    invocation_match = re.fullmatch(
        rf"https://github\.com/{re.escape(args.repository)}/actions/runs/"
        r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
        authenticated_publisher["build_invocation_id"],
    )
    if invocation_match is None:
        raise SystemExit("publisher workflow run identity is invalid")

    artifacts = []
    for name in names:
        summary = summaries[name]
        detail = dict(artifacts_by_name[name])
        detail["attestation"] = {
            "certificate_present": True,
            "status": "verified",
            "verified_attestations": summary["verified_attestations"],
            "verified_timestamps": summary["verified_timestamps"],
        }
        artifacts.append(detail)
    harness = harness_evidence(args.harness_root)
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
        "publisher": {
            "identity": authenticated_publisher,
            "status": "authenticated",
            "workflow_run": {
                "attempt": int(invocation_match.group(2)),
                "id": int(invocation_match.group(1)),
                "url": authenticated_publisher["build_invocation_id"],
            },
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
            "harness": harness,
            "platform": {
                "architecture": platform.machine(),
                "kernel_release": platform.release(),
                "operating_system": platform.system(),
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
            },
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
