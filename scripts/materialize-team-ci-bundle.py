#!/usr/bin/env python3
"""Strictly materialize one self-contained team CI secret bundle."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import NoReturn


BUNDLE_NAMESPACE = "again.team-ci-bundle.v1"
PROFILE_NAMESPACE = "again.team-profile.v1"
MAX_BUNDLE_BYTES = 64 * 1024
MAX_PROFILE_BYTES = 64 * 1024
TOKEN_PATTERN = re.compile(
    r"ag1\.[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\.[A-Za-z0-9_-]{32,128}\Z"
)

BUNDLE_KEYS = {"schema_version", "namespace", "profile", "files"}
PROFILE_KEYS = {
    "schema_version",
    "namespace",
    "endpoint_origin",
    "tenant_id",
    "repository_id",
    "generation_id",
    "pinned_root_key_id",
    "pinned_root_public_key_hex",
    "lookup_protocol",
    "lookup_budget",
    "publisher",
}
PUBLISHER_KEYS = {"publish_budget"}
LOOKUP_BUDGET_KEYS = {"max_requests", "max_response_bytes", "total_timeout_ms"}
PUBLISH_BUDGET_KEYS = {"max_requests", "max_transfer_bytes", "total_timeout_ms"}
FILE_KEYS = {
    "read_token",
    "repository_key",
    "sharing_policy",
    "write_token",
    "producer_signing_key",
}
REPOSITORY_KEY_KEYS = {"schema_version", "namespace", "key_id", "key_hex"}
SHARING_POLICY_KEYS = {
    "schema_version",
    "namespace",
    "version",
    "include_prefixes",
    "exclude_prefixes",
    "max_output_bytes",
}
PRODUCER_KEY_KEYS = {
    "schema_version",
    "namespace",
    "key_id",
    "producer_id",
    "secret_key_hex",
}
PATH_KEYS = {
    "read_token_file",
    "repository_key_file",
    "sharing_policy_file",
    "checkpoint_file",
    "runtime_attestation_checkpoint_file",
    "write_token_file",
    "producer_signing_key_file",
}
FILE_LIMITS = {
    "read.token": 256,
    "repository-key.json": 1024,
    "sharing-policy.json": 64 * 1024,
    "write.token": 256,
    "producer-signing-key.json": 2048,
}


def fail(message: str) -> NoReturn:
    print(f"again-team-ci: {message}", file=sys.stderr)
    raise SystemExit(2)


def exact_object(value: object, keys: set[str], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        fail(f"{label} must contain exactly the documented fields")
    return value


def encode_json(value: object, label: str) -> bytes:
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        fail(f"{label} is not bounded JSON data")


def exact_versioned_object(
    value: object, keys: set[str], namespace: str, label: str
) -> dict[str, object]:
    result = exact_object(value, keys, label)
    if (
        type(result["schema_version"]) is not int
        or result["schema_version"] != 1
        or result["namespace"] != namespace
    ):
        fail(f"{label} namespace or schema version is unsupported")
    return result


def identifier(value: object, label: str) -> str:
    if type(value) is not str or not value:
        fail(f"{label} is invalid")
    try:
        encoded_length = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        fail(f"{label} is invalid")
    if encoded_length > 256 or any(
        character.isspace() or unicodedata.category(character) == "Cc"
        for character in value
    ):
        fail(f"{label} is invalid")
    return value


def lower_hex_32(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        fail(f"{label} must contain 32 lower-case hexadecimal bytes")
    return value


def private_directory(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{label} is unavailable")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or path.resolve() != path
    ):
        fail(f"{label} must be a canonical owner-private directory")


def write_private(path: Path, payload: bytes, limit: int, label: str) -> None:
    if not payload or len(payload) > limit:
        fail(f"{label} has an invalid byte length")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        metadata = path.lstat()
    except OSError:
        fail(f"could not create {label}")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or path.resolve() != path
    ):
        fail(f"{label} is not an owner-private single-link file")


def load_bundle() -> dict[str, object]:
    payload = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    if not payload or len(payload) > MAX_BUNDLE_BYTES:
        fail("the CI bundle must contain between 1 and 65536 bytes")

    def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object field")
            result[key] = value
        return result

    def reject_constant(_: str) -> NoReturn:
        raise ValueError("non-finite JSON number")

    try:
        bundle = json.loads(
            payload,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        fail("the CI bundle must be valid UTF-8 JSON")
    return exact_object(bundle, BUNDLE_KEYS, "the CI bundle")


def main() -> None:
    if len(sys.argv) != 2:
        fail("the materializer requires one private-directory path")
    root = Path(sys.argv[1])
    if not root.is_absolute():
        fail("the materializer root must be absolute")
    private_directory(root, "the materializer root")

    bundle = load_bundle()
    if (
        type(bundle["schema_version"]) is not int
        or bundle["schema_version"] != 1
        or bundle["namespace"] != BUNDLE_NAMESPACE
    ):
        fail("the CI bundle namespace or schema version is unsupported")

    raw_profile = bundle["profile"]
    if type(raw_profile) is dict and any(key in raw_profile for key in PATH_KEYS):
        fail("profile-controlled paths must not be supplied in the CI bundle")
    profile = exact_object(raw_profile, PROFILE_KEYS, "profile")
    if (
        type(profile["schema_version"]) is not int
        or profile["schema_version"] != 1
        or profile["namespace"] != PROFILE_NAMESPACE
    ):
        fail("the profile namespace or schema version is unsupported")
    raw_publisher = profile["publisher"]
    if type(raw_publisher) is dict and any(key in raw_publisher for key in PATH_KEYS):
        fail("publisher-controlled paths must not be supplied in the CI bundle")
    publisher = exact_object(raw_publisher, PUBLISHER_KEYS, "publisher")

    files = exact_object(bundle["files"], FILE_KEYS, "files")
    exact_object(profile["lookup_budget"], LOOKUP_BUDGET_KEYS, "lookup_budget")
    exact_object(publisher["publish_budget"], PUBLISH_BUDGET_KEYS, "publish_budget")
    read_token = files["read_token"]
    write_token = files["write_token"]
    if type(read_token) is not str or not TOKEN_PATTERN.fullmatch(read_token):
        fail("read_token does not match the strict ag1 token format")
    if type(write_token) is not str or not TOKEN_PATTERN.fullmatch(write_token):
        fail("write_token does not match the strict ag1 token format")

    repository_key = exact_versioned_object(
        files["repository_key"],
        REPOSITORY_KEY_KEYS,
        "again.repository-encryption-key.v1",
        "repository_key",
    )
    identifier(repository_key["key_id"], "repository_key.key_id")
    lower_hex_32(repository_key["key_hex"], "repository_key.key_hex")

    sharing_policy = exact_versioned_object(
        files["sharing_policy"],
        SHARING_POLICY_KEYS,
        "again.repository-sharing-policy.v1",
        "sharing_policy",
    )
    if (
        type(sharing_policy["version"]) is not str
        or type(sharing_policy["include_prefixes"]) is not list
        or type(sharing_policy["exclude_prefixes"]) is not list
        or any(
            type(prefix) is not str for prefix in sharing_policy["include_prefixes"]
        )
        or any(
            type(prefix) is not str for prefix in sharing_policy["exclude_prefixes"]
        )
        or type(sharing_policy["max_output_bytes"]) is not int
    ):
        fail("sharing_policy fields have invalid JSON types")

    producer_key = exact_versioned_object(
        files["producer_signing_key"],
        PRODUCER_KEY_KEYS,
        "again.producer-signing-key.v1",
        "producer_signing_key",
    )
    identifier(producer_key["key_id"], "producer_signing_key.key_id")
    identifier(producer_key["producer_id"], "producer_signing_key.producer_id")
    lower_hex_32(
        producer_key["secret_key_hex"], "producer_signing_key.secret_key_hex"
    )

    state = root / "state"
    try:
        os.mkdir(state, 0o700)
    except OSError:
        fail("could not create the owner-private state directory")
    private_directory(state, "the state directory")

    paths = {
        "read_token_file": state / "read.token",
        "repository_key_file": state / "repository-key.json",
        "sharing_policy_file": state / "sharing-policy.json",
        "checkpoint_file": state / "trust-checkpoint.json",
        "runtime_attestation_checkpoint_file": state / "runtime-checkpoint.json",
        "write_token_file": state / "write.token",
        "producer_signing_key_file": state / "producer-signing-key.json",
    }
    write_private(
        paths["read_token_file"],
        read_token.encode("ascii"),
        FILE_LIMITS["read.token"],
        "read token",
    )
    write_private(
        paths["repository_key_file"],
        encode_json(files["repository_key"], "repository_key"),
        FILE_LIMITS["repository-key.json"],
        "repository key",
    )
    write_private(
        paths["sharing_policy_file"],
        encode_json(files["sharing_policy"], "sharing_policy"),
        FILE_LIMITS["sharing-policy.json"],
        "sharing policy",
    )
    write_private(
        paths["write_token_file"],
        write_token.encode("ascii"),
        FILE_LIMITS["write.token"],
        "write token",
    )
    write_private(
        paths["producer_signing_key_file"],
        encode_json(files["producer_signing_key"], "producer_signing_key"),
        FILE_LIMITS["producer-signing-key.json"],
        "producer signing key",
    )

    materialized = dict(profile)
    materialized.update(
        {
            "read_token_file": str(paths["read_token_file"]),
            "repository_key_file": str(paths["repository_key_file"]),
            "sharing_policy_file": str(paths["sharing_policy_file"]),
            "checkpoint_file": str(paths["checkpoint_file"]),
            "runtime_attestation_checkpoint_file": str(
                paths["runtime_attestation_checkpoint_file"]
            ),
        }
    )
    materialized_publisher = dict(publisher)
    materialized_publisher.update(
        {
            "write_token_file": str(paths["write_token_file"]),
            "producer_signing_key_file": str(paths["producer_signing_key_file"]),
        }
    )
    materialized["publisher"] = materialized_publisher
    encoded_profile = encode_json(materialized, "the materialized profile")
    write_private(
        state / "profile.json",
        encoded_profile,
        MAX_PROFILE_BYTES,
        "team profile",
    )

    # Persist the directory entries before the offline inspector opens them.
    try:
        descriptor = os.open(state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        fail("could not sync the owner-private state directory")


if __name__ == "__main__":
    main()
