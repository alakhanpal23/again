#!/usr/bin/env python3
"""Generate or verify the byte-stable Again alpha Homebrew formula."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import stat
import tempfile


MAX_CHECKSUM_BYTES = 1024 * 1024
MAX_FORMULA_BYTES = 128 * 1024
REPOSITORY = "alakhanpal23/again"
TARGETS = (
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
)
ALPHA_TAG = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-alpha\.(0|[1-9][0-9]*)$"
)
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})[ \t]+\*?([^ \t\r\n]+)$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--checksums", required=True, type=Path)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--verify", type=Path)
    return parser.parse_args()


def regular_file(path: Path, maximum: int, description: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as error:
        raise SystemExit(f"{description} is unavailable: {error}") from error
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise SystemExit(f"{description} must be a regular non-symlink file")
    if info.st_size <= 0 or info.st_size > maximum:
        raise SystemExit(f"{description} size is outside the fixed limit")
    try:
        return path.read_bytes()
    except OSError as error:
        raise SystemExit(f"{description} cannot be read: {error}") from error


def release_identity(tag: str, source_commit: str) -> tuple[str, str]:
    match = ALPHA_TAG.fullmatch(tag)
    if match is None or len(tag) > 128:
        raise SystemExit("Homebrew formula generation requires vX.Y.Z-alpha.N")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise SystemExit("source commit must be 40 lowercase hexadecimal characters")
    return tag[1:], ".".join(match.groups()[:3])


def parse_checksums(path: Path, tag: str) -> dict[str, str]:
    raw = regular_file(path, MAX_CHECKSUM_BYTES, "checksum manifest")
    try:
        manifest = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise SystemExit("checksum manifest must be ASCII") from error
    if not manifest.endswith("\n"):
        raise SystemExit("checksum manifest must end with one complete line")
    parsed: dict[str, str] = {}
    for line in manifest.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise SystemExit("checksum manifest contains a malformed entry")
        digest, name = match.groups()
        if name in parsed:
            raise SystemExit("checksum manifest contains a duplicate artifact")
        parsed[name] = digest
    expected = {f"again-{tag}-{target}.tar.gz" for target in TARGETS}
    expected.add(f"again-{tag}-source.cdx.json")
    if set(parsed) != expected:
        raise SystemExit("checksum manifest does not contain the exact release assets")
    return parsed


def render_formula(tag: str, source_commit: str, checksums: Path) -> bytes:
    version, core_version = release_identity(tag, source_commit)
    digests = parse_checksums(checksums, tag)
    template_path = Path(__file__).with_name("again-alpha.rb.in")
    try:
        template = regular_file(
            template_path, MAX_FORMULA_BYTES, "Homebrew formula template"
        ).decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit("Homebrew formula template must be UTF-8") from error
    base_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}"
    replacements = {
        "@VERSION@": version,
        "@CORE_VERSION@": core_version,
        "@SOURCE_COMMIT@": source_commit,
        "@AARCH64_APPLE_URL@": f"{base_url}/again-{tag}-aarch64-apple-darwin.tar.gz",
        "@AARCH64_APPLE_SHA256@": digests[
            f"again-{tag}-aarch64-apple-darwin.tar.gz"
        ],
        "@AARCH64_LINUX_URL@": f"{base_url}/again-{tag}-aarch64-unknown-linux-gnu.tar.gz",
        "@AARCH64_LINUX_SHA256@": digests[
            f"again-{tag}-aarch64-unknown-linux-gnu.tar.gz"
        ],
        "@X86_64_APPLE_URL@": f"{base_url}/again-{tag}-x86_64-apple-darwin.tar.gz",
        "@X86_64_APPLE_SHA256@": digests[
            f"again-{tag}-x86_64-apple-darwin.tar.gz"
        ],
        "@X86_64_LINUX_URL@": f"{base_url}/again-{tag}-x86_64-unknown-linux-gnu.tar.gz",
        "@X86_64_LINUX_SHA256@": digests[
            f"again-{tag}-x86_64-unknown-linux-gnu.tar.gz"
        ],
    }
    for token, value in replacements.items():
        if template.count(token) != 1:
            raise SystemExit(f"formula template token count is invalid: {token}")
        template = template.replace(token, value)
    if re.search(r"@[A-Z0-9_]+@", template):
        raise SystemExit("formula template contains an unresolved token")
    encoded = template.encode("utf-8")
    if len(encoded) > MAX_FORMULA_BYTES:
        raise SystemExit("generated formula exceeds the fixed size limit")
    return encoded


def write_exclusive(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise SystemExit("formula output already exists; refusing to overwrite it")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise SystemExit(
                "formula output appeared during generation; refusing to overwrite it"
            ) from error
        path.chmod(0o644)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    args = parse_args()
    expected = render_formula(args.version, args.source_commit, args.checksums)
    if args.output is not None:
        write_exclusive(args.output, expected)
        return
    actual = regular_file(args.verify, MAX_FORMULA_BYTES, "generated Homebrew formula")
    if actual != expected:
        raise SystemExit("Homebrew formula does not match deterministic generation")


if __name__ == "__main__":
    main()
