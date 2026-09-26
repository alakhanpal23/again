#!/usr/bin/env python3
"""Bounded, pinned repository archive setup for historical editable tasks."""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import signal
import subprocess
import tarfile
import tempfile
import time

import agent_gateway_editable_pair as pair


ROOT = pathlib.Path(__file__).resolve().parents[1]


def create_fixture(
    root: pathlib.Path,
    *,
    parent_sha: str,
    archive_sha256: str,
    target: str,
    oracle: str,
    expected_failures: tuple[str, ...],
) -> dict[str, str]:
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", parent_sha],
        capture_output=True, check=True, timeout=30,
    ).stdout
    if hashlib.sha256(archive).hexdigest() != archive_sha256:
        raise RuntimeError("historical repository archive changed")
    count = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            relative = pathlib.PurePosixPath(member.name)
            if (relative.is_absolute() or not relative.parts
                    or any(part in (".", "..") for part in relative.parts)):
                raise RuntimeError("historical archive has an invalid path")
            path = root.joinpath(*relative.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and member.size <= pair.MAX_FIXTURE_FILE_BYTES:
                count += 1
                if count > pair.MAX_FIXTURE_FILES:
                    raise RuntimeError("historical archive has too many files")
                path.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise RuntimeError("historical archive file unavailable")
                path.write_bytes(source.read())
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise RuntimeError("historical archive has an unsupported entry")
    source = root / target
    source.write_text(source.read_text() + oracle)
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, timeout=15)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, timeout=30)
    subprocess.run(
        ["git", "-c", "user.name=Again Benchmark", "-c", "user.email=benchmark@localhost",
         "commit", "--quiet", "-m", "Historical pre-fix fixture"],
        cwd=root, check=True, timeout=30,
    )
    before = pair.snapshot(root)
    failed = subprocess.run(
        pair.TEST_COMMAND, cwd=root, capture_output=True, text=True, timeout=300,
    )
    output = failed.stdout + failed.stderr
    if failed.returncode != 101 or not all(name in output for name in expected_failures):
        raise RuntimeError("historical pre-fix regressions did not fail as expected")
    if pair.snapshot(root) != before:
        raise RuntimeError("historical prewarm changed tracked fixture files")
    return before


def run_tests(root: pathlib.Path, timeout: float) -> tuple[bool, float, str]:
    """Run the Rust oracle without limiting compiler artifact file size."""
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            pair.TEST_COMMAND, cwd=root, stdin=subprocess.DEVNULL,
            stdout=stdout, stderr=stderr, start_new_session=True,
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait(timeout=10)
        oversized = any(os.fstat(stream.fileno()).st_size > pair.MAX_CAPTURE_BYTES
                        for stream in (stdout, stderr))
        digest = hashlib.sha256()
        for stream in (stdout, stderr):
            stream.seek(0)
            for block in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(block)
    return returncode == 0 and not timed_out and not oversized, (time.monotonic() - started) * 1000, digest.hexdigest()


def validate_edit(original_validate_edit, root: pathlib.Path,
                  before: dict[str, str], timeout: float, *, target: str, oracle: str) -> dict:
    result = original_validate_edit(root, before, timeout)
    oracle_preserved = (root / target).read_text().endswith(oracle)
    result["oracle_preserved"] = oracle_preserved
    result["passed"] = bool(result["passed"] and oracle_preserved)
    return result
