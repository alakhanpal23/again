"""Pinned public repository fixture with an independent failing Python oracle."""

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


def source_checkout(name: str, url: str, parent_sha: str) -> pathlib.Path:
    cache = pathlib.Path(os.environ.get("AGAIN_BENCH_REPOSITORY_CACHE", "/tmp/again-bench-repositories"))
    cache.mkdir(parents=True, exist_ok=True)
    checkout = cache / name
    if not checkout.exists():
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", url,
                        str(checkout)], check=True, timeout=120)
    remote = subprocess.run(["git", "-C", str(checkout), "remote", "get-url", "origin"],
                            capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if remote != url:
        raise RuntimeError("public fixture cache has a different origin")
    subprocess.run(["git", "-C", str(checkout), "cat-file", "-e", f"{parent_sha}^{{commit}}"],
                   check=True, timeout=30)
    return checkout


def create_fixture(root: pathlib.Path, *, name: str, url: str, parent_sha: str,
                   archive_sha256: str, test_path: str, oracle: str,
                   expected_failures: tuple[str, ...]) -> dict[str, str]:
    checkout = source_checkout(name, url, parent_sha)
    archive = subprocess.run(["git", "-C", str(checkout), "archive", parent_sha],
                             capture_output=True, check=True, timeout=60).stdout
    if hashlib.sha256(archive).hexdigest() != archive_sha256:
        raise RuntimeError("public fixture archive digest changed")
    count = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            relative = pathlib.PurePosixPath(member.name)
            if relative.is_absolute() or not relative.parts or any(part in (".", "..") for part in relative.parts):
                raise RuntimeError("public fixture archive has an invalid path")
            path = root.joinpath(*relative.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile() and member.size <= pair.MAX_FIXTURE_FILE_BYTES:
                count += 1
                if count > pair.MAX_FIXTURE_FILES:
                    raise RuntimeError("public fixture archive has too many files")
                path.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise RuntimeError("public fixture archive file unavailable")
                path.write_bytes(source.read())
                path.chmod(0o755 if member.mode & 0o111 else 0o644)
            else:
                raise RuntimeError("public fixture archive has an unsupported entry")
    test = root / test_path
    if test.exists():
        raise RuntimeError("public fixture oracle path already exists")
    test.parent.mkdir(parents=True, exist_ok=True)
    test.write_text(oracle)
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, timeout=15)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, timeout=30)
    subprocess.run(["git", "-c", "user.name=Again Benchmark", "-c",
                    "user.email=benchmark@localhost", "commit", "--quiet", "-m",
                    "Pinned pre-fix public repository fixture"], cwd=root, check=True, timeout=30)
    before = pair.snapshot(root)
    failed = subprocess.run(pair.TEST_COMMAND, cwd=root, capture_output=True, text=True,
                            timeout=60)
    output = failed.stdout + failed.stderr
    if failed.returncode != 1 or not all(name in output for name in expected_failures):
        raise RuntimeError("public fixture regression did not fail as expected")
    if pair.snapshot(root) != before:
        raise RuntimeError("public fixture prewarm changed tracked files")
    return before


def run_tests(root: pathlib.Path, timeout: float) -> tuple[bool, float, str]:
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(pair.TEST_COMMAND, cwd=root, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait(timeout=10)
        digest = hashlib.sha256()
        oversized = False
        for stream in (stdout, stderr):
            oversized |= os.fstat(stream.fileno()).st_size > pair.MAX_CAPTURE_BYTES
            stream.seek(0)
            for block in iter(lambda: stream.read(64 * 1024), b""):
                digest.update(block)
    return returncode == 0 and not timed_out and not oversized, (time.monotonic() - started) * 1000, digest.hexdigest()
