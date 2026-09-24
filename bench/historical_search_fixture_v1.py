#!/usr/bin/env python3
"""Pinned pre-fix Again repository and independent search-output regressions."""

from __future__ import annotations

import hashlib
import io
import os
import pathlib
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time

import agent_gateway_editable_pair as pair


ROOT = pathlib.Path(__file__).resolve().parents[1]
PARENT_SHA = "337af76ab8c88d8d75802130fd5fa66c6b6e397d"
FIX_SHA = "c747f8bb312ca21a95750055e5ecf898262f49cd"
ARCHIVE_SHA256 = "ad46e7b84dc34c9bd8f98df11d4c77720ac297d0a6aacb875e81a67ce96d7d3d"
TARGET = "src/agent_gateway_runtime.rs"
ORACLE = '''

#[cfg(test)]
mod historical_search_oracle {
    use super::*;

    #[test]
    fn long_matching_line_is_bounded() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("input.txt"), format!("MARK{}\\n", "x".repeat(16_000))).unwrap();
        let root = fs::canonicalize(workspace.path()).unwrap();
        let result = repository_search_v1(&root, &json!({"path":".", "pattern":"MARK", "maxResults":500})).unwrap();
        let match_result = &result["structuredContent"]["matches"][0];
        assert_eq!(match_result["lineTruncated"], true);
        assert!(match_result["text"].as_str().unwrap().len() <= 4 * 1024);
    }

    #[test]
    fn total_rendered_matches_are_bounded() {
        let workspace = tempfile::tempdir().unwrap();
        let line = format!("MARK{}\\n", "x".repeat(4_000));
        fs::write(workspace.path().join("input.txt"), line.repeat(200)).unwrap();
        let root = fs::canonicalize(workspace.path()).unwrap();
        let result = repository_search_v1(&root, &json!({"path":".", "pattern":"MARK", "maxResults":500})).unwrap();
        assert!(result["content"][0]["text"].as_str().unwrap().len() <= 512 * 1024);
        assert_eq!(result["structuredContent"]["truncated"], true);
    }
}
'''
PROMPT = (
    "Fix repo.search in src/agent_gateway_runtime.rs: long matching lines and many matches "
    "can produce oversized responses. Bound each returned snippet to 4 KiB and the total "
    "rendered match output to 512 KiB. Report line and result truncation accurately while "
    "preserving existing search behavior. Edit only src/agent_gateway_runtime.rs. "
    "Run cargo test --locked --lib historical_search_oracle after editing, then stop."
)


def source_at(commit: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{commit}:{TARGET}"],
        capture_output=True, check=True, timeout=15,
    )
    return result.stdout.decode("utf-8")


def configure(original_validate_edit) -> None:
    cargo = shutil.which("cargo")
    if not cargo:
        raise RuntimeError("historical search fixture requires cargo")
    pair.MAX_FIXTURE_FILES = max(pair.MAX_FIXTURE_FILES, 512)
    pair.TARGET_ORACLE_MODE = "behavior"
    pair.TARGET = TARGET
    pair.TEST = TARGET
    pair.BUGGY = source_at(PARENT_SHA) + ORACLE
    pair.FIXED = source_at(FIX_SHA) + ORACLE
    pair.PROMPT = PROMPT
    pair.TEST_COMMAND = (cargo, "test", "--locked", "--lib", "historical_search_oracle", "--quiet")
    pair.FIXTURE = {
        "parentGitSha": PARENT_SHA,
        "archiveSha256": ARCHIVE_SHA256,
        "oracleSha256": hashlib.sha256(ORACLE.encode()).hexdigest(),
    }
    pair.create_fixture = create_fixture
    pair.run_tests = run_tests
    pair.validate_edit = lambda root, before, timeout: validate_edit(
        original_validate_edit, root, before, timeout
    )


def create_fixture(root: pathlib.Path) -> dict[str, str]:
    archive = subprocess.run(
        ["git", "-C", str(ROOT), "archive", PARENT_SHA],
        capture_output=True, check=True, timeout=30,
    ).stdout
    if hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
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
    target = root / TARGET
    target.write_text(target.read_text() + ORACLE)
    subprocess.run(["git", "init", "--quiet", str(root)], check=True, timeout=15)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, timeout=30)
    subprocess.run(
        ["git", "-c", "user.name=Again Benchmark", "-c", "user.email=benchmark@localhost",
         "commit", "--quiet", "-m", "Historical pre-fix fixture"],
        cwd=root, check=True, timeout=30,
    )
    before = pair.snapshot(root)
    failed = subprocess.run(
        pair.TEST_COMMAND, cwd=root, capture_output=True, text=True, timeout=120,
    )
    output = failed.stdout + failed.stderr
    if failed.returncode != 101 or not all(name in output for name in (
        "long_matching_line_is_bounded", "total_rendered_matches_are_bounded"
    )):
        raise RuntimeError("historical pre-fix regressions did not fail as expected")
    if pair.snapshot(root) != before:
        raise RuntimeError("historical prewarm changed tracked fixture files")
    return before


def run_tests(root: pathlib.Path, timeout: float) -> tuple[bool, float, str]:
    """Run the fixed Rust oracle without limiting compiler artifact file size."""
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
                  before: dict[str, str], timeout: float) -> dict:
    result = original_validate_edit(root, before, timeout)
    oracle_preserved = (root / TARGET).read_text().endswith(ORACLE)
    result["oracle_preserved"] = oracle_preserved
    result["passed"] = bool(result["passed"] and oracle_preserved)
    return result
