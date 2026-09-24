#!/usr/bin/env python3
"""Pinned pre-fix Again repository and independent search-output regressions."""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess

import agent_gateway_editable_pair as pair
import historical_repo_fixture_core_v1 as core


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
    pair.run_tests = core.run_tests
    pair.validate_edit = lambda root, before, timeout: validate_edit(
        original_validate_edit, root, before, timeout
    )


def create_fixture(root: pathlib.Path) -> dict[str, str]:
    return core.create_fixture(
        root, parent_sha=PARENT_SHA, archive_sha256=ARCHIVE_SHA256,
        target=TARGET, oracle=ORACLE,
        expected_failures=("long_matching_line_is_bounded", "total_rendered_matches_are_bounded"),
    )


def validate_edit(original_validate_edit, root: pathlib.Path,
                  before: dict[str, str], timeout: float) -> dict:
    return core.validate_edit(
        original_validate_edit, root, before, timeout, target=TARGET, oracle=ORACLE,
    )
