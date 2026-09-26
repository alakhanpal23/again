#!/usr/bin/env python3
"""Pinned pre-fix Again repository and independent Python index regressions."""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess

import agent_gateway_editable_pair as pair
import historical_repo_fixture_core_v1 as core


ROOT = pathlib.Path(__file__).resolve().parents[1]
PARENT_SHA = "39185f9d3ac77363df2b9dd4875ac1137bafb9d8"
FIX_SHA = "146af520fa9350ba4c0af6956519c21e4afa32eb"
ARCHIVE_SHA256 = "56b4c0ced058c4b796b01290b0f74f9a996a4c0d0732facc959dffe51cd02aa8"
TARGET = "src/code_intelligence/extract.rs"
ORACLE = '''

#[cfg(test)]
mod historical_python_quote_oracle {
    use super::*;

    #[test]
    fn closing_triple_quote_at_line_end_preserves_following_code() {
        let mut block = false;
        let mut triple = None;
        assert_eq!(sanitize_line_v1("value = \\\"\\\"\\\"", CodeLanguageV1::Python, &mut block, &mut triple), "value =    ");
        assert_eq!(triple, Some("\\\"\\\"\\\""));
        assert_eq!(sanitize_line_v1("\\\"\\\"\\\"", CodeLanguageV1::Python, &mut block, &mut triple), "   ");
        assert_eq!(triple, None);
        assert_eq!(sanitize_line_v1("next_value = 1", CodeLanguageV1::Python, &mut block, &mut triple), "next_value = 1");
    }

    #[test]
    fn triple_marker_inside_regular_string_does_not_hide_later_code() {
        let mut block = false;
        let mut triple = None;
        let sanitized = sanitize_line_v1("value = '\\\"\\\"\\\"' # comment", CodeLanguageV1::Python, &mut block, &mut triple);
        assert!(sanitized.starts_with("value = "));
        assert_eq!(triple, None);
        assert_eq!(sanitize_line_v1("next_value = 1", CodeLanguageV1::Python, &mut block, &mut triple), "next_value = 1");
    }
}
'''
PROMPT = (
    "Fix the Python code index sanitizer: triple-quote markers at line boundaries can hide "
    "following code or panic, and a marker inside an ordinary string can incorrectly begin "
    "a multiline string. Preserve other language parsing and existing public behavior. "
    "Edit only the implementation of the Python sanitizer. Run "
    "cargo test --locked --lib historical_python_quote_oracle after editing, then stop."
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
        raise RuntimeError("historical Python fixture requires cargo")
    pair.MAX_FIXTURE_FILES = max(pair.MAX_FIXTURE_FILES, 1024)
    pair.TARGET_ORACLE_MODE = "behavior"
    pair.TARGET = TARGET
    pair.TEST = TARGET
    pair.BUGGY = source_at(PARENT_SHA) + ORACLE
    pair.FIXED = source_at(FIX_SHA) + ORACLE
    pair.PROMPT = PROMPT
    pair.TEST_COMMAND = (cargo, "test", "--locked", "--lib", "historical_python_quote_oracle", "--quiet")
    pair.FIXTURE = {
        "parentGitSha": PARENT_SHA,
        "archiveSha256": ARCHIVE_SHA256,
        "oracleSha256": hashlib.sha256(ORACLE.encode()).hexdigest(),
    }
    pair.create_fixture = create_fixture
    pair.run_tests = core.run_tests
    pair.validate_edit = lambda root, before, timeout: core.validate_edit(
        original_validate_edit, root, before, timeout, target=TARGET, oracle=ORACLE,
    )


def create_fixture(root: pathlib.Path) -> dict[str, str]:
    return core.create_fixture(
        root, parent_sha=PARENT_SHA, archive_sha256=ARCHIVE_SHA256,
        target=TARGET, oracle=ORACLE,
        expected_failures=(
            "closing_triple_quote_at_line_end_preserves_following_code",
            "triple_marker_inside_regular_string_does_not_hide_later_code",
        ),
    )
