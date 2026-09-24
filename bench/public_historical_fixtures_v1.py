"""Two pinned public Python bug fixes for multi-repository Codex evaluation."""

from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess

import agent_gateway_editable_pair as pair
import external_historical_fixture_v1 as external


CASES = {
    "camelcase-number-separator": {
        "name": "camelcase",
        "url": "https://github.com/sindresorhus/camelcase.git",
        "parent": "c9fa59df2e32611c5c71d0f219f661fa8e1dfdf8",
        "fix": "e7dccc901ce645138a52dd5945e245773b4684c5",
        "archive": "2e5cdf65814e52ee44add2c7766eecbe0d90f5f795f2a74ec0be06c8ff0edbb7",
        "target": "index.js",
        "test": "tests/test_again_oracle.mjs",
        "prompt": (
            "Fix camelCase so a digit-plus-letter segment before an underscore or hyphen "
            "stays intact: b2b_registration_request should become b2bRegistrationRequest, "
            "including PascalCase. Preserve normal numeric camelization. Edit only index.js. "
            "Run node --test tests/test_again_oracle.mjs after editing, then stop."
        ),
        "prior_task": (
            "Inspect the existing number and separator post-processing in index.js. Run "
            "rg -n 'NUMBERS_AND_IDENTIFIER|SEPARATORS_AND_IDENTIFIER' index.js and report "
            "the matching lines. Do not edit files or run tests."
        ),
        "oracle": '''import test from 'node:test';
import assert from 'node:assert/strict';
import camelCase from '../index.js';

test('number before underscore remains part of the word', () => {
  assert.equal(camelCase('b2b_registration_request'), 'b2bRegistrationRequest');
  assert.equal(camelCase('b2b_registration_b2b_request'), 'b2bRegistrationB2bRequest');
});
test('number before hyphen remains part of the word', () => {
  assert.equal(camelCase('b2b-registration-request'), 'b2bRegistrationRequest');
});
test('PascalCase and ordinary controls', () => {
  assert.equal(camelCase('b2b_registration_request', {pascalCase: true}), 'B2bRegistrationRequest');
  assert.equal(camelCase('foo-bar'), 'fooBar');
  assert.equal(camelCase('foo2bar'), 'foo2Bar');
});
''',
        "failures": ("number before underscore", "number before hyphen", "PascalCase and ordinary controls"),
    },
    "packaging-empty-platforms": {
        "name": "packaging",
        "url": "https://github.com/pypa/packaging.git",
        "parent": "b097450461523502ada842f98274449ad74ff1ff",
        "fix": "4e79787a31c99348649bb0dafee2a5078d3595be",
        "archive": "9810b42f2d7d2771a4da124c1ba2a354b2c8c3f5801591a231e910aa0243aaeb",
        "target": "src/packaging/tags.py",
        "test": "tests/test_again_oracle.py",
        "prompt": (
            "Fix the packaging tag generators so an explicitly empty platforms iterable stays "
            "empty rather than falling back to host platform tags. Preserve normal behavior "
            "when platforms is omitted. Edit only src/packaging/tags.py. Run "
            "python3 -m unittest discover -s tests -p test_again_oracle.py after editing, then stop."
        ),
        "prior_task": (
            "Inspect the current platform fallback in src/packaging/tags.py. Run "
            "rg -n 'platforms = list' src/packaging/tags.py and report its matching lines. "
            "Do not edit files or run tests."
        ),
        "oracle": '''import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from packaging import tags


class AgainEmptyPlatformsOracle(unittest.TestCase):
    def test_cpython_explicit_empty(self):
        with mock.patch.object(tags, "platform_tags", side_effect=AssertionError("fallback called")):
            self.assertEqual(list(tags.cpython_tags((3, 11), abis=["abi"], platforms=[])), [])

    def test_generic_explicit_empty(self):
        with mock.patch.object(tags, "platform_tags", side_effect=AssertionError("fallback called")):
            self.assertEqual(list(tags.generic_tags("cp311", ["abi"], [])), [])

    def test_compatible_keeps_any_tags(self):
        with mock.patch.object(tags, "platform_tags", side_effect=AssertionError("fallback called")):
            self.assertEqual(list(tags.compatible_tags((3,), "cp3", [])), [
                tags.Tag("cp3", "none", "any"), tags.Tag("py3", "none", "any")])
''',
        "failures": ("test_cpython_explicit_empty", "test_generic_explicit_empty", "test_compatible_keeps_any_tags"),
    },
    "tomlkit-array-slice": {
        "name": "tomlkit",
        "url": "https://github.com/sdispater/tomlkit.git",
        "parent": "7ab7469addd60e03ca3bfbb1287642e8d771e1c0",
        "fix": "4b38becd75405e0f38ef3e47e9839eb407591c8a",
        "archive": "907a3a7d681686276541c56a59ca83c570db1da5bd3816fa9f218bac393262c5",
        "target": "tomlkit/items.py",
        "test": "tests/test_again_oracle.py",
        "prompt": (
            "Fix tomlkit array slice assignment so unsupported slices raise ValueError before "
            "mutating the array or its rendered TOML. Normal indexed assignment must continue "
            "to work. Edit only tomlkit/items.py. Run "
            "python3 -m unittest discover -s tests -p test_again_oracle.py after editing, then stop."
        ),
        "prior_task": (
            "Inspect the slice-assignment rejection in tomlkit/items.py. Run "
            "rg -n 'slice assignment is not supported' tomlkit/items.py and report its "
            "matching line. Do not edit files or run tests."
        ),
        "oracle": '''import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from tomlkit import parse


class AgainArraySliceOracle(unittest.TestCase):
    def test_slice_does_not_mutate(self):
        original = "a = [\\n    1, # first\\n    2,\\n    3,\\n]\\n"
        for index, replacement in ((slice(None), [4, 5, 6]),
                                   (slice(1, 2), [4, 5]),
                                   (slice(1, 1), [4]),
                                   (slice(None, None, -1), [4, 5, 6])):
            doc = parse(original)
            array = doc["a"]
            with self.assertRaisesRegex(ValueError, "slice assignment is not supported"):
                array[index] = replacement
            self.assertEqual(array, [1, 2, 3])
            self.assertEqual(doc.as_string(), original)
            array[-1] = 4
            self.assertEqual(array, [1, 2, 4])
''',
        "failures": ("test_slice_does_not_mutate",),
    },
}


def configure(name: str) -> None:
    case = CASES[name]
    is_node = name == "camelcase-number-separator"
    executable = shutil.which("node" if is_node else "python3")
    if executable is None:
        raise RuntimeError("public fixture requires its language runtime")
    checkout = external.source_checkout(case["name"], case["url"], case["parent"])
    pair.MAX_FIXTURE_FILES = max(pair.MAX_FIXTURE_FILES, 512)
    pair.TARGET_ORACLE_MODE = "behavior"
    pair.TARGET = case["target"]
    pair.TEST = case["test"]
    pair.BUGGY = subprocess.run(["git", "-C", str(checkout), "show",
                                 f"{case['parent']}:{case['target']}"],
                                capture_output=True, check=True, timeout=20).stdout.decode()
    pair.FIXED = subprocess.run(["git", "-C", str(checkout), "show",
                                 f"{case['fix']}:{case['target']}"],
                                capture_output=True, check=True, timeout=20).stdout.decode()
    pair.PROMPT = case["prompt"]
    pair.TEST_COMMAND = ((executable, "--test", case["test"]) if is_node else
                         (executable, "-m", "unittest", "discover", "-s", "tests",
                          "-p", "test_again_oracle.py"))
    pair.FIXTURE = {
        "upstream": case["url"], "parentGitSha": case["parent"],
        "fixGitSha": case["fix"], "archiveSha256": case["archive"],
        "oracleSha256": hashlib.sha256(case["oracle"].encode()).hexdigest(),
    }
    pair.create_fixture = lambda root: external.create_fixture(
        root, name=case["name"], url=case["url"], parent_sha=case["parent"],
        archive_sha256=case["archive"], test_path=case["test"],
        oracle=case["oracle"], expected_failures=case["failures"])
    pair.run_tests = external.run_tests
